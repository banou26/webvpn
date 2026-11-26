//! The WebTransport carrier: an endpoint whose clients carry their session over HTTP/3.
//!
//! Make an endpoint from [`server_config`] and hand it to [`serve`], which runs every session that arrives on it under
//! a [`Relay`] until the relay stops. A program with an accept loop of its own wraps each accepted [`Connection`] in a
//! [`WtTransport`] and hands it to [`Relay::serve`] with [`UdpCarrier::Bidi`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::task::TaskTracker;
use tracing::debug;
use webvpn_proto::reset;
use wtransport::config::states::WantsIdentity;
use wtransport::config::{QuicTransportConfig, ServerConfigBuilder};
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::quinn::congestion::BbrConfig;
use wtransport::quinn::{self, MtuDiscoveryConfig};
use wtransport::{Connection, Endpoint, Identity, RecvStream, SendStream, ServerConfig, VarInt};

use crate::policy::Policy;
use crate::relay::{Relay, CLOSE_WAIT};
use crate::session::{Setup, UdpCarrier};
use crate::transport::{SendHalf, Transport};

/// The endpoint settings the relay's sessions are tuned for, with `identity` as the endpoint's certificate.
///
/// `bind` says where the endpoint listens: `ServerConfig::builder()` given a bound socket (`with_bind_socket`) or an
/// address. Nothing is bound until an endpoint is made from the result. For `Endpoint::reload_config(config, false)`,
/// which keeps the socket the endpoint holds, any bind does, for example `with_bind_default(0)`.
///
/// The certificate is the caller's to load and renew: build the [`Identity`] (`Identity::load_pemfiles`, or
/// `Identity::self_signed`, whose certificate a browser takes only by its hash and for 14 days at most), and reload the
/// endpoint with a new config when the certificate changes. Open sessions keep theirs.
pub fn server_config(bind: ServerConfigBuilder<WantsIdentity>, identity: Identity) -> ServerConfig {
    let mut transport = QuicTransportConfig::default();
    transport
        .congestion_controller_factory(Arc::new(BbrConfig::default()))
        // the windows keep one stream full at about 500 ms of round trip and 300 Mbps
        .stream_receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024))
        .receive_window(quinn::VarInt::from_u32(256 * 1024 * 1024))
        .send_window(256 * 1024 * 1024)
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(1024))
        .datagram_send_buffer_size(8 * 1024 * 1024)
        .datagram_receive_buffer_size(Some(8 * 1024 * 1024))
        // quinn's MTU is the UDP payload, so an initial MTU of 1500 loses every full-size packet on ordinary paths
        // (measured: Firefox sessions that hung now and then). From quinn's floor, path MTU discovery probes up to its
        // default of 1452, exactly 1500 bytes on IPv6.
        .initial_mtu(1200)
        .mtu_discovery_config(Some(MtuDiscoveryConfig::default()))
        // inside the idle timeout, quinn's 30 s or the client's own when shorter, so a quiet session stays open
        .keep_alive_interval(Some(Duration::from_secs(5)));
    bind.with_custom_transport(identity, transport).build()
}

/// One client's WebTransport session, as a [`Transport`] for [`Relay::serve`].
///
/// [`close`](Transport::close) ends the QUIC connection with the session's code and reason as its application close,
/// and resolves once the connection is closed; the endpoint sends the close from there. A native client reads the code
/// and the reason. A browser reads neither: its `WebTransport.closed` rejects, which Chromium 156 reports as
/// "Connection lost.".
///
/// With the cargo feature `close-capsule`, the code and reason go in a CLOSE_WEBTRANSPORT_SESSION capsule instead,
/// which `WebTransport.closed` resolves with, and the connection closes once the capsule is acknowledged. The feature
/// needs a wtransport patched in over 0.7.2 whose `Connection::close_session` sends that capsule, also for a session
/// closed right after `accept` (wtransport's pull request 337 adds the method). wtransport 0.7.2 from crates.io has no
/// such method, so with it this crate does not build with the feature.
pub struct WtTransport {
    connection: Connection,
}

impl WtTransport {
    /// The session of a connection `SessionRequest::accept` returned.
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

// A WebTransport stream code rides HTTP/3's error space from 0x52e4a40fa8db, skipping its reserved codepoints
// (draft-ietf-webtrans-http3, webtransport_code_to_http_code); the browser reports the code it maps back to.
fn http3_code(code: u32) -> VarInt {
    let code = u64::from(code);
    VarInt::try_from_u64(0x52e4_a40f_a8db + code + code / 0x1e).expect("below 2^62")
}

/// Both reset the stream with their `webvpn_proto::reset` code mapped into HTTP/3's error space, so a browser reports
/// the code itself as the stream's error code: 1 for [`fail`](SendHalf::fail), 0 for [`abandon`](SendHalf::abandon).
impl SendHalf for SendStream {
    fn fail(&mut self) {
        let _ = self.reset(http3_code(reset::PEER_RESET));
    }

    fn abandon(&mut self) {
        let _ = self.reset(http3_code(reset::CLOSED));
    }
}

impl Transport for WtTransport {
    type Send = SendStream;
    type Recv = RecvStream;

    /// An IPv4 client that reached a dual-stack socket reads as its IPv4 address.
    fn remote_ip(&self) -> IpAddr {
        self.connection.remote_address().ip().to_canonical()
    }

    fn rtt(&self) -> Duration {
        self.connection.rtt()
    }

    async fn close(&self, code: u32, reason: &str) {
        #[cfg(not(feature = "close-capsule"))]
        self.connection.close(VarInt::from_u32(code), reason.as_bytes());
        #[cfg(feature = "close-capsule")]
        self.connection.close_session(code, reason.as_bytes());
        self.connection.closed().await;
    }

    fn send_datagram(&self, data: Vec<u8>) -> Result<()> {
        self.connection.send_datagram(data)?;
        Ok(())
    }

    async fn control_stream(&self) -> Result<(SendStream, RecvStream)> {
        self.open_bi().await
    }

    async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        Ok(self.connection.open_bi().await?.await?)
    }

    async fn open_uni(&self) -> Result<SendStream> {
        Ok(self.connection.open_uni().await?.await?)
    }

    /// A stream carries no type: the client tells a UDP socket's stream from a TCP socket's by the id it starts with.
    async fn open_udp_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.open_bi().await
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>> {
        Ok(self.connection.receive_datagram().await?.payload().to_vec())
    }

    async fn accept_uni(&self) -> Result<RecvStream> {
        Ok(self.connection.accept_uni().await?)
    }
}

/// Serves `relay`'s sessions on `endpoint` until the relay stops, each connection in a task of its own.
///
/// An arrival takes a place among the sessions setting up
/// ([`Config::max_pending_sessions`](crate::Config::max_pending_sessions)), and its QUIC and HTTP/3 handshakes count
/// against [`Config::setup_timeout`](crate::Config::setup_timeout) with the hello exchange: a client still in its
/// handshake at the deadline is dropped. An arrival is refused at the QUIC level, which a browser's dial
/// reports at once, while every place is taken and from the moment [`Relay::stop`] is called. Every accepted session
/// goes to the relay, which admits it or closes it with its code: see [`Relay::serve`].
///
/// Returns once the stop began and every connection it took ended, after giving the endpoint up to 2 seconds to send
/// the closes still owed (`Endpoint::wait_idle`). It never closes the endpoint, and nothing answers an arrival after it
/// returned. wtransport's `Endpoint::accept` panics on a closed endpoint, so the endpoint must stay open while this
/// runs. What it logs names no client.
pub async fn serve<P: Policy>(relay: Relay<P>, endpoint: Arc<Endpoint<Server>>) {
    let connections = TaskTracker::new();
    let done = async {
        relay.stopped().await;
        connections.close();
        connections.wait().await;
    };
    tokio::pin!(done);
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            () = &mut done => break,
        };
        let setup = if relay.stopping() { None } else { relay.pending() };
        match setup {
            Some(setup) => {
                connections.spawn(connection(relay.clone(), incoming, setup));
            }
            None => incoming.refuse(),
        }
    }
    let _ = tokio::time::timeout(CLOSE_WAIT, endpoint.wait_idle()).await;
}

/// One arrival, from its handshakes to the end of its session.
async fn connection<P: Policy>(relay: Relay<P>, incoming: IncomingSession, setup: Setup) {
    let accepted = tokio::time::timeout_at(setup.deadline, async { incoming.await?.accept().await }).await;
    match accepted {
        Ok(Ok(connection)) => relay.serve_setup(WtTransport::new(connection), UdpCarrier::Bidi, setup).await,
        Ok(Err(_)) => debug!("a WebTransport client left during its handshake"),
        Err(_) => debug!("a WebTransport client did not finish its handshake in time"),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio::time::{timeout, Instant};
    use webvpn_proto::{close, ClientPacket, Hello, RelayPacket};
    use wtransport::error::{ConnectingError, ConnectionError, StreamReadError};
    use wtransport::proto::frame::Frame;
    use wtransport::proto::headers::Headers;
    use wtransport::proto::session::SessionRequest;
    use wtransport::proto::settings::Settings;
    use wtransport::proto::stream_header::StreamHeader;
    use wtransport::quinn::congestion::Bbr;
    use wtransport::tls::Sha256Digest;
    use wtransport::ClientConfig;

    use super::*;
    use crate::policy::Basic;
    use crate::relay::Config;

    /// How long a client waits on the relay before the test fails.
    const WAIT: Duration = Duration::from_secs(5);

    async fn within<F: Future>(future: F) -> F::Output {
        timeout(WAIT, future).await.expect("done in time")
    }

    fn loopback() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    fn identity() -> (Identity, Sha256Digest) {
        let identity = Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
        let hash = identity.certificate_chain().as_slice()[0].hash();
        (identity, hash)
    }

    fn client_config(hash: &Sha256Digest) -> ClientConfig {
        ClientConfig::builder().with_bind_address(loopback()).with_server_certificate_hashes([hash.clone()]).build()
    }

    /// A policy that lets sessions reach loopback.
    fn local() -> Basic {
        let mut policy = Basic::default();
        policy.allow_private_targets = true;
        policy
    }

    /// A relay serving WebTransport on loopback.
    struct Served {
        relay: Relay<Basic>,
        address: SocketAddr,
        hash: Sha256Digest,
        serving: JoinHandle<()>,
    }

    fn served(policy: Basic, config: Config) -> Served {
        let (identity, hash) = identity();
        let bind = ServerConfig::builder().with_bind_address(loopback());
        let endpoint = Endpoint::server(server_config(bind, identity)).unwrap();
        let address = endpoint.local_addr().unwrap();
        let relay = Relay::new(policy, config);
        let serving = tokio::spawn(serve(relay.clone(), Arc::new(endpoint)));
        Served { relay, address, hash, serving }
    }

    impl Served {
        async fn connect(&self) -> Result<Connection, ConnectingError> {
            let client = Endpoint::client(client_config(&self.hash)).unwrap();
            within(client.connect(format!("https://{}/", self.address))).await
        }

        /// A QUIC connection that says nothing over HTTP/3.
        async fn quic(&self) -> Result<quinn::Connection, quinn::ConnectionError> {
            let client = quinn::Endpoint::client(loopback()).unwrap();
            let quic_config = client_config(&self.hash).quic_config().clone();
            within(client.connect_with(quic_config, self.address, "localhost").unwrap()).await
        }

        /// A session past its hello exchange.
        async fn open(&self) -> (Connection, Control<SendStream, RecvStream>) {
            let connection = self.connect().await.unwrap();
            let (send, recv) = within(connection.accept_bi()).await.unwrap();
            (connection, greet(send, recv).await)
        }
    }

    fn refused<T>(connecting: Result<T, quinn::ConnectionError>) -> bool {
        matches!(
            connecting,
            Err(quinn::ConnectionError::ConnectionClosed(close))
                if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED
        )
    }

    /// The code and reason the relay closed a client's session with.
    async fn closed(connecting: Result<Connection, ConnectingError>) -> (u64, String) {
        let error = match connecting {
            Ok(connection) => within(connection.closed()).await,
            Err(ConnectingError::ConnectionError(error)) => error,
            Err(error) => panic!("the connect failed with {error}"),
        };
        match error {
            ConnectionError::ApplicationClosed(close) => {
                (close.code().into_inner(), String::from_utf8_lossy(close.reason()).into_owned())
            }
            error => panic!("the session ended with {error}"),
        }
    }

    /// The client's side of the control stream, as frames.
    struct Control<S, R> {
        send: S,
        recv: R,
        buf: Vec<u8>,
    }

    impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> Control<S, R> {
        async fn send(&mut self, packet: ClientPacket) {
            let mut frame = Vec::new();
            packet.encode(&mut frame);
            within(self.send.write_all(&frame)).await.unwrap();
        }

        async fn next(&mut self) -> RelayPacket {
            within(async {
                loop {
                    if let Some((packet, taken)) = RelayPacket::decode(&self.buf).unwrap() {
                        self.buf.drain(..taken);
                        return packet;
                    }
                    assert_ne!(self.recv.read_buf(&mut self.buf).await.unwrap(), 0, "the control stream ended");
                }
            })
            .await
        }

        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.send(request).await;
            self.next().await
        }
    }

    /// Reads the relay's hello off the first stream it opened, and answers with the client's.
    async fn greet<S: AsyncWrite + Unpin, R: AsyncRead + Unpin>(send: S, recv: R) -> Control<S, R> {
        let mut control = Control { send, recv, buf: Vec::new() };
        assert!(matches!(control.next().await, RelayPacket::Hello(_)));
        control.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;
        control
    }

    async fn tcp_connect(control: &mut Control<SendStream, RecvStream>, id: u32, remote: SocketAddr) -> u32 {
        let RelayPacket::Socket { id: answered, socket, remote: Some(peer), .. } =
            control.ask(ClientPacket::TcpConnect { id, remote }).await
        else {
            panic!("the connect was not answered with its socket");
        };
        assert_eq!((answered, peer), (id, remote));
        socket
    }

    /// The stream the relay opened for `socket`, past the socket id it starts with.
    async fn socket_stream(connection: &Connection, socket: u32) -> (SendStream, RecvStream) {
        let (send, mut recv) = within(connection.accept_bi()).await.unwrap();
        let mut id = [0; 4];
        within(recv.read_exact(&mut id)).await.unwrap();
        assert_eq!(u32::from_be_bytes(id), socket);
        (send, recv)
    }

    /// The code the relay reset its side of a stream with, as the client reads it.
    async fn reset_code(recv: &mut RecvStream) -> u64 {
        within(async {
            loop {
                match recv.read(&mut [0; 4096]).await {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("the stream finished instead of being reset"),
                    Err(StreamReadError::Reset(code)) => return code.into_inner(),
                    Err(error) => panic!("the stream failed with {error}"),
                }
            }
        })
        .await
    }

    #[tokio::test]
    async fn a_session_is_served_end_to_end_and_a_tcp_socket_carries_bytes_both_ways() {
        let echo = TcpListener::bind(loopback()).await.unwrap();
        let remote = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut peer, _) = echo.accept().await.unwrap();
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).await.unwrap();
            peer.write_all(&bytes).await.unwrap();
            // held open until the client closes
            let _ = peer.read(&mut bytes).await;
        });

        let served = served(local(), Config::default());
        let (connection, mut control) = served.open().await;
        let socket = tcp_connect(&mut control, 1, remote).await;
        let (mut send, mut recv) = socket_stream(&connection, socket).await;
        within(send.write_all(b"ping")).await.unwrap();
        let mut echoed = [0; 4];
        within(recv.read_exact(&mut echoed)).await.unwrap();
        assert_eq!(&echoed, b"ping");
        assert_eq!(served.relay.sessions(), 1);
    }

    #[tokio::test]
    async fn a_refused_admission_closes_the_session_with_session_limit_and_the_policy_s_message() {
        let mut policy = Basic::default();
        policy.max_sessions = 0;
        let message = policy.admit(Ipv4Addr::LOCALHOST.into()).unwrap_err().message.into_owned();
        let served = served(policy, Config::default());
        assert_eq!(closed(served.connect().await).await, (u64::from(close::SESSION_LIMIT), message));
        assert_eq!(served.relay.sessions(), 0);
    }

    #[tokio::test]
    async fn after_stop_an_arrival_is_refused_and_serve_returns_once_the_open_session_ended() {
        let served = served(Basic::default(), Config::default());
        let (connection, mut control) = served.open().await;
        let relay = served.relay.clone();
        let stopping = tokio::spawn(async move { relay.stop(Duration::from_secs(60)).await });
        assert_eq!(control.next().await, RelayPacket::Draining);

        assert!(refused(served.quic().await), "an arrival after the stop is refused");
        assert!(!served.serving.is_finished());

        connection.close(VarInt::from_u32(0), b"");
        within(stopping).await.unwrap();
        within(served.serving).await.unwrap();
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_its_handshake_holds_its_place_until_the_deadline_drops_it() {
        const SETUP: Duration = Duration::from_millis(500);
        let config = Config { max_pending_sessions: 1, setup_timeout: SETUP, ..Config::default() };
        let served = served(Basic::default(), config);
        let start = Instant::now();
        let silent = served.quic().await.unwrap();
        assert!(refused(served.quic().await), "an arrival while the only place is taken is refused");

        within(silent.closed()).await;
        assert!(start.elapsed() >= SETUP, "dropped after {:?}", start.elapsed());
        // the place is free again
        served.open().await;
    }

    #[tokio::test]
    async fn abandon_and_fail_reach_the_client_as_resets_with_their_codes_in_http3_s_space() {
        let listener = TcpListener::bind(loopback()).await.unwrap();
        let remote = listener.local_addr().unwrap();
        let served = served(local(), Config::default());
        let (connection, mut control) = served.open().await;

        // the client resets its socket, so the relay abandons the socket's stream
        let socket = tcp_connect(&mut control, 1, remote).await;
        let _peer = within(listener.accept()).await.unwrap();
        let (_send, mut recv) = socket_stream(&connection, socket).await;
        assert_eq!(control.ask(ClientPacket::TcpReset { id: 2, socket }).await, RelayPacket::Ok { id: 2 });
        assert_eq!(reset_code(&mut recv).await, 0x52e4_a40f_a8db);

        // the peer resets its connection, so the relay fails the socket's stream
        let socket = tcp_connect(&mut control, 3, remote).await;
        let (peer, _) = within(listener.accept()).await.unwrap();
        let (_send, mut recv) = socket_stream(&connection, socket).await;
        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer);
        assert_eq!(reset_code(&mut recv).await, 0x52e4_a40f_a8dc);
    }

    #[tokio::test]
    async fn the_tuned_config_keeps_its_numbers_and_its_congestion_controller() {
        let (identity, hash) = identity();
        let config = server_config(ServerConfig::builder().with_bind_address(loopback()), identity);
        let transport = format!("{:?}", config.quic_config().transport);
        for expected in [
            "max_concurrent_bidi_streams: 1024,",
            "max_concurrent_uni_streams: 1024,",
            "max_idle_timeout: Some(30000),",
            "stream_receive_window: 16777216,",
            " receive_window: 268435456,",
            "send_window: 268435456,",
            "initial_mtu: 1200,",
            "upper_bound: 1452,",
            "keep_alive_interval: Some(5s),",
            "datagram_receive_buffer_size: Some(8388608),",
            "datagram_send_buffer_size: 8388608,",
        ] {
            assert!(transport.contains(expected), "{expected:?} is not in {transport}");
        }

        // the congestion controller shows only on a connection
        let server = Endpoint::server(config).unwrap();
        let client = Endpoint::client(client_config(&hash)).unwrap();
        let url = format!("https://{}/", server.local_addr().unwrap());
        let (accepted, _client) = tokio::join!(
            within(async { server.accept().await.await?.accept().await }),
            within(client.connect(url)),
        );
        let controller = accepted.unwrap().quic_connection().congestion_state();
        assert!(controller.into_any().downcast::<Bbr>().is_ok());
    }

    fn encoded(frame: Frame<'_>) -> Vec<u8> {
        let mut bytes = Vec::new();
        frame.write(&mut bytes).unwrap();
        bytes
    }

    /// One QUIC variable-length integer.
    async fn varint(recv: &mut quinn::RecvStream) -> u64 {
        let first = within(recv.read_u8()).await.unwrap();
        let mut value = u64::from(first & 0x3f);
        for _ in 1..(1 << (first >> 6)) {
            value = (value << 8) | u64::from(within(recv.read_u8()).await.unwrap());
        }
        value
    }

    // wtransport 0.7.1 took every frame on the CONNECT stream for DATA, so a HEADERS frame or a reserved frame type
    // there panicked the connection's driver task and ended the session (wtransport issue 317, fixed in 0.7.2). No
    // WebTransport client writes a frame of its own choosing there, so this client speaks HTTP/3 itself.
    #[tokio::test]
    async fn a_frame_other_than_data_on_the_connect_stream_leaves_the_session_working() {
        let served = served(Basic::default(), Config::default());
        let connection = served.quic().await.unwrap();
        let mut h3_control = Vec::new();
        StreamHeader::new_control().write(&mut h3_control).unwrap();
        let settings = Settings::builder()
            .enable_webtransport()
            .enable_h3_datagrams()
            .webtransport_max_sessions(VarInt::from_u32(1))
            .build();
        settings.generate_frame().write(&mut h3_control).unwrap();
        // finishing this stream would close the connection, so it lives as long as the test
        let mut h3_control_stream = within(connection.open_uni()).await.unwrap();
        within(h3_control_stream.write_all(&h3_control)).await.unwrap();
        let (mut connect, _response) = within(connection.open_bi()).await.unwrap();
        let request = SessionRequest::new(format!("https://localhost:{}/", served.address.port())).unwrap();
        within(connect.write_all(&encoded(request.headers().generate_frame()))).await.unwrap();

        // the relay's stream starts with WEBTRANSPORT_STREAM and the session id
        let (send, mut recv) = within(connection.accept_bi()).await.unwrap();
        assert_eq!(varint(&mut recv).await, 0x41);
        varint(&mut recv).await;
        let mut control = greet(send, recv).await;

        let frames = [
            ("a reserved frame type", Frame::new_exercise(VarInt::from_u32(0x21), b"".into())),
            ("HEADERS", Headers::from_iter([("x-trailer", "1")]).generate_frame()),
        ];
        for (id, (kind, frame)) in (1..).zip(frames) {
            within(connect.write_all(&encoded(frame))).await.unwrap();
            // wtransport reads the CONNECT stream in a task of its own, which nothing on the session waits on
            tokio::time::sleep(Duration::from_millis(500)).await;
            let answer = control.ask(ClientPacket::AuthClear { id }).await;
            assert_eq!(answer, RelayPacket::Ok { id }, "the session stopped answering after {kind}");
        }
        served.open().await;
    }
}
