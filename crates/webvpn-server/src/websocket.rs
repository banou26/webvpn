//! The WebSocket carrier: a listener whose clients carry their session over the WebSocket mux.
//!
//! The TLS settings [`Options::tls`] takes are of [`rustls`], at the version this crate builds with, which is
//! re-exported here so a program needs no dependency of its own on it.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
pub use tokio_rustls::rustls;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::WebSocketStream;
use tokio_util::either::Either;
use tracing::{debug, warn};

use crate::policy::Policy;
use crate::relay::Relay;
use crate::session::{Setup, UdpCarrier};
use crate::ws;

/// The most the listener reads of a request head, from the request line to the blank line that ends it.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;

/// Answers a request that is not a WebSocket upgrade. It is given the request's method and its path without the
/// query, and returns the JSON body of a `200` answer, or `None` for a `404`. It is called on the async runtime, so
/// it must answer at once and never block.
pub type Handler = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

/// How [`serve`] takes its connections. `Options::default()` serves plain `ws://` and answers every request that is
/// not an upgrade with a `404`.
#[derive(Clone, Default)]
pub struct Options {
    /// The TLS settings, for `wss://`. A connection takes the value the receiver holds when it is accepted, so a new
    /// value (a renewed certificate, say) applies to the connections accepted after it and leaves open ones as they
    /// are. The listener speaks HTTP/1.1 only: the config's ALPN protocols must be empty or `http/1.1`.
    ///
    /// `None` serves plain `ws://`, for tests and for a relay behind something that ends TLS for it.
    pub tls: Option<watch::Receiver<Arc<ServerConfig>>>,
    /// Answers the requests that are not a WebSocket upgrade. A body is sent as JSON that any origin may read
    /// (`access-control-allow-origin: *`) and nothing may cache (`cache-control: no-store`), to anyone who asks, so
    /// it should carry counts only. Such a request takes the same TCP and TLS path as a session, so a client that
    /// times one, a load probe for example, measures the round trip its session would have.
    ///
    /// `None` answers every such request with a `404`.
    pub http: Option<Handler>,
}

type Upgraded = WebSocketStream<Prefixed<Either<TlsStream<TcpStream>, TcpStream>>>;

/// Accepts clients on `listener` and serves each one's session on `relay` over the WebSocket mux, until
/// [`Relay::stop`] is called. Then it returns and drops the listener, so a client connecting later reaches whatever
/// else listens on the port, or is refused and tries another relay. Sessions open by then are left to the stop.
///
/// Each connection runs as a task of its own, and:
/// - is dropped when it is accepted once the relay is stopping, and closed with `RESTARTING` once upgraded when the
///   stop comes during its setup;
/// - takes a place among the sessions setting up as it is accepted, before anything is read from it, and is dropped
///   when [`Config::max_pending_sessions`](crate::Config::max_pending_sessions) are setting up already, for the
///   client to try again later;
/// - has [`Config::setup_timeout`](crate::Config::setup_timeout) from its accept for the TLS handshake, the request
///   head, the WebSocket upgrade and the session's hello exchange, and is dropped past it, or closed with
///   `PROTOCOL_ERROR` once upgraded;
/// - is dropped when its request head is longer than 8 KiB;
/// - is answered by [`Options::http`] when it is not a WebSocket upgrade.
///
/// The relay asks its policy about the session after the upgrade, so a refusal reaches the client as a `Bye` with
/// `SESSION_LIMIT` and the policy's message, then a WebSocket close with code 4003 (4000 plus `SESSION_LIMIT`) and the
/// same message. Nothing it logs names a client.
pub async fn serve<P: Policy>(relay: Relay<P>, listener: TcpListener, options: Options) {
    loop {
        // The accept goes first: a connection the listener holds when the stop comes is taken and dropped below,
        // the same way every time.
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => accepted,
            () = relay.stopped() => return,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!("the WebSocket listener could not accept a connection: {error}");
                continue;
            }
        };
        if relay.stopping() {
            return;
        }
        // Turned away before a task or a buffer is spent on it; the client's retry recovers.
        let Some(setup) = relay.pending() else {
            continue;
        };
        let tls = options.tls.as_ref().map(|tls| tls.borrow().clone());
        tokio::spawn(connection(relay.clone(), tcp, peer.ip(), tls, options.http.clone(), setup));
    }
}

async fn connection<P: Policy>(
    relay: Relay<P>,
    tcp: TcpStream,
    peer: IpAddr,
    tls: Option<Arc<ServerConfig>>,
    http: Option<Handler>,
    setup: Setup,
) {
    let upgraded = tokio::time::timeout_at(setup.deadline, handshake(tcp, tls, http)).await;
    let ws = match upgraded.unwrap_or_else(|_| Err(anyhow!("the setup's time ran out"))) {
        Ok(Some(ws)) => ws,
        Ok(None) => return,
        Err(error) => {
            debug!("a WebSocket connection ended before its session: {error:#}");
            return;
        }
    };
    let (transport, tasks) = ws::spawn_session(ws, peer, relay.shared_metrics());
    relay.serve_setup(transport, UdpCarrier::UniStreamRequired, setup).await;
    // Only after the session, whose close gave the writer a second to send it: a writer that still waits on a client
    // reading nothing is stopped then instead of holding the connection.
    tasks.shutdown().await;
}

/// The TLS handshake, the request head, then the WebSocket upgrade, or `None` once a plain request was answered.
async fn handshake(tcp: TcpStream, tls: Option<Arc<ServerConfig>>, http: Option<Handler>) -> Result<Option<Upgraded>> {
    let mut stream = match tls {
        Some(config) => Either::Left(TlsAcceptor::from(config).accept(tcp).await.context("the TLS handshake failed")?),
        None => Either::Right(tcp),
    };
    let head = read_head(&mut stream).await?;
    if !is_websocket_upgrade(&head) {
        answer(stream, &head, http).await?;
        return Ok(None);
    }
    let config = WebSocketConfig::default().max_message_size(Some(ws::MAX_WS_MESSAGE_BYTES));
    let stream = Prefixed { head: head.into(), inner: stream };
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await.context("the upgrade failed")?;
    Ok(Some(ws))
}

/// Reads up to the blank line that ends a request head, and returns every byte read, the ones past the head
/// included, for the upgrade to read again.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            bail!("the connection ended inside its request head");
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            bail!("the request head is longer than the listener reads");
        }
    }
}

fn is_websocket_upgrade(head: &[u8]) -> bool {
    let head = head.to_ascii_lowercase();
    let Some(at) = head.windows(10).position(|w| w == b"\r\nupgrade:") else {
        return false;
    };
    let value = &head[at + 10..];
    let end = value.windows(2).position(|w| w == b"\r\n").unwrap_or(value.len());
    value[..end].windows(9).any(|w| w == b"websocket")
}

/// The request's method and path. The query is cut off, so a probe that adds one to get past caches still routes.
fn request_line(head: &[u8]) -> Option<(&str, &str)> {
    let end = head.windows(2).position(|w| w == b"\r\n")?;
    let mut parts = std::str::from_utf8(&head[..end]).ok()?.split(' ');
    let (method, target) = (parts.next()?, parts.next()?);
    Some((method, target.split('?').next()?))
}

async fn answer<S: AsyncWrite + Unpin>(mut stream: S, head: &[u8], http: Option<Handler>) -> Result<()> {
    let body = request_line(head).zip(http).and_then(|((method, path), handler)| handler(method, path));
    let response = match body {
        Some(body) => format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\naccess-control-allow-origin: *\r\n\
             cache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len(),
        ),
        None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// A stream whose first reads give `head`, the bytes the listener already took off the connection, so the upgrade
/// reads the request as the client sent it, and any frame the client sent right after it.
struct Prefixed<S> {
    head: Bytes,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.head.is_empty() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let n = self.head.len().min(buf.remaining());
        buf.put_slice(&self.head.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::SocketAddr;
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpSocket;
    use tokio::task::JoinHandle;
    use tokio::time::{sleep, timeout, Instant};
    use tokio_rustls::client;
    use tokio_rustls::rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;
    use webvpn_proto::mux::{self, kind, stream_type, CONTROL_STREAM};
    use webvpn_proto::{close, ClientPacket, Hello, RelayPacket};

    use super::*;
    use crate::relay::STOPPING;
    use crate::testing::WAIT;
    use crate::{Basic, Config, Counter};

    async fn within<F: Future>(future: F) -> F::Output {
        timeout(WAIT, future).await.expect("done in time")
    }

    /// A relay whose policy lets sessions reach loopback.
    fn relay(config: Config) -> Relay<Basic> {
        Relay::new(Basic { allow_private_targets: true, ..Basic::default() }, config)
    }

    /// `serve` on a loopback port of its own: the port, and the task serving it.
    async fn start<P: Policy>(relay: &Relay<P>, options: Options) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (address, tokio::spawn(serve(relay.clone(), listener, options)))
    }

    /// A certificate for `localhost` signed with its own key: the relay's TLS settings with it, and a client that
    /// trusts it and nothing else.
    fn certificate() -> (Arc<ServerConfig>, TlsConnector) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key.into())
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        (Arc::new(server), TlsConnector::from(Arc::new(client)))
    }

    async fn tls_connect(address: SocketAddr, connector: &TlsConnector) -> io::Result<client::TlsStream<TcpStream>> {
        let tcp = within(TcpStream::connect(address)).await?;
        within(connector.connect(ServerName::try_from("localhost").unwrap(), tcp)).await
    }

    /// Whether the relay ended the connection without answering: it reads its end or a reset.
    async fn dropped(tcp: &mut TcpStream) -> bool {
        matches!(within(tcp.read(&mut [0; 1])).await, Ok(0) | Err(_))
    }

    /// Sends `request` as it is and reads the whole answer.
    async fn ask(address: SocketAddr, request: &str) -> String {
        let mut tcp = within(TcpStream::connect(address)).await.unwrap();
        within(tcp.write_all(request.as_bytes())).await.unwrap();
        let mut answer = String::new();
        within(tcp.read_to_string(&mut answer)).await.unwrap();
        answer
    }

    /// The client's side of a session over the mux.
    struct Client<S> {
        ws: WebSocketStream<S>,
        /// Control stream bytes not decoded yet.
        control: Vec<u8>,
    }

    /// What the relay sent: a control packet, or a frame of another stream.
    #[derive(Debug, PartialEq)]
    enum Received {
        Control(RelayPacket),
        Frame(u8, u32, Vec<u8>),
    }

    async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Client<S> {
        let (ws, _) = within(tokio_tungstenite::client_async("ws://localhost/", stream)).await.expect("an upgrade");
        Client { ws, control: Vec::new() }
    }

    async fn connect(address: SocketAddr) -> Client<TcpStream> {
        upgrade(within(TcpStream::connect(address)).await.unwrap()).await
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
        async fn frame(&mut self, frame_kind: u8, stream: u32, payload: &[u8]) {
            within(self.ws.send(Message::Binary(mux::encode(frame_kind, stream, payload).into()))).await.unwrap();
        }

        async fn send(&mut self, packet: ClientPacket) {
            let mut bytes = Vec::new();
            packet.encode(&mut bytes);
            self.frame(kind::DATA, CONTROL_STREAM, &bytes).await;
        }

        async fn next(&mut self) -> Received {
            within(async {
                loop {
                    if let Some((packet, taken)) = RelayPacket::decode(&self.control).unwrap() {
                        self.control.drain(..taken);
                        return Received::Control(packet);
                    }
                    let Message::Binary(data) = self.ws.next().await.expect("an open WebSocket").unwrap() else {
                        continue;
                    };
                    let (frame_kind, stream, payload) = mux::decode(&data).expect("a whole frame");
                    if (frame_kind, stream) != (kind::DATA, CONTROL_STREAM) {
                        return Received::Frame(frame_kind, stream, payload.to_vec());
                    }
                    self.control.extend_from_slice(payload);
                }
            })
            .await
        }

        /// Reads the relay's hello and answers with the client's.
        async fn hello(&mut self) {
            assert!(matches!(self.next().await, Received::Control(RelayPacket::Hello(_))));
            self.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;
        }

        /// The close the relay ended the WebSocket with.
        async fn closed(&mut self) -> CloseFrame {
            within(async {
                loop {
                    match self.ws.next().await {
                        Some(Ok(Message::Close(Some(frame)))) => return frame,
                        Some(Ok(_)) => {}
                        other => panic!("the WebSocket ended without a close: {other:?}"),
                    }
                }
            })
            .await
        }

        /// The bytes of DATA frames on `stream` until there are `bytes` of them.
        async fn data(&mut self, stream: u32, bytes: usize) -> Vec<u8> {
            let mut data = Vec::new();
            while data.len() < bytes {
                match self.next().await {
                    Received::Frame(kind::DATA, id, payload) if id == stream => data.extend(payload),
                    other => panic!("expected DATA on stream {stream}, got {other:?}"),
                }
            }
            data
        }
    }

    /// A local server that sends back what it reads.
    async fn echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let (mut from, mut to) = peer.split();
            let _ = tokio::io::copy(&mut from, &mut to).await;
        });
        address
    }

    /// Hellos both ways, then a `TcpConnect` to an echo server, whose stream is announced with OPEN and carries bytes
    /// both ways.
    async fn a_whole_session<S: AsyncRead + AsyncWrite + Unpin>(client: &mut Client<S>) {
        let remote = echo().await;
        client.hello().await;
        client.send(ClientPacket::TcpConnect { id: 1, remote }).await;
        // The reply and the stream may come in either order.
        let (mut socket, mut stream, mut id) = (None, None, Vec::new());
        while socket.is_none() || id.len() < 4 {
            match client.next().await {
                Received::Control(RelayPacket::Socket { id: 1, socket: named, .. }) => socket = Some(named),
                Received::Frame(kind::OPEN, opened, payload) => {
                    assert_eq!(payload, [stream_type::TCP]);
                    stream = Some(opened);
                }
                Received::Frame(kind::DATA, on, payload) if Some(on) == stream => id.extend(payload),
                other => panic!("expected the socket and its stream, got {other:?}"),
            }
        }
        assert_eq!(id, socket.unwrap().to_be_bytes());
        let stream = stream.unwrap();
        client.frame(kind::DATA, stream, b"ping").await;
        assert_eq!(client.data(stream, 4).await, b"ping");
    }

    #[tokio::test]
    async fn a_session_runs_end_to_end_over_plain_websocket() {
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options::default()).await;
        a_whole_session(&mut connect(address).await).await;
        assert_eq!(relay.metrics().get(Counter::WsSessions), 1);
    }

    #[tokio::test]
    async fn a_session_runs_end_to_end_over_tls() {
        let (config, connector) = certificate();
        let (_config, tls) = watch::channel(config);
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options { tls: Some(tls), http: None }).await;
        a_whole_session(&mut upgrade(tls_connect(address, &connector).await.unwrap()).await).await;
    }

    #[tokio::test]
    async fn a_new_tls_config_is_used_by_the_connections_accepted_after_it() {
        let (first, trusts_first) = certificate();
        let (second, trusts_second) = certificate();
        let (renew, tls) = watch::channel(first);
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options { tls: Some(tls), http: None }).await;
        let mut before = upgrade(tls_connect(address, &trusts_first).await.unwrap()).await;

        renew.send(second).unwrap();
        upgrade(tls_connect(address, &trusts_second).await.unwrap()).await.hello().await;
        assert!(tls_connect(address, &trusts_first).await.is_err());
        before.hello().await;
    }

    #[tokio::test]
    async fn a_refused_admission_reaches_the_client_as_a_bye_then_a_close_with_the_session_code_and_message() {
        let policy = Basic { max_sessions: 0, ..Basic::default() };
        let refusal = policy.admit(IpAddr::from([127, 0, 0, 1])).unwrap_err();
        let relay = Relay::new(policy, Config::default());
        let (address, _serving) = start(&relay, Options::default()).await;
        let mut client = connect(address).await;
        let bye = RelayPacket::Bye { code: close::SESSION_LIMIT, reason: refusal.message.to_string() };
        assert_eq!(client.next().await, Received::Control(bye));
        let close = client.closed().await;
        assert_eq!(u16::from(close.code), 4003);
        assert_eq!(close.reason.as_str(), refusal.message);
    }

    #[tokio::test]
    async fn a_stop_past_its_grace_says_bye_with_restarting_before_the_close() {
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options::default()).await;
        let mut client = connect(address).await;
        client.hello().await;
        let stopping = tokio::spawn({
            let relay = relay.clone();
            async move { relay.stop(Duration::from_millis(100)).await }
        });
        assert_eq!(client.next().await, Received::Control(RelayPacket::Draining));
        let bye = RelayPacket::Bye { code: close::RESTARTING, reason: STOPPING.into() };
        assert_eq!(client.next().await, Received::Control(bye));
        let close = client.closed().await;
        assert_eq!((u16::from(close.code), close.reason.as_str()), (4004, STOPPING));
        within(stopping).await.unwrap();
    }

    #[tokio::test]
    async fn serve_ends_with_the_stop_and_a_connection_waiting_for_it_then_is_dropped() {
        let relay = relay(Config::default());
        let (_, serving) = start(&relay, Options::default()).await;
        within(relay.stop(Duration::ZERO)).await;
        within(serving).await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waiting = within(TcpStream::connect(listener.local_addr().unwrap())).await.unwrap();
        within(serve(relay, listener, Options::default())).await;
        let upgrade = within(tokio_tungstenite::client_async("ws://localhost/", waiting)).await;
        assert!(upgrade.is_err(), "a connection was upgraded after the stop");
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_dropped_at_the_setup_deadline_and_frees_its_place() {
        let setup_timeout = Duration::from_millis(500);
        let relay = relay(Config { max_pending_sessions: 1, setup_timeout, ..Config::default() });
        let (address, _serving) = start(&relay, Options::default()).await;
        let began = Instant::now();
        let mut silent = within(TcpStream::connect(address)).await.unwrap();
        assert!(dropped(&mut silent).await);
        assert!(began.elapsed() >= setup_timeout);
        connect(address).await.hello().await;
    }

    #[tokio::test]
    async fn a_connection_finding_no_place_free_is_dropped_before_anything_is_read() {
        let relay = relay(Config { max_pending_sessions: 1, ..Config::default() });
        let (address, _serving) = start(&relay, Options::default()).await;
        let _holding = within(TcpStream::connect(address)).await.unwrap();
        // The setup's deadline is 15 seconds away, so an end within the wait comes before any read.
        let mut turned_away = within(TcpStream::connect(address)).await.unwrap();
        assert!(dropped(&mut turned_away).await);
    }

    #[tokio::test]
    async fn a_plain_request_gets_the_handler_s_body_or_a_404() {
        let load: Handler = Arc::new(|method: &str, path: &str| {
            (method == "GET" && path == "/load").then(|| r#"{"sessions":0}"#.to_owned())
        });
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options { tls: None, http: Some(load) }).await;
        let answer = ask(address, "GET /load?t=1 HTTP/1.1\r\nHost: relay\r\n\r\n").await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        for header in ["content-type: application/json", "access-control-allow-origin: *", "cache-control: no-store"] {
            assert!(answer.contains(&format!("\r\n{header}\r\n")), "{answer}");
        }
        assert!(answer.ends_with("\r\ncontent-length: 14\r\nconnection: close\r\n\r\n{\"sessions\":0}"), "{answer}");
        for request in ["GET /other HTTP/1.1\r\n\r\n", "POST /load HTTP/1.1\r\n\r\n"] {
            assert!(ask(address, request).await.starts_with("HTTP/1.1 404 Not Found\r\n"));
        }

        let (address, _serving) = start(&relay, Options::default()).await;
        assert!(ask(address, "GET /load HTTP/1.1\r\n\r\n").await.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[tokio::test]
    async fn a_request_head_over_the_bound_is_refused() {
        let relay = relay(Config::default());
        let (address, _serving) = start(&relay, Options::default()).await;
        let filler = "a".repeat(MAX_REQUEST_HEAD_BYTES - 1024);
        let answer = ask(address, &format!("GET / HTTP/1.1\r\nx-filler: {filler}\r\n\r\n")).await;
        assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"));

        let mut tcp = within(TcpStream::connect(address)).await.unwrap();
        let filler = "a".repeat(MAX_REQUEST_HEAD_BYTES);
        let _ = within(tcp.write_all(format!("GET / HTTP/1.1\r\nx-filler: {filler}\r\n").as_bytes())).await;
        // The setup's deadline is 15 seconds away, so an end within the wait is the bound's.
        assert!(dropped(&mut tcp).await);
    }

    #[tokio::test]
    async fn a_client_that_reads_nothing_loses_its_connection_a_second_after_its_session_ends() {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = source.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut peer, _) = source.accept().await.unwrap();
            let _ = peer.write_all(&vec![0; 2 << 20]).await;
        });
        // Small socket buffers on both sides, so the relay's writer soon waits on a client that reads nothing.
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(16).unwrap();
        let address = listener.local_addr().unwrap();
        let relay = relay(Config::default());
        tokio::spawn(serve(relay.clone(), listener, Options::default()));
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut client = upgrade(within(socket.connect(address)).await.unwrap()).await;
        client.hello().await;
        client.send(ClientPacket::TcpConnect { id: 1, remote }).await;

        // Far more than both socket buffers hold went toward the client.
        let enough = || relay.metrics().get(Counter::BytesDown) >= 256 * 1024;
        for _ in 0..100 {
            if enough() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert!(enough());

        // The close ends the session. Stopping the writer then closes the connection, and the relay resets it at the
        // next byte the client writes, which the write after that meets.
        within(client.ws.send(Message::Close(None))).await.unwrap();
        let began = Instant::now();
        let tcp = client.ws.get_mut();
        let mut writes = 0;
        while writes < 100 && within(tcp.write_all(b"x")).await.is_ok() {
            writes += 1;
            sleep(Duration::from_millis(50)).await;
        }
        assert!(writes < 100, "the connection outlived its session by 5 seconds");
        // The writer's second, and not a second wait after it.
        assert!(began.elapsed() < Duration::from_millis(1500), "the connection lasted {:?}", began.elapsed());
    }

    #[tokio::test]
    async fn a_stop_returns_once_the_bye_and_the_close_reached_a_client_that_reads_slowly() {
        // The relay runs on a runtime of its own, shut down as soon as its stop returns, as a program ends after it.
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = source.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut peer, _) = source.accept().await.unwrap();
            let _ = peer.write_all(&vec![0; 2 << 20]).await;
            let _ = peer.read(&mut [0; 1]).await;
        });
        let relay = relay(Config::default());
        let address = runtime
            .spawn({
                let relay = relay.clone();
                async move {
                    let socket = TcpSocket::new_v4().unwrap();
                    socket.set_send_buffer_size(4096).unwrap();
                    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                    let listener = socket.listen(16).unwrap();
                    let address = listener.local_addr().unwrap();
                    tokio::spawn(serve(relay, listener, Options::default()));
                    address
                }
            })
            .await
            .unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut client = upgrade(within(socket.connect(address)).await.unwrap()).await;
        client.hello().await;
        client.send(ClientPacket::TcpConnect { id: 1, remote }).await;
        // Far more than both socket buffers hold went toward the client, so the relay's writer waits on it.
        let enough = || relay.metrics().get(Counter::BytesDown) >= 256 * 1024;
        for _ in 0..100 {
            if enough() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert!(enough());

        // The client reads again a moment into the stop, well within the second the writer is given.
        let reading = tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            let (mut control, mut bye) = (Vec::new(), None);
            loop {
                match within(client.ws.next()).await {
                    Some(Ok(Message::Binary(data))) => {
                        let Some((kind::DATA, CONTROL_STREAM, payload)) = mux::decode(&data) else { continue };
                        control.extend_from_slice(payload);
                        while let Some((packet, taken)) = RelayPacket::decode(&control).unwrap() {
                            control.drain(..taken);
                            if let RelayPacket::Bye { code, .. } = packet {
                                bye = Some(code);
                            }
                        }
                    }
                    Some(Ok(Message::Close(frame))) => return (bye, frame.map(|frame| u16::from(frame.code))),
                    Some(Ok(_)) => {}
                    None | Some(Err(_)) => return (bye, None),
                }
            }
        });
        within(runtime.spawn(async move { relay.stop(Duration::ZERO).await })).await.unwrap();
        runtime.shutdown_background();
        assert_eq!(within(reading).await.unwrap(), (Some(close::RESTARTING), Some(4004)));
    }

    #[test]
    fn requests_are_told_apart_by_their_upgrade_header_and_routed_by_method_and_path() {
        assert!(is_websocket_upgrade(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
        assert!(is_websocket_upgrade(b"GET / HTTP/1.1\r\nUpGrAdE: WebSocket\r\n\r\n"));
        let probe: &[u8] = b"GET /load HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(!is_websocket_upgrade(probe));
        assert_eq!(request_line(probe), Some(("GET", "/load")));
        assert_eq!(request_line(b"GET /load?t=123 HTTP/1.1\r\n\r\n"), Some(("GET", "/load")));
        assert_eq!(request_line(b"POST /load HTTP/1.1\r\n\r\n"), Some(("POST", "/load")));
        assert_eq!(request_line(b"GET\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn prefixed_replays_the_head_before_the_inner_stream() {
        let (mut far, near) = tokio::io::duplex(64);
        far.write_all(b"tail").await.unwrap();
        let mut stream = Prefixed { head: Bytes::from_static(b"head-"), inner: near };
        let mut out = [0; 9];
        within(stream.read_exact(&mut out)).await.unwrap();
        assert_eq!(&out, b"head-tail");
    }

    #[tokio::test]
    async fn read_head_keeps_the_bytes_past_the_blank_line_for_the_upgrade() {
        let (mut far, mut near) = tokio::io::duplex(64);
        far.write_all(b"GET / HTTP/1.1\r\n\r\nextra").await.unwrap();
        assert_eq!(within(read_head(&mut near)).await.unwrap(), b"GET / HTTP/1.1\r\n\r\nextra");
    }
}
