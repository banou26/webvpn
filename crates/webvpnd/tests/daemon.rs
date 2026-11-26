//! Whole relays started in this process on loopback, with ports the system picks, and the built program itself.

use std::env::VarError;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use webvpn_proto::mux::{self, kind, stream_type, CONTROL_STREAM};
use webvpn_proto::{features, ClientPacket, ErrorCode, Hello, RelayPacket};
use webvpnd::{CertificateFiles, Daemon, Settings};
use wtransport::tls::{Sha256Digest, Sha256DigestFmt};
use wtransport::{Endpoint, Identity, RecvStream, SendStream};

/// How long a test waits on the relay, or on the program, before it fails.
const WAIT: Duration = Duration::from_secs(5);
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

async fn within<F: Future>(future: F) -> F::Output {
    timeout(WAIT, future).await.expect("done in time")
}

/// The default settings, on loopback ports the system picks, for a relay that may reach loopback.
fn settings() -> Settings {
    let mut settings = Settings::parse(|_| Err(VarError::NotPresent)).unwrap();
    settings.address = LOCALHOST;
    (settings.webtransport_port, settings.websocket_port, settings.http_port) = (0, 0, 0);
    settings.policy.allow_private_targets = true;
    settings
}

/// A certificate for `localhost` signed with its own key, written as a PEM pair in a directory of its own.
struct Pair {
    files: CertificateFiles,
    der: Vec<u8>,
    hash: Sha256Digest,
}

impl Pair {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("webvpnd-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let files = CertificateFiles { cert: directory.join("chain.pem"), key: directory.join("key.pem") };
        let mut pair = Self { files, der: Vec::new(), hash: Sha256Digest::new([0; 32]) };
        pair.renew();
        pair
    }

    /// Writes a new certificate and key over the files.
    // Not with wtransport's `store_pemfile`, whose write may land after it returned: it does not flush its file.
    fn renew(&mut self) {
        let identity = Identity::self_signed(["localhost"]).unwrap();
        let leaf = &identity.certificate_chain().as_slice()[0];
        std::fs::write(&self.files.key, identity.private_key().to_secret_pem()).unwrap();
        std::fs::write(&self.files.cert, leaf.to_pem()).unwrap();
        (self.der, self.hash) = (leaf.der().to_vec(), leaf.hash());
    }

    /// A TLS client that trusts this certificate and nothing else.
    fn trusted(&self) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone().into()).unwrap();
        TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()))
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.files.cert.parent().unwrap());
    }
}

/// A started relay serving the certificate `pair` holds.
async fn start(mut settings: Settings, pair: &Pair) -> Daemon {
    settings.certificate = Some(pair.files.clone());
    within(Daemon::start(settings)).await.unwrap()
}

async fn tls(port: u16, connector: &TlsConnector) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = within(TcpStream::connect((LOCALHOST, port))).await?;
    within(connector.connect(ServerName::try_from("localhost").unwrap(), tcp)).await
}

/// Sends `GET path` and reads the whole answer: its head in lower case, and its body.
async fn get<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, path: &str) -> (String, String) {
    let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
    within(stream.write_all(request.as_bytes())).await.unwrap();
    let mut answer = String::new();
    within(stream.read_to_string(&mut answer)).await.unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").expect("a whole answer");
    (head.to_ascii_lowercase(), body.to_owned())
}

/// `GET path` on the plain HTTP listener.
async fn http(port: u16, path: &str) -> (String, String) {
    get(within(TcpStream::connect((LOCALHOST, port))).await.unwrap(), path).await
}

fn status(head: &str) -> &str {
    head.lines().next().unwrap()
}

/// A local server that sends back what it reads.
async fn echo() -> SocketAddr {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let (mut from, mut to) = peer.split();
        let _ = tokio::io::copy(&mut from, &mut to).await;
    });
    address
}

/// A client's session over the WebSocket mux.
struct Mux {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    /// Control stream bytes not decoded yet.
    control: Vec<u8>,
}

#[derive(Debug)]
enum Received {
    Control(RelayPacket),
    Frame(u8, u32, Vec<u8>),
}

impl Mux {
    async fn open(port: u16, connector: &TlsConnector) -> Self {
        let tls = tls(port, connector).await.unwrap();
        let (ws, _) = within(tokio_tungstenite::client_async("wss://localhost/", tls)).await.expect("an upgrade");
        Self { ws, control: Vec::new() }
    }

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
                match self.ws.next().await.expect("an open WebSocket").unwrap() {
                    Message::Binary(data) => {
                        let (frame_kind, stream, payload) = mux::decode(&data).expect("a whole frame");
                        if (frame_kind, stream) != (kind::DATA, CONTROL_STREAM) {
                            return Received::Frame(frame_kind, stream, payload.to_vec());
                        }
                        self.control.extend_from_slice(payload);
                    }
                    Message::Close(frame) => panic!("the relay closed the session: {frame:?}"),
                    _ => {}
                }
            }
        })
        .await
    }

    async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
        self.send(request).await;
        match self.next().await {
            Received::Control(packet) => packet,
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// Reads the relay's hello and answers with the client's. Returns the relay's feature bits.
    async fn hello(&mut self) -> u32 {
        let Received::Control(RelayPacket::Hello(hello)) = self.next().await else {
            panic!("the relay did not start with its hello");
        };
        self.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;
        hello.features
    }

    /// Connects to `remote` and checks that bytes go there and back over the socket's stream.
    async fn connect_and_echo(&mut self, id: u32, remote: SocketAddr) {
        self.send(ClientPacket::TcpConnect { id, remote }).await;
        // The reply and the stream may come in either order.
        let (mut socket, mut stream, mut socket_id) = (None, None, Vec::new());
        while socket.is_none() || socket_id.len() < 4 {
            match self.next().await {
                Received::Control(RelayPacket::Socket { id: answered, socket: named, .. }) if answered == id => {
                    socket = Some(named)
                }
                Received::Frame(kind::OPEN, opened, payload) => {
                    assert_eq!(payload, [stream_type::TCP]);
                    stream = Some(opened);
                }
                Received::Frame(kind::DATA, on, payload) if Some(on) == stream => socket_id.extend(payload),
                other => panic!("expected the socket and its stream, got {other:?}"),
            }
        }
        assert_eq!(socket_id, socket.unwrap().to_be_bytes());
        let stream = stream.unwrap();
        self.frame(kind::DATA, stream, b"ping").await;
        match self.next().await {
            Received::Frame(kind::DATA, on, payload) if on == stream => assert_eq!(payload, b"ping"),
            other => panic!("expected the echo, got {other:?}"),
        }
    }

    /// The WebSocket close code the relay ended the session with.
    async fn closed(&mut self) -> u16 {
        within(async {
            loop {
                match self.ws.next().await {
                    Some(Ok(Message::Close(Some(frame)))) => return u16::from(frame.code),
                    Some(Ok(_)) => {}
                    other => panic!("the WebSocket ended without a close: {other:?}"),
                }
            }
        })
        .await
    }
}

#[tokio::test]
async fn the_http_listener_answers_health_ready_metrics_and_the_certificate_hash() {
    let pair = Pair::new("http");
    let daemon = start(settings(), &pair).await;
    let port = daemon.ports().http;

    let (head, body) = http(port, "/health").await;
    assert_eq!((status(&head), body.as_str()), ("http/1.1 200 ok", "OK"));
    let (head, body) = http(port, "/ready").await;
    assert_eq!((status(&head), body.as_str()), ("http/1.1 200 ok", "Ready"));
    let (head, body) = http(port, "/metrics").await;
    assert_eq!(status(&head), "http/1.1 200 ok");
    assert!(body.lines().any(|line| line == "webvpn_active_connections_total 0"), "{body}");

    let (head, body) = http(port, "/cert-hash").await;
    assert_eq!(status(&head), "http/1.1 200 ok");
    for header in ["access-control-allow-origin: *", "content-type: application/json"] {
        assert!(head.lines().any(|line| line == header), "{header:?} is not in {head}");
    }
    assert_eq!(body, pair.hash.fmt(Sha256DigestFmt::BytesArray));

    assert_eq!(status(&http(port, "/other").await.0), "http/1.1 404 not found");
}

#[tokio::test]
async fn a_websocket_session_runs_end_to_end_and_load_counts_it() {
    let pair = Pair::new("websocket");
    let mut settings = settings();
    settings.policy.max_sessions = 7;
    let daemon = start(settings, &pair).await;
    let port = daemon.ports().websocket.unwrap();
    let load = |sessions: usize| {
        format!(r#"{{"sessions":{sessions},"maxSessions":7,"version":"{}"}}"#, env!("CARGO_PKG_VERSION"))
    };

    let (head, body) = get(tls(port, &pair.trusted()).await.unwrap(), "/load?t=1").await;
    assert_eq!(status(&head), "http/1.1 200 ok");
    for header in ["content-type: application/json", "access-control-allow-origin: *", "cache-control: no-store"] {
        assert!(head.lines().any(|line| line == header), "{header:?} is not in {head}");
    }
    assert_eq!(body, load(0));

    let mut client = Mux::open(port, &pair.trusted()).await;
    assert_eq!(client.hello().await & features::AUTH, 0, "a relay without credentials takes none");
    client.connect_and_echo(1, echo().await).await;
    assert_eq!(get(tls(port, &pair.trusted()).await.unwrap(), "/load").await.1, load(1));
}

/// The client's side of a WebTransport stream, as control frames.
struct Control {
    send: SendStream,
    recv: RecvStream,
    buf: Vec<u8>,
}

impl Control {
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
}

#[tokio::test]
async fn a_webtransport_session_runs_end_to_end_on_the_self_signed_certificate_by_its_hash() {
    let mut settings = settings();
    settings.watch_own_ipv6 = true;
    let daemon = within(Daemon::start(settings)).await.unwrap();
    let ports = daemon.ports();
    let (head, body) = http(ports.http, "/cert-hash").await;
    assert!(head.lines().any(|line| line == "access-control-allow-origin: *"), "{head}");
    let hash = Sha256Digest::from_str_fmt(&body, Sha256DigestFmt::BytesArray).expect("a hash");

    let config = wtransport::ClientConfig::builder()
        .with_bind_address((LOCALHOST, 0).into())
        .with_server_certificate_hashes([hash])
        .build();
    let endpoint = Endpoint::client(config).unwrap();
    let connection = within(endpoint.connect(format!("https://127.0.0.1:{}/", ports.webtransport))).await.unwrap();
    let (send, recv) = within(connection.accept_bi()).await.unwrap();
    let mut control = Control { send, recv, buf: Vec::new() };
    assert!(matches!(control.next().await, RelayPacket::Hello(_)));
    control.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;

    let remote = echo().await;
    control.send(ClientPacket::TcpConnect { id: 1, remote }).await;
    let RelayPacket::Socket { id: 1, socket, .. } = control.next().await else {
        panic!("the connect was not answered with its socket");
    };
    let (mut send, mut recv) = within(connection.accept_bi()).await.unwrap();
    let mut id = [0; 4];
    within(recv.read_exact(&mut id)).await.unwrap();
    assert_eq!(u32::from_be_bytes(id), socket);
    within(send.write_all(b"ping")).await.unwrap();
    let mut echoed = [0; 4];
    within(recv.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn with_credentials_a_socket_waits_for_an_accepted_one() {
    let pair = Pair::new("credentials");
    let mut settings = settings();
    settings.credentials = vec!["right-credential".into(), "another".into()];
    let daemon = start(settings, &pair).await;
    let mut client = Mux::open(daemon.ports().websocket.unwrap(), &pair.trusted()).await;
    assert_eq!(client.hello().await & features::AUTH_REQUIRED, features::AUTH_REQUIRED);

    let remote = echo().await;
    let refused = |reply: RelayPacket| match reply {
        RelayPacket::Error { code, .. } => code,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert_eq!(refused(client.ask(ClientPacket::TcpConnect { id: 1, remote }).await), ErrorCode::AUTH_REQUIRED);
    for (id, wrong) in (2..).zip(["wrong", "right-credentia", "right-credential!", ""]) {
        let reply = client.ask(ClientPacket::Auth { id, credential: wrong.into() }).await;
        assert_eq!(refused(reply), ErrorCode::AUTH_FAILED, "{wrong:?} was not refused");
    }
    let reply = client.ask(ClientPacket::Auth { id: 10, credential: "right-credential".into() }).await;
    assert_eq!(reply, RelayPacket::Ok { id: 10 });
    client.connect_and_echo(11, remote).await;
}

#[tokio::test]
async fn the_stop_drains_turns_ready_off_and_returns_within_the_grace() {
    const GRACE: Duration = Duration::from_secs(1);
    let pair = Pair::new("stop");
    let mut settings = settings();
    settings.drain = GRACE;
    let daemon = start(settings, &pair).await;
    let ports = daemon.ports();
    let mut client = Mux::open(ports.websocket.unwrap(), &pair.trusted()).await;
    client.hello().await;

    let (stop, stopped) = oneshot::channel::<()>();
    let running = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));
    let began = Instant::now();
    stop.send(()).unwrap();
    assert!(matches!(client.next().await, Received::Control(RelayPacket::Draining)));
    let (head, body) = http(ports.http, "/ready").await;
    assert_eq!((status(&head), body.as_str()), ("http/1.1 503 service unavailable", "Draining"));

    // the session stays open, so the grace runs out and closes it with RESTARTING
    assert_eq!(client.closed().await, 4004);
    within(running).await.unwrap();
    let took = began.elapsed();
    assert!(took >= GRACE && took < GRACE + Duration::from_secs(4), "the stop took {took:?}");
}

#[tokio::test]
async fn a_renewed_certificate_is_served_to_the_next_connection_after_the_reread() {
    let mut pair = Pair::new("reread");
    let first = pair.trusted();
    let mut settings = settings();
    settings.reread = Duration::from_millis(100);
    let daemon = start(settings, &pair).await;
    let ports = daemon.ports();
    let port = ports.websocket.unwrap();
    let mut before = Mux::open(port, &first).await;
    before.hello().await;

    pair.renew();
    let renewed = pair.trusted();
    let next = within(async {
        loop {
            if let Ok(next) = tls(port, &renewed).await {
                break next;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let (mut ws, _) = within(tokio_tungstenite::client_async("wss://localhost/", next)).await.unwrap();
    assert!(matches!(within(ws.next()).await, Some(Ok(Message::Binary(_)))), "the relay's hello");
    assert!(tls(port, &first).await.is_err(), "the old certificate is still served");
    assert_eq!(http(ports.http, "/cert-hash").await.1, pair.hash.fmt(Sha256DigestFmt::BytesArray));
    // a session open before the renewal is untouched
    before.connect_and_echo(1, echo().await).await;
}

#[tokio::test]
async fn a_websocket_port_that_is_taken_leaves_webtransport_serving() {
    let pair = Pair::new("taken");
    let taken = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let mut settings = settings();
    settings.websocket_port = taken.local_addr().unwrap().port();
    let daemon = start(settings, &pair).await;
    assert_eq!(daemon.ports().websocket, None);
    assert_eq!(status(&http(daemon.ports().http, "/ready").await.0), "http/1.1 200 ok");
}

#[tokio::test]
async fn the_program_refuses_a_value_that_does_not_parse_by_its_name() {
    let program = Command::new(env!("CARGO_BIN_EXE_webvpnd")).env_clear().env("WEBVPN_MAX_SESSIONS", "lots").output();
    let output = within(program).await.unwrap();
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("WEBVPN_MAX_SESSIONS does not parse"), "{said}");
}

#[tokio::test]
async fn the_program_answers_health_and_exits_0_on_sigterm() {
    let mut program = Command::new(env!("CARGO_BIN_EXE_webvpnd"))
        .env_clear()
        .envs([
            ("WEBVPN_ADDRESS", "127.0.0.1"),
            ("WEBVPN_WEBTRANSPORT_PORT", "0"),
            ("WEBVPN_WEBSOCKET_PORT", "0"),
            ("WEBVPN_HTTP_PORT", "0"),
        ])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(program.stdout.take().unwrap()).lines();
    let port: u16 = within(async {
        loop {
            let line = lines.next_line().await.unwrap().expect("the program logs its HTTP port");
            if let Some((_, rest)) = line.split_once("HTTP listening on tcp/") {
                break rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap();
            }
        }
    })
    .await;
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });

    let (head, body) = http(port, "/health").await;
    assert_eq!((status(&head), body.as_str()), ("http/1.1 200 ok", "OK"));
    let pid = program.id().unwrap().to_string();
    assert!(within(Command::new("kill").args(["-TERM", &pid]).status()).await.unwrap().success());
    assert_eq!(within(program.wait()).await.unwrap().code(), Some(0));
}
