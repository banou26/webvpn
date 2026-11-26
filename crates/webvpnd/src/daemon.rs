use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{error, info, warn};
use webvpn_server::{websocket, webtransport, Counter, Relay};
use wtransport::endpoint::endpoint_side::Server;
use wtransport::tls::Sha256DigestFmt;
use wtransport::{Endpoint, Identity, ServerConfig};

use crate::policy::Credentials;
use crate::settings::{CertificateFiles, Settings};

/// How long the stop waits for the carriers once the relay stopped: the WebTransport acceptor's own wait for QUIC to
/// send the closes still owed. A client still in its handshake does not hold the stop past it.
const SEND_CLOSES: Duration = Duration::from_secs(2);

/// The ports a started [`Daemon`] holds. A setting of port 0 leaves the port to the system, and this says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub webtransport: u16,
    /// `None` when the WebSocket listener could not start.
    pub websocket: Option<u16>,
    pub http: u16,
}

/// One relay with the program's policy, serving on WebTransport and WebSocket, with its plain HTTP listener.
///
/// [`start`](Self::start) takes the ports and serves at once; [`run`](Self::run) waits for the stop signal and stops
/// the relay. Dropping it ends the accept loops, the HTTP listener and the certificate re-read; a session already
/// open runs on until it ends.
pub struct Daemon {
    relay: Relay<Credentials>,
    ports: Ports,
    drain: Duration,
    /// The accept loops of the two carriers, which end with the stop.
    carriers: JoinSet<()>,
    /// The HTTP listener and the certificate re-read, which run until the daemon is dropped.
    background: JoinSet<()>,
}

impl Daemon {
    /// Loads the certificate or makes a self-signed one, takes the ports and serves.
    ///
    /// An error is a certificate that cannot be read, a WebTransport or HTTP port that cannot be taken, or the
    /// system's IPv6 addresses that cannot be read when they are watched. A WebSocket port that cannot be taken is
    /// logged and leaves WebTransport serving alone. Logs name the ports the daemon holds and never an address.
    pub async fn start(settings: Settings) -> Result<Self> {
        let Certificate { identity, tls, hash } = match &settings.certificate {
            Some(files) => Certificate::read(files).await?,
            None => {
                warn!("no certificate is set: a self-signed one is served, which browsers take by hash for 14 days");
                Certificate::self_signed(settings.address)?
            }
        };
        let bind = ServerConfig::builder().with_bind_address((settings.address, settings.webtransport_port).into());
        let endpoint = Endpoint::server(webtransport::server_config(bind, identity))
            .with_context(|| format!("WebTransport could not take udp/{}", settings.webtransport_port))?;
        let endpoint = Arc::new(endpoint);
        let webtransport_port = endpoint.local_addr()?.port();

        let max_sessions = settings.policy.max_sessions;
        if !settings.credentials.is_empty() {
            info!("a client presents a credential before it opens a socket");
        }
        let relay = Relay::new(Credentials::new(settings.policy, settings.credentials), settings.config);
        if settings.watch_own_ipv6 {
            relay.watch_own_ipv6().context("the system's IPv6 addresses could not be read")?;
        }

        let mut carriers = JoinSet::new();
        carriers.spawn(webtransport::serve(relay.clone(), endpoint.clone()));
        let (tls_sender, tls) = watch::channel(tls);
        // WebSocket is the fallback carrier: a listener that cannot start must not take WebTransport down with it.
        let websocket = match TcpListener::bind((settings.address, settings.websocket_port)).await {
            Ok(listener) => {
                let options = websocket::Options { tls: Some(tls), http: Some(load(relay.clone(), max_sessions)) };
                let port = listener.local_addr()?.port();
                carriers.spawn(websocket::serve(relay.clone(), listener, options));
                Some(port)
            }
            Err(error) => {
                error!("WebSocket could not take tcp/{}, WebTransport serves alone: {error}", settings.websocket_port);
                None
            }
        };

        // Last, so `/ready` answers only once both carriers serve.
        let http = TcpListener::bind((settings.http_address, settings.http_port))
            .await
            .with_context(|| format!("the HTTP listener could not take tcp/{}", settings.http_port))?;
        let ports = Ports { webtransport: webtransport_port, websocket, http: http.local_addr()?.port() };
        let (hash_sender, hash) = watch::channel(hash);
        let mut background = JoinSet::new();
        background.spawn(serve_http(http, relay.clone(), hash));
        if let Some(files) = settings.certificate {
            background.spawn(reread(files, settings.reread, endpoint, tls_sender, hash_sender));
        }

        info!("WebTransport listening on udp/{}", ports.webtransport);
        if let Some(port) = ports.websocket {
            info!("WebSocket listening on tcp/{port}");
        }
        info!("HTTP listening on tcp/{}", ports.http);
        Ok(Self { relay, ports, drain: settings.drain, carriers, background })
    }

    /// The ports the daemon holds, the ones the system picked included.
    pub fn ports(&self) -> Ports {
        self.ports
    }

    /// Serves until `stop` resolves, then stops the relay: open sessions are sent `Draining`, `/ready` answers 503,
    /// and nothing new is taken. Returns once every session ended or was closed when the drain's grace passed, and
    /// the closes went out: within the grace and 4 seconds.
    pub async fn run(mut self, stop: impl Future<Output = ()>) {
        stop.await;
        info!("stopping: no new session is taken");
        self.relay.stop(self.drain).await;
        let carriers = async { while self.carriers.join_next().await.is_some() {} };
        let _ = tokio::time::timeout(SEND_CLOSES, carriers).await;
        // the counter rarely outlives the process to a scrape, so its last value goes here
        let closed = self.relay.metrics().get(Counter::DrainCapCloses);
        info!("stopped, {closed} sessions closed when the grace ran out");
        self.background.shutdown().await;
    }
}

/// The relay's certificate, in the forms the two carriers and `/cert-hash` take it.
struct Certificate {
    identity: Identity,
    tls: Arc<rustls::ServerConfig>,
    /// The SHA-256 of the leaf certificate as `/cert-hash` serves it: JSON, an array of 32 numbers.
    hash: String,
}

impl Certificate {
    async fn read(files: &CertificateFiles) -> Result<Self> {
        let identity =
            Identity::load_pemfiles(&files.cert, &files.key).await.context("the certificate was not read")?;
        Self::new(identity)
    }

    /// A browser takes a certificate by its hash (`serverCertificateHashes`) only when it is valid for 14 days at
    /// most, which is what wtransport makes.
    fn self_signed(address: IpAddr) -> Result<Self> {
        let mut names = vec!["localhost".to_owned(), "127.0.0.1".to_owned(), "::1".to_owned()];
        if !address.is_unspecified() && !address.is_loopback() {
            names.push(address.to_string());
        }
        Self::new(Identity::self_signed(names)?)
    }

    fn new(identity: Identity) -> Result<Self> {
        let chain = identity.certificate_chain().as_slice();
        let leaf = chain.first().context("the certificate file holds no certificate")?;
        let hash = leaf.hash().fmt(Sha256DigestFmt::BytesArray);
        let chain = chain.iter().map(|certificate| CertificateDer::from(certificate.der().to_vec())).collect();
        let key = PrivateKeyDer::try_from(identity.private_key().secret_der().to_vec()).map_err(anyhow::Error::msg)?;
        // only the `ring` provider is compiled in, so the default builder takes it without an install
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("the certificate and its key do not go together")?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { identity, tls: Arc::new(tls), hash })
    }
}

/// Reads the certificate files every `every` and hands what they hold to both carriers and `/cert-hash`, so a renewed
/// certificate is served without closing a session: open sessions keep the one they started with.
async fn reread(
    files: CertificateFiles,
    every: Duration,
    endpoint: Arc<Endpoint<Server>>,
    tls: watch::Sender<Arc<rustls::ServerConfig>>,
    hash: watch::Sender<String>,
) {
    let mut ticker = tokio::time::interval(every);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        // the files only, never a self-signed certificate, so a read in the middle of a renewal keeps the one in use
        let certificate = match Certificate::read(&files).await {
            Ok(certificate) => certificate,
            Err(error) => {
                warn!("the certificate in use is kept: {error:#}");
                continue;
            }
        };
        // the bind is ignored: the endpoint keeps its socket
        let config = webtransport::server_config(ServerConfig::builder().with_bind_default(0), certificate.identity);
        if let Err(error) = endpoint.reload_config(config, false) {
            warn!("the certificate in use is kept: {error}");
            continue;
        }
        tls.send_replace(certificate.tls);
        if hash.send_replace(certificate.hash.clone()) != certificate.hash {
            info!("a renewed certificate is served");
        }
    }
}

/// The answer to `GET /load` on the WebSocket port, so one request from a client measures the round trip of the
/// path its session would take and reads the relay's load. Counts only.
fn load(relay: Relay<Credentials>, max_sessions: usize) -> websocket::Handler {
    Arc::new(move |method: &str, path: &str| {
        (method == "GET" && path == "/load").then(|| {
            let (sessions, version) = (relay.sessions(), env!("CARGO_PKG_VERSION"));
            format!(r#"{{"sessions":{sessions},"maxSessions":{max_sessions},"version":"{version}"}}"#)
        })
    })
}

async fn serve_http(listener: TcpListener, relay: Relay<Credentials>, hash: watch::Receiver<String>) {
    let ready = relay.clone();
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/ready",
            get(move || {
                let answer = match ready.stopping() {
                    true => (StatusCode::SERVICE_UNAVAILABLE, "Draining"),
                    false => (StatusCode::OK, "Ready"),
                };
                async move { answer }
            }),
        )
        .route("/metrics", get(move || async move { relay.render_metrics() }))
        .route(
            "/cert-hash",
            get(move || {
                let hash = hash.borrow().clone();
                let headers = [("access-control-allow-origin", "*"), ("content-type", "application/json")];
                async move { (headers, hash) }
            }),
        );
    if let Err(error) = axum::serve(listener, app).await {
        error!("the HTTP listener stopped: {error}");
    }
}
