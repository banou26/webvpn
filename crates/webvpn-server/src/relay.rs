use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::debug;
use webvpn_proto::{close, features};

use crate::dns::Dns;
use crate::hairpin::Hairpin;
use crate::metrics::Metrics;
use crate::policy::{Auth, Policy};
use crate::session::{self, Setup, UdpCarrier};
use crate::transport::Transport;

/// The reason a session closed with `RESTARTING` carries, for a person.
pub(crate) const STOPPING: &str = "the relay is stopping";

/// How long a stop waits for closes to go out. It is spent twice: once for the sessions to say `Bye`, close and
/// release (a session takes at most `session::BYE_WAIT` of it, and one over the WebSocket mux a second more for its
/// writer to send the close), once more for QUIC to deliver its closes (that second wait is the WebTransport
/// carrier's, on its endpoint).
pub(crate) const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// How a relay is set up, apart from its policy.
#[derive(Debug, Clone)]
pub struct Config {
    /// Named in the relay's hello, for a person reading a client's log.
    pub agent: String,
    /// Whether clients may listen for inbound TCP connections.
    pub listen: bool,
    /// The DNS over HTTPS endpoint (RFC 8484) that answers name lookups. `None` turns them off.
    pub dns_upstream: Option<String>,
    /// Sockets one session may hold at once.
    pub max_sockets_per_session: usize,
    /// The relay's own public addresses. A connection to one of them goes to the socket another session bound on
    /// that port, and is refused when there is none.
    pub own_addresses: Vec<IpAddr>,
    /// Sessions the relay holds in setup at once, from the client's arrival to its hello. A client that arrives
    /// while that many are setting up is turned away at once: the WebSocket listener drops its connection before
    /// reading anything, the WebTransport acceptor refuses it at the QUIC level, and [`Relay::serve`] closes the
    /// session with `SESSION_LIMIT`.
    pub max_pending_sessions: usize,
    /// How long a session's setup may take, from the client's arrival (for a carrier of your own, from its call to
    /// [`Relay::serve`]) to its hello. A session past it is closed with `PROTOCOL_ERROR`.
    pub setup_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: concat!("webvpn-server/", env!("CARGO_PKG_VERSION")).into(),
            listen: true,
            dns_upstream: None,
            max_sockets_per_session: 4096,
            own_addresses: Vec::new(),
            max_pending_sessions: 256,
            setup_timeout: Duration::from_secs(15),
        }
    }
}

/// What every session of one relay shares.
pub(crate) struct Shared {
    pub config: Config,
    pub hairpin: Hairpin,
    pub dns: Option<Dns>,
    pub metrics: Arc<Metrics>,
    /// Cancelled when the stop begins: sessions are told `Draining`, and no new one is served.
    pub stopping: CancellationToken,
    /// Cancelled when the stop's grace has passed: every session still open says `Bye` and closes.
    pub closing: CancellationToken,
}

impl Shared {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            hairpin: Hairpin::new(config.own_addresses.clone()),
            dns: config.dns_upstream.clone().map(Dns::new),
            metrics: Arc::default(),
            stopping: CancellationToken::new(),
            closing: CancellationToken::new(),
            config,
        })
    }

    /// The feature bits of the relay's hello.
    pub fn features(&self, auth: Auth) -> u32 {
        let mut bits = 0;
        if self.config.listen {
            bits |= features::LISTEN;
        }
        if self.dns.is_some() {
            bits |= features::DNS;
        }
        match auth {
            Auth::None => {}
            Auth::Optional => bits |= features::AUTH,
            Auth::Required => bits |= features::AUTH | features::AUTH_REQUIRED,
        }
        bits
    }
}

/// A relay: its policy, its settings and the sessions it holds. Cheap to clone; clones are the same relay.
///
/// A carrier accepts clients and hands each one's session to [`serve`](Self::serve); [`stop`](Self::stop) ends them
/// all. Nothing in it is process-wide, so one process may run several relays, each with its own counts.
pub struct Relay<P: Policy>(Arc<Inner<P>>);

struct Inner<P> {
    policy: P,
    shared: Arc<Shared>,
    /// One permit for each session still setting up.
    setup_slots: Arc<Semaphore>,
    /// Holds a token for each session from its admission until it ends.
    sessions: TaskTracker,
}

impl<P: Policy> Clone for Relay<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: Policy> Relay<P> {
    /// A relay that admits sessions under `policy` and runs them as `config` says. It serves nothing until a carrier
    /// hands it a session.
    pub fn new(policy: P, config: Config) -> Self {
        let setup_slots = Arc::new(Semaphore::new(config.max_pending_sessions.min(Semaphore::MAX_PERMITS)));
        Self(Arc::new(Inner {
            policy,
            shared: Shared::new(config),
            setup_slots,
            sessions: TaskTracker::new(),
        }))
    }

    /// The policy the relay asks about every session.
    pub fn policy(&self) -> &P {
        &self.0.policy
    }

    /// Reads the relay's own global IPv6 addresses from the system now, then again every second, and treats each as
    /// one of [`Config::own_addresses`]: a connection to one of them is routed to the socket a session bound on that
    /// port, or refused, and so is a connection to another address on the same link. Linux only: elsewhere the
    /// system lists none and nothing is added. Call it once, before the relay takes sessions. The reading ends
    /// within a second of the relay, its clones and its sessions being dropped.
    ///
    /// An error means the system's list exists but could not be read or parsed, and nothing was started; it names no
    /// address. A later read that fails keeps the addresses read before.
    pub fn watch_own_ipv6(&self) -> std::io::Result<()> {
        self.0.shared.hairpin.watch_kernel_ipv6()
    }

    /// What this relay counted since it was made, and nothing another relay counted.
    pub fn metrics(&self) -> &Metrics {
        &self.0.shared.metrics
    }

    /// The same counters as [`metrics`](Self::metrics), for a carrier's tasks that outlive a borrow of the relay.
    #[cfg(feature = "websocket")]
    pub(crate) fn shared_metrics(&self) -> Arc<Metrics> {
        self.0.shared.metrics.clone()
    }

    /// Sessions the policy admitted that have not ended yet, the ones still in their hello exchange included. A client
    /// still in its carrier's handshake, or turned away before its admission, is not counted.
    pub fn sessions(&self) -> usize {
        self.0.sessions.len()
    }

    /// The relay's counters in the Prometheus text format, with [`sessions`](Self::sessions) as the open sessions
    /// gauge. See [`Metrics::render`].
    pub fn render_metrics(&self) -> String {
        self.metrics().render(self.sessions())
    }

    /// Runs one client's session on `transport` until it ends, on any carrier. `carrier` says how the session's UDP
    /// sockets reach the client, and must match what the carrier's clients read.
    ///
    /// The session is closed with:
    /// - `RESTARTING` once [`stop`](Self::stop) was called, before the policy is asked;
    /// - `SESSION_LIMIT` when [`Config::max_pending_sessions`] sessions are setting up already, and with the policy's
    ///   message when [`Policy::admit`] refuses it;
    /// - `PROTOCOL_ERROR` when its setup, from this call to the client's hello, takes longer than
    ///   [`Config::setup_timeout`] or the client breaks the protocol, and `VERSION_MISMATCH` when the client's
    ///   version does not suit;
    /// - `NORMAL` when the client ends it.
    ///
    /// Before each close the client is told the same code and reason in a `Bye` on the control stream, whenever the
    /// stream can carry it. A session closed before its hello gets a control stream with the `Bye` alone.
    ///
    /// Nothing is returned: what ended a session is logged at debug level, and names no client.
    pub async fn serve<T: Transport>(&self, transport: T, carrier: UdpCarrier) {
        let Some(setup) = self.pending() else {
            let reason = "the relay holds as many sessions in setup as it allows";
            return session::refuse(&transport, close::SESSION_LIMIT, reason).await;
        };
        self.serve_setup(transport, carrier, setup).await;
    }

    /// A place among the sessions still setting up, with a deadline [`Config::setup_timeout`] from now. A built-in
    /// carrier takes it as a client arrives, before its own handshake, and hands it to
    /// [`serve_setup`](Self::serve_setup), so the place and the deadline cover the handshake too. `None` when
    /// [`Config::max_pending_sessions`] are setting up: the carrier then turns the client away.
    pub(crate) fn pending(&self) -> Option<Setup> {
        let permit = self.0.setup_slots.clone().try_acquire_owned().ok()?;
        Some(Setup { permit, deadline: Instant::now() + self.0.shared.config.setup_timeout })
    }

    /// [`serve`](Self::serve) with the place and deadline a carrier took itself, from [`pending`](Self::pending).
    pub(crate) async fn serve_setup<T: Transport>(&self, transport: T, carrier: UdpCarrier, setup: Setup) {
        let relay = &*self.0;
        if self.stopping() {
            return session::refuse(&transport, close::RESTARTING, STOPPING).await;
        }
        let policy = match relay.policy.admit(transport.remote_ip().to_canonical()) {
            Ok(policy) => policy,
            Err(refusal) => return session::refuse(&transport, close::SESSION_LIMIT, &refusal.message).await,
        };
        let _open = relay.sessions.token();
        let (shared, auth) = (relay.shared.clone(), relay.policy.auth());
        if let Err(error) = session::run(Arc::new(transport), policy, shared, auth, carrier, setup).await {
            debug!("a session ended: {error:#}");
        }
    }

    /// True once [`stop`](Self::stop) was called. A carrier's listener refuses whatever arrives from then on.
    pub fn stopping(&self) -> bool {
        self.0.shared.stopping.is_cancelled()
    }

    /// Resolves once [`stop`](Self::stop) was called.
    pub async fn stopped(&self) {
        self.0.shared.stopping.cancelled().await
    }

    /// Stops the relay. Every open session is sent `Draining` once and keeps its sockets, and every session served
    /// from now on is closed with `RESTARTING`. Then waits until every session ended or `grace` passed, has the ones
    /// still open say `Bye` and close with `RESTARTING` (counted as [`Counter::DrainCapCloses`](crate::Counter)), and
    /// waits up to 2 seconds more for those closes to go out. Returns at once when no session is open. Calling it again
    /// is harmless.
    pub async fn stop(&self, grace: Duration) {
        let relay = &*self.0;
        relay.shared.stopping.cancel();
        relay.sessions.close();
        let _ = tokio::time::timeout(grace, relay.sessions.wait()).await;
        relay.shared.closing.cancel();
        let _ = tokio::time::timeout(CLOSE_WAIT, relay.sessions.wait()).await;
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::AsyncReadExt;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use webvpn_proto::{ClientPacket, Hello, RelayPacket};

    use super::*;
    use crate::metrics::Counter;
    use crate::policy::{Basic, BasicSession, Refusal};
    use crate::session::BYE_WAIT;
    use crate::testing::{self, Client, Control, Opened, WAIT};

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const GRACE: Duration = Duration::from_secs(1);

    async fn within<F: Future>(future: F) -> F::Output {
        timeout(WAIT, future).await.expect("done in time")
    }

    fn relay() -> Relay<Basic> {
        Relay::new(Basic::default(), Config::default())
    }

    /// A policy that admits no session.
    fn full() -> Basic {
        Basic { max_sessions: 0, ..Basic::default() }
    }

    /// A client arriving at `relay`, and the task serving its session.
    fn arrive<P: Policy>(relay: &Relay<P>) -> (Client, JoinHandle<()>) {
        let (transport, client) = testing::session(CLIENT);
        let relay = relay.clone();
        (client, tokio::spawn(async move { relay.serve(transport, UdpCarrier::Bidi).await }))
    }

    /// A client whose session is past its hello exchange.
    struct Open {
        client: Client,
        control: Control,
        serving: JoinHandle<()>,
    }

    impl Open {
        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.control.send(request).await;
            self.control.next().await.expect("the relay answers")
        }

        /// Binds a UDP socket, and gives the address it was bound on.
        async fn bind(&mut self) -> SocketAddr {
            let local = "127.0.0.1:0".parse().unwrap();
            let RelayPacket::Socket { id: 1, local, .. } = self.ask(ClientPacket::UdpBind { id: 1, local }).await else {
                panic!("the bind was not answered with its socket");
            };
            local
        }
    }

    async fn open<P: Policy>(relay: &Relay<P>) -> Open {
        let (mut client, serving) = arrive(relay);
        let mut control = client.control().await;
        assert!(matches!(control.next().await, Some(RelayPacket::Hello(_))));
        control.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;
        Open { client, control, serving }
    }

    /// `Basic`, noting the address each client was admitted under.
    #[derive(Default)]
    struct Noting {
        rules: Basic,
        admitted: std::sync::Mutex<Vec<IpAddr>>,
    }

    impl Policy for Noting {
        type Session = BasicSession;

        fn admit(&self, peer: IpAddr) -> Result<BasicSession, Refusal> {
            self.admitted.lock().unwrap().push(peer);
            self.rules.admit(peer)
        }
    }

    fn stop(relay: &Relay<Basic>, grace: Duration) -> JoinHandle<()> {
        let relay = relay.clone();
        tokio::spawn(async move { relay.stop(grace).await })
    }

    // A listener on every address reports an IPv4 client as an IPv4-mapped IPv6 address, and a policy that counts by
    // address must find that client under the key any other carrier gives it.
    #[tokio::test]
    async fn a_policy_is_given_an_ipv4_client_as_ipv4_however_its_carrier_spells_the_address() {
        let relay = Relay::new(Noting::default(), Config::default());
        let IpAddr::V4(client) = CLIENT else { unreachable!() };
        let (transport, mut arrived) = testing::session(IpAddr::V6(client.to_ipv6_mapped()));
        let serving = tokio::spawn({
            let relay = relay.clone();
            async move { relay.serve(transport, UdpCarrier::Bidi).await }
        });
        let mut control = within(arrived.control()).await;
        assert!(matches!(within(control.next()).await, Some(RelayPacket::Hello(_))));
        assert_eq!(*relay.policy().admitted.lock().unwrap(), [CLIENT]);
        serving.abort();
    }

    #[tokio::test]
    async fn a_served_session_answers_counts_as_open_and_is_closed_normal_when_it_ends() {
        let relay = relay();
        let mut open = open(&relay).await;
        open.bind().await;
        assert_eq!(relay.sessions(), 1);

        open.control.finish().await;
        assert_eq!(testing::bye(&mut open.control, &mut open.client).await.0, close::NORMAL);
        within(open.serving).await.unwrap();
        assert_eq!(relay.sessions(), 0);
        let counted = [Counter::Sessions, Counter::SocketsOpened, Counter::SocketsClosed];
        assert_eq!(counted.map(|counter| relay.metrics().get(counter)), [1, 1, 1]);
    }

    #[tokio::test]
    async fn a_session_dropped_while_it_holds_a_socket_leaves_no_socket_counted_as_open() {
        let relay = relay();
        let mut open = open(&relay).await;
        open.bind().await;
        let rendered = |relay: &Relay<Basic>| relay.render_metrics().lines().any(|line| line == "webvpn_active_sockets 0");
        assert!(!rendered(&relay));

        open.serving.abort();
        assert!(within(open.serving).await.unwrap_err().is_cancelled());
        assert_eq!(relay.sessions(), 0);
        assert!(rendered(&relay), "{}", relay.render_metrics());
    }

    #[tokio::test]
    async fn a_refused_admission_closes_with_session_limit_and_the_policy_s_message() {
        let policy = full();
        let refusal = policy.admit(CLIENT).unwrap_err();
        let relay = Relay::new(policy, Config::default());
        let (mut client, serving) = arrive(&relay);
        // the `Bye` is the only frame: no hello comes before it
        let mut control = client.control().await;
        let said = testing::bye(&mut control, &mut client).await;
        assert_eq!(said, (close::SESSION_LIMIT, refusal.message.into_owned()));
        within(serving).await.unwrap();
        assert_eq!(relay.sessions(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_arriving_while_setup_is_full_is_closed_with_session_limit_and_setup_has_its_timeout() {
        let config = Config { max_pending_sessions: 1, setup_timeout: Duration::from_secs(3), ..Config::default() };
        let relay = Relay::new(Basic::default(), config);
        let start = Instant::now();
        let (mut silent, first) = arrive(&relay);
        let mut never_answered = silent.control().await;
        assert!(matches!(never_answered.next().await, Some(RelayPacket::Hello(_))));

        let (mut turned_away, second) = arrive(&relay);
        let mut refused = turned_away.control().await;
        assert_eq!(testing::bye(&mut refused, &mut turned_away).await.0, close::SESSION_LIMIT);
        within(second).await.unwrap();

        assert_eq!(testing::bye(&mut never_answered, &mut silent).await.0, close::PROTOCOL_ERROR);
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        within(first).await.unwrap();
        // The place the silent client held is free again.
        open(&relay).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_sends_draining_and_waits_for_a_session_that_ends_within_the_grace() {
        let relay = relay();
        let mut open = open(&relay).await;
        let stopping = stop(&relay, Duration::from_secs(60));
        assert_eq!(open.control.next().await, Some(RelayPacket::Draining));
        within(relay.stopped()).await;
        assert!(relay.stopping());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!stopping.is_finished());

        open.control.finish().await;
        assert_eq!(testing::bye(&mut open.control, &mut open.client).await.0, close::NORMAL);
        within(stopping).await.unwrap();
        assert_eq!(relay.metrics().get(Counter::DrainCapCloses), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_returns_at_once_when_no_session_is_open_and_twice_is_harmless() {
        let relay = relay();
        let start = Instant::now();
        for _ in 0..2 {
            within(relay.stop(Duration::from_secs(60))).await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(relay.stopping());
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_open_after_the_grace_says_bye_restarting_ends_its_sockets_and_is_counted() {
        let relay = relay();
        let mut open = open(&relay).await;
        open.bind().await;
        let mut socket = open.client.next_stream().await;
        assert_eq!(socket.opened, Opened::UdpBi);
        within(socket.recv.read_exact(&mut [0; 4])).await.unwrap();

        let start = Instant::now();
        let stopping = stop(&relay, GRACE);
        assert_eq!(open.control.next().await, Some(RelayPacket::Draining));
        assert_eq!(within(socket.recv.read(&mut [0; 1])).await.unwrap(), 0);
        let bye = RelayPacket::Bye { code: close::RESTARTING, reason: STOPPING.into() };
        assert_eq!(open.control.next().await, Some(bye));
        assert_eq!(open.client.closed().await.0, close::RESTARTING);
        assert_eq!(relay.metrics().get(Counter::DrainCapCloses), 1);

        // The session ends by itself once it said `Bye` and closed.
        within(stopping).await.unwrap();
        within(open.serving).await.unwrap();
        assert_eq!(start.elapsed(), GRACE);
        assert_eq!(relay.sessions(), 0);
        assert_eq!(relay.metrics().get(Counter::SocketsClosed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_whose_client_reads_nothing_still_closes_once_its_bye_had_its_time_and_then_ends_its_sockets() {
        let relay = relay();
        let mut open = open(&relay).await;
        open.bind().await;
        let mut socket = open.client.next_stream().await;
        within(socket.recv.read_exact(&mut [0; 4])).await.unwrap();
        // Enough answers, never read, to fill the control stream and the reply queue, so the `Bye` finds no room.
        for id in 0..8000 {
            open.control.send(ClientPacket::AuthClear { id }).await;
        }
        let start = Instant::now();
        let stopping = stop(&relay, GRACE);
        // The socket outlives the time the `Bye` is given, so a client that reads it learns why before its sockets end.
        assert_eq!(within(socket.recv.read(&mut [0; 1])).await.unwrap(), 0);
        assert_eq!(start.elapsed(), GRACE + BYE_WAIT);
        within(stopping).await.unwrap();
        assert_eq!(open.client.closed().await.0, close::RESTARTING);
        within(open.serving).await.unwrap();
        assert_eq!(start.elapsed(), GRACE + BYE_WAIT);
        assert_eq!(relay.sessions(), 0);
    }

    #[tokio::test]
    async fn a_client_arriving_after_stop_is_closed_restarting_before_the_policy_is_asked() {
        let relay = Relay::new(full(), Config::default());
        within(relay.stop(GRACE)).await;
        let (mut client, serving) = arrive(&relay);
        let mut control = client.control().await;
        assert_eq!(testing::bye(&mut control, &mut client).await, (close::RESTARTING, STOPPING.to_owned()));
        within(serving).await.unwrap();
        assert_eq!(relay.metrics().get(Counter::DrainCapCloses), 0);
    }

    #[tokio::test]
    async fn two_relays_in_one_process_keep_their_counts_and_their_stop_apart() {
        let (one, two) = (relay(), relay());
        let mut on_one = open(&one).await;
        let mut on_two = open(&two).await;
        on_one.bind().await;
        assert_eq!(on_two.ask(ClientPacket::AuthClear { id: 1 }).await, RelayPacket::Ok { id: 1 });
        assert_eq!((one.sessions(), two.sessions()), (1, 1));
        let sockets = |relay: &Relay<Basic>| relay.metrics().get(Counter::SocketsOpened);
        assert_eq!((sockets(&one), sockets(&two)), (1, 0));

        let stopping = stop(&two, Duration::from_secs(60));
        assert_eq!(on_two.control.next().await, Some(RelayPacket::Draining));
        drop(on_two.control);
        within(stopping).await.unwrap();
        assert!(!one.stopping());
        assert_eq!(on_one.ask(ClientPacket::AuthClear { id: 2 }).await, RelayPacket::Ok { id: 2 });
        assert_eq!((one.sessions(), two.sessions()), (1, 0));
    }

    #[tokio::test]
    async fn render_keeps_the_old_names_and_no_line_carries_an_address() {
        let relay = relay();
        let mut open = open(&relay).await;
        let local = open.bind().await;
        let rendered = relay.render_metrics();
        for expected in [
            "# TYPE webvpn_active_connections_total gauge",
            "webvpn_active_connections_total 1",
            "webvpn_active_sockets 1",
            "webvpn_handshakes_total 1",
            r#"webvpn_bandwidth_bytes_total{direction="down"} 0"#,
            r#"webvpn_udp_dropped_total{reason="channel_full"} 0"#,
        ] {
            assert!(rendered.lines().any(|line| line == expected), "{expected:?} is not in\n{rendered}");
        }
        let addresses = [CLIENT.to_string(), local.ip().to_string(), local.port().to_string()];
        for line in rendered.lines() {
            assert!(!addresses.iter().any(|address| line.contains(address.as_str())), "{line:?} names an address");
            let labels = line.split_once('{').map_or("", |(_, labels)| labels);
            for label in labels.split(',').filter(|label| !label.is_empty()) {
                let key = label.split('=').next().unwrap();
                assert!(["direction", "reason", "outcome", "stage"].contains(&key), "{line:?} has label {key}");
            }
        }
    }
}
