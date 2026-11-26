use std::net::IpAddr;
use std::sync::Arc;

use webvpn_proto::features;

use crate::dns::Dns;
use crate::hairpin::Hairpin;
use crate::metrics::Metrics;
use crate::policy::Auth;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: concat!("webvpn-server/", env!("CARGO_PKG_VERSION")).into(),
            listen: true,
            dns_upstream: None,
            max_sockets_per_session: 4096,
            own_addresses: Vec::new(),
        }
    }
}

/// What every session of one relay shares.
pub(crate) struct Shared {
    pub config: Config,
    pub hairpin: Hairpin,
    pub dns: Option<Dns>,
    pub metrics: Arc<Metrics>,
}

impl Shared {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            hairpin: Hairpin::new(config.own_addresses.clone()),
            dns: config.dns_upstream.clone().map(Dns::new),
            metrics: Arc::default(),
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
