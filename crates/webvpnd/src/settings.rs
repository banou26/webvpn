use std::env::VarError;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use webvpn_server::{Basic, Config};

/// Everything the program is set up with, read from the `WEBVPN_` environment variables by [`Settings::from_env`].
/// It is not `Debug`, so a credential cannot reach a log through it.
#[derive(Clone)]
pub struct Settings {
    /// The address both carriers bind.
    pub address: IpAddr,
    /// The UDP port of the WebTransport carrier.
    pub webtransport_port: u16,
    /// The TCP port of the WebSocket carrier.
    pub websocket_port: u16,
    /// The address of the plain HTTP listener for `/health`, `/ready`, `/metrics` and `/cert-hash`.
    pub http_address: IpAddr,
    pub http_port: u16,
    /// The PEM certificate chain and its private key, or `None` for a self-signed certificate.
    pub certificate: Option<CertificateFiles>,
    /// How often the certificate files are read again.
    pub reread: Duration,
    /// The relay's settings apart from its policy, with the defaults of `Config` where no variable sets them.
    pub config: Config,
    /// Whether the relay reads its own global IPv6 addresses from the system, see `Relay::watch_own_ipv6`.
    pub watch_own_ipv6: bool,
    /// The ceilings and egress rules of the default policy.
    pub policy: Basic,
    /// The credentials a client may present. Empty for a relay open to every client.
    pub credentials: Vec<String>,
    /// How long a stop leaves open sessions before it closes them.
    pub drain: Duration,
}

/// The paths of a PEM certificate chain and of its private key.
#[derive(Debug, Clone)]
pub struct CertificateFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Settings {
    /// The settings from the process's environment. See [`Settings::parse`].
    pub fn from_env() -> Result<Self> {
        Self::parse(|name| std::env::var(name))
    }

    /// The settings from `var`, which looks a variable up as `std::env::var` does. A variable that is not set takes
    /// its default. A value that does not parse, or a certificate without its key or a key without its certificate,
    /// is an error that names the variable and never repeats its value.
    pub fn parse(var: impl Fn(&str) -> Result<String, VarError>) -> Result<Self> {
        let vars = Vars(var);
        let certificate = match (vars.get("WEBVPN_CERT")?, vars.get("WEBVPN_KEY")?) {
            (Some(cert), Some(key)) => Some(CertificateFiles { cert: cert.into(), key: key.into() }),
            (None, None) => None,
            _ => bail!("WEBVPN_CERT and WEBVPN_KEY go together: set both, or neither for a self-signed certificate"),
        };
        let defaults = Config::default();
        let config = Config {
            listen: vars.or("WEBVPN_LISTEN", defaults.listen)?,
            dns_upstream: vars.get("WEBVPN_DNS_UPSTREAM")?,
            max_sockets_per_session: vars.or("WEBVPN_MAX_SOCKETS_PER_SESSION", defaults.max_sockets_per_session)?,
            own_addresses: vars.list("WEBVPN_OWN_ADDRESSES")?,
            ..defaults
        };
        let mut policy = Basic::default();
        policy.max_sessions = vars.or("WEBVPN_MAX_SESSIONS", policy.max_sessions)?;
        policy.max_sockets = vars.or("WEBVPN_MAX_SOCKETS", policy.max_sockets)?;
        policy.allow_private_targets = vars.or("WEBVPN_ALLOW_PRIVATE_TARGETS", policy.allow_private_targets)?;
        policy.min_bind_port = vars.or("WEBVPN_MIN_BIND_PORT", policy.min_bind_port)?;
        Ok(Self {
            address: vars.or("WEBVPN_ADDRESS", Ipv4Addr::UNSPECIFIED.into())?,
            webtransport_port: vars.or("WEBVPN_WEBTRANSPORT_PORT", 4433)?,
            websocket_port: vars.or("WEBVPN_WEBSOCKET_PORT", 8443)?,
            http_address: vars.or("WEBVPN_HTTP_ADDRESS", Ipv4Addr::LOCALHOST.into())?,
            http_port: vars.or("WEBVPN_HTTP_PORT", 8080)?,
            certificate,
            reread: Duration::from_secs(60),
            config,
            watch_own_ipv6: vars.or("WEBVPN_WATCH_OWN_IPV6", false)?,
            policy,
            credentials: vars.list("WEBVPN_CREDENTIALS")?,
            drain: Duration::from_secs(vars.or("WEBVPN_DRAIN_SECONDS", 5)?),
        })
    }
}

struct Vars<F>(F);

impl<F: Fn(&str) -> Result<String, VarError>> Vars<F> {
    fn get(&self, name: &str) -> Result<Option<String>> {
        match (self.0)(name) {
            Ok(value) => Ok(Some(value)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => Err(anyhow!("{name} is not valid text")),
        }
    }

    /// The value parsed, or `default` when the variable is not set.
    fn or<T: FromStr>(&self, name: &str, default: T) -> Result<T>
    where
        T::Err: Display,
    {
        match self.get(name)? {
            Some(value) => value.parse().map_err(|error| anyhow!("{name} does not parse: {error}")),
            None => Ok(default),
        }
    }

    /// The comma separated items, each trimmed and parsed. Not set, or set to nothing, is no item. An empty item is
    /// an error, so a stray comma never stands for an empty credential.
    fn list<T: FromStr>(&self, name: &str) -> Result<Vec<T>>
    where
        T::Err: Display,
    {
        let Some(value) = self.get(name)?.filter(|value| !value.trim().is_empty()) else {
            return Ok(Vec::new());
        };
        value
            .split(',')
            .map(|item| match item.trim() {
                "" => Err(anyhow!("{name} does not parse: an item is empty")),
                item => item.parse().map_err(|error| anyhow!("{name} does not parse: {error}")),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;

    use super::*;

    fn parse(vars: &[(&str, &str)]) -> Result<Settings> {
        let vars: HashMap<_, _> = vars.iter().map(|&(name, value)| (name.to_owned(), value.to_owned())).collect();
        Settings::parse(|name| vars.get(name).cloned().ok_or(VarError::NotPresent))
    }

    fn refusal(vars: &[(&str, &str)]) -> String {
        match parse(vars) {
            Ok(_) => panic!("{vars:?} was taken"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn nothing_set_gives_the_defaults() {
        let settings = parse(&[]).unwrap();
        assert_eq!(settings.address, IpAddr::from([0, 0, 0, 0]));
        assert_eq!((settings.webtransport_port, settings.websocket_port), (4433, 8443));
        assert_eq!((settings.http_address, settings.http_port), (IpAddr::from([127, 0, 0, 1]), 8080));
        assert!(settings.certificate.is_none());
        assert_eq!(settings.reread, Duration::from_secs(60));
        let config = Config::default();
        assert_eq!(settings.config.listen, config.listen);
        assert_eq!(settings.config.dns_upstream, None);
        assert_eq!(settings.config.max_sockets_per_session, config.max_sockets_per_session);
        assert!(settings.config.own_addresses.is_empty());
        assert!(!settings.watch_own_ipv6);
        let basic = Basic::default();
        assert_eq!(
            (settings.policy.max_sessions, settings.policy.max_sockets, settings.policy.min_bind_port),
            (basic.max_sessions, basic.max_sockets, basic.min_bind_port)
        );
        assert!(!settings.policy.allow_private_targets);
        assert!(settings.credentials.is_empty());
        assert_eq!(settings.drain, Duration::from_secs(5));
    }

    #[test]
    fn every_variable_is_read() {
        let settings = parse(&[
            ("WEBVPN_ADDRESS", "::"),
            ("WEBVPN_WEBTRANSPORT_PORT", "443"),
            ("WEBVPN_WEBSOCKET_PORT", "444"),
            ("WEBVPN_HTTP_ADDRESS", "0.0.0.0"),
            ("WEBVPN_HTTP_PORT", "9000"),
            ("WEBVPN_CERT", "/certs/chain.pem"),
            ("WEBVPN_KEY", "/certs/key.pem"),
            ("WEBVPN_OWN_ADDRESSES", "203.0.113.7, 2001:db8::7"),
            ("WEBVPN_WATCH_OWN_IPV6", "true"),
            ("WEBVPN_LISTEN", "false"),
            ("WEBVPN_DNS_UPSTREAM", "https://dns.example/dns-query"),
            ("WEBVPN_MAX_SOCKETS_PER_SESSION", "12"),
            ("WEBVPN_MAX_SESSIONS", "3"),
            ("WEBVPN_MAX_SOCKETS", "30"),
            ("WEBVPN_ALLOW_PRIVATE_TARGETS", "true"),
            ("WEBVPN_MIN_BIND_PORT", "2000"),
            ("WEBVPN_CREDENTIALS", "first,second "),
            ("WEBVPN_DRAIN_SECONDS", "20"),
        ])
        .unwrap();
        assert_eq!(settings.address, "::".parse::<IpAddr>().unwrap());
        assert_eq!((settings.webtransport_port, settings.websocket_port), (443, 444));
        assert_eq!((settings.http_address, settings.http_port), (IpAddr::from([0, 0, 0, 0]), 9000));
        let files = settings.certificate.unwrap();
        assert_eq!((files.cert.to_str(), files.key.to_str()), (Some("/certs/chain.pem"), Some("/certs/key.pem")));
        let own: [IpAddr; 2] = ["203.0.113.7", "2001:db8::7"].map(|ip| ip.parse().unwrap());
        assert_eq!(settings.config.own_addresses, own);
        assert!(settings.watch_own_ipv6);
        assert!(!settings.config.listen);
        assert_eq!(settings.config.dns_upstream.as_deref(), Some("https://dns.example/dns-query"));
        assert_eq!(settings.config.max_sockets_per_session, 12);
        assert_eq!((settings.policy.max_sessions, settings.policy.max_sockets), (3, 30));
        assert!(settings.policy.allow_private_targets);
        assert_eq!(settings.policy.min_bind_port, 2000);
        assert_eq!(settings.credentials, ["first", "second"]);
        assert_eq!(settings.drain, Duration::from_secs(20));
    }

    #[test]
    fn a_value_that_does_not_parse_is_refused_by_its_name_and_never_repeated() {
        for (name, value) in [
            ("WEBVPN_ADDRESS", "relay.example"),
            ("WEBVPN_WEBTRANSPORT_PORT", "65536"),
            ("WEBVPN_WEBSOCKET_PORT", "-1"),
            ("WEBVPN_HTTP_ADDRESS", "300.0.0.1"),
            ("WEBVPN_HTTP_PORT", "eighty"),
            ("WEBVPN_OWN_ADDRESSES", "203.0.113.7,203.0.113.300"),
            ("WEBVPN_OWN_ADDRESSES", "203.0.113.7,"),
            ("WEBVPN_WATCH_OWN_IPV6", "yes"),
            ("WEBVPN_LISTEN", "1"),
            ("WEBVPN_MAX_SOCKETS_PER_SESSION", "many"),
            ("WEBVPN_MAX_SESSIONS", "1.5"),
            ("WEBVPN_MAX_SOCKETS", ""),
            ("WEBVPN_ALLOW_PRIVATE_TARGETS", "TRUE"),
            ("WEBVPN_MIN_BIND_PORT", "70000"),
            ("WEBVPN_CREDENTIALS", "secret-one,,secret-two"),
            ("WEBVPN_DRAIN_SECONDS", "5s"),
        ] {
            let refusal = refusal(&[(name, value)]);
            assert!(refusal.starts_with(name), "{refusal:?} does not name {name}");
            for item in value.split(',').filter(|item| item.len() > 2) {
                assert!(!refusal.contains(item), "{refusal:?} repeats the value of {name}");
            }
        }
    }

    #[test]
    fn a_value_that_is_not_text_is_refused_by_its_name() {
        let refusal = Settings::parse(|name| match name {
            "WEBVPN_CREDENTIALS" => Err(VarError::NotUnicode(OsString::from("x"))),
            _ => Err(VarError::NotPresent),
        });
        assert_eq!(refusal.err().unwrap().to_string(), "WEBVPN_CREDENTIALS is not valid text");
    }

    #[test]
    fn a_certificate_without_its_key_or_a_key_without_its_certificate_is_refused() {
        for name in ["WEBVPN_CERT", "WEBVPN_KEY"] {
            let refusal = refusal(&[(name, "/certs/one.pem")]);
            assert!(refusal.contains("WEBVPN_CERT and WEBVPN_KEY go together"), "{refusal}");
        }
    }

    #[test]
    fn an_empty_list_is_no_item() {
        let settings = parse(&[("WEBVPN_CREDENTIALS", ""), ("WEBVPN_OWN_ADDRESSES", " ")]).unwrap();
        assert!(settings.credentials.is_empty());
        assert!(settings.config.own_addresses.is_empty());
    }
}
