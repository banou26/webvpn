use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use subtle::{Choice, ConstantTimeEq};
use webvpn_proto::ErrorCode;
use webvpn_server::{Auth, Basic, BasicSession, Policy, Proto, Refusal, Session, Slot, SocketKind};

/// The program's policy: [`Basic`], and when credentials are configured, a client must present one of them before it
/// may open a socket. Without credentials the relay is open and takes none, as `Basic` does.
pub struct Credentials {
    basic: Basic,
    accepted: Arc<[Box<[u8]>]>,
}

impl Credentials {
    /// `basic`'s rules, with `accepted` as the credentials a client may present. None leaves the relay open.
    pub fn new(basic: Basic, accepted: impl IntoIterator<Item = String>) -> Self {
        let accepted = accepted.into_iter().map(|credential| credential.into_bytes().into_boxed_slice()).collect();
        Self { basic, accepted }
    }
}

impl Policy for Credentials {
    type Session = CredentialSession;

    fn auth(&self) -> Auth {
        if self.accepted.is_empty() {
            Auth::None
        } else {
            Auth::Required
        }
    }

    fn admit(&self, peer: IpAddr) -> Result<CredentialSession, Refusal> {
        Ok(CredentialSession { basic: self.basic.admit(peer)?, accepted: self.accepted.clone() })
    }
}

/// A session [`Credentials`] admitted.
pub struct CredentialSession {
    basic: BasicSession,
    accepted: Arc<[Box<[u8]>]>,
}

impl Session for CredentialSession {
    type Permit = Slot;

    /// Accepts a credential equal to one of the configured ones. Each configured one is compared, and one of the same
    /// length over all its bytes, so the time taken shows neither how much of a credential matched nor which one did.
    fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
        let matched =
            self.accepted.iter().fold(Choice::from(0), |matched, accepted| matched | accepted.ct_eq(credential));
        if bool::from(matched) {
            Ok(())
        } else {
            Err(Refusal::new(ErrorCode::AUTH_FAILED, "the credential was not accepted"))
        }
    }

    fn open_socket(&self, kind: SocketKind) -> Result<Slot, Refusal> {
        self.basic.open_socket(kind)
    }

    fn check_egress(&self, proto: Proto, target: SocketAddr) -> Result<(), Refusal> {
        self.basic.check_egress(proto, target)
    }

    fn check_bind(&self, proto: Proto, local: SocketAddr) -> Result<(), Refusal> {
        self.basic.check_bind(proto, local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    fn session(accepted: &[&str]) -> (Credentials, CredentialSession) {
        let policy = Credentials::new(Basic::default(), accepted.iter().map(|credential| credential.to_string()));
        let session = policy.admit(CLIENT).unwrap();
        (policy, session)
    }

    #[test]
    fn with_credentials_only_an_equal_one_is_accepted() {
        let (policy, session) = session(&["first-credential", "second"]);
        assert_eq!(policy.auth(), Auth::Required);
        for accepted in ["first-credential", "second"] {
            assert_eq!(session.authenticate(accepted.as_bytes()), Ok(()));
        }
        for refused in ["", "first", "first-credentia", "first-credential!", "First-credential", "second ", "third"] {
            let refusal = session.authenticate(refused.as_bytes()).unwrap_err();
            assert_eq!(refusal.code, ErrorCode::AUTH_FAILED, "{refused:?}");
        }
    }

    // With `Auth::None` the server answers a credential `UNSUPPORTED` itself and never asks the policy.
    #[test]
    fn without_credentials_the_relay_is_open_and_accepts_none() {
        let (policy, session) = session(&[]);
        assert_eq!(policy.auth(), Auth::None);
        for credential in ["", "anything"] {
            assert_eq!(session.authenticate(credential.as_bytes()).unwrap_err().code, ErrorCode::AUTH_FAILED);
        }
    }

    #[test]
    fn the_rest_is_basic_s() {
        let mut basic = Basic::default();
        basic.max_sessions = 1;
        basic.max_sockets = 1;
        let policy = Credentials::new(basic, ["credential".to_owned()]);
        let session = policy.admit(CLIENT).unwrap();
        assert_eq!(policy.admit(CLIENT).err().unwrap().code, ErrorCode::CAPACITY);
        let _socket = session.open_socket(SocketKind::Tcp).unwrap();
        assert_eq!(session.open_socket(SocketKind::Udp).err().unwrap().code, ErrorCode::CAPACITY);
        let private = "10.0.0.1:443".parse().unwrap();
        assert_eq!(session.check_egress(Proto::Tcp, private).unwrap_err().code, ErrorCode::REFUSED);
        assert_eq!(session.check_bind(Proto::Udp, "0.0.0.0:80".parse().unwrap()).unwrap_err().code, ErrorCode::REFUSED);
    }
}
