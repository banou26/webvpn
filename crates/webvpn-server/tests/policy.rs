use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use webvpn_proto::ErrorCode;
use webvpn_server::{Auth, Basic, Direction, Policy, Proto, Refusal, Session, SocketKind};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn address(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// The output of a future that is ready at once, as a policy's `relayed` is when it does not pace.
fn now<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future was not ready"),
    }
}

#[test]
fn basic_holds_sessions_and_sockets_under_their_ceilings_and_frees_them_on_drop() {
    let mut relay = Basic::default();
    (relay.max_sessions, relay.max_sockets) = (2, 3);
    let first = relay.admit(ip("203.0.113.1")).unwrap();
    let second = relay.admit(ip("203.0.113.2")).unwrap();
    assert_eq!(relay.admit(ip("203.0.113.3")).unwrap_err().code, ErrorCode::CAPACITY);
    drop(second);
    let third = relay.admit(ip("203.0.113.3")).unwrap();

    let held = [
        first.open_socket(SocketKind::Tcp).unwrap(),
        first.open_socket(SocketKind::Udp).unwrap(),
        third.open_socket(SocketKind::TcpListener).unwrap(),
    ];
    assert_eq!(third.open_socket(SocketKind::Tcp).unwrap_err().code, ErrorCode::CAPACITY);
    drop(held);
    assert!(third.open_socket(SocketKind::Tcp).is_ok());
}

#[test]
fn basic_reaches_public_addresses_only_unless_told_otherwise() {
    let session = Basic::default().admit(ip("203.0.113.1")).unwrap();
    assert!(session.check_egress(Proto::Tcp, address("1.1.1.1:443")).is_ok());
    for target in ["10.0.0.1:80", "127.0.0.1:22", "169.254.169.254:80", "[::1]:80", "[::ffff:192.168.0.1]:80"] {
        let refusal = session.check_egress(Proto::Udp, address(target)).unwrap_err();
        assert_eq!(refusal.code, ErrorCode::REFUSED, "{target}");
    }

    let mut trusting = Basic::default();
    trusting.allow_private_targets = true;
    let trusted = trusting.admit(ip("10.0.0.2")).unwrap();
    assert!(trusted.check_egress(Proto::Tcp, address("10.0.0.1:80")).is_ok());
}

#[test]
fn basic_binds_any_free_port_and_no_port_under_its_floor() {
    let session = Basic::default().admit(ip("203.0.113.1")).unwrap();
    assert!(session.check_bind(Proto::Tcp, address("0.0.0.0:0")).is_ok());
    assert!(session.check_bind(Proto::Udp, address("[::]:1024")).is_ok());
    assert_eq!(session.check_bind(Proto::Tcp, address("0.0.0.0:1023")).unwrap_err().code, ErrorCode::REFUSED);
}

#[test]
fn basic_takes_no_credentials_and_lets_bytes_through_at_once() {
    let relay = Basic::default();
    assert_eq!(relay.auth(), Auth::None);
    let session = relay.admit(ip("203.0.113.1")).unwrap();
    assert_eq!(session.authenticate(b"anything").unwrap_err().code, ErrorCode::UNSUPPORTED);
    now(session.relayed(Direction::Down, 1 << 20));
}

/// A relay with accounts, the shape an operator's own policy takes: a ceiling of sessions for each address, a
/// ceiling of sessions for each account, and bytes counted under the account once a session presented one and
/// under its address before. It shows that the two interfaces carry all of it.
#[derive(Default)]
struct Shared {
    sessions_by_address: Mutex<HashMap<IpAddr, usize>>,
    sessions_by_account: Mutex<HashMap<String, usize>>,
    bytes: Mutex<HashMap<String, usize>>,
}

#[derive(Default)]
struct Accounts(Arc<Shared>);

struct AccountSession {
    shared: Arc<Shared>,
    peer: IpAddr,
    account: Mutex<Option<String>>,
}

const SESSIONS_PER_ADDRESS: usize = 2;
const SESSIONS_PER_ACCOUNT: usize = 1;

impl Policy for Accounts {
    type Session = AccountSession;

    fn auth(&self) -> Auth {
        Auth::Optional
    }

    fn admit(&self, peer: IpAddr) -> Result<AccountSession, Refusal> {
        let mut held = self.0.sessions_by_address.lock().unwrap();
        let count = held.entry(peer).or_default();
        if *count == SESSIONS_PER_ADDRESS {
            return Err(Refusal::new(ErrorCode::CAPACITY, "too many sessions from this address"));
        }
        *count += 1;
        Ok(AccountSession { shared: self.0.clone(), peer, account: Mutex::default() })
    }
}

impl AccountSession {
    fn leave(&self, account: Option<String>) {
        if let Some(account) = account {
            *self.shared.sessions_by_account.lock().unwrap().get_mut(&account).unwrap() -= 1;
        }
    }
}

impl Session for AccountSession {
    type Permit = ();

    fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
        let name = std::str::from_utf8(credential)
            .ok()
            .and_then(|text| text.strip_prefix("account:"))
            .ok_or(Refusal::new(ErrorCode::AUTH_FAILED, "not a credential"))?;
        let mut account = self.account.lock().unwrap();
        if account.as_deref() != Some(name) {
            let mut held = self.shared.sessions_by_account.lock().unwrap();
            let count = held.entry(name.to_owned()).or_default();
            if *count == SESSIONS_PER_ACCOUNT {
                return Err(Refusal::new(ErrorCode::CAPACITY, "too many sessions on this account"));
            }
            *count += 1;
            drop(held);
            self.leave(account.replace(name.to_owned()));
        }
        Ok(())
    }

    fn clear_auth(&self) {
        self.leave(self.account.lock().unwrap().take());
    }

    fn open_socket(&self, _kind: SocketKind) -> Result<(), Refusal> {
        Ok(())
    }

    fn check_egress(&self, _proto: Proto, _target: SocketAddr) -> Result<(), Refusal> {
        Ok(())
    }

    fn relayed(&self, _direction: Direction, bytes: usize) -> impl Future<Output = ()> + Send {
        let bucket = self.account.lock().unwrap().clone().unwrap_or_else(|| self.peer.to_string());
        *self.shared.bytes.lock().unwrap().entry(bucket).or_default() += bytes;
        std::future::ready(())
    }
}

impl Drop for AccountSession {
    fn drop(&mut self) {
        self.clear_auth();
        *self.shared.sessions_by_address.lock().unwrap().get_mut(&self.peer).unwrap() -= 1;
    }
}

#[test]
fn a_policy_with_accounts_fits_the_interfaces() {
    let relay = Accounts::default();
    let bytes = |bucket: &str| relay.0.bytes.lock().unwrap().get(bucket).copied().unwrap_or(0);

    let home = ip("203.0.113.5");
    let first = relay.admit(home).unwrap();
    let second = relay.admit(home).unwrap();
    assert_eq!(relay.admit(home).err().unwrap().code, ErrorCode::CAPACITY);
    drop(second);
    let other = relay.admit(ip("198.51.100.7")).unwrap();

    now(first.relayed(Direction::Up, 10));
    assert_eq!(bytes("203.0.113.5"), 10);

    assert_eq!(first.authenticate(b"nonsense").unwrap_err().code, ErrorCode::AUTH_FAILED);
    first.authenticate(b"account:ana").unwrap();
    first.authenticate(b"account:ana").unwrap();
    now(first.relayed(Direction::Down, 5));
    assert_eq!((bytes("ana"), bytes("203.0.113.5")), (5, 10));

    // a refused credential leaves the session as it was: still counted under its address
    assert_eq!(other.authenticate(b"account:ana").unwrap_err().code, ErrorCode::CAPACITY);
    now(other.relayed(Direction::Up, 7));
    assert_eq!((bytes("ana"), bytes("198.51.100.7")), (5, 7));

    first.clear_auth();
    now(first.relayed(Direction::Up, 1));
    assert_eq!((bytes("ana"), bytes("203.0.113.5")), (5, 11));

    other.authenticate(b"account:ana").unwrap();
    drop(other);
    first.authenticate(b"account:ana").unwrap();
}
