//! Name lookups: a client's whole DNS message goes to one DNS over HTTPS resolver and the resolver's whole message
//! comes back. The relay reads no name, keeps nothing and logs nothing of a lookup.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::Semaphore;

/// Lookups one session may have waiting or in flight. One more is answered `CAPACITY`.
pub(crate) const MAX_LOOKUPS_PER_SESSION: usize = 256;

pub(crate) struct Dns {}

impl Dns {
    pub fn new(upstream: String) -> Self {
        let _ = upstream;
        todo!()
    }

    /// The lookups one visitor may have at the resolver at once, shared by every session from its address.
    pub fn visitor_slots(&self, ip: IpAddr) -> Arc<Semaphore> {
        let _ = ip;
        todo!()
    }

    /// The resolver's whole answer to `query`, or `None` when it gave none in time.
    pub async fn lookup(&self, visitor_slots: &Semaphore, query: Vec<u8>) -> Option<Vec<u8>> {
        let _ = (visitor_slots, query);
        todo!()
    }
}

/// The first A record of a DNS answer.
pub(crate) fn first_a_record(message: &[u8]) -> Option<Ipv4Addr> {
    let _ = message;
    todo!()
}
