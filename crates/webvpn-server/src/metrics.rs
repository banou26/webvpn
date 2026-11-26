use std::sync::atomic::{AtomicU64, Ordering};

/// What a relay counts. None of them carries anything about a client or a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Counter {
    /// Sessions that finished the hello exchange.
    Sessions,
    /// Of those, the ones over the WebSocket mux.
    WsSessions,
    BytesUp,
    BytesDown,
    /// Connections a client's listener accepted.
    InboundAccepted,
    /// Of those, the ones announced to the client.
    InboundAnnounced,
    InboundBytes,
    TcpResets,
    UdpDisconnects,
    /// UDP packets the system refused to send.
    UdpDroppedSend,
    /// UDP packets dropped because a socket's queue was full.
    UdpDroppedChannel,
    UdpDroppedSerialize,
    /// UDP packets toward the relay dropped because the session's byte budget for them was spent.
    UdpUploadShed,
    /// UDP payload bytes handed off, both ways.
    UdpBytesDelivered,
    UdpDeliverFailed,
    UdpSendFailed,
    UdpUploadIdMismatch,
    WsUdpIngressDroppedFull,
    WsUdpIngressDroppedClosed,
    /// Requests answered `BUSY` because their socket's queue was full.
    ControlDroppedFull,
    AuthAccepted,
    AuthRefused,
    AuthCleared,
    DnsAnswered,
    DnsFailed,
    DnsRefused,
    /// Sessions closed because a stopping relay's wait for them ran out.
    DrainCapCloses,
}

const COUNTERS: usize = Counter::DrainCapCloses as usize + 1;

/// A relay's counters.
#[derive(Debug, Default)]
pub struct Metrics([AtomicU64; COUNTERS]);

impl Metrics {
    pub fn add(&self, counter: Counter, amount: u64) {
        self.0[counter as usize].fetch_add(amount, Ordering::Relaxed);
    }

    pub fn count(&self, counter: Counter) {
        self.add(counter, 1);
    }

    pub fn get(&self, counter: Counter) -> u64 {
        self.0[counter as usize].load(Ordering::Relaxed)
    }
}
