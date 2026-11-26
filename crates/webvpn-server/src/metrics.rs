use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a relay counts. None of them carries anything about a client or a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Counter {
    /// Sessions that finished the hello exchange.
    Sessions,
    /// Of those, the ones over the WebSocket mux.
    WsSessions,
    /// Bytes relayed from clients toward their peers.
    BytesUp,
    /// Bytes relayed from peers toward their clients.
    BytesDown,
    /// Connections a client's listener accepted.
    InboundAccepted,
    /// Of those, the ones announced to the client.
    InboundAnnounced,
    /// Bytes the peers of those connections sent toward the client.
    InboundBytes,
    /// TCP sockets reset at the client's request.
    TcpResets,
    /// UDP sockets whose peer the client cleared.
    UdpDisconnects,
    /// UDP packets toward the client that the carrier did not take as a datagram.
    UdpDroppedSend,
    /// UDP packets dropped because a socket's queue was full.
    UdpDroppedChannel,
    /// UDP packets dropped because they could not be written as a packet.
    UdpDroppedSerialize,
    /// UDP packets toward the relay dropped because the session's byte budget for them was spent.
    UdpUploadShed,
    /// UDP payload bytes handed off, both ways.
    UdpBytesDelivered,
    /// UDP packets toward the client dropped because their stream's write failed.
    UdpDeliverFailed,
    /// UDP packets toward a peer that the system failed to send.
    UdpSendFailed,
    /// UDP packets that came for one socket and named another.
    UdpUploadIdMismatch,
    /// UDP packets from a WebSocket client dropped because the session's queue for them was full.
    WsUdpIngressDroppedFull,
    /// UDP packets from a WebSocket client dropped because the session no longer reads them.
    WsUdpIngressDroppedClosed,
    /// Requests answered `BUSY` because their socket's queue was full.
    ControlDroppedFull,
    /// Credentials the policy accepted.
    AuthAccepted,
    /// Credentials the policy refused.
    AuthRefused,
    /// Sessions that gave their credential up.
    AuthCleared,
    /// Name lookups the resolver answered.
    DnsAnswered,
    /// Name lookups the resolver did not answer.
    DnsFailed,
    /// Name lookups refused because the session had too many waiting or the query was over 512 bytes.
    DnsRefused,
    /// Sockets sessions took in: connections, listeners and UDP sockets.
    SocketsOpened,
    /// Of those, the ones that ended.
    SocketsClosed,
    /// Sessions closed because a stopping relay's wait for them ran out.
    DrainCapCloses,
}

const COUNTERS: usize = Counter::DrainCapCloses as usize + 1;

/// A relay's counters, read one by one with [`get`](Self::get) or all at once with [`render`](Self::render). Each
/// relay has its own.
#[derive(Debug, Default)]
pub struct Metrics([AtomicU64; COUNTERS]);

impl Metrics {
    /// Adds `amount` to `counter`.
    pub fn add(&self, counter: Counter, amount: u64) {
        self.0[counter as usize].fetch_add(amount, Ordering::Relaxed);
    }

    /// Adds one to `counter`.
    pub fn count(&self, counter: Counter) {
        self.add(counter, 1);
    }

    /// What `counter` holds now.
    pub fn get(&self, counter: Counter) -> u64 {
        self.0[counter as usize].load(Ordering::Relaxed)
    }

    /// Every counter in the Prometheus text format, with `sessions` as the gauge of open sessions. The series keep
    /// the names an earlier relay served them under, and no label says anything about a client, an address or a
    /// destination.
    pub fn render(&self, sessions: usize) -> String {
        use Counter::*;
        let get = |counter| self.get(counter);
        let mut out = String::new();
        let mut family = |name: &str, kind: &str, help: &str, series: &[(&str, u64)]| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (labels, value) in series {
                let _ = writeln!(out, "{name}{labels} {value}");
            }
        };
        // A gauge despite its `_total` name, which dashboards already read.
        family("webvpn_active_connections_total", "gauge", "Currently open sessions.", &[("", sessions as u64)]);
        family(
            "webvpn_active_sockets",
            "gauge",
            "Currently open tunnelled sockets (TCP + UDP + listeners).",
            // read one after the other, so a socket that opens and closes in between shows as closed only
            &[("", get(SocketsOpened).saturating_sub(get(SocketsClosed)))],
        );
        family(
            "webvpn_bandwidth_bytes_total",
            "counter",
            "Bytes tunnelled since start, by direction.",
            &[(r#"{direction="down"}"#, get(BytesDown)), (r#"{direction="up"}"#, get(BytesUp))],
        );
        family("webvpn_handshakes_total", "counter", "Sessions admitted since start.", &[("", get(Sessions))]);
        family(
            "webvpn_ws_sessions_total",
            "counter",
            "Sessions admitted over the WebSocket fallback since start.",
            &[("", get(WsSessions))],
        );
        family(
            "webvpn_udp_dropped_total",
            "counter",
            "UDP packets dropped by the relay, by reason.",
            &[
                (r#"{reason="send"}"#, get(UdpDroppedSend)),
                (r#"{reason="channel_full"}"#, get(UdpDroppedChannel)),
                (r#"{reason="serialize"}"#, get(UdpDroppedSerialize)),
                (r#"{reason="upload_budget"}"#, get(UdpUploadShed)),
                (r#"{reason="ws_ingress_full"}"#, get(WsUdpIngressDroppedFull)),
                (r#"{reason="ws_ingress_closed"}"#, get(WsUdpIngressDroppedClosed)),
                (r#"{reason="stream_write"}"#, get(UdpDeliverFailed)),
                (r#"{reason="os_send"}"#, get(UdpSendFailed)),
                (r#"{reason="id_mismatch"}"#, get(UdpUploadIdMismatch)),
            ],
        );
        family(
            "webvpn_udp_delivered_bytes_total",
            "counter",
            "UDP payload bytes actually handed off (stream write or OS send completed), both directions.",
            &[("", get(UdpBytesDelivered))],
        );
        family(
            "webvpn_control_dropped_total",
            "counter",
            "Non-terminal control requests shed on a full per-socket queue.",
            &[("", get(ControlDroppedFull))],
        );
        family(
            "webvpn_credentials_accepted_total",
            "counter",
            "Credentials accepted for an open session since start.",
            &[("", get(AuthAccepted))],
        );
        family(
            "webvpn_credentials_refused_total",
            "counter",
            "Credentials the policy refused since start.",
            &[("", get(AuthRefused))],
        );
        family(
            "webvpn_credentials_cleared_total",
            "counter",
            "Sessions that gave their credential up since start.",
            &[("", get(AuthCleared))],
        );
        family(
            "webvpn_tcp_resets_total",
            "counter",
            "Tunnelled TCP sockets reset at client request since start.",
            &[("", get(TcpResets))],
        );
        family(
            "webvpn_udp_disconnects_total",
            "counter",
            "Tunnelled UDP socket associations dissolved at client request since start.",
            &[("", get(UdpDisconnects))],
        );
        family(
            "webvpn_dns_lookups_total",
            "counter",
            "DNS lookups made for clients since start, by outcome.",
            &[
                (r#"{outcome="answered"}"#, get(DnsAnswered)),
                (r#"{outcome="failed"}"#, get(DnsFailed)),
                (r#"{outcome="refused"}"#, get(DnsRefused)),
            ],
        );
        family(
            "webvpn_inbound_connections_total",
            "counter",
            "Connections clients' listeners accepted since start, by stage: announced ones reached the client.",
            &[(r#"{stage="accepted"}"#, get(InboundAccepted)), (r#"{stage="announced"}"#, get(InboundAnnounced))],
        );
        family(
            "webvpn_inbound_bytes_total",
            "counter",
            "Bytes the peers of accepted connections sent toward the client since start.",
            &[("", get(InboundBytes))],
        );
        family(
            "webvpn_drain_cap_closed_sessions_total",
            "counter",
            "Sessions still open when the stop's grace passed, closed with the restarting reason.",
            &[("", get(DrainCapCloses))],
        );
        out
    }
}
