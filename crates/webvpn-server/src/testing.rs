//! An in-memory carrier for tests. [`MemoryTransport`] is the relay's side of a session, a [`Transport`] over
//! `tokio::io::duplex` streams, and [`Client`] holds the client's side of the same streams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::timeout;
use webvpn_proto::{ClientPacket, ErrorCode, RelayPacket};

use crate::policy::Refusal;
use crate::transport::{SendHalf, Transport};
use crate::tunnel::{Forwarder, TunnelEnd};

/// How long a client waits on the relay before the test fails.
pub(crate) const WAIT: Duration = Duration::from_secs(5);

/// The bytes each direction of a stream holds unread before its writer waits.
pub(crate) const STREAM_BUFFER: usize = 64 * 1024;

impl SendHalf for DuplexStream {}

/// Which [`Transport`] method opened a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Opened {
    Control,
    Bi,
    UdpBi,
    Uni,
    IpBi,
}

/// A stream the relay opened, from the client's side.
pub(crate) struct Stream {
    pub opened: Opened,
    /// What the client writes. `None` on a stream toward the client only.
    pub send: Option<DuplexStream>,
    pub recv: DuplexStream,
}

/// The code and reason the session was closed with, once it was.
type Closed = Option<(u32, String)>;

/// The relay's side of an in-memory session.
pub(crate) struct MemoryTransport {
    peer: IpAddr,
    opened: mpsc::UnboundedSender<Stream>,
    datagrams: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    streams: Mutex<mpsc::UnboundedReceiver<DuplexStream>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
    closed: watch::Sender<Closed>,
    /// Makes every stream the relay opens for a socket fail, as on a session with no room for more streams.
    pub refuse_streams: bool,
}

/// The client's side of an in-memory session.
pub(crate) struct Client {
    opened: mpsc::UnboundedReceiver<Stream>,
    datagrams: mpsc::UnboundedSender<Vec<u8>>,
    streams: mpsc::UnboundedSender<DuplexStream>,
    from_relay: mpsc::UnboundedReceiver<Vec<u8>>,
    closed: watch::Receiver<Closed>,
}

/// A session from a client at `peer`: the relay's side and the client's.
pub(crate) fn session(peer: IpAddr) -> (MemoryTransport, Client) {
    let (opened, opened_by_relay) = mpsc::unbounded_channel();
    let (datagrams_to_relay, datagrams) = mpsc::unbounded_channel();
    let (streams_to_relay, streams) = mpsc::unbounded_channel();
    let (to_client, from_relay) = mpsc::unbounded_channel();
    let (closed, closed_by_relay) = watch::channel(None);
    let transport = MemoryTransport {
        peer,
        opened,
        datagrams: Mutex::new(datagrams),
        streams: Mutex::new(streams),
        to_client,
        closed,
        refuse_streams: false,
    };
    let client = Client {
        opened: opened_by_relay,
        datagrams: datagrams_to_relay,
        streams: streams_to_relay,
        from_relay,
        closed: closed_by_relay,
    };
    (transport, client)
}

impl MemoryTransport {
    fn open(&self, opened: Opened) -> Result<(DuplexStream, DuplexStream)> {
        if self.refuse_streams && opened != Opened::Control {
            bail!("the session has no room for more streams");
        }
        let (relay_send, client_recv) = duplex(STREAM_BUFFER);
        let (client_send, relay_recv) = duplex(STREAM_BUFFER);
        let send = (opened != Opened::Uni).then_some(client_send);
        self.opened.send(Stream { opened, send, recv: client_recv }).map_err(|_| anyhow!("the client is gone"))?;
        Ok((relay_send, relay_recv))
    }
}

impl Transport for MemoryTransport {
    type Send = DuplexStream;
    type Recv = DuplexStream;

    fn remote_ip(&self) -> IpAddr {
        self.peer
    }

    /// Keeps the first close, as a carrier does.
    async fn close(&self, code: u32, reason: &str) {
        self.closed.send_if_modified(|closed| {
            let first = closed.is_none();
            if first {
                *closed = Some((code, reason.to_owned()));
            }
            first
        });
    }

    fn send_datagram(&self, data: Vec<u8>) -> Result<()> {
        self.to_client.send(data).map_err(|_| anyhow!("the client is gone"))
    }

    async fn control_stream(&self) -> Result<(DuplexStream, DuplexStream)> {
        self.open(Opened::Control)
    }

    async fn open_bi(&self) -> Result<(DuplexStream, DuplexStream)> {
        self.open(Opened::Bi)
    }

    async fn open_uni(&self) -> Result<DuplexStream> {
        Ok(self.open(Opened::Uni)?.0)
    }

    async fn open_udp_bi(&self) -> Result<(DuplexStream, DuplexStream)> {
        self.open(Opened::UdpBi)
    }

    async fn open_ip_bi(&self) -> Result<(DuplexStream, DuplexStream)> {
        self.open(Opened::IpBi)
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>> {
        self.datagrams.lock().await.recv().await.ok_or_else(|| anyhow!("the client is gone"))
    }

    async fn accept_uni(&self) -> Result<DuplexStream> {
        self.streams.lock().await.recv().await.ok_or_else(|| anyhow!("the client is gone"))
    }
}

impl Client {
    /// The next stream the relay opened, in the order it opened them.
    pub(crate) async fn next_stream(&mut self) -> Stream {
        timeout(WAIT, self.opened.recv()).await.expect("the relay opens a stream in time").expect("the relay is gone")
    }

    /// The control stream, which the relay opens before any other.
    pub(crate) async fn control(&mut self) -> Control {
        let stream = self.next_stream().await;
        assert_eq!(stream.opened, Opened::Control);
        let to_relay = stream.send.expect("the control stream goes both ways");
        Control { to_relay, from_relay: stream.recv, buf: Vec::new() }
    }

    /// Sends one datagram, which the relay's `recv_datagram` returns.
    pub(crate) fn send_datagram(&self, datagram: Vec<u8>) {
        self.datagrams.send(datagram).expect("the relay is there");
    }

    /// The next datagram the relay sent with `send_datagram`.
    pub(crate) async fn datagram(&mut self) -> Vec<u8> {
        timeout(WAIT, self.from_relay.recv())
            .await
            .expect("the relay sends a datagram in time")
            .expect("the relay is gone")
    }

    /// Opens a stream toward the relay, which its `accept_uni` returns, and gives the client's end.
    pub(crate) fn open_uni(&self) -> DuplexStream {
        let (client, relay) = duplex(STREAM_BUFFER);
        self.streams.send(relay).expect("the relay is there");
        client
    }

    /// The code and reason the relay closed the session with.
    pub(crate) async fn closed(&mut self) -> (u32, String) {
        let closed = timeout(WAIT, self.closed.wait_for(Option::is_some))
            .await
            .expect("the relay closes the session in time")
            .expect("the relay is gone without closing the session");
        closed.clone().expect("the session is closed")
    }
}

/// The `Bye` the relay says as the last frame of `control`, which the session's close must match: its code and reason.
pub(crate) async fn bye(control: &mut Control, client: &mut Client) -> (u32, String) {
    let Some(RelayPacket::Bye { code, reason }) = control.next().await else { panic!("the relay said no Bye") };
    assert_eq!(control.next().await, None, "the Bye is the last frame");
    assert_eq!(client.closed().await, (code, reason.clone()), "the close matches the Bye");
    (code, reason)
}

/// The client's side of the control stream, as frames.
pub(crate) struct Control {
    to_relay: DuplexStream,
    from_relay: DuplexStream,
    buf: Vec<u8>,
}

impl Control {
    pub(crate) async fn send(&mut self, packet: ClientPacket) {
        let mut frame = Vec::new();
        packet.encode(&mut frame);
        self.write(&frame).await;
    }

    /// Writes bytes as they are, for a frame the protocol does not lay out.
    pub(crate) async fn write(&mut self, bytes: &[u8]) {
        self.to_relay.write_all(bytes).await.expect("the relay reads the control stream");
    }

    /// Finishes the client's side of the stream, as a client that ends its session does.
    pub(crate) async fn finish(&mut self) {
        self.to_relay.shutdown().await.expect("the relay reads the control stream");
    }

    /// The next frame from the relay, or `None` once the relay finished the stream.
    pub(crate) async fn next(&mut self) -> Option<RelayPacket> {
        let read = async {
            loop {
                if let Some((packet, taken)) = RelayPacket::decode(&self.buf).expect("the relay's frames are whole") {
                    self.buf.drain(..taken);
                    return Some(packet);
                }
                if self.from_relay.read_buf(&mut self.buf).await.expect("the control stream reads") == 0 {
                    return None;
                }
            }
        };
        timeout(WAIT, read).await.expect("the relay writes in time")
    }
}

/// The packets each tunnel's channel holds before the forwarder drops one.
const FORWARDER_CHANNEL: usize = 1024;
/// The first public port a [`TestForwarder`] gives.
pub(crate) const PUBLIC_PORTS: u16 = 30000;

/// A forwarder for tests. Tunnel `n`, counted among the ones attached now, is given 198.18.0.(2 + n) and
/// fd00::(2 + n), so a tunnel opened after another ended is given its addresses again. It notes what tunnels send,
/// and lets a test deliver packets to a tunnel or end it.
pub(crate) struct TestForwarder {
    pub mtu: u16,
    /// The public ports each tunnel is given: tunnel `index` holds this many from `PUBLIC_PORTS + index * ports` on.
    pub ports: u16,
    max_tunnels: usize,
    ends: std::sync::Mutex<Vec<mpsc::Sender<Vec<u8>>>>,
    sent: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl TestForwarder {
    pub(crate) fn new(mtu: u16, max_tunnels: usize) -> Self {
        Self { mtu, ports: 0, max_tunnels, ends: Default::default(), sent: Default::default() }
    }

    pub(crate) fn addresses(index: usize) -> (Ipv4Addr, Ipv6Addr) {
        let host = (2 + index) as u8;
        (Ipv4Addr::new(198, 18, 0, host), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, host.into()))
    }

    /// The tunnels whose end the relay still holds.
    pub(crate) fn held(&self) -> usize {
        self.ends.lock().unwrap().iter().filter(|end| !end.is_closed()).count()
    }

    /// Resolves once the relay holds `ends` ends, and fails the test if it does not in time.
    pub(crate) async fn holds(&self, ends: usize) {
        let held = async {
            while self.held() != ends {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        timeout(WAIT, held).await.expect("the relay holds as many tunnel ends as expected in time");
    }

    /// Hands `packet` to tunnel `index` as a forwarder does, without waiting: false when its channel is full or gone.
    pub(crate) fn deliver(&self, index: usize, packet: Vec<u8>) -> bool {
        self.ends.lock().unwrap().get(index).is_some_and(|end| end.try_send(packet).is_ok())
    }

    /// The packets in tunnel `index`'s channel that the relay has not taken yet.
    pub(crate) fn waiting(&self, index: usize) -> usize {
        let ends = self.ends.lock().unwrap();
        ends[index].max_capacity() - ends[index].capacity()
    }

    /// Ends tunnel `index` from the forwarder's side.
    pub(crate) fn end(&self, index: usize) {
        let (sender, _) = mpsc::channel(1);
        self.ends.lock().unwrap()[index] = sender;
    }

    /// What tunnels sent, in order, once there are `count` packets.
    pub(crate) async fn sent(&self, count: usize) -> Vec<Vec<u8>> {
        let sent = async {
            loop {
                if self.sent.lock().unwrap().len() >= count {
                    return self.sent.lock().unwrap().clone();
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        timeout(WAIT, sent).await.expect("the tunnels send in time")
    }
}

impl Forwarder for TestForwarder {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn public_ports(&self) -> Option<std::ops::RangeInclusive<u16>> {
        let count = self.max_tunnels as u16 * self.ports;
        (count > 0).then(|| PUBLIC_PORTS..=PUBLIC_PORTS + count - 1)
    }

    fn attach(&self) -> Result<TunnelEnd, Refusal> {
        let mut ends = self.ends.lock().unwrap();
        let free = ends.iter().position(mpsc::Sender::is_closed).unwrap_or(ends.len());
        if free >= self.max_tunnels {
            return Err(Refusal::new(ErrorCode::CAPACITY, "the test forwarder has no address left"));
        }
        let (sender, packets) = mpsc::channel(FORWARDER_CHANNEL);
        match ends.get_mut(free) {
            Some(end) => *end = sender,
            None => ends.push(sender),
        }
        let (ipv4, ipv6) = Self::addresses(free);
        let first_port = PUBLIC_PORTS.wrapping_add(free as u16 * self.ports);
        Ok(TunnelEnd { ipv4: Some(ipv4), ipv6: Some(ipv6), first_port, ports: self.ports, packets })
    }

    fn send(&self, packet: &[u8]) {
        self.sent.lock().unwrap().push(packet.to_vec());
    }
}
