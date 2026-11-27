//! The WebSocket mux: a session's streams as frames on one WebSocket, for a client without WebTransport.
//!
//! Each mux stream carries the same bytes as the WebTransport stream it stands for (the socket id first, the same UDP
//! framing), so the session and socket code runs unchanged over [`Transport`].
//!
//! The reader never pauses, since that would stop the control stream with the rest and can deadlock the session.
//! Backpressure toward the client comes from stream credit, the small bulk lane filling and [`MuxSend`] pending. What
//! the client sends is held within byte bounds per stream and per session, and going over resets one backlogged stream
//! rather than stalling the session.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tokio::time::MissedTickBehavior;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::{CancellationToken, DropGuard, PollSender};
use tracing::{debug, warn};
use webvpn_proto::mux::{self, kind, stream_type, CONTROL_STREAM};

use crate::metrics::{Counter, Metrics};
use crate::transport::{SendHalf, Transport};

const MAX_DATA_PAYLOAD: usize = 64 * 1024;
/// The window every stream but the control stream starts with, in bytes.
const INITIAL_STREAM_WINDOW: u64 = 1_048_576;

/// Outbound lane depths, in frames. The bulk lane is small so a client that reads slowly soon holds back the read from
/// the peer; the priority lane never drops a control frame.
const PRIORITY_LANE_CAP: usize = 1024;
const BULK_LANE_CAP: usize = 64;
/// After this many priority frames in a row with bulk frames waiting, the writer sends one bulk frame, so control
/// traffic cannot starve downloads.
const PRIORITY_QUANTUM: usize = 32;
/// The largest WebSocket message the listener takes: the tungstenite default, pinned. A client may send a large DATA
/// frame as one message, so it must not shrink; byte admission bounds what a session holds.
pub(crate) const MAX_WS_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Every queued inbound chunk is charged at least this many bytes, so the cost of each item stays bounded. The item
/// caps derive from it so the byte bound refuses before a channel reports full: many tiny frames cannot force a false
/// stream reset.
const MIN_CHUNK_CHARGE: usize = 512;
const INBOUND_STREAM_BYTES: usize = 4 * 1024 * 1024;
const INBOUND_STREAM_CAP: usize = INBOUND_STREAM_BYTES / MIN_CHUNK_CHARGE;
/// The ceiling across the inbound buffers of a session's socket streams. When it refuses, the stream with the largest
/// backlog is reset, not the one the chunk arrived for (that would cascade resets across healthy streams), and the
/// arriving chunk is taken over the ceiling, since dropping it would break a reliable stream.
const SESSION_INBOUND_BYTES: usize = 64 * 1024 * 1024;
/// The least backlog a stream holds to be reset for the session's ceiling. Below it the ceiling is held by chunks of
/// streams already gone and not yet read, and a reset would free nothing.
const SESSION_VICTIM_FLOOR_BYTES: usize = INBOUND_STREAM_BYTES / 2;
/// The control stream is a byte stream and must never lose bytes, so going over here means the control plane is stuck
/// and the session ends. Its own byte pool keeps socket-stream backlog from failing a control enqueue.
const INBOUND_CONTROL_CAP: usize = 4096;
const INBOUND_CONTROL_BYTES: usize = 4 * 1024 * 1024;
/// UDP packets from the client, which may be dropped, with their own byte pool so a burst never takes the reliable
/// streams' budget.
const DATAGRAM_IN_CAP: usize = 512;
const DATAGRAM_IN_BYTES: usize = 4 * 1024 * 1024;
/// RFC 6455 holds a Close frame to 125 bytes, two of them the code. A receiver fails the connection on a longer one,
/// which loses the code too, so a longer reason is cut.
const MAX_CLOSE_REASON_BYTES: usize = 123;
/// How long the writer is given to send what is queued ahead of the close, and the close.
const WRITER_WAIT: Duration = Duration::from_secs(1);

const PEER_RESET_PAYLOAD: [u8; 4] = webvpn_proto::reset::PEER_RESET.to_be_bytes();

fn broken_pipe() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

fn frame_stream_id(frame: &[u8]) -> u32 {
    u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]])
}

struct ByteBudget {
    used: AtomicUsize,
    cap: usize,
}

impl ByteBudget {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self { used: AtomicUsize::new(0), cap })
    }

    fn try_charge(budget: &Arc<Self>, len: usize) -> Option<ByteReservation> {
        let amount = len.max(MIN_CHUNK_CHARGE);
        let mut used = budget.used.load(Ordering::Relaxed);
        loop {
            let next = used.checked_add(amount).filter(|next| *next <= budget.cap)?;
            match budget.used.compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(ByteReservation { budget: budget.clone(), amount }),
                Err(actual) => used = actual,
            }
        }
    }

    /// Charges past the cap. Only for a chunk that must not be refused: a reliable stream cannot lose bytes without a
    /// reset.
    fn charge(budget: &Arc<Self>, len: usize) -> ByteReservation {
        let amount = len.max(MIN_CHUNK_CHARGE);
        budget.used.fetch_add(amount, Ordering::Relaxed);
        ByteReservation { budget: budget.clone(), amount }
    }
}

struct ByteReservation {
    budget: Arc<ByteBudget>,
    amount: usize,
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.amount, Ordering::Relaxed);
    }
}

/// The reservations stay held through partial reads (`MuxRecv::leftover`) until the whole chunk is read.
struct InboundChunk {
    data: Bytes,
    _charges: [Option<ByteReservation>; 2],
}

impl InboundChunk {
    fn empty() -> Self {
        Self { data: Bytes::new(), _charges: [None, None] }
    }
}

#[derive(Clone)]
struct InboundEntry {
    tx: mpsc::Sender<InboundChunk>,
    budget: Arc<ByteBudget>,
}

/// FIN and RESET frames owed to the client. `MuxSend::drop`, `MuxSend::fail` and the overflow path cannot wait for
/// room in a lane, so they park here and the writer sends them ahead of the lanes, one per stream: a RESET replaces a
/// FIN, and the first RESET stays. A terminal goes out only once its stream's OPEN is written and none of its DATA is
/// still queued, which keeps OPEN, DATA, FIN in that order on the wire.
#[derive(Default)]
struct Terminals {
    state: Mutex<TerminalState>,
    notify: Notify,
}

#[derive(Default)]
struct TerminalState {
    /// The FIN or RESET owed for each stream, with the frame's payload.
    pending: HashMap<u32, (u8, &'static [u8])>,
    queued_data: HashMap<u32, usize>,
}

impl Terminals {
    fn push(&self, id: u32, frame_kind: u8, payload: &'static [u8]) {
        {
            let mut state = self.state.lock().unwrap();
            let slot = state.pending.entry(id).or_insert((frame_kind, payload));
            if frame_kind == kind::RESET && slot.0 == kind::FIN {
                *slot = (frame_kind, payload);
            }
        }
        self.notify.notify_one();
    }

    /// Must run before the frame is queued, so the writer's decrement never misses it.
    fn note_data_queued(&self, id: u32) {
        *self.state.lock().unwrap().queued_data.entry(id).or_insert(0) += 1;
    }

    fn note_data_written(&self, id: u32) {
        let mut state = self.state.lock().unwrap();
        if let Some(count) = state.queued_data.get_mut(&id) {
            *count -= 1;
            if *count == 0 {
                state.queued_data.remove(&id);
            }
        }
    }

    fn has_eligible(&self, opened: &HashSet<u32>) -> bool {
        let state = self.state.lock().unwrap();
        state.pending.keys().any(|id| opened.contains(id) && !state.queued_data.contains_key(id))
    }

    fn pop_eligible(&self, opened: &HashSet<u32>) -> Option<(u32, u8, &'static [u8])> {
        let mut state = self.state.lock().unwrap();
        let id = state.pending.keys().copied().find(|id| opened.contains(id) && !state.queued_data.contains_key(id))?;
        let (frame_kind, payload) = state.pending.remove(&id)?;
        Some((id, frame_kind, payload))
    }

    async fn notified(&self) {
        self.notify.notified().await;
    }
}

type StreamRegistry = Arc<Mutex<HashMap<u32, InboundEntry>>>;
type SendStates = Arc<Mutex<HashMap<u32, Arc<SendState>>>>;

/// `granted` and `sent` are cumulative, so a CREDIT counts the bytes sent before it arrived.
struct SendFlow {
    granted: u64,
    sent: u64,
    reset: bool,
    write_waker: Option<Waker>,
}

struct SendState {
    flow: Mutex<SendFlow>,
}

impl SendState {
    fn new(window: u64) -> Self {
        Self { flow: Mutex::new(SendFlow { granted: window, sent: 0, reset: false, write_waker: None }) }
    }

    fn grant(&self, amount: u32) {
        if amount == 0 {
            return;
        }
        let waker = {
            let mut flow = self.flow.lock().unwrap();
            if flow.reset {
                return;
            }
            flow.granted = flow.granted.saturating_add(u64::from(amount));
            if flow.granted > flow.sent {
                flow.write_waker.clone()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn reset(&self) {
        let waker = {
            let mut flow = self.flow.lock().unwrap();
            flow.reset = true;
            flow.write_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn register_waker(&self, waker: &Waker) {
        self.flow.lock().unwrap().write_waker = Some(waker.clone());
    }

    fn clear_waker(&self) {
        self.flow.lock().unwrap().write_waker = None;
    }
}

/// The relay's side of one mux stream. A write sends one DATA frame of at most 64 KiB and pends while the stream's
/// window is spent or its lane is full; it fails once the stream is reset. Dropping it finishes the stream with FIN,
/// unless it was shut down or reset.
pub(crate) struct MuxSend {
    id: u32,
    lane: PollSender<Vec<u8>>,
    send_states: SendStates,
    state: Arc<SendState>,
    terminals: Arc<Terminals>,
    fin_sent: bool,
}

impl MuxSend {
    fn poll_allowance(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut flow = self.state.flow.lock().unwrap();
        flow.write_waker = Some(cx.waker().clone());
        if flow.reset {
            return Poll::Ready(Err(broken_pipe()));
        }
        if flow.granted > flow.sent {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}

impl AsyncWrite for MuxSend {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let max = buf.len().min(MAX_DATA_PAYLOAD);
        match this.poll_allowance(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => {
                this.state.clear_waker();
                return Poll::Ready(Err(err));
            }
            Poll::Pending => {
                this.lane.abort_send();
                return Poll::Pending;
            }
        }
        match this.lane.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                this.state.clear_waker();
                return Poll::Ready(Err(broken_pipe()));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Credit is charged while the frame is queued, so a CREDIT or RESET arriving meanwhile cannot let one extra
        // frame through.
        let state = this.state.clone();
        let mut flow = state.flow.lock().unwrap();
        if flow.reset {
            flow.write_waker = None;
            this.lane.abort_send();
            return Poll::Ready(Err(broken_pipe()));
        }
        let n = flow.granted.saturating_sub(flow.sent).min(max as u64) as usize;
        if n == 0 {
            flow.write_waker = Some(cx.waker().clone());
            drop(flow);
            this.lane.abort_send();
            return Poll::Pending;
        }
        if this.id != CONTROL_STREAM {
            this.terminals.note_data_queued(this.id);
        }
        let result = match this.lane.send_item(mux::encode(kind::DATA, this.id, &buf[..n])) {
            Ok(()) => {
                flow.sent = flow.sent.saturating_add(n as u64);
                Ok(n)
            }
            Err(_) => {
                if this.id != CONTROL_STREAM {
                    this.terminals.note_data_written(this.id);
                }
                Err(broken_pipe())
            }
        };
        flow.write_waker = None;
        Poll::Ready(result)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Ok(()));
        }
        this.state.register_waker(cx.waker());
        if this.state.flow.lock().unwrap().reset {
            this.state.clear_waker();
            this.fin_sent = true;
            return Poll::Ready(Ok(()));
        }
        match this.lane.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                this.state.clear_waker();
                this.fin_sent = true;
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => return Poll::Pending,
        }
        let state = this.state.clone();
        let mut flow = state.flow.lock().unwrap();
        if flow.reset {
            this.lane.abort_send();
        } else {
            let _ = this.lane.send_item(mux::encode(kind::FIN, this.id, &[]));
        }
        flow.write_waker = None;
        this.fin_sent = true;
        Poll::Ready(Ok(()))
    }
}

// `abandon` keeps the trait's no-op here: the drop that follows finishes the stream with FIN.
impl SendHalf for MuxSend {
    fn fail(&mut self) {
        self.state.reset();
        self.terminals.push(self.id, kind::RESET, &PEER_RESET_PAYLOAD);
    }
}

impl Drop for MuxSend {
    fn drop(&mut self) {
        // A socket closed over the control stream still owes the client its end. The control stream's end is the
        // session's.
        let reset = self.state.flow.lock().unwrap().reset;
        if !self.fin_sent && !reset && self.id != CONTROL_STREAM {
            self.terminals.push(self.id, kind::FIN, &[]);
        }
        // Only the send side goes: a FIN is a half close, and the client may still be sending.
        if let Ok(mut map) = self.send_states.lock() {
            map.remove(&self.id);
        }
    }
}

/// What the client sends on one mux stream. FIN, RESET and the end of the session all read as the end of the stream.
pub(crate) struct MuxRecv {
    id: u32,
    inbound: mpsc::Receiver<InboundChunk>,
    registry: StreamRegistry,
    leftover: InboundChunk,
}

impl Drop for MuxRecv {
    fn drop(&mut self) {
        // The reader may have removed it already. Ids are never reused, so this then removes nothing.
        if let Ok(mut map) = self.registry.lock() {
            map.remove(&self.id);
        }
    }
}

impl AsyncRead for MuxRecv {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.leftover.data.is_empty() {
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => this.leftover = chunk,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = this.leftover.data.len().min(buf.remaining());
        buf.put_slice(&this.leftover.data[..n]);
        this.leftover.data.advance(n);
        if this.leftover.data.is_empty() {
            this.leftover = InboundChunk::empty();
        }
        Poll::Ready(Ok(()))
    }
}

struct Inner {
    peer: IpAddr,
    priority_tx: mpsc::Sender<Vec<u8>>,
    bulk_tx: mpsc::Sender<Vec<u8>>,
    next_id: AtomicU32,
    inbound: StreamRegistry,
    send_states: SendStates,
    terminals: Arc<Terminals>,
    datagram_in: AsyncMutex<mpsc::Receiver<InboundChunk>>,
    close_tx: mpsc::Sender<(u16, String)>,
    cancel: CancellationToken,
    /// Cancelled once the writer task ended.
    written: CancellationToken,
    // A session can end without `close`; the guard then stops the tasks, which would otherwise hold the connection.
    _cancel_guard: DropGuard,
}

/// One client's session over the WebSocket mux.
pub(crate) struct WsTransport {
    inner: Arc<Inner>,
}

/// The reader and writer tasks of one session.
pub(crate) struct WsSessionTasks {
    cancel: CancellationToken,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl WsSessionTasks {
    /// Stops both tasks at once. A session that closed gave its writer its time in `WsTransport::close`, so waiting
    /// again here would hold the connection of a client that reads nothing a second longer.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        self.reader.abort();
        self.writer.abort();
        let _ = self.reader.await;
        let _ = self.writer.await;
    }
}

impl WsTransport {
    /// Ids are never reused within a session, so wrapping would collide with live streams. Running out refuses only
    /// the new stream, never the session.
    fn alloc_id(&self) -> Result<u32> {
        let mut current = self.inner.next_id.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(1) else {
                anyhow::bail!("the WebSocket mux has no stream id left");
            };
            match self.inner.next_id.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(current),
                Err(actual) => current = actual,
            }
        }
    }

    fn make_send(&self, id: u32, control: bool) -> MuxSend {
        // The control stream is never credited, so its window has no end.
        let (lane, window) = if control {
            (self.inner.priority_tx.clone(), u64::MAX)
        } else {
            (self.inner.bulk_tx.clone(), INITIAL_STREAM_WINDOW)
        };
        let state = Arc::new(SendState::new(window));
        self.inner.send_states.lock().unwrap().insert(id, state.clone());
        MuxSend {
            id,
            lane: PollSender::new(lane),
            send_states: self.inner.send_states.clone(),
            state,
            terminals: self.inner.terminals.clone(),
            fin_sent: false,
        }
    }

    fn register_bidi(&self, id: u32, control: bool) -> (MuxSend, MuxRecv) {
        let (cap, bytes) = if control {
            (INBOUND_CONTROL_CAP, INBOUND_CONTROL_BYTES)
        } else {
            (INBOUND_STREAM_CAP, INBOUND_STREAM_BYTES)
        };
        let (in_tx, in_rx) = mpsc::channel::<InboundChunk>(cap);
        let entry = InboundEntry { tx: in_tx, budget: ByteBudget::new(bytes) };
        self.inner.inbound.lock().unwrap().insert(id, entry);
        let send = self.make_send(id, control);
        let recv =
            MuxRecv { id, inbound: in_rx, registry: self.inner.inbound.clone(), leftover: InboundChunk::empty() };
        (send, recv)
    }

    /// OPEN goes on the priority lane so it reaches the client before the stream's DATA on the bulk lane.
    async fn open(&self, id: u32, opened: u8) -> Result<()> {
        self.inner
            .priority_tx
            .send(mux::encode(kind::OPEN, id, &[opened]))
            .await
            .map_err(|_| anyhow::anyhow!("the WebSocket session is closed"))
    }
}

impl Transport for WsTransport {
    type Send = MuxSend;
    type Recv = MuxRecv;

    fn remote_ip(&self) -> IpAddr {
        self.inner.peer
    }

    async fn close(&self, code: u32, reason: &str) {
        let reason = &reason[..reason.floor_char_boundary(MAX_CLOSE_REASON_BYTES)];
        let _ = self.inner.close_tx.try_send((webvpn_proto::close::websocket(code), reason.to_owned()));
        self.inner.cancel.cancel();
        // The writer may wait on a client that reads slowly. Waiting for it here keeps the session open until the
        // `Bye` and the close went out, so a stop, which waits for its sessions and then lets its program end, does
        // not drop them.
        let _ = tokio::time::timeout(WRITER_WAIT, self.inner.written.cancelled()).await;
    }

    fn send_datagram(&self, _data: Vec<u8>) -> Result<()> {
        anyhow::bail!("the WebSocket mux sends no datagrams toward the client")
    }

    async fn control_stream(&self) -> Result<(Self::Send, Self::Recv)> {
        // Never opened: the client knows stream 0 as the control stream.
        Ok(self.register_bidi(CONTROL_STREAM, true))
    }

    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv)> {
        let id = self.alloc_id()?;
        let streams = self.register_bidi(id, false);
        self.open(id, stream_type::TCP).await?;
        Ok(streams)
    }

    async fn open_uni(&self) -> Result<Self::Send> {
        let id = self.alloc_id()?;
        let send = self.make_send(id, false);
        self.open(id, stream_type::UDP_DOWNLOAD).await?;
        Ok(send)
    }

    async fn open_udp_bi(&self) -> Result<(Self::Send, Self::Recv)> {
        anyhow::bail!("the WebSocket mux has no UDP stream both ways")
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>> {
        let mut rx = self.inner.datagram_in.lock().await;
        match rx.recv().await {
            Some(chunk) => Ok(chunk.data.to_vec()),
            None => Err(anyhow::anyhow!("the WebSocket session is closed")),
        }
    }

    async fn accept_uni(&self) -> Result<Self::Recv> {
        std::future::pending().await
    }
}

/// Runs the mux on an upgraded WebSocket. The session ends when the client closes the WebSocket, on
/// [`Transport::close`], or when the transport is dropped.
pub(crate) fn spawn_session<S>(
    ws: WebSocketStream<S>,
    peer: IpAddr,
    metrics: Arc<Metrics>,
) -> (WsTransport, WsSessionTasks)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    spawn_with_session_budget(ws, peer, metrics, SESSION_INBOUND_BYTES)
}

fn spawn_with_session_budget<S>(
    ws: WebSocketStream<S>,
    peer: IpAddr,
    metrics: Arc<Metrics>,
    session_inbound_bytes: usize,
) -> (WsTransport, WsSessionTasks)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ws_sink, ws_stream) = ws.split();
    let (priority_tx, priority_rx) = mpsc::channel::<Vec<u8>>(PRIORITY_LANE_CAP);
    let (bulk_tx, bulk_rx) = mpsc::channel::<Vec<u8>>(BULK_LANE_CAP);
    let (close_tx, close_rx) = mpsc::channel::<(u16, String)>(1);
    let (datagram_in_tx, datagram_in_rx) = mpsc::channel::<InboundChunk>(DATAGRAM_IN_CAP);
    let inbound: StreamRegistry = Arc::default();
    let send_states: SendStates = Arc::default();
    let terminals = Arc::new(Terminals::default());
    let cancel = CancellationToken::new();
    let written = CancellationToken::new();

    let writer = tokio::spawn(writer_task(
        ws_sink,
        priority_rx,
        bulk_rx,
        close_rx,
        terminals.clone(),
        cancel.clone(),
        written.clone().drop_guard(),
    ));
    let reader = tokio::spawn(reader_task(
        ws_stream,
        inbound.clone(),
        send_states.clone(),
        terminals.clone(),
        ByteBudget::new(session_inbound_bytes),
        ByteBudget::new(DATAGRAM_IN_BYTES),
        datagram_in_tx,
        metrics,
        cancel.clone(),
    ));

    let transport = WsTransport {
        inner: Arc::new(Inner {
            peer,
            priority_tx,
            bulk_tx,
            next_id: AtomicU32::new(1),
            inbound,
            send_states,
            terminals,
            datagram_in: AsyncMutex::new(datagram_in_rx),
            close_tx,
            written,
            _cancel_guard: cancel.clone().drop_guard(),
            cancel: cancel.clone(),
        }),
    };
    let tasks = WsSessionTasks { cancel, reader, writer };
    (transport, tasks)
}

/// Stops routing the stream's upload, marks its send side so the download stops counting bytes the client will
/// discard, and parks a RESET that goes out even with both lanes full.
fn reset_inbound_stream(inbound: &StreamRegistry, send_states: &SendStates, terminals: &Terminals, id: u32) {
    inbound.lock().unwrap().remove(&id);
    let state = send_states.lock().unwrap().get(&id).cloned();
    if let Some(state) = state {
        state.reset();
    }
    terminals.push(id, kind::RESET, &[]);
}

fn session_pool_victim(inbound: &StreamRegistry) -> Option<u32> {
    inbound
        .lock()
        .unwrap()
        .iter()
        .map(|(id, entry)| (*id, entry.budget.used.load(Ordering::Relaxed)))
        .filter(|(id, _)| *id != CONTROL_STREAM)
        .max_by_key(|(_, used)| *used)
        .filter(|(_, used)| *used >= SESSION_VICTIM_FLOOR_BYTES)
        .map(|(id, _)| id)
}

#[allow(clippy::too_many_arguments)]
async fn reader_task<S>(
    mut ws_stream: SplitStream<WebSocketStream<S>>,
    inbound: StreamRegistry,
    send_states: SendStates,
    terminals: Arc<Terminals>,
    session_budget: Arc<ByteBudget>,
    datagram_budget: Arc<ByteBudget>,
    datagram_in_tx: mpsc::Sender<InboundChunk>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => break,
            m = ws_stream.next() => m,
        };
        let Some(msg) = msg else { break };
        let data: Bytes = match msg {
            Ok(Message::Binary(data)) => data,
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_)) => continue,
            Err(e) => {
                debug!("WS read error: {e}");
                break;
            }
        };
        let Some((frame_kind, id, payload)) = mux::decode(&data) else {
            continue;
        };
        let payload = data.slice_ref(payload);

        match frame_kind {
            kind::DATA => {
                if payload.is_empty() {
                    continue;
                }
                let entry = inbound.lock().unwrap().get(&id).cloned();
                let Some(entry) = entry else { continue };
                if id == CONTROL_STREAM {
                    let Some(charge) = ByteBudget::try_charge(&entry.budget, payload.len()) else {
                        warn!("WS control stream backlog over its bound, closing the session");
                        break;
                    };
                    let chunk = InboundChunk { data: payload, _charges: [Some(charge), None] };
                    match entry.tx.try_send(chunk) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("WS control stream backlog over its bound, closing the session");
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            inbound.lock().unwrap().remove(&id);
                        }
                    }
                    continue;
                }
                let Some(stream_charge) = ByteBudget::try_charge(&entry.budget, payload.len()) else {
                    reset_inbound_stream(&inbound, &send_states, &terminals, id);
                    debug!("WS stream {id} inbound backlog over its bound, reset");
                    continue;
                };
                let session_charge = match ByteBudget::try_charge(&session_budget, payload.len()) {
                    Some(charge) => charge,
                    None => {
                        if let Some(victim) = session_pool_victim(&inbound) {
                            reset_inbound_stream(&inbound, &send_states, &terminals, victim);
                            debug!("WS stream {victim} reset for the session's inbound bound");
                            if victim == id {
                                continue;
                            }
                        }
                        ByteBudget::charge(&session_budget, payload.len())
                    }
                };
                match entry
                    .tx
                    .try_send(InboundChunk { data: payload, _charges: [Some(stream_charge), Some(session_charge)] })
                {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        reset_inbound_stream(&inbound, &send_states, &terminals, id);
                        debug!("WS stream {id} inbound backlog over its bound, reset");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        inbound.lock().unwrap().remove(&id);
                    }
                }
            }
            kind::FIN => {
                // A half close: the download keeps flowing.
                inbound.lock().unwrap().remove(&id);
            }
            kind::RESET => {
                // Both sides. A UDP stream toward the client has no inbound entry, only a send state.
                inbound.lock().unwrap().remove(&id);
                let state = send_states.lock().unwrap().get(&id).cloned();
                if let Some(state) = state {
                    state.reset();
                }
            }
            kind::CREDIT if id != CONTROL_STREAM => {
                let Ok(amount) = <[u8; 4]>::try_from(&payload[..]) else {
                    continue;
                };
                let state = send_states.lock().unwrap().get(&id).cloned();
                if let Some(state) = state {
                    state.grant(u32::from_be_bytes(amount));
                }
            }
            kind::DATAGRAM => {
                if payload.is_empty() {
                    continue;
                }
                let Some(charge) = ByteBudget::try_charge(&datagram_budget, payload.len()) else {
                    metrics.count(Counter::WsUdpIngressDroppedFull);
                    continue;
                };
                let chunk = InboundChunk { data: payload, _charges: [Some(charge), None] };
                match datagram_in_tx.try_send(chunk) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => metrics.count(Counter::WsUdpIngressDroppedFull),
                    Err(mpsc::error::TrySendError::Closed(_)) => metrics.count(Counter::WsUdpIngressDroppedClosed),
                }
            }
            _ => {}
        }
    }
    inbound.lock().unwrap().clear();
    let states: Vec<_> = send_states.lock().unwrap().values().cloned().collect();
    for state in states {
        state.reset();
    }
    cancel.cancel();
}

async fn writer_task<S>(
    mut ws_sink: SplitSink<WebSocketStream<S>, Message>,
    mut priority_rx: mpsc::Receiver<Vec<u8>>,
    mut bulk_rx: mpsc::Receiver<Vec<u8>>,
    mut close_rx: mpsc::Receiver<(u16, String)>,
    terminals: Arc<Terminals>,
    cancel: CancellationToken,
    _written: DropGuard,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut ping = tokio::time::interval(Duration::from_secs(15));
    ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ping.tick().await;

    // A bulk frame waits for its stream's OPEN, or the client drops it. The set grows by one u32 per stream, which
    // costs less than tracking when each stream ends.
    let mut opened: HashSet<u32> = HashSet::new();
    // While a frame is held here the bulk lane is not polled, since taking more would reorder them, so one slot
    // is enough.
    let mut stash: Option<Vec<u8>> = None;
    let mut priority_run = 0usize;

    enum Next {
        Close(u16, String),
        Terminal,
        Priority(Vec<u8>),
        Bulk(Vec<u8>),
        Wake,
        Ping,
    }

    loop {
        if let Some(frame) = stash.take_if(|f| opened.contains(&frame_stream_id(f))) {
            let id = frame_stream_id(&frame);
            let is_data = frame[0] == kind::DATA;
            if ws_sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                break;
            }
            if is_data {
                terminals.note_data_written(id);
            }
            priority_run = 0;
            continue;
        }

        let has_terminal = terminals.has_eligible(&opened);
        let prefer_bulk = stash.is_none() && priority_run >= PRIORITY_QUANTUM;
        let next = if prefer_bulk {
            tokio::select! {
                biased;
                Some((code, reason)) = close_rx.recv() => Next::Close(code, reason),
                _ = cancel.cancelled() => break,
                _ = std::future::ready(()), if has_terminal => Next::Terminal,
                Some(frame) = bulk_rx.recv() => Next::Bulk(frame),
                Some(frame) = priority_rx.recv() => Next::Priority(frame),
                _ = terminals.notified() => Next::Wake,
                _ = ping.tick() => Next::Ping,
                else => break,
            }
        } else {
            tokio::select! {
                biased;
                // A queued close must win over cancellation, or the client never reads its code and reason.
                Some((code, reason)) = close_rx.recv() => Next::Close(code, reason),
                _ = cancel.cancelled() => break,
                _ = std::future::ready(()), if has_terminal => Next::Terminal,
                Some(frame) = priority_rx.recv() => Next::Priority(frame),
                Some(frame) = bulk_rx.recv(), if stash.is_none() => Next::Bulk(frame),
                _ = terminals.notified() => Next::Wake,
                _ = ping.tick() => Next::Ping,
                else => break,
            }
        };

        match next {
            Next::Close(code, reason) => {
                // What the control stream queued ahead of the close, its `Bye` last, goes out first. The lane holds at
                // most PRIORITY_LANE_CAP frames, and `WsTransport::close` gives this writer a second in all.
                while let Ok(frame) = priority_rx.try_recv() {
                    if ws_sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                        break;
                    }
                }
                let close = CloseFrame { code: CloseCode::from(code), reason: reason.into() };
                let _ = ws_sink.send(Message::Close(Some(close))).await;
                let _ = ws_sink.flush().await;
                break;
            }
            Next::Terminal => {
                // Only the writer removes entries, so the peek above still holds.
                let Some((id, frame_kind, payload)) = terminals.pop_eligible(&opened) else {
                    continue;
                };
                let frame = mux::encode(frame_kind, id, payload);
                if ws_sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                    break;
                }
            }
            Next::Priority(frame) => {
                let frame_kind = frame[0];
                let id = frame_stream_id(&frame);
                if ws_sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                    break;
                }
                if frame_kind == kind::OPEN {
                    opened.insert(id);
                }
                // Preferring bulk polled the bulk lane first and found it empty, so this starts a new run rather than
                // extending the last one.
                priority_run = if prefer_bulk { 1 } else { priority_run + 1 };
            }
            Next::Bulk(frame) => {
                let id = frame_stream_id(&frame);
                if id != CONTROL_STREAM && !opened.contains(&id) {
                    stash = Some(frame);
                } else {
                    let is_data = frame[0] == kind::DATA;
                    if ws_sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                        break;
                    }
                    if is_data {
                        terminals.note_data_written(id);
                    }
                    priority_run = 0;
                }
            }
            Next::Wake => {}
            Next::Ping => {
                if ws_sink.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = ws_sink.close().await;
    cancel.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
    use webvpn_proto::close;

    type Client = WebSocketStream<DuplexStream>;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    async fn ws_ends() -> (WebSocketStream<DuplexStream>, Client) {
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let config = WebSocketConfig::default().max_message_size(Some(MAX_WS_MESSAGE_BYTES));
        let server = WebSocketStream::from_raw_socket(server_io, Role::Server, Some(config)).await;
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        (server, client)
    }

    async fn ws_pair() -> (WsTransport, Client) {
        let (server, client) = ws_ends().await;
        let (transport, _tasks) = spawn_session(server, LOCALHOST, Arc::default());
        (transport, client)
    }

    async fn ws_pair_with(session_bytes: usize, metrics: Arc<Metrics>) -> (WsTransport, Client) {
        let (server, client) = ws_ends().await;
        let (transport, _tasks) = spawn_with_session_budget(server, LOCALHOST, metrics, session_bytes);
        (transport, client)
    }

    async fn next_binary(ws: &mut Client) -> Bytes {
        loop {
            if let Message::Binary(data) = ws.next().await.expect("ws ended").expect("ws error") {
                return data;
            }
        }
    }

    async fn next_close(ws: &mut Client) -> CloseFrame {
        loop {
            if let Message::Close(frame) = ws.next().await.expect("ws ended").expect("ws error") {
                return frame.expect("a close code");
            }
        }
    }

    /// The id an OPEN frame announces.
    async fn next_open(ws: &mut Client) -> u32 {
        let open = next_binary(ws).await;
        assert_eq!(open[0], kind::OPEN);
        frame_stream_id(&open)
    }

    fn parts(frame: &[u8]) -> (u8, u32, &[u8]) {
        mux::decode(frame).expect("a whole frame")
    }

    async fn send_frame(ws: &mut Client, frame_kind: u8, id: u32, payload: &[u8]) {
        ws.send(Message::Binary(mux::encode(frame_kind, id, payload).into())).await.unwrap();
    }

    /// Reads the DATA frames that carry `bytes` bytes on stream `id`, written in frames of at most 64 KiB.
    async fn read_data(ws: &mut Client, id: u32, bytes: usize) {
        let mut got = 0;
        for _ in 0..bytes.div_ceil(MAX_DATA_PAYLOAD) {
            let frame = next_binary(ws).await;
            let (frame_kind, stream, payload) = parts(&frame);
            assert_eq!((frame_kind, stream), (kind::DATA, id));
            got += payload.len();
        }
        assert_eq!(got, bytes);
    }

    // The client decodes these exact bytes.
    #[tokio::test]
    async fn frames_are_kind_then_big_endian_stream_then_payload() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            transport.inner.next_id.store(0x0102_0304, Ordering::Relaxed);
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let _udp = transport.open_uni().await.unwrap();
            send.write_all(b"hi").await.unwrap();
            drop(send);

            assert_eq!(&next_binary(&mut client).await[..], [0, 1, 2, 3, 4, 0]);
            assert_eq!(&next_binary(&mut client).await[..], [0, 1, 2, 3, 5, 1]);
            assert_eq!(&next_binary(&mut client).await[..], [1, 1, 2, 3, 4, b'h', b'i']);
            assert_eq!(&next_binary(&mut client).await[..], [2, 1, 2, 3, 4]);
        })
        .await
        .expect("the frames never arrived");
    }

    #[tokio::test]
    async fn control_frames_go_ahead_of_queued_bulk_data() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut control, _control_recv) = transport.control_stream().await.unwrap();
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            // Nothing here yields on a current-thread runtime, so the writer first runs with both lanes holding a
            // frame, the bulk one queued first.
            send.write_all(b"bulk").await.unwrap();
            control.write_all(b"ctl").await.unwrap();

            let id = next_open(&mut client).await;
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, CONTROL_STREAM, b"ctl".as_slice()));
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"bulk".as_slice()));
        })
        .await
        .expect("the frames never arrived");
    }

    #[tokio::test]
    async fn control_churn_cannot_starve_bulk_downloads() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut control, _control_recv) = transport.control_stream().await.unwrap();
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;
            send.write_all(b"bulk").await.unwrap();

            for _ in 0..(PRIORITY_LANE_CAP / 2) {
                transport.inner.priority_tx.try_send(mux::encode(kind::DATA, CONTROL_STREAM, &[0u8; 16])).unwrap();
            }
            let churn = tokio::spawn(async move {
                for _ in 0..(2 * PRIORITY_LANE_CAP) {
                    if control.write_all(&[0u8; 16]).await.is_err() {
                        break;
                    }
                }
            });

            let mut saw_bulk = false;
            for _ in 0..PRIORITY_LANE_CAP {
                let frame = next_binary(&mut client).await;
                if frame[0] == kind::DATA && frame_stream_id(&frame) == id {
                    saw_bulk = true;
                    break;
                }
            }
            churn.abort();
            assert!(saw_bulk, "bulk DATA starved behind continuous control traffic");
        })
        .await
        .expect("fairness test stalled");
    }

    #[tokio::test]
    async fn quantum_bulk_service_keeps_open_before_data() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            for _ in 0..(PRIORITY_QUANTUM + 8) {
                transport.inner.priority_tx.try_send(mux::encode(kind::DATA, CONTROL_STREAM, &[0u8; 8])).unwrap();
            }
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            send.write_all(b"first").await.unwrap();

            let mut open_seen = false;
            let mut saw_data = false;
            for _ in 0..(PRIORITY_QUANTUM + 10) {
                let frame = next_binary(&mut client).await;
                match parts(&frame) {
                    (kind::OPEN, _, _) => open_seen = true,
                    (kind::DATA, id, payload) if id != CONTROL_STREAM => {
                        assert!(open_seen, "bulk DATA overtook its OPEN");
                        assert_eq!(payload, b"first");
                        saw_data = true;
                        break;
                    }
                    _ => {}
                }
            }
            assert!(saw_data, "the stream's DATA never arrived");
        })
        .await
        .expect("the held frame was never sent");
    }

    #[tokio::test]
    async fn a_stream_sends_no_byte_past_its_window_until_credit() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;
            let window = INITIAL_STREAM_WINDOW as usize;

            let mut write = tokio::spawn(async move {
                send.write_all(&vec![7u8; window + 1]).await?;
                Ok::<_, io::Error>(send)
            });
            read_data(&mut client, id, window).await;
            assert!(tokio::time::timeout(Duration::from_millis(50), next_binary(&mut client)).await.is_err());
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut write).await.is_err());

            send_frame(&mut client, kind::CREDIT, id, &1u32.to_be_bytes()).await;
            let _send = write.await.unwrap().unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, [7u8].as_slice()));
        })
        .await
        .expect("a write within the window stalled");
    }

    #[tokio::test]
    async fn credit_adds_to_the_window_and_counts_bytes_already_sent() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (_control_send, mut control_recv) = transport.control_stream().await.unwrap();
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;
            let window = INITIAL_STREAM_WINDOW as usize;

            send.write_all(&vec![0u8; window - 1]).await.unwrap();
            read_data(&mut client, id, window - 1).await;

            // One byte of the window is left, so the CREDIT makes five, not four.
            send_frame(&mut client, kind::CREDIT, id, &4u32.to_be_bytes()).await;
            send_frame(&mut client, kind::DATA, CONTROL_STREAM, b"mark").await;
            control_recv.read_exact(&mut [0u8; 4]).await.unwrap();
            let mut write = tokio::spawn(async move {
                send.write_all(b"abcdef").await?;
                Ok::<_, io::Error>(send)
            });
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"abcde".as_slice()));
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut write).await.is_err());

            send_frame(&mut client, kind::CREDIT, id, &1u32.to_be_bytes()).await;
            let _send = write.await.unwrap().unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"f".as_slice()));
        })
        .await
        .expect("a credited write stalled");
    }

    #[tokio::test]
    async fn reset_wakes_a_writer_waiting_for_credit() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;
            let window = INITIAL_STREAM_WINDOW as usize;

            let write = tokio::spawn(async move { send.write_all(&vec![0u8; window + 1]).await });
            read_data(&mut client, id, window).await;

            send_frame(&mut client, kind::RESET, id, &[]).await;
            write.await.unwrap().expect_err("a writer waiting for credit survived RESET");
        })
        .await
        .expect("RESET did not wake the writer waiting for credit");
    }

    #[tokio::test]
    async fn reset_wakes_a_writer_waiting_for_the_lane() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (lane, _lane_rx) = mpsc::channel::<Vec<u8>>(1);
            lane.try_send(vec![0]).unwrap();
            let state = Arc::new(SendState::new(INITIAL_STREAM_WINDOW));
            let send_states: SendStates = Arc::default();
            send_states.lock().unwrap().insert(7, state.clone());
            let mut send = MuxSend {
                id: 7,
                lane: PollSender::new(lane),
                send_states,
                state: state.clone(),
                terminals: Arc::default(),
                fin_sent: false,
            };

            let write = tokio::spawn(async move { send.write_all(b"x").await });
            tokio::task::yield_now().await;
            assert!(state.flow.lock().unwrap().write_waker.is_some());

            state.reset();
            write.await.unwrap().expect_err("a writer waiting for the lane survived RESET");
        })
        .await
        .expect("RESET did not wake the writer waiting for the lane");
    }

    #[tokio::test]
    async fn download_fin_keeps_client_upload_flowing() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (send, mut recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            drop(send);
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::FIN, id, &[]));

            send_frame(&mut client, kind::DATA, id, b"tail").await;
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tail");

            send_frame(&mut client, kind::FIN, id, &[]).await;
            assert_eq!(recv.read(&mut buf).await.unwrap(), 0);
        })
        .await
        .expect("the upload stalled after the download finished");
    }

    #[tokio::test]
    async fn drop_fin_survives_a_full_bulk_lane() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;
            let (mut other, _other_recv) = transport.open_bi().await.unwrap();

            for _ in 0..BULK_LANE_CAP {
                other.write_all(&[0u8; 8]).await.unwrap();
            }
            assert_eq!(transport.inner.bulk_tx.capacity(), 0);
            drop(send);

            let mut saw_fin = false;
            for _ in 0..(BULK_LANE_CAP + 2) {
                let frame = next_binary(&mut client).await;
                if parts(&frame) == (kind::FIN, id, &[][..]) {
                    saw_fin = true;
                    break;
                }
            }
            assert!(saw_fin, "the dropped stream's FIN never arrived");
        })
        .await
        .expect("the FIN was lost while the bulk lane was full");
    }

    #[tokio::test]
    async fn drop_fin_follows_queued_stream_data() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            send.write_all(b"tail").await.unwrap();
            drop(send);

            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"tail".as_slice()));
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::FIN, id, &[]));
        })
        .await
        .expect("the FIN never arrived after the DATA");
    }

    #[tokio::test]
    async fn a_failed_stream_resets_with_the_peer_reset_code_after_its_data() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            send.write_all(b"tail").await.unwrap();
            send.fail();
            drop(send);

            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"tail".as_slice()));
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::RESET, id, &[0, 0, 0, 1]));
            // A FIN still owed for the stream would go out ahead of the next stream's OPEN.
            let _next = transport.open_bi().await.unwrap();
            assert_eq!(next_binary(&mut client).await[0], kind::OPEN);
        })
        .await
        .expect("the stream's RESET never arrived");
    }

    #[test]
    fn a_terminal_reset_replaces_fin_and_is_never_replaced() {
        let terminals = Terminals::default();
        let opened = HashSet::from([3u32, 4]);

        terminals.push(3, kind::FIN, &[]);
        terminals.push(3, kind::RESET, &[]);
        assert_eq!(terminals.pop_eligible(&opened), Some((3, kind::RESET, &[][..])));
        assert_eq!(terminals.pop_eligible(&opened), None);

        terminals.push(4, kind::RESET, &PEER_RESET_PAYLOAD);
        terminals.push(4, kind::FIN, &[]);
        terminals.push(4, kind::RESET, &[]);
        assert_eq!(terminals.pop_eligible(&opened), Some((4, kind::RESET, &PEER_RESET_PAYLOAD[..])));
    }

    #[test]
    fn terminals_wait_for_open_and_queued_data() {
        let terminals = Terminals::default();
        terminals.note_data_queued(5);
        terminals.push(5, kind::FIN, &[]);

        let opened = HashSet::from([5u32]);
        assert_eq!(terminals.pop_eligible(&opened), None);
        terminals.note_data_written(5);
        assert_eq!(terminals.pop_eligible(&HashSet::new()), None);
        assert_eq!(terminals.pop_eligible(&opened), Some((5, kind::FIN, &[][..])));
    }

    #[tokio::test]
    async fn inbound_overflow_resets_both_sides() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            let chunk = vec![0u8; MAX_DATA_PAYLOAD];
            for _ in 0..(INBOUND_STREAM_BYTES / MAX_DATA_PAYLOAD + 8) {
                send_frame(&mut client, kind::DATA, id, &chunk).await;
            }
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::RESET, id, &[]));
            send.write(b"x").await.expect_err("the download survived its own RESET");
        })
        .await
        .expect("the overflow RESET never arrived");
    }

    #[tokio::test]
    async fn session_pool_refusal_resets_largest_holder_not_arriving_stream() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let session_bytes = SESSION_VICTIM_FLOOR_BYTES;
            let (transport, mut client) = ws_pair_with(session_bytes, Arc::default()).await;
            let (mut stalled_send, _stalled_recv) = transport.open_bi().await.unwrap();
            let (mut send, mut recv) = transport.open_bi().await.unwrap();
            let stalled_id = next_open(&mut client).await;
            let id = next_open(&mut client).await;

            let chunk = vec![0u8; MAX_DATA_PAYLOAD];
            for _ in 0..(session_bytes / MAX_DATA_PAYLOAD) {
                send_frame(&mut client, kind::DATA, stalled_id, &chunk).await;
            }
            send_frame(&mut client, kind::DATA, id, b"hi").await;

            let mut buf = [0u8; 2];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::RESET, stalled_id, &[]));
            stalled_send.write(b"x").await.expect_err("the reset stream's download survived");
            send.write_all(b"ok").await.unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"ok".as_slice()));
        })
        .await
        .expect("the session's bound disturbed the healthy stream");
    }

    #[tokio::test]
    async fn session_pool_refusal_resets_arriving_stream_when_it_is_largest() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let session_bytes = SESSION_VICTIM_FLOOR_BYTES;
            let (transport, mut client) = ws_pair_with(session_bytes, Arc::default()).await;
            let (mut other_send, mut other_recv) = transport.open_bi().await.unwrap();
            let (_stalled_send, _stalled_recv) = transport.open_bi().await.unwrap();
            let other_id = next_open(&mut client).await;
            let stalled_id = next_open(&mut client).await;

            let chunk = vec![0u8; MAX_DATA_PAYLOAD];
            for _ in 0..(session_bytes / MAX_DATA_PAYLOAD + 1) {
                send_frame(&mut client, kind::DATA, stalled_id, &chunk).await;
            }
            assert_eq!(next_binary(&mut client).await, mux::encode(kind::RESET, stalled_id, &[]));

            send_frame(&mut client, kind::DATA, other_id, b"hi").await;
            let mut buf = [0u8; 2];
            other_recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
            other_send.write_all(b"ok").await.unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, other_id, b"ok".as_slice()));
        })
        .await
        .expect("resetting the largest holder disturbed the session");
    }

    #[tokio::test]
    async fn session_pool_refusal_below_floor_resets_nobody() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let session_bytes = MAX_DATA_PAYLOAD;
            let (transport, mut client) = ws_pair_with(session_bytes, Arc::default()).await;
            let (mut idle_send, mut idle_recv) = transport.open_bi().await.unwrap();
            let (mut send, mut recv) = transport.open_bi().await.unwrap();
            let idle_id = next_open(&mut client).await;
            let id = next_open(&mut client).await;

            let payload = vec![7u8; MAX_DATA_PAYLOAD];
            send_frame(&mut client, kind::DATA, idle_id, &payload).await;
            send_frame(&mut client, kind::DATA, id, b"hi").await;

            let mut buf = [0u8; 2];
            recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hi");
            let mut got = vec![0u8; MAX_DATA_PAYLOAD];
            idle_recv.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload);
            idle_send.write_all(b"a").await.unwrap();
            send.write_all(b"b").await.unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, idle_id, b"a".as_slice()));
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"b".as_slice()));
        })
        .await
        .expect("a refusal below the floor disturbed the session");
    }

    #[tokio::test]
    async fn tiny_write_bursts_do_not_force_a_reset() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, mut recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            for i in 0..=255u8 {
                send_frame(&mut client, kind::DATA, id, &[i]).await;
            }
            send_frame(&mut client, kind::FIN, id, &[]).await;

            let mut buf = Vec::new();
            recv.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.len(), 256);

            send.write_all(b"ok").await.unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"ok".as_slice()));
        })
        .await
        .expect("a burst of tiny writes stalled the stream");
    }

    #[test]
    fn byte_budget_floors_charges_and_releases_on_drop() {
        let budget = ByteBudget::new(4 * MIN_CHUNK_CHARGE);
        let small = ByteBudget::try_charge(&budget, 1).unwrap();
        assert_eq!(small.amount, MIN_CHUNK_CHARGE);
        let rest = ByteBudget::try_charge(&budget, 3 * MIN_CHUNK_CHARGE).unwrap();
        assert!(ByteBudget::try_charge(&budget, 1).is_none());
        drop(small);
        assert!(ByteBudget::try_charge(&budget, MIN_CHUNK_CHARGE).is_some());
        drop(rest);
        assert!(ByteBudget::try_charge(&budget, usize::MAX).is_none());
        assert!(ByteBudget::try_charge(&budget, MIN_CHUNK_CHARGE).is_some());
    }

    #[test]
    fn byte_budget_unconditional_charge_goes_over_cap_and_releases() {
        let budget = ByteBudget::new(MIN_CHUNK_CHARGE);
        let first = ByteBudget::try_charge(&budget, MIN_CHUNK_CHARGE).unwrap();
        assert!(ByteBudget::try_charge(&budget, 1).is_none());
        let over = ByteBudget::charge(&budget, 1);
        assert_eq!(over.amount, MIN_CHUNK_CHARGE);
        drop(first);
        assert!(ByteBudget::try_charge(&budget, 1).is_none());
        drop(over);
        assert!(ByteBudget::try_charge(&budget, 1).is_some());
    }

    #[test]
    fn session_pool_victim_picks_largest_holder_above_the_floor() {
        let inbound: StreamRegistry = Arc::default();
        let insert = |id: u32, used: usize| {
            let (tx, _rx) = mpsc::channel::<InboundChunk>(1);
            let entry = InboundEntry { tx, budget: ByteBudget::new(SESSION_INBOUND_BYTES) };
            entry.budget.used.store(used, Ordering::Relaxed);
            inbound.lock().unwrap().insert(id, entry);
        };

        assert_eq!(session_pool_victim(&inbound), None);

        insert(CONTROL_STREAM, SESSION_INBOUND_BYTES);
        assert_eq!(session_pool_victim(&inbound), None);

        insert(7, SESSION_VICTIM_FLOOR_BYTES - 1);
        assert_eq!(session_pool_victim(&inbound), None);

        insert(8, SESSION_VICTIM_FLOOR_BYTES);
        insert(9, SESSION_VICTIM_FLOOR_BYTES + 1);
        assert_eq!(session_pool_victim(&inbound), Some(9));
    }

    #[tokio::test]
    async fn datagram_ingress_drops_and_counts_what_it_cannot_hold() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let metrics = Arc::new(Metrics::default());
            let (transport, mut client) = ws_pair_with(SESSION_INBOUND_BYTES, metrics.clone()).await;
            let (_control_send, mut control_recv) = transport.control_stream().await.unwrap();
            let mut mark = [0u8; 4];

            for _ in 0..(DATAGRAM_IN_CAP + 16) {
                send_frame(&mut client, kind::DATAGRAM, 0, &[1u8; 16]).await;
            }
            // The reader handles frames in order, so the mark arriving means every datagram before it was handled.
            send_frame(&mut client, kind::DATA, CONTROL_STREAM, b"mark").await;
            control_recv.read_exact(&mut mark).await.unwrap();
            assert_eq!(metrics.get(Counter::WsUdpIngressDroppedFull), 16);

            for _ in 0..DATAGRAM_IN_CAP {
                transport.recv_datagram().await.unwrap();
            }
            send_frame(&mut client, kind::DATAGRAM, 0, b"after").await;
            assert_eq!(transport.recv_datagram().await.unwrap(), b"after");

            transport.inner.datagram_in.lock().await.close();
            send_frame(&mut client, kind::DATAGRAM, 0, b"late").await;
            send_frame(&mut client, kind::DATA, CONTROL_STREAM, b"mark").await;
            control_recv.read_exact(&mut mark).await.unwrap();
            assert_eq!(metrics.get(Counter::WsUdpIngressDroppedClosed), 1);
            assert_eq!(metrics.get(Counter::WsUdpIngressDroppedFull), 16);
        })
        .await
        .expect("datagram overflow stalled the session");
    }

    #[tokio::test]
    async fn malformed_frames_are_ignored() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (_control_send, mut control_recv) = transport.control_stream().await.unwrap();

            for bad in [
                vec![kind::DATA],
                mux::encode(kind::CREDIT, 1, &[1, 2]),
                mux::encode(9, 1, b"?"),
                mux::encode(kind::DATA, 1, &[]),
                mux::encode(kind::DATAGRAM, 0, &[]),
            ] {
                client.send(Message::Binary(bad.into())).await.unwrap();
            }
            send_frame(&mut client, kind::DATA, CONTROL_STREAM, b"ok").await;
            let mut buf = [0u8; 2];
            control_recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ok");
        })
        .await
        .expect("malformed frames stalled the reader");
    }

    #[tokio::test]
    async fn close_sends_the_session_code_and_reason_before_the_tasks_stop() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (server, mut client) = ws_ends().await;
            let (transport, tasks) = spawn_session(server, LOCALHOST, Arc::default());
            transport.close(close::RESTARTING, "the relay is stopping").await;
            drop(transport);
            tasks.shutdown().await;
            let frame = next_close(&mut client).await;
            assert_eq!(u16::from(frame.code), 4004);
            assert_eq!(frame.reason.as_str(), "the relay is stopping");
        })
        .await
        .expect("the Close frame never arrived");
    }

    #[tokio::test]
    async fn a_long_close_reason_is_cut_on_a_character_and_keeps_the_code() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            transport.close(close::SESSION_LIMIT, &"é".repeat(100)).await;
            let frame = next_close(&mut client).await;
            assert_eq!(u16::from(frame.code), 4003);
            assert_eq!(frame.reason.as_str(), "é".repeat(61));
        })
        .await
        .expect("the Close frame never arrived");
    }

    #[tokio::test]
    async fn dropping_the_transport_ends_the_session() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            drop(transport);
            loop {
                match client.next().await {
                    None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                    Some(Ok(_)) => continue,
                }
            }
        })
        .await
        .expect("the client never saw the session end");
    }

    #[tokio::test]
    async fn stream_id_exhaustion_refuses_only_new_streams() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (transport, mut client) = ws_pair().await;
            let (mut send, _recv) = transport.open_bi().await.unwrap();
            let id = next_open(&mut client).await;

            transport.inner.next_id.store(u32::MAX, Ordering::Relaxed);
            assert!(transport.open_bi().await.is_err());
            assert!(transport.open_uni().await.is_err());
            assert_eq!(transport.inner.next_id.load(Ordering::Relaxed), u32::MAX);

            send.write_all(b"still-open").await.unwrap();
            let frame = next_binary(&mut client).await;
            assert_eq!(parts(&frame), (kind::DATA, id, b"still-open".as_slice()));
        })
        .await
        .expect("running out of ids disturbed the live session");
    }

    #[tokio::test]
    async fn the_mux_refuses_what_only_webtransport_carries() {
        let (transport, _client) = ws_pair().await;
        assert!(transport.open_udp_bi().await.is_err());
        assert!(transport.send_datagram(vec![0u8; 8]).is_err());
    }
}
