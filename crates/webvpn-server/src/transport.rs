//! What the session and socket code asks of a carrier, so it runs unchanged over WebTransport (one QUIC stream for
//! each socket) and over the WebSocket mux (one connection carrying the same streams).

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Covers opening a socket's stream and writing its 4-byte socket id. Either can wait without end on stream credit
/// the client does not give.
pub(crate) const SOCKET_STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The relay's side of a stream it opened for a socket.
pub trait SendHalf: AsyncWrite + Unpin + Send + 'static {
    /// Ends the stream at once with `webvpn_proto::reset::PEER_RESET`, dropping what is unsent, for a socket whose
    /// peer reset its connection. Finishing the stream instead would tell the client the peer closed in order.
    fn fail(&mut self) {}

    /// Ends the stream for a socket the client closed, dropping what is unsent. The default does nothing, which
    /// leaves the stream to finish when it is dropped.
    ///
    /// Over WebTransport this must be a reset with `webvpn_proto::reset::CLOSED` and not that finish. Firefox (151 and 158
    /// measured, bug 1986138) forgets a stream on the STOP_SENDING that dropping its receive side sends, and quinn
    /// writes that frame ahead of the finish, so the finish is never read, the stream is kept, and its credit never
    /// returns: a session stopped opening streams after about 100 such closes. A reset ends the client's receive
    /// side without a read.
    fn abandon(&mut self) {}

    /// Resolves once the client read what was written on the stream, as far as the carrier can tell. The relay calls it
    /// on the control stream after its `Bye`, within a bound, and closes the session once it resolved, so a carrier
    /// whose close can overtake what was written waits here. The default resolves at once, which suits a carrier whose
    /// close goes out behind what the control stream wrote.
    fn deliver(&mut self) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

/// One client's session on a carrier.
///
/// The relay opens every stream. A client writes only on its side of a stream the relay opened, and in datagrams.
/// The one stream a client opens is the one [`accept_uni`](Transport::accept_uni) returns.
pub trait Transport: Send + Sync + 'static {
    type Send: SendHalf;
    type Recv: AsyncRead + Unpin + Send + 'static;

    /// The client's address as the carrier saw it, which the policy is asked about.
    fn remote_ip(&self) -> IpAddr;

    /// The smoothed round trip time, or zero where the carrier measures none.
    fn rtt(&self) -> Duration {
        Duration::ZERO
    }

    /// Closes the session with a `webvpn_proto::close` code and a reason for a person, and resolves once the carrier
    /// holds the close and will send it before its connection ends. A carrier that drops its connection sooner loses
    /// both, and a client then reads the end of its streams as its peers closing. The relay says `Bye` with the same
    /// code and reason on the control stream first, whenever it has one, and waits for [`SendHalf::deliver`].
    ///
    /// Each carrier documents how far its close reaches. The WebTransport carrier's default close is a QUIC
    /// connection close, whose code and reason a native client reads and a browser does not; its `close-capsule`
    /// feature sends the close a browser reads, a CLOSE_WEBTRANSPORT_SESSION capsule.
    fn close(&self, code: u32, reason: &str) -> impl Future<Output = ()> + Send;

    /// Sends one UDP packet outside any stream. Used for a UDP socket whose stream could not be opened.
    fn send_datagram(&self, data: Vec<u8>) -> Result<()>;

    /// The control stream. Called exactly once, and before any other stream is opened, so the client sees it first.
    fn control_stream(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv)>> + Send;

    /// A stream for one TCP socket.
    fn open_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv)>> + Send;

    /// A stream that carries a UDP socket's packets toward the client only.
    fn open_uni(&self) -> impl Future<Output = Result<Self::Send>> + Send;

    /// A stream that carries a UDP socket's packets both ways. WebTransport only.
    fn open_udp_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv)>> + Send;

    /// A stream for one IP tunnel. The default opens it as a TCP socket's stream, which suits a carrier whose streams
    /// carry no type, as WebTransport's do.
    fn open_ip_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv)>> + Send {
        self.open_bi()
    }

    fn recv_datagram(&self) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// The stream a client opens for a UDP socket whose own stream did not reach it. Never resolves on a carrier
    /// whose clients open no streams.
    fn accept_uni(&self) -> impl Future<Output = Result<Self::Recv>> + Send;
}

fn stream_setup_deadline(session_setup: Option<Instant>) -> Instant {
    let own = Instant::now() + SOCKET_STREAM_SETUP_TIMEOUT;
    session_setup.map_or(own, |deadline| deadline.min(own))
}

pub(crate) async fn open_bi_with_prefix<T: Transport>(
    transport: &T,
    socket: u32,
    deadline: Option<Instant>,
) -> Result<(T::Send, T::Recv)> {
    tokio::time::timeout_at(stream_setup_deadline(deadline), async {
        let (mut send, recv) = transport.open_bi().await?;
        send.write_all(&socket.to_be_bytes()).await?;
        Ok((send, recv))
    })
    .await
    .context("the socket's stream was not open in time")?
}

pub(crate) async fn open_udp_bi_with_prefix<T: Transport>(transport: &T, socket: u32) -> Result<(T::Send, T::Recv)> {
    tokio::time::timeout_at(stream_setup_deadline(None), async {
        let (mut send, recv) = transport.open_udp_bi().await?;
        send.write_all(&socket.to_be_bytes()).await?;
        Ok((send, recv))
    })
    .await
    .context("the UDP socket's stream was not open in time")?
}

pub(crate) async fn open_ip_bi_with_prefix<T: Transport>(transport: &T, socket: u32) -> Result<(T::Send, T::Recv)> {
    tokio::time::timeout_at(stream_setup_deadline(None), async {
        let (mut send, recv) = transport.open_ip_bi().await?;
        send.write_all(&socket.to_be_bytes()).await?;
        Ok((send, recv))
    })
    .await
    .context("the tunnel's stream was not open in time")?
}

pub(crate) async fn open_uni_with_prefix<T: Transport>(transport: &T, socket: u32) -> Result<T::Send> {
    tokio::time::timeout_at(stream_setup_deadline(None), async {
        let mut send = transport.open_uni().await?;
        send.write_all(&socket.to_be_bytes()).await?;
        Ok(send)
    })
    .await
    .context("the UDP socket's stream was not open in time")?
}
