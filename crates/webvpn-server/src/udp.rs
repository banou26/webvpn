//! A UDP socket: the socket the relay holds for a client, and the two pumps between it and the client.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use webvpn_proto::ClientPacket;

use crate::policy::Session;
use crate::session::{QueuedDatagram, SessionHandle};
use crate::transport::Transport;

/// Runs a socket a client asked for. `requests` yields its `UdpBind` first. `datagrams` yields the client's packets
/// for this socket that came outside its own stream, and `queue` is where the socket puts the ones its stream
/// brings.
pub(crate) async fn bind<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    requests: mpsc::Receiver<ClientPacket>,
    datagrams: mpsc::Receiver<QueuedDatagram>,
    queue: mpsc::Sender<QueuedDatagram>,
) -> Result<()> {
    let _ = (session, socket, requests, datagrams, queue);
    todo!()
}
