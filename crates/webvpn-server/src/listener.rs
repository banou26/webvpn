//! A TCP listener: a port the relay holds for a client, whose connections become sockets of the client's session.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use webvpn_proto::ClientPacket;

use crate::policy::Session;
use crate::session::{RegisterSocket, SessionHandle};
use crate::transport::Transport;

/// Runs a listener a client asked for. `requests` yields its `TcpListen` first. Each connection it accepts is handed
/// to the session through `register`.
pub(crate) async fn listen<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    requests: mpsc::Receiver<ClientPacket>,
    register: mpsc::Sender<RegisterSocket>,
) -> Result<()> {
    let _ = (session, socket, requests, register);
    todo!()
}
