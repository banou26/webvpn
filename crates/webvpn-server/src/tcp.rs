//! A TCP socket: the connection the relay holds for a client, and the two pumps between it and the socket's stream.

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use webvpn_proto::ClientPacket;

use crate::policy::Session;
use crate::session::SessionHandle;
use crate::transport::Transport;

/// Runs a socket a client asked for. `requests` yields its `TcpConnect` or `TcpConnectName` first.
pub(crate) async fn connect<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    requests: mpsc::Receiver<ClientPacket>,
) -> Result<()> {
    let _ = (session, socket, requests);
    todo!()
}

/// Runs a socket one of the client's listeners accepted: announces it with `Accepted`, then moves its bytes.
pub(crate) async fn accepted<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    listener: u32,
    connection: TcpStream,
    requests: mpsc::Receiver<ClientPacket>,
) -> Result<()> {
    let _ = (session, socket, listener, connection, requests);
    todo!()
}
