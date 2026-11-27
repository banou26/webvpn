//! A TCP listener: a port the relay holds for a client, whose connections become sockets of the client's session.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::warn;
use webvpn_proto::{ClientPacket, RelayPacket};

use crate::metrics::Counter;
use crate::policy::{Proto, Refusal, Session, SocketKind};
use crate::session::{PER_SOCKET_CHANNEL_BUFFER, RegisterSocket, SessionHandle, error};
use crate::transport::Transport;

/// Runs a listener a client asked for. `requests` yields its `TcpListen` first. Each connection it accepts is handed
/// to the session through `register`.
pub(crate) async fn listen<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    mut requests: mpsc::Receiver<ClientPacket>,
    register: mpsc::Sender<RegisterSocket>,
) -> Result<()> {
    let Some(ClientPacket::TcpListen { id, local }) = requests.recv().await else {
        bail!("a listener's first request is not a listen");
    };
    // Port 0 takes a free port and any other is bound exactly or refused, as BSD sockets bind. The port is never
    // forced to 0: the policy's floor and the system's AddrInUse keep a port from being taken over.
    let bound = async {
        session.policy.check_bind(Proto::Tcp, local)?;
        let listener = TcpListener::bind(local).await.map_err(|failure| Refusal::from_io(&failure))?;
        let bound = listener.local_addr().map_err(|failure| Refusal::from_io(&failure))?;
        Ok::<_, Refusal>((listener, bound))
    };
    let (listener, bound) = match bound.await {
        Ok(bound) => bound,
        Err(refusal) => {
            let code = refusal.code.0;
            session.reply(error(id, refusal)).await;
            bail!("the listener did not bind: code {code}");
        }
    };
    // after the listener, so the record drops before the system frees the port
    let _on_record = session.relay.hairpin.register(Proto::Tcp, bound);
    let local = session.relay.hairpin.public_spelling(bound);
    session.reply(RelayPacket::Socket { id, socket, local, remote: None }).await;

    let mut unlisten = None;
    let mut pending: Option<RegisterSocket> = None;
    loop {
        tokio::select! {
            request = requests.recv() => match request {
                Some(ClientPacket::TcpUnlisten { id, .. }) => {
                    unlisten = Some(id);
                    break;
                }
                // the session hands a listener no other request
                Some(_) => {}
                None => break,
            },
            accepted = listener.accept(), if pending.is_none() => match accepted {
                Ok((connection, peer)) => {
                    session.relay.metrics.count(Counter::InboundAccepted);
                    pending = Some(registration(&session, socket, connection, peer));
                }
                Err(failure) => {
                    warn!(socket, "a listener stopped accepting: {failure}");
                    session.reply(RelayPacket::Closed { socket, code: Refusal::from_io(&failure).code }).await;
                    break;
                }
            },
            permit = register.reserve(), if pending.is_some() => match permit {
                Ok(permit) => permit.send(pending.take().expect("a registration is pending")),
                Err(_) => break,
            },
        }
    }
    if let Some(id) = unlisten {
        session.reply(RelayPacket::Ok { id }).await;
    }
    session.answer_left(&mut requests).await;
    Ok(())
}

/// What the session takes in for a connection the listener accepted. A connection it turns away is told to the
/// client with `AcceptRefused`.
fn registration<T: Transport, S: Session>(
    session: &Arc<SessionHandle<T, S>>,
    listener: u32,
    connection: TcpStream,
    peer: SocketAddr,
) -> RegisterSocket {
    let (requests, queue) = mpsc::channel(PER_SOCKET_CHANNEL_BUFFER);
    let remote = session.relay.hairpin.public_spelling(peer);
    let replies = session.replies.clone();
    let session = session.clone();
    RegisterSocket {
        kind: SocketKind::Tcp,
        requests,
        // a TCP socket takes no datagrams
        datagrams: mpsc::channel(1).0,
        run: Box::new(move |socket| Box::pin(crate::tcp::accepted(session, socket, listener, connection, queue))),
        // try_send: this runs on the session's own loop, which must never wait on the client reading its control
        // stream, so a full queue drops the notice
        refused: Box::new(move |refusal| {
            let _ = replies.try_send(RelayPacket::AcceptRefused { listener, code: refusal.code, remote });
        }),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;
    use webvpn_proto::ErrorCode;

    use super::*;
    use crate::relay::Config;
    use crate::tcp::tests::{code, handle, local, within, CLIENT, PUBLIC};
    use crate::testing::{self, Client, MemoryTransport};

    const LISTENER: u32 = 4;

    /// A listener of a relay whose own address is `PUBLIC`, after it answered its `TcpListen`.
    struct Listening<S: Session> {
        session: Arc<SessionHandle<MemoryTransport, S>>,
        replies: mpsc::Receiver<RelayPacket>,
        requests: mpsc::Sender<ClientPacket>,
        registered: mpsc::Receiver<RegisterSocket>,
        task: JoinHandle<Result<()>>,
        client: Client,
        answer: RelayPacket,
    }

    async fn listening<S: Session>(policy: S, local: &str) -> Listening<S> {
        let (transport, client) = testing::session(CLIENT);
        let config = Config { own_addresses: vec![PUBLIC], ..Config::default() };
        let (session, mut replies) = handle(transport, policy, config);
        let (requests, queue) = mpsc::channel(4);
        requests.try_send(ClientPacket::TcpListen { id: 1, local: local.parse().unwrap() }).unwrap();
        let (register, registered) = mpsc::channel(4);
        let task = tokio::spawn(listen(session.clone(), LISTENER, queue, register));
        let answer = within(replies.recv()).await.expect("an answer");
        Listening { session, replies, requests, registered, task, client, answer }
    }

    /// The port a listener's `Socket` answer carries.
    fn port(answer: &RelayPacket) -> u16 {
        match answer {
            RelayPacket::Socket { local, .. } => local.port(),
            other => panic!("expected a socket, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_listener_answers_its_public_address_and_holds_its_port_on_record_until_unlisten() {
        let mut listening = listening(local(), "127.0.0.1:0").await;
        let RelayPacket::Socket { id: 1, socket: LISTENER, local, remote: None } = listening.answer else {
            panic!("expected the listener's socket, got {:?}", listening.answer);
        };
        assert_eq!(local.ip(), PUBLIC);
        assert_ne!(local.port(), 0);
        let hairpin = &listening.session.relay.hairpin;
        let route = hairpin.own_route(Proto::Tcp, local).unwrap().unwrap();
        assert_eq!(route.dial, SocketAddr::from(([127, 0, 0, 1], local.port())));

        listening.requests.send(ClientPacket::TcpUnlisten { id: 2, socket: LISTENER }).await.unwrap();
        assert_eq!(within(listening.replies.recv()).await, Some(RelayPacket::Ok { id: 2 }));
        within(listening.task).await.unwrap().unwrap();
        assert_eq!(hairpin.own_route(Proto::Tcp, local).unwrap().unwrap_err().code, ErrorCode::REFUSED);
        TcpListener::bind(("127.0.0.1", local.port())).await.expect("the port is free again");
    }

    #[tokio::test]
    async fn a_port_other_than_0_is_bound_exactly_or_refused_when_taken() {
        let wanted = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let bound = listening(local(), &wanted.to_string()).await;
        assert_eq!(port(&bound.answer), wanted.port());

        let holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = listening(local(), &holder.local_addr().unwrap().to_string()).await;
        assert_eq!(code(&taken.answer), (1, ErrorCode::ADDRESS_IN_USE));
        assert!(within(taken.task).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_port_the_policy_refuses_is_not_bound() {
        let refused = listening(local(), "127.0.0.1:80").await;
        assert_eq!(code(&refused.answer), (1, ErrorCode::REFUSED));
        assert!(within(refused.task).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn an_accepted_connection_is_announced_and_carries_bytes_both_ways() {
        let mut listening = listening(local(), "127.0.0.1:0").await;
        let port = port(&listening.answer);
        let mut peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let registration = within(listening.registered.recv()).await.unwrap();
        assert_eq!(registration.kind, SocketKind::Tcp);
        let socket = tokio::spawn((registration.run)(9));

        let stream = listening.client.next_stream().await;
        let (mut download, mut upload) = (stream.recv, stream.send.expect("a stream both ways"));
        let mut head = [0; 4];
        within(download.read_exact(&mut head)).await.unwrap();
        assert_eq!(u32::from_be_bytes(head), 9);
        let remote = SocketAddr::new(PUBLIC, peer.local_addr().unwrap().port());
        let announced =
            RelayPacket::Accepted { listener: LISTENER, socket: 9, local: SocketAddr::new(PUBLIC, port), remote };
        assert_eq!(within(listening.replies.recv()).await, Some(announced));

        peer.write_all(b"handshake").await.unwrap();
        let mut inbound = [0; 9];
        within(download.read_exact(&mut inbound)).await.unwrap();
        upload.write_all(b"reply").await.unwrap();
        let mut outbound = [0; 5];
        within(peer.read_exact(&mut outbound)).await.unwrap();
        assert_eq!((&inbound, &outbound), (b"handshake", b"reply"));

        registration.requests.send(ClientPacket::TcpClose { id: 5, socket: 9 }).await.unwrap();
        assert_eq!(within(listening.replies.recv()).await, Some(RelayPacket::Ok { id: 5 }));
        within(socket).await.unwrap().unwrap();
        let metrics = &listening.session.relay.metrics;
        let counted =
            [Counter::InboundAccepted, Counter::InboundAnnounced, Counter::InboundBytes].map(|of| metrics.get(of));
        assert_eq!(counted, [1, 1, 9]);
    }

    #[tokio::test]
    async fn a_connection_the_session_turns_away_is_told_with_accept_refused() {
        let mut listening = listening(local(), "127.0.0.1:0").await;
        let mut peer = TcpStream::connect(("127.0.0.1", port(&listening.answer))).await.unwrap();
        let RegisterSocket { run, refused, .. } = within(listening.registered.recv()).await.unwrap();
        refused(Refusal::new(ErrorCode::CAPACITY, "the session holds as many sockets as it allows"));
        drop(run);

        let remote = SocketAddr::new(PUBLIC, peer.local_addr().unwrap().port());
        let told = RelayPacket::AcceptRefused { listener: LISTENER, code: ErrorCode::CAPACITY, remote };
        assert_eq!(within(listening.replies.recv()).await, Some(told));
        assert_eq!(within(peer.read(&mut [0; 1])).await.unwrap(), 0, "the connection is closed");
        let metrics = &listening.session.relay.metrics;
        assert_eq!((metrics.get(Counter::InboundAccepted), metrics.get(Counter::InboundAnnounced)), (1, 0));
    }
}
