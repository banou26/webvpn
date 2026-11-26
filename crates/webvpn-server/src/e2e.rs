//! Whole sessions over the in-memory transport: the session, the socket modules and the default policy together.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};
use webvpn_proto::{ClientPacket, ErrorCode, Hello, RelayPacket, TcpOption, UdpPacket};

use crate::policy::{Auth, Basic, Policy};
use crate::relay::{Config, Shared};
use crate::session::{run, Setup, UdpCarrier};
use crate::testing::{self, Client, Control, Opened, Stream, WAIT};

struct Harness {
    client: Client,
    control: Control,
}

/// A session past its hello exchange, on a relay whose policy lets it reach loopback.
async fn open() -> Harness {
    let peer = IpAddr::from([192, 0, 2, 1]);
    let (transport, mut client) = testing::session(peer);
    let mut policy = Basic::default();
    policy.allow_private_targets = true;
    let setup = Setup {
        permit: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
        deadline: Instant::now() + WAIT,
    };
    tokio::spawn(run(
        Arc::new(transport),
        policy.admit(peer).unwrap(),
        Shared::new(Config::default()),
        Auth::None,
        UdpCarrier::Bidi,
        setup,
    ));
    let mut control = client.control().await;
    assert!(matches!(control.next().await, Some(RelayPacket::Hello(_))));
    control.send(ClientPacket::Hello(Hello::new(0, "test"))).await;
    Harness { client, control }
}

impl Harness {
    async fn reply(&mut self) -> RelayPacket {
        timeout(WAIT, self.control.next()).await.expect("a frame in time").expect("an open control stream")
    }

    /// The next stream the relay opened, which must be `socket`'s and of the kind `opened`.
    async fn stream(&mut self, opened: Opened, socket: u32) -> Stream {
        let mut stream = timeout(WAIT, self.client.next_stream()).await.expect("a stream in time");
        assert_eq!(stream.opened, opened);
        let mut id = [0; 4];
        timeout(WAIT, stream.recv.read_exact(&mut id)).await.expect("the socket id in time").unwrap();
        assert_eq!(u32::from_be_bytes(id), socket);
        stream
    }
}

#[tokio::test]
async fn a_tcp_socket_carries_bytes_both_ways_through_a_whole_session() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut peer, _) = echo.accept().await.unwrap();
        let mut bytes = [0; 4];
        peer.read_exact(&mut bytes).await.unwrap();
        peer.write_all(&bytes).await.unwrap();
        // held open until the client closes
        let _ = peer.read(&mut bytes).await;
    });

    let mut session = open().await;
    session.control.send(ClientPacket::TcpConnect { id: 1, remote }).await;
    let RelayPacket::Socket { id: 1, socket, remote: Some(peer), .. } = session.reply().await else {
        panic!("the connect was not answered with its socket");
    };
    assert_eq!(peer, remote);

    let mut stream = session.stream(Opened::Bi, socket).await;
    stream.send.as_mut().unwrap().write_all(b"ping").await.unwrap();
    let mut echoed = [0; 4];
    timeout(WAIT, stream.recv.read_exact(&mut echoed)).await.expect("the echo in time").unwrap();
    assert_eq!(&echoed, b"ping");

    session.control.send(ClientPacket::TcpClose { id: 2, socket }).await;
    assert_eq!(session.reply().await, RelayPacket::Ok { id: 2 });
}

#[tokio::test]
async fn a_udp_socket_carries_packets_both_ways_through_a_whole_session() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut bytes = [0; 16];
        let (length, from) = echo.recv_from(&mut bytes).await.unwrap();
        echo.send_to(&bytes[..length], from).await.unwrap();
    });

    let mut session = open().await;
    session.control.send(ClientPacket::UdpBind { id: 1, local: "127.0.0.1:0".parse().unwrap() }).await;
    let RelayPacket::Socket { id: 1, socket, local, remote: None } = session.reply().await else {
        panic!("the bind was not answered with its socket");
    };
    assert_ne!(local.port(), 0);

    let mut stream = session.stream(Opened::UdpBi, socket).await;
    let send = stream.send.as_mut().unwrap();
    let mut framed = socket.to_be_bytes().to_vec();
    UdpPacket { socket, remote: Some(remote), data: b"ping" }.encode_framed(&mut framed);
    send.write_all(&framed).await.unwrap();

    let mut length = [0; 4];
    timeout(WAIT, stream.recv.read_exact(&mut length)).await.expect("the echo in time").unwrap();
    let mut packet = vec![0; u32::from_be_bytes(length) as usize];
    timeout(WAIT, stream.recv.read_exact(&mut packet)).await.expect("the echo in time").unwrap();
    assert_eq!(UdpPacket::decode(&packet), Ok(UdpPacket { socket, remote: Some(remote), data: b"ping" }));

    session.control.send(ClientPacket::UdpClose { id: 2, socket }).await;
    assert_eq!(session.reply().await, RelayPacket::Ok { id: 2 });
}

#[tokio::test]
async fn a_listener_hands_its_connections_to_the_session_and_takes_only_its_own_requests() {
    let mut session = open().await;
    session.control.send(ClientPacket::TcpListen { id: 1, local: "127.0.0.1:0".parse().unwrap() }).await;
    let RelayPacket::Socket { id: 1, socket: listener, local, remote: None } = session.reply().await else {
        panic!("the listen was not answered with its socket");
    };

    let mut peer = TcpStream::connect(local).await.unwrap();
    let RelayPacket::Accepted { listener: from, socket, remote, .. } = session.reply().await else {
        panic!("the connection was not announced");
    };
    assert_eq!((from, remote), (listener, peer.local_addr().unwrap()));
    assert!(socket > listener);

    let mut stream = session.stream(Opened::Bi, socket).await;
    peer.write_all(b"knock").await.unwrap();
    let mut heard = [0; 5];
    timeout(WAIT, stream.recv.read_exact(&mut heard)).await.expect("the bytes in time").unwrap();
    assert_eq!(&heard, b"knock");

    // the listener's id names no UDP socket and no TCP connection, so the listener lives on
    let other_kinds = [
        ClientPacket::UdpClose { id: 5, socket: listener },
        ClientPacket::TcpClose { id: 5, socket: listener },
        ClientPacket::TcpSetOption { id: 5, socket: listener, option: TcpOption::NoDelay(true) },
    ];
    for request in other_kinds {
        session.control.send(request).await;
        let RelayPacket::Error { id: 5, code, .. } = session.reply().await else {
            panic!("a request for another kind of socket was not refused");
        };
        assert_eq!(code, ErrorCode::UNKNOWN_SOCKET);
    }
    drop(TcpStream::connect(local).await.unwrap());
    assert!(matches!(session.reply().await, RelayPacket::Accepted { .. }));

    session.control.send(ClientPacket::TcpUnlisten { id: 7, socket: listener }).await;
    assert_eq!(session.reply().await, RelayPacket::Ok { id: 7 });
}
