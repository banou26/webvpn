use std::net::SocketAddr;

use webvpn_proto::{
    features, mux, ClientPacket, DecodeError, ErrorCode, Hello, RelayPacket, TcpOption, UdpOption, UdpPacket,
    MAX_CLIENT_FRAME_BYTES, MAX_UDP_PAYLOAD_BYTES, VERSION,
};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/v0.txt"));

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap()).collect()
}

fn vectors(group: &str) -> Vec<(&'static str, Vec<u8>)> {
    VECTORS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap())
        })
        .filter(|(of, _, _)| *of == group)
        .map(|(_, name, bytes)| (name, unhex(bytes)))
        .collect()
}

fn address(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

const SITE: &str = "192.0.2.7:443";
const RESOLVER: &str = "192.0.2.7:53";
const RELAY_PORT: &str = "198.51.100.4:50000";
const LISTENER: &str = "203.0.113.9:8080";

fn client_packet(name: &str) -> ClientPacket {
    match name {
        "hello" => ClientPacket::Hello(Hello::new(0, "example")),
        "auth" => ClientPacket::Auth { id: 6, credential: vec![0xde, 0xad, 0xbe, 0xef] },
        "auth-clear" => ClientPacket::AuthClear { id: 6 },
        "tcp-connect" => ClientPacket::TcpConnect { id: 1, remote: address(SITE) },
        "tcp-connect-name" => ClientPacket::TcpConnectName { id: 9, port: 443, query: vec![1, 2] },
        "tcp-close" => ClientPacket::TcpClose { id: 11, socket: 5 },
        "tcp-reset" => ClientPacket::TcpReset { id: 12, socket: 5 },
        "tcp-set-option" => ClientPacket::TcpSetOption {
            id: 5,
            socket: 5,
            option: TcpOption::KeepAlive { enabled: true, initial_delay_seconds: 30 },
        },
        "tcp-listen" => ClientPacket::TcpListen { id: 4, local: address(LISTENER) },
        "tcp-unlisten" => ClientPacket::TcpUnlisten { id: 13, socket: 6 },
        "udp-bind" => ClientPacket::UdpBind { id: 3, local: address("[::]:0") },
        "udp-close" => ClientPacket::UdpClose { id: 14, socket: 9 },
        "udp-connect" => ClientPacket::UdpConnect { id: 15, socket: 9, remote: address(RESOLVER) },
        "udp-disconnect" => ClientPacket::UdpDisconnect { id: 16, socket: 9 },
        "udp-set-option" => ClientPacket::UdpSetOption {
            id: 10,
            socket: 9,
            option: UdpOption::AddMembershipV4 { group: [239, 1, 2, 3].into(), interface: [0, 0, 0, 0].into() },
        },
        "dns-query" => ClientPacket::DnsQuery { id: 8, query: vec![1, 2, 3] },
        other => panic!("no client packet is named {other}"),
    }
}

fn relay_packet(name: &str) -> RelayPacket {
    match name {
        "hello" => RelayPacket::Hello(Hello::new(features::LISTEN | features::DNS, "webvpnd")),
        "ok" => RelayPacket::Ok { id: 7 },
        "error" => RelayPacket::Error {
            id: 2,
            code: ErrorCode::CONNECTION_REFUSED,
            message: "connection refused".into(),
        },
        "socket-connected" => RelayPacket::Socket {
            id: 1,
            socket: 5,
            local: address(RELAY_PORT),
            remote: Some(address(SITE)),
        },
        "socket-bound" => RelayPacket::Socket { id: 4, socket: 6, local: address(LISTENER), remote: None },
        "dns-answer" => RelayPacket::DnsAnswer { id: 8, answer: vec![9, 8] },
        "accepted" => RelayPacket::Accepted {
            listener: 6,
            socket: 7,
            local: address(LISTENER),
            remote: address(RELAY_PORT),
        },
        "accept-refused" => RelayPacket::AcceptRefused {
            listener: 6,
            code: ErrorCode::CAPACITY,
            remote: address(RELAY_PORT),
        },
        "closed" => RelayPacket::Closed { socket: 9, code: ErrorCode::CAPACITY },
        "draining" => RelayPacket::Draining,
        other => panic!("no relay packet is named {other}"),
    }
}

#[test]
fn client_frames_match_the_vectors_both_ways() {
    let vectors = vectors("client");
    assert_eq!(vectors.len(), 16);
    for (name, bytes) in vectors {
        let packet = client_packet(name);
        let mut written = Vec::new();
        packet.encode(&mut written);
        assert_eq!(hex(&written), hex(&bytes), "{name} written");
        assert_eq!(ClientPacket::decode(&bytes), Ok(Some((packet, bytes.len()))), "{name} read");
    }
}

#[test]
fn relay_frames_match_the_vectors_both_ways() {
    let vectors = vectors("relay");
    assert_eq!(vectors.len(), 10);
    for (name, bytes) in vectors {
        let packet = relay_packet(name);
        let mut written = Vec::new();
        packet.encode(&mut written);
        assert_eq!(hex(&written), hex(&bytes), "{name} written");
        assert_eq!(RelayPacket::decode(&bytes), Ok(Some((packet, bytes.len()))), "{name} read");
    }
}

#[test]
fn data_packets_match_the_vectors_both_ways() {
    let vectors = vectors("data");
    assert_eq!(vectors.len(), 3);
    for (name, bytes) in vectors {
        if name == "mux-open-tcp" {
            assert_eq!(mux::encode(mux::kind::OPEN, 3, &[mux::stream_type::TCP]), bytes);
            assert_eq!(mux::decode(&bytes), Some((mux::kind::OPEN, 3, &[mux::stream_type::TCP][..])));
            continue;
        }
        let packet = UdpPacket {
            socket: 9,
            remote: match name {
                "udp-packet" => Some(address(RESOLVER)),
                "udp-packet-bare" => None,
                other => panic!("no data packet is named {other}"),
            },
            data: b"hi",
        };
        let mut written = Vec::new();
        packet.encode(&mut written);
        assert_eq!(hex(&written), hex(&bytes), "{name} written");
        assert_eq!(UdpPacket::decode(&bytes), Ok(packet), "{name} read");

        let mut framed = Vec::new();
        packet.encode_framed(&mut framed);
        assert_eq!(framed[..4], (bytes.len() as u32).to_be_bytes());
        assert_eq!(framed[4..], bytes[..]);
    }
}

#[test]
fn a_frame_is_read_only_once_it_is_whole_and_leaves_the_next_one() {
    for (name, bytes) in vectors("relay") {
        for cut in 0..bytes.len() {
            assert_eq!(RelayPacket::decode(&bytes[..cut]), Ok(None), "{name} cut at {cut}");
        }
        let mut two = bytes.clone();
        two.extend_from_slice(&[0x20, 0, 0, 0, 0]);
        let (_, taken) = RelayPacket::decode(&two).unwrap().unwrap();
        assert_eq!(taken, bytes.len(), "{name}");
        assert_eq!(RelayPacket::decode(&two[taken..]), Ok(Some((RelayPacket::Draining, 5))));
    }
}

#[test]
fn a_frame_over_the_limit_is_refused_from_its_header_alone() {
    let mut header = vec![0x01];
    header.extend_from_slice(&(MAX_CLIENT_FRAME_BYTES as u32 + 1).to_be_bytes());
    assert_eq!(ClientPacket::decode(&header), Err(DecodeError::TooLong));

    header[1..].copy_from_slice(&(MAX_CLIENT_FRAME_BYTES as u32).to_be_bytes());
    assert_eq!(ClientPacket::decode(&header), Ok(None));
}

#[test]
fn a_request_of_an_unknown_type_keeps_its_id_for_the_refusal() {
    let frame = [0x7f, 0, 0, 0, 6, 0, 0, 0, 42, 1, 2];
    assert_eq!(ClientPacket::decode(&frame), Ok(Some((ClientPacket::Unknown { kind: 0x7f, id: Some(42) }, 11))));

    let no_id = [0x7f, 0, 0, 0, 2, 1, 2];
    assert_eq!(ClientPacket::decode(&no_id), Ok(Some((ClientPacket::Unknown { kind: 0x7f, id: None }, 7))));
}

#[test]
fn a_relay_frame_of_an_unknown_type_is_skipped_by_its_length() {
    let mut bytes = vec![0x7f, 0, 0, 0, 3, 1, 2, 3];
    RelayPacket::Ok { id: 7 }.encode(&mut bytes);
    assert_eq!(RelayPacket::decode(&bytes), Ok(Some((RelayPacket::Unknown { kind: 0x7f }, 8))));
    assert_eq!(RelayPacket::decode(&bytes[8..]), Ok(Some((RelayPacket::Ok { id: 7 }, 9))));
}

#[test]
fn bytes_after_the_known_fields_are_ignored_and_missing_ones_are_not() {
    let longer = [0x01, 0, 0, 0, 6, 0, 0, 0, 7, 0xaa, 0xbb];
    assert_eq!(RelayPacket::decode(&longer), Ok(Some((RelayPacket::Ok { id: 7 }, 11))));

    let shorter = [0x01, 0, 0, 0, 3, 0, 0, 0];
    assert_eq!(RelayPacket::decode(&shorter), Err(DecodeError::Truncated));
}

#[test]
fn an_option_of_an_unknown_tag_is_kept_for_the_refusal() {
    let frame = [0x14, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 5, 0x63];
    let expected = ClientPacket::TcpSetOption { id: 1, socket: 5, option: TcpOption::Unknown(0x63) };
    assert_eq!(ClientPacket::decode(&frame), Ok(Some((expected, 14))));
}

#[test]
fn a_hello_suits_only_the_same_minor_while_the_major_is_0() {
    assert!(Hello::new(0, "").compatible());
    let mut other = Hello::new(0, "");
    other.minor = VERSION.1 + 1;
    assert!(!other.compatible());
    other = Hello::new(0, "");
    other.major = 1;
    assert!(!other.compatible());

    let not_webvpn = [0x00, 0, 0, 0, 10, b'H', b'T', b'T', b'P', 0, 1, 0, 0, 0, 0];
    assert!(matches!(RelayPacket::decode(&not_webvpn), Err(DecodeError::Invalid(_))));
}

#[test]
fn an_agent_is_cut_at_255_bytes_on_a_character() {
    let mut written = Vec::new();
    ClientPacket::Hello(Hello::new(0, "é".repeat(200))).encode(&mut written);
    let Ok(Some((ClientPacket::Hello(hello), _))) = ClientPacket::decode(&written) else {
        panic!("a hello");
    };
    assert_eq!(hello.agent, "é".repeat(127));
}

#[test]
fn a_udp_payload_over_the_limit_is_refused_from_its_length() {
    let mut packet = vec![0, 0, 0, 9, 2];
    packet.extend_from_slice(&(MAX_UDP_PAYLOAD_BYTES as u32 + 1).to_be_bytes());
    assert_eq!(UdpPacket::decode(&packet), Err(DecodeError::TooLong));

    let cut_short = [0, 0, 0, 9, 2, 0, 0, 0, 4, b'h', b'i'];
    assert_eq!(UdpPacket::decode(&cut_short), Err(DecodeError::Truncated));
}
