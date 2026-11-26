use std::net::{IpAddr, Ipv6Addr};

use webvpn_server::egress::{embedded_v4, is_public};

fn public(text: &str) -> bool {
    is_public(text.parse::<IpAddr>().unwrap())
}

#[test]
fn each_ipv4_block_is_refused_from_its_first_address_to_its_last() {
    let blocks = [
        ("0.255.255.255", "1.0.0.0"),
        ("10.0.0.0", "9.255.255.255"),
        ("10.255.255.255", "11.0.0.0"),
        ("100.64.0.0", "100.63.255.255"),
        ("100.127.255.255", "100.128.0.0"),
        ("127.0.0.1", "126.255.255.255"),
        ("127.255.255.255", "128.0.0.0"),
        ("169.254.169.254", "169.253.255.255"),
        ("169.254.255.255", "169.255.0.0"),
        ("172.16.0.0", "172.15.255.255"),
        ("172.31.255.255", "172.32.0.0"),
        ("192.0.0.9", "191.255.255.255"),
        ("192.0.0.255", "192.0.1.0"),
        ("192.0.2.0", "192.0.1.255"),
        ("192.0.2.255", "192.0.3.0"),
        ("192.88.99.1", "192.88.98.255"),
        ("192.168.0.0", "192.167.255.255"),
        ("192.168.255.255", "192.169.0.0"),
        ("198.18.0.0", "198.17.255.255"),
        ("198.19.255.255", "198.20.0.0"),
        ("198.51.100.0", "198.51.99.255"),
        ("198.51.100.255", "198.51.101.0"),
        ("203.0.113.0", "203.0.112.255"),
        ("203.0.113.255", "203.0.114.0"),
        ("224.0.0.0", "223.255.255.255"),
        ("255.255.255.255", "8.8.8.8"),
    ];
    for (refused, allowed) in blocks {
        assert!(!public(refused), "{refused} is not public");
        assert!(public(allowed), "{allowed} is public");
    }
}

#[test]
fn ipv6_is_public_only_inside_the_global_block_and_outside_its_reserved_parts() {
    for allowed in ["2606:4700:4700::1111", "2000::1", "2001:200::1", "2001:db9::1", "2a02:6ea0::1", "3ffe::1"] {
        assert!(public(allowed), "{allowed} is public");
    }
    let refused = [
        "::",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "ff02::1",
        "100::1",
        "64:ff9b:1::1",
        "2001::1",
        "2001:1ff:ffff::1",
        "2001:db8::1",
        "3fff::1",
        "3fff:fff:ffff::1",
        "5f00::1",
        "4000::1",
    ];
    for refused in refused {
        assert!(!public(refused), "{refused} is not public");
    }
}

#[test]
fn an_ipv6_spelling_of_an_ipv4_address_is_judged_as_that_address() {
    let spellings = |v4: &str| {
        let [a, b, c, d] = v4.parse::<std::net::Ipv4Addr>().unwrap().octets();
        let (high, low) = (u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]));
        [
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, high, low),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, high, low),
            Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, high, low),
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, high, low),
            Ipv6Addr::new(0x2002, high, low, 0, 0, 0, 0, 1),
        ]
    };
    for refused in ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1"] {
        for spelling in spellings(refused) {
            assert_eq!(embedded_v4(spelling), Some(refused.parse().unwrap()), "{spelling}");
            assert!(!is_public(spelling.into()), "{spelling} spells {refused}");
        }
    }
    for spelling in spellings("8.8.8.8") {
        assert!(is_public(spelling.into()), "{spelling} spells a public address");
    }
    assert_eq!(embedded_v4("2606:4700:4700::1111".parse().unwrap()), None);
}
