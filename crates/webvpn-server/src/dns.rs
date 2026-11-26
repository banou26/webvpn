//! Name lookups: a client's whole DNS message goes to one DNS over HTTPS resolver and the resolver's whole message
//! comes back. The relay reads no name, keeps nothing and logs nothing of a lookup.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tokio::sync::Semaphore;
use webvpn_proto::ErrorCode;

use crate::metrics::{Counter, Metrics};
use crate::policy::Refusal;

/// Lookups one session may have waiting or in flight. One more is answered `CAPACITY`.
pub(crate) const MAX_LOOKUPS_PER_SESSION: usize = 256;

// each one holds a connection of its own to the resolver, since reqwest is built here without HTTP/2
const MAX_LOOKUPS: usize = 64;

// so the names of one visitor that never answer wait on each other and leave the other slots to everyone else
const MAX_VISITOR_LOOKUPS: usize = 16;

// counted from the call, the wait for a slot included, so a lookup that cannot finish is answered, not left waiting:
// the protocol's limit on the relay's answer to a lookup (spec/protocol.md, Limits)
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest query the protocol carries (spec/protocol.md, Limits). One question fits in about 270 bytes.
pub(crate) const MAX_QUERY_BYTES: usize = 512;

// the longest DNS message, since its length over TCP is two bytes
const MAX_ANSWER_BYTES: usize = u16::MAX as usize;

const DNS_MESSAGE: &str = "application/dns-message";

/// The relay's resolver, and the share of it each visitor gets.
pub(crate) struct Dns {
    client: reqwest::Client,
    upstream: String,
    slots: Semaphore,
    visitors: Mutex<HashMap<IpAddr, Weak<Semaphore>>>,
}

impl Dns {
    /// A resolver that posts every lookup to `upstream`, a DNS over HTTPS endpoint (RFC 8484).
    pub fn new(upstream: String) -> Self {
        Self {
            // reqwest takes a proxy from the environment unless told not to
            client: reqwest::Client::builder().no_proxy().build().expect("an HTTP client"),
            upstream,
            slots: Semaphore::new(MAX_LOOKUPS),
            visitors: Mutex::default(),
        }
    }

    /// The lookups one visitor may have at the resolver at once, shared by every session from its address. It is
    /// kept only while one of those sessions holds it.
    pub fn visitor_slots(&self, ip: IpAddr) -> Arc<Semaphore> {
        let mut visitors = self.visitors.lock().unwrap();
        visitors.retain(|_, slots| slots.strong_count() > 0);
        let visitor = visitor(ip);
        if let Some(slots) = visitors.get(&visitor).and_then(Weak::upgrade) {
            return slots;
        }
        let slots = Arc::new(Semaphore::new(MAX_VISITOR_LOOKUPS));
        visitors.insert(visitor, Arc::downgrade(&slots));
        slots
    }

    /// The resolver's whole answer to `query`, or `None` when it gave none in time. The caller refuses a query over
    /// [`MAX_QUERY_BYTES`] first, with [`check_query`]. No reason is kept, since an error could carry what was asked.
    pub async fn lookup(&self, visitor_slots: &Semaphore, query: Vec<u8>) -> Option<Vec<u8>> {
        let answer = async {
            let _visitor_slot = visitor_slots.acquire().await.ok()?;
            let _slot = self.slots.acquire().await.ok()?;
            let response = self
                .client
                .post(&self.upstream)
                .header(CONTENT_TYPE, DNS_MESSAGE)
                .header(ACCEPT, DNS_MESSAGE)
                .body(query)
                .send()
                .await
                .ok()
                .filter(|response| response.status().is_success())?;
            let answer = response.bytes().await.ok()?;
            (answer.len() <= MAX_ANSWER_BYTES).then(|| answer.into())
        };
        tokio::time::timeout(LOOKUP_TIMEOUT, answer).await.ok().flatten()
    }
}

/// `REFUSED`, counted as [`Counter::DnsRefused`], for a query longer than [`MAX_QUERY_BYTES`], which then never
/// reaches the resolver. The refusal names nothing of the query.
pub(crate) fn check_query(query: &[u8], metrics: &Metrics) -> Result<(), Refusal> {
    if query.len() <= MAX_QUERY_BYTES {
        return Ok(());
    }
    metrics.count(Counter::DnsRefused);
    Err(Refusal::new(ErrorCode::REFUSED, "a DNS query holds at most 512 bytes"))
}

// IPv4 as it is, IPv6 as its /64: a client may take any address in its /64, so all of them are one visitor
fn visitor(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

// a name is walked by its length bytes and never read, and a pointer always ends one
fn past_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        match *message.get(at)? {
            0 => return Some(at + 1),
            0xc0.. => return Some(at + 2),
            length => at += 1 + length as usize,
        }
    }
}

/// The first A record of a DNS answer, past its questions and any CNAME, or `None` when it has none or ends early.
pub(crate) fn first_a_record(message: &[u8]) -> Option<Ipv4Addr> {
    let u16_at = |at: usize| Some(u16::from_be_bytes(message.get(at..at + 2)?.try_into().ok()?));
    let (questions, answers) = (u16_at(4)?, u16_at(6)?);
    let mut at = 12;
    for _ in 0..questions {
        at = past_name(message, at)? + 4;
    }
    for _ in 0..answers {
        at = past_name(message, at)?;
        let (kind, length) = (u16_at(at)?, u16_at(at + 8)? as usize);
        let data = message.get(at + 10..at + 10 + length)?;
        match <[u8; 4]>::try_from(data) {
            Ok(octets) if kind == 1 => return Some(Ipv4Addr::from(octets)),
            _ => at += 10 + length,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn query(name: &str) -> Vec<u8> {
        let mut message = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message
    }

    fn asked_name(query: &[u8]) -> String {
        let mut labels = Vec::new();
        let mut at = 12;
        while query[at] != 0 {
            let end = at + 1 + query[at] as usize;
            labels.push(String::from_utf8_lossy(&query[at + 1..end]).into_owned());
            at = end;
        }
        labels.join(".")
    }

    fn with_a_record(query: &[u8]) -> Vec<u8> {
        let mut message = query.to_vec();
        message[2..4].copy_from_slice(&[0x81, 0x80]);
        message[7] = 1;
        message.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        message
    }

    /// A relay's resolver posting to a local one, which answers by the name asked, and the count of lookups that
    /// reached the local one.
    async fn upstream() -> (Dns, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns = Dns::new(format!("http://{}/dns-query", listener.local_addr().unwrap()));
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(answer(stream, counter.clone()));
            }
        });
        (dns, seen)
    }

    async fn answer(mut stream: TcpStream, seen: Arc<AtomicUsize>) -> Option<()> {
        let mut request = Vec::new();
        let head_end = loop {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = String::from_utf8(request[..head_end].to_vec()).ok()?.to_ascii_lowercase();
        let length: usize = head.split("\r\n").find_map(|line| line.strip_prefix("content-length: "))?.parse().ok()?;
        let mut query = request.split_off(head_end);
        let mut rest = vec![0; length - query.len()];
        stream.read_exact(&mut rest).await.ok()?;
        query.extend(rest);
        seen.fetch_add(1, Ordering::SeqCst);

        let rfc_8484 = head.starts_with("post /dns-query ")
            && head.contains("\r\ncontent-type: application/dns-message\r\n")
            && head.contains("\r\naccept: application/dns-message\r\n");
        let (status, body) = match asked_name(&query).as_str() {
            _ if !rfc_8484 => ("400 Bad Request", Vec::new()),
            "public.example" => ("200 OK", with_a_record(&query)),
            "missing.example" => {
                let mut message = query.clone();
                message[2..4].copy_from_slice(&[0x81, 0x83]);
                ("200 OK", message)
            }
            "longest.example" => ("200 OK", vec![0; MAX_ANSWER_BYTES]),
            "oversized.example" => ("200 OK", vec![0; MAX_ANSWER_BYTES + 1]),
            "hangs.example" => std::future::pending().await,
            _ => ("502 Bad Gateway", Vec::new()),
        };
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {DNS_MESSAGE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.ok()?;
        stream.write_all(&body).await.ok()
    }

    fn hang(dns: &Arc<Dns>, visitor: IpAddr, lookups: usize) {
        let slots = dns.visitor_slots(visitor);
        for _ in 0..lookups {
            let (dns, slots) = (dns.clone(), slots.clone());
            tokio::spawn(async move { dns.lookup(&slots, query("hangs.example")).await });
        }
    }

    async fn until_seen(seen: &AtomicUsize, lookups: usize) {
        for _ in 0..400 {
            if seen.load(Ordering::SeqCst) >= lookups {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the resolver saw {} lookups, not {lookups}", seen.load(Ordering::SeqCst));
    }

    #[test]
    fn a_visitor_is_every_session_from_one_address_kept_only_while_one_holds_it() {
        let dns = Dns::new(String::new());
        let first = dns.visitor_slots(IpAddr::from([198, 51, 100, 60]));
        assert!(Arc::ptr_eq(&first, &dns.visitor_slots(IpAddr::from([198, 51, 100, 60]))));
        assert!(Arc::ptr_eq(&first, &dns.visitor_slots("::ffff:198.51.100.60".parse().unwrap())));
        assert!(!Arc::ptr_eq(&first, &dns.visitor_slots(IpAddr::from([198, 51, 100, 61]))));
        let v6 = dns.visitor_slots("2001:db8:1:2::7".parse().unwrap());
        assert!(Arc::ptr_eq(&v6, &dns.visitor_slots("2001:db8:1:2:ffff::9".parse().unwrap())));
        assert!(!Arc::ptr_eq(&v6, &dns.visitor_slots("2001:db8:1:3::7".parse().unwrap())));

        drop((first, v6));
        let _next = dns.visitor_slots(IpAddr::from([198, 51, 100, 62]));
        let visitors = dns.visitors.lock().unwrap();
        assert_eq!(visitors.keys().collect::<Vec<_>>(), [&IpAddr::from([198, 51, 100, 62])]);
    }

    #[tokio::test]
    async fn the_resolver_s_answer_comes_back_whole() {
        let (dns, _) = upstream().await;
        let answer = dns.lookup(&Semaphore::new(1), query("public.example")).await;
        assert_eq!(answer, Some(with_a_record(&query("public.example"))));
    }

    #[tokio::test]
    async fn a_name_with_no_records_is_an_answer_not_a_failure() {
        let (dns, _) = upstream().await;
        let answer = dns.lookup(&Semaphore::new(1), query("missing.example")).await.expect("an answer");
        assert_eq!(answer[3] & 0x0f, 3, "the NXDOMAIN code reaches the client");
    }

    #[tokio::test]
    async fn a_resolver_error_is_no_answer() {
        let (dns, seen) = upstream().await;
        assert_eq!(dns.lookup(&Semaphore::new(1), query("broken.example")).await, None);
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_ends_at_the_limit() {
        let (dns, _) = upstream().await;
        let started = tokio::time::Instant::now();
        assert_eq!(dns.lookup(&Semaphore::new(1), query("hangs.example")).await, None);
        assert_eq!(started.elapsed(), LOOKUP_TIMEOUT);
    }

    #[tokio::test]
    async fn an_answer_longer_than_a_dns_message_is_no_answer() {
        let (dns, _) = upstream().await;
        let slots = Semaphore::new(1);
        assert_eq!(dns.lookup(&slots, query("longest.example")).await.map(|a| a.len()), Some(MAX_ANSWER_BYTES));
        assert_eq!(dns.lookup(&slots, query("oversized.example")).await, None);
    }

    #[test]
    fn a_query_over_512_bytes_is_refused_and_counted() {
        let metrics = Metrics::default();
        assert_eq!(check_query(&[0; MAX_QUERY_BYTES], &metrics), Ok(()));
        let refusal = check_query(&[0; MAX_QUERY_BYTES + 1], &metrics).unwrap_err();
        assert_eq!((refusal.code, metrics.get(Counter::DnsRefused)), (ErrorCode::REFUSED, 1));
    }

    #[tokio::test]
    async fn one_visitor_s_slow_names_leave_the_resolver_to_every_other_visitor() {
        let (dns, seen) = upstream().await;
        let dns = Arc::new(dns);
        hang(&dns, IpAddr::from([198, 51, 100, 1]), 2 * MAX_VISITOR_LOOKUPS);
        until_seen(&seen, MAX_VISITOR_LOOKUPS).await;
        assert_eq!(dns.slots.available_permits(), MAX_LOOKUPS - MAX_VISITOR_LOOKUPS);

        let other = dns.visitor_slots(IpAddr::from([198, 51, 100, 2]));
        let answer = tokio::time::timeout(Duration::from_secs(1), dns.lookup(&other, query("public.example")))
            .await
            .expect("no wait behind the slow visitor");
        assert!(answer.is_some());
        assert_eq!(seen.load(Ordering::SeqCst), MAX_VISITOR_LOOKUPS + 1);
    }

    #[tokio::test]
    async fn the_relay_holds_at_most_its_lookups_at_the_resolver() {
        let (dns, seen) = upstream().await;
        let dns = Arc::new(dns);
        for visitor in 0..=(MAX_LOOKUPS / MAX_VISITOR_LOOKUPS) as u8 {
            hang(&dns, IpAddr::from([198, 51, 100, visitor]), MAX_VISITOR_LOOKUPS);
        }
        until_seen(&seen, MAX_LOOKUPS).await;

        let other = dns.visitor_slots(IpAddr::from([203, 0, 113, 1]));
        let waited =
            tokio::time::timeout(Duration::from_millis(200), dns.lookup(&other, query("public.example"))).await;
        assert!(waited.is_err(), "a lookup past the relay's bound waits");
        assert_eq!(seen.load(Ordering::SeqCst), MAX_LOOKUPS);
    }

    /// Every event and span field, as text.
    struct Captured(Arc<Mutex<String>>);

    struct Fields<'a>(&'a mut String);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {field}={value:?}"));
        }
    }

    impl tracing::Subscriber for Captured {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            span.record(&mut Fields(&mut self.0.lock().unwrap()));
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            values.record(&mut Fields(&mut self.0.lock().unwrap()));
        }

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut text = self.0.lock().unwrap();
            text.push_str(event.metadata().target());
            event.record(&mut Fields(&mut text));
            text.push('\n');
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    // tokio::test's single thread runs every task, so this thread's subscriber sees them all
    #[tokio::test]
    async fn no_log_line_carries_a_name_at_any_level() {
        let (dns, _) = upstream().await;
        let log = Arc::new(Mutex::new(String::new()));
        let _subscriber = tracing::subscriber::set_default(Captured(log.clone()));
        // with one dispatcher alive, tracing settles a callsite for good by the first thread to reach it, which may
        // have none
        let _second = tracing::Dispatch::new(Captured(Arc::default()));

        let slots = Semaphore::new(1);
        assert!(dns.lookup(&slots, query("public.example")).await.is_some());
        assert_eq!(dns.lookup(&slots, query("secretsite.example")).await, None);

        // control: this subscriber does capture, and the HTTP client under the lookup wrote through it
        tracing::info!("control secretsite");
        let text = log.lock().unwrap().clone();
        assert_eq!(text.matches("secretsite").count(), 1, "{text}");
        assert!(text.contains("hyper"), "{text}");
        assert!(!text.contains("public"), "{text}");
    }

    const QUESTION: &[u8] = &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];

    fn answer_with(answers: u8, records: &[&[u8]]) -> Vec<u8> {
        let mut message = vec![0, 1, 0x81, 0x80, 0, 1, 0, answers, 0, 0, 0, 0];
        message.extend_from_slice(QUESTION);
        for record in records {
            message.extend_from_slice(record);
        }
        message
    }

    #[test]
    fn the_first_a_record_is_read_past_the_question_and_a_cname() {
        let cname = [0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'x', 0xc0, 12];
        let first = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7];
        let second = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 8];
        let answer = answer_with(3, &[&cname, &first, &second]);
        assert_eq!(first_a_record(&answer), Some(Ipv4Addr::new(198, 51, 100, 7)));

        // a name spelled out in the record, where a server may compress it or not
        let spelled = [&QUESTION[..13], &[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]].concat();
        assert_eq!(first_a_record(&answer_with(1, &[&spelled])), Some(Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn an_answer_with_no_a_record_has_no_address() {
        let aaaa = [&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16][..], &[0x20; 16]].concat();
        assert_eq!(first_a_record(&answer_with(1, &[&aaaa])), None);
        assert_eq!(first_a_record(&answer_with(0, &[])), None);
    }

    #[test]
    fn an_answer_that_ends_early_has_no_address() {
        let record = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7];
        let answer = answer_with(1, &[&record]);
        assert!(first_a_record(&answer).is_some());
        for length in 0..answer.len() {
            assert_eq!(first_a_record(&answer[..length]), None, "cut at {length}");
        }
    }
}
