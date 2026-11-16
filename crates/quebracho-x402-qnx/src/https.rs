//! A blocking HTTPS client for the core's [`Https`] port: `rustls` with the pure-Rust `rustls-rustcrypto`
//! provider (decision of Leo, 2026-11-16: "siempre vamos por rust puro donde se pueda").
//!
//! What it guarantees, because the core relies on it:
//! - **https only**, the server certificate verified against the shipped Mozilla roots (`webpki-roots`,
//!   compiled in: nothing read from the file system), or against roots the caller passes;
//! - **no redirects**: a 3xx comes back as a 3xx, so a signed payment reaches only the host it was for;
//! - **bounded**: connect, read and write time out, and an answer larger than [`MAX_RESPONSE`] is refused
//!   (threat T12);
//! - no header injection: a name or value with CR or LF is refused before anything is sent.
//!
//! Certificate validity uses the system clock: a device without trusted time cannot check certificates
//! either, which is why the seller refuses payments then (threat T6).
//!
//! One HTTP/1.1 request per connection (`Connection: close`), body by `Content-Length` or chunked.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use quebracho_x402::ports::{Https, HttpsRequest, HttpsResponse, HttpsUnavailable};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// The largest answer read by default, headers included.
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;

pub struct HttpsClient {
    config: Arc<ClientConfig>,
    timeout: Duration,
    deadline: Duration,
    max_response: usize,
}

impl HttpsClient {
    /// Trusts the Mozilla roots shipped in the binary.
    pub fn new() -> Self {
        Self::with_roots(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    /// Trusts only `roots` (a private CA: a test, or a gateway's own certificate).
    pub fn with_roots(roots: RootCertStore) -> Self {
        let config = ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()
            .expect("the pure-Rust provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            config: Arc::new(config),
            timeout: Duration::from_secs(30),
            deadline: Duration::from_secs(120),
            max_response: MAX_RESPONSE,
        }
    }

    /// The largest answer accepted ([`MAX_RESPONSE`] by default). A list sync needs more: OFAC's SDN.CSV is
    /// several megabytes (the PHP library allows 64 MiB).
    pub fn max_response(mut self, bytes: usize) -> Self {
        self.max_response = bytes;
        self
    }

    /// The most a whole answer may take, however it trickles in (120 s by default). The timeout below
    /// bounds each read; this bounds them all.
    pub fn deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Connect, read and write timeout (30 s by default). Keep it below what the caller can wait.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn exchange(&self, request: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable> {
        let url = Url::parse(&request.url).ok_or(HttpsUnavailable)?;
        let head = head(request, &url).ok_or(HttpsUnavailable)?;
        let address = (url.host.as_str(), url.port)
            .to_socket_addrs()
            .map_err(|_| HttpsUnavailable)?
            .next()
            .ok_or(HttpsUnavailable)?;
        let tcp =
            TcpStream::connect_timeout(&address, self.timeout).map_err(|_| HttpsUnavailable)?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|_| HttpsUnavailable)?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(|_| HttpsUnavailable)?;
        let name = ServerName::try_from(url.host.clone()).map_err(|_| HttpsUnavailable)?;
        let tls = ClientConnection::new(self.config.clone(), name).map_err(|_| HttpsUnavailable)?;
        let mut stream = StreamOwned::new(tls, tcp);
        stream.write_all(&head).map_err(|_| HttpsUnavailable)?;
        stream
            .write_all(&request.body)
            .map_err(|_| HttpsUnavailable)?;
        stream.flush().map_err(|_| HttpsUnavailable)?;

        let started = std::time::Instant::now();
        let mut raw = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        // Whether the head has fully arrived: searched only in the bytes that arrived since.
        let mut head_seen = false;
        // Ok(0) from rustls means the peer closed TLS properly (close_notify); an error means the connection
        // was cut, which an attacker on the path can do to truncate an answer.
        let mut clean_close = false;
        loop {
            if head_seen
                && complete(&raw)
                && let Some(done) = parse(&raw)
            {
                return done;
            }
            if started.elapsed() > self.deadline {
                return Err(HttpsUnavailable);
            }
            match stream.read(&mut chunk) {
                Ok(0) => {
                    clean_close = true;
                    break;
                }
                Ok(n) => {
                    let from = raw.len().saturating_sub(3);
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > self.max_response {
                        return Err(HttpsUnavailable);
                    }
                    head_seen = head_seen || raw[from..].windows(4).any(|w| w == b"\r\n\r\n");
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // A peer that closes without close_notify: only a complete message counts.
                Err(_) => break,
            }
        }
        if !clean_close {
            // Only a message whose length it declared, and that fully arrived, survives a cut.
            return parse(&raw).unwrap_or(Err(HttpsUnavailable));
        }
        match parse_at_eof(&raw) {
            Some(done) => done,
            None => Err(HttpsUnavailable),
        }
    }
}

impl Default for HttpsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Https for HttpsClient {
    fn send(&self, request: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable> {
        self.exchange(request)
    }
}

struct Url {
    host: String,
    port: u16,
    target: String,
}

impl Url {
    /// `https://host[:port][/path][?query]`; anything else (another scheme, user info, an empty host) is
    /// refused.
    fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("https://")?;
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') || target.contains('#') {
            return None;
        }
        let (host, port) = match authority.strip_prefix('[') {
            // An IPv6 literal: "[::1]" or "[::1]:8443".
            Some(v6) => {
                let (host, rest) = v6.split_once(']')?;
                match rest {
                    "" => (host, 443),
                    _ => (host, rest.strip_prefix(':')?.parse().ok()?),
                }
            }
            None => match authority.split_once(':') {
                Some((h, p)) => (h, p.parse().ok()?),
                None => (authority, 443),
            },
        };
        if host.is_empty() {
            return None;
        }
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_string()
        };
        Some(Self {
            host: host.to_string(),
            port,
            target,
        })
    }
}

/// The request line and headers, or `None` when a header would inject a line.
fn head(request: &HttpsRequest, url: &Url) -> Option<Vec<u8>> {
    let clean = |s: &str| !s.contains(['\r', '\n']);
    if !clean(request.method)
        || !clean(&url.target)
        || !request
            .headers
            .iter()
            .all(|(n, v)| clean(n) && clean(v) && !n.is_empty() && !n.contains(':'))
    {
        return None;
    }
    let host = if url.port == 443 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let mut out = format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: quebracho-x402\r\nAccept: application/json\r\nConnection: close\r\n",
        request.method, url.target
    );
    if !request.body.is_empty() || request.method == "POST" {
        out.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    for (name, value) in &request.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    Some(out.into_bytes())
}

enum Framing {
    Length(usize),
    Chunked,
    UntilClose,
}

/// The status, the framing and where the body starts, once the head is complete.
type Head = (u16, Framing, usize, Vec<(String, String)>);

fn split(raw: &[u8]) -> Option<Result<Head, HttpsUnavailable>> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let Ok(head) = std::str::from_utf8(&raw[..end]) else {
        return Some(Err(HttpsUnavailable));
    };
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1."))
        .and_then(|l| l.get(2..5))
        .and_then(|s| s.parse::<u16>().ok());
    let Some(status) = status else {
        return Some(Err(HttpsUnavailable));
    };
    let mut framing = Framing::UntilClose;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        headers.push((name.trim().to_string(), value.to_string()));
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            framing = Framing::Chunked;
        } else if name.eq_ignore_ascii_case("content-length")
            && !matches!(framing, Framing::Chunked)
        {
            match value.parse() {
                Ok(n) => framing = Framing::Length(n),
                Err(_) => return Some(Err(HttpsUnavailable)),
            }
        }
    }
    Some(Ok((status, framing, end + 4, headers)))
}

/// A complete message, or `None` while more bytes are needed.
fn parse(raw: &[u8]) -> Option<Result<HttpsResponse, HttpsUnavailable>> {
    let (status, framing, start, headers) = match split(raw)? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    let body = &raw[start..];
    match framing {
        Framing::Length(n) => (body.len() >= n).then(|| {
            Ok(HttpsResponse {
                status,
                headers,
                body: body[..n].to_vec(),
            })
        }),
        Framing::Chunked => dechunk(body).map(|b| {
            b.map(|body| HttpsResponse {
                status,
                headers,
                body,
            })
        }),
        Framing::UntilClose => None,
    }
}

/// At end of stream: a body read until close is complete; anything still short is not.
fn parse_at_eof(raw: &[u8]) -> Option<Result<HttpsResponse, HttpsUnavailable>> {
    match split(raw)? {
        Ok((status, Framing::UntilClose, start, headers)) => Some(Ok(HttpsResponse {
            status,
            headers,
            body: raw[start..].to_vec(),
        })),
        Ok(_) => parse(raw),
        Err(e) => Some(Err(e)),
    }
}

/// Cheap test of whether a message whose head arrived may be whole: it avoids decoding a chunked body
/// (or rescanning a long one) on every read. Performance only: a wrong "maybe" just costs a parse.
fn complete(raw: &[u8]) -> bool {
    match split(raw) {
        Some(Ok((_, Framing::Length(n), start, _))) => raw.len() - start >= n,
        Some(Ok((_, Framing::Chunked, _, _))) => {
            raw.ends_with(b"\r\n\r\n") || raw.ends_with(b"0\r\n")
        }
        Some(Ok((_, Framing::UntilClose, _, _))) => false,
        // A bad head: parse() says so at once.
        Some(Err(_)) | None => true,
    }
}

/// A chunked body, or `None` until its last chunk arrived.
fn dechunk(mut body: &[u8]) -> Option<Result<Vec<u8>, HttpsUnavailable>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let Ok(size) =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
        else {
            return Some(Err(HttpsUnavailable));
        };
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(Ok(out));
        }
        // A size no answer can have (it would overflow) is refused, not trusted.
        let Some(need) = size.checked_add(2) else {
            return Some(Err(HttpsUnavailable));
        };
        if body.len() < need {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[need..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://x402.org/facilitator/verify").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("x402.org", 443, "/facilitator/verify")
        );
        let u = Url::parse("https://127.0.0.1:8443?x=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("127.0.0.1", 8443, "/?x=1")
        );
        for bad in [
            "http://x402.org",
            "https://",
            "https://user@host/",
            "https://host/#frag",
            "https://host:notaport/",
        ] {
            assert!(Url::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn framing() {
        let ok = |raw: &[u8]| parse(raw).unwrap().unwrap();
        assert_eq!(
            ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").body,
            b"hi"
        );
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi").is_none());
        assert_eq!(ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n3;x=y\r\nyou\r\n0\r\n\r\n").body, b"hiyou");
        assert_eq!(
            parse_at_eof(b"HTTP/1.0 302 Found\r\nLocation: https://evil/\r\n\r\nbye")
                .unwrap()
                .unwrap()
                .status,
            302
        );
        assert!(parse(b"garbage\r\n\r\n").unwrap().is_err());
    }

    #[test]
    fn malformed_heads_and_bodies_are_refused() {
        assert!(Url::parse("https://[]/").is_none());
        assert!(
            matches!(parse(b"HTTP/1.1 200 \xff\r\n\r\n"), Some(Err(_))),
            "not UTF-8"
        );
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: ten\r\n\r\n"),
            Some(Err(_))
        ));
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"),
            Some(Err(_))
        ));
        assert!(matches!(parse_at_eof(b"garbage\r\n\r\n"), Some(Err(_))));
        // A header line without a colon is ignored; the body is read until close.
        let r = parse_at_eof(b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\nrest")
            .unwrap()
            .unwrap();
        assert_eq!(r.body, b"rest");
        assert!(
            parse(b"HTTP/1.1 200 OK\r\n\r\nrest").is_none(),
            "until close: not complete yet"
        );
        // complete(): cheap and conservative.
        assert!(complete(b"garbage\r\n\r\nx"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\n\r\nrest"));
        assert!(complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
        assert!(!complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"
        ));
    }

    /// A chunk larger than the default cap is fine when the client allows more (an OFAC sync).
    #[test]
    fn a_big_chunk_within_the_cap_is_read() {
        let size = 5 * 1024 * 1024;
        let mut raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
            .into_bytes();
        raw.extend(std::iter::repeat_n(b'a', size));
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(parse(&raw).unwrap().unwrap().body.len(), size);
    }

    /// Half of a big chunk is "not yet", never an error, even when its last bytes look like an end.
    #[test]
    fn half_a_big_chunk_waits_for_more() {
        let size = 5 * 1024 * 1024;
        let mut raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
            .into_bytes();
        raw.extend(std::iter::repeat_n(b'a', 1024 * 1024));
        raw.extend_from_slice(b"0\r\n");
        assert!(parse(&raw).is_none());
    }

    /// Audit M1: a chunk size near usize::MAX must be refused, not overflow.
    #[test]
    fn a_huge_chunk_size_is_refused_without_panicking() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nxx";
        assert!(matches!(parse(raw), Some(Err(_))));
        assert!(matches!(parse_at_eof(raw), Some(Err(_))));
    }

    #[test]
    fn ipv6_literals_parse_with_and_without_a_port() {
        let u = Url::parse("https://[::1]/settle").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("::1", 443, "/settle")
        );
        let u = Url::parse("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("2001:db8::1", 8443, "/")
        );
        assert!(Url::parse("https://[::1/").is_none(), "no closing bracket");
        assert!(
            Url::parse("https://[::1]x/").is_none(),
            "junk after the bracket"
        );
        assert!(Url::parse("https://[::1]:port/").is_none());
    }

    #[test]
    fn transfer_encoding_other_than_chunked_is_not_chunked() {
        let r =
            parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 2\r\n\r\nhi")
                .unwrap()
                .unwrap();
        assert_eq!(r.body, b"hi");
        // Content-Length after chunked is ignored.
        let r = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n\r\n2\r\nhi\r\n0\r\n\r\n").unwrap().unwrap();
        assert_eq!(r.body, b"hi");
    }

    #[test]
    fn heads_say_host_length_and_refuse_injection_anywhere() {
        let req = |method: &'static str, url: &str, body: &[u8]| HttpsRequest {
            method,
            url: url.into(),
            headers: vec![],
            body: body.to_vec(),
        };
        let text = |r: &HttpsRequest| {
            String::from_utf8(head(r, &Url::parse(&r.url).unwrap()).unwrap()).unwrap()
        };
        let get = text(&req("GET", "https://h/a", b""));
        assert!(
            get.contains("Host: h\r\n") && !get.contains("Content-Length"),
            "{get}"
        );
        let post = text(&req("POST", "https://h:8443/a", b""));
        assert!(
            post.contains("Host: h:8443\r\n") && post.contains("Content-Length: 0\r\n"),
            "{post}"
        );
        let put = text(&req("PUT", "https://h/a", b"xyz"));
        assert!(put.contains("Content-Length: 3\r\n"), "{put}");
        let bad_method = req("GET\r\nX: 1", "https://h/a", b"");
        assert!(head(&bad_method, &Url::parse("https://h/a").unwrap()).is_none());
        let bad_target = req("GET", "https://h/a\r\nX: 1", b"");
        assert!(head(&bad_target, &Url::parse(&bad_target.url).unwrap()).is_none());
        let empty_name = HttpsRequest {
            method: "GET",
            url: "https://h/".into(),
            headers: vec![(String::new(), "v".into())],
            body: vec![],
        };
        assert!(head(&empty_name, &Url::parse("https://h/").unwrap()).is_none());
    }

    #[test]
    fn no_header_injection() {
        let url = Url::parse("https://h/").unwrap();
        let req = |n: &str, v: &str| HttpsRequest {
            method: "GET",
            url: "https://h/".into(),
            headers: vec![(n.into(), v.into())],
            body: vec![],
        };
        assert!(head(&req("X", "ok"), &url).is_some());
        assert!(head(&req("X", "a\r\nEvil: 1"), &url).is_none());
        assert!(head(&req("X:Y", "a"), &url).is_none());
    }
}
