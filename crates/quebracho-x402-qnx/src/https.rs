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

/// The largest answer read, headers included.
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;

pub struct HttpsClient {
    config: Arc<ClientConfig>,
    timeout: Duration,
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
        }
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

        let mut raw = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if let Some(done) = parse(&raw) {
                return done;
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > MAX_RESPONSE {
                        return Err(HttpsUnavailable);
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // A peer that closes without close_notify: only a complete message counts.
                Err(_) => break,
            }
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
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, p.parse().ok()?),
            _ => (authority, 443),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
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
fn split(raw: &[u8]) -> Option<Result<(u16, Framing, usize), HttpsUnavailable>> {
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
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
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
    Some(Ok((status, framing, end + 4)))
}

/// A complete message, or `None` while more bytes are needed.
fn parse(raw: &[u8]) -> Option<Result<HttpsResponse, HttpsUnavailable>> {
    let (status, framing, start) = match split(raw)? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    let body = &raw[start..];
    match framing {
        Framing::Length(n) => (body.len() >= n).then(|| {
            Ok(HttpsResponse {
                status,
                body: body[..n].to_vec(),
            })
        }),
        Framing::Chunked => dechunk(body).map(|b| b.map(|body| HttpsResponse { status, body })),
        Framing::UntilClose => None,
    }
}

/// At end of stream: a body read until close is complete; anything still short is not.
fn parse_at_eof(raw: &[u8]) -> Option<Result<HttpsResponse, HttpsUnavailable>> {
    match split(raw)? {
        Ok((status, Framing::UntilClose, start)) => Some(Ok(HttpsResponse {
            status,
            body: raw[start..].to_vec(),
        })),
        Ok(_) => parse(raw),
        Err(e) => Some(Err(e)),
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
        if body.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
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
