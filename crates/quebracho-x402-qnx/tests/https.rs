//! The HTTPS client against a local TLS server (rustls, the same pure-Rust provider). The certificate is
//! made by `openssl` at test time, so no private key lives in the repository; without `openssl` the tests
//! say so and pass.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use quebracho_x402::http_facilitator::HttpFacilitator;
use quebracho_x402::ports::{Facilitator, Https, HttpsRequest, Sleep};
use quebracho_x402_qnx::HttpsClient;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::json;

/// A fresh self-signed certificate for 127.0.0.1 and localhost, or `None` without openssl.
fn certificate(name: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::temp_dir().join(format!("x402-https-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    let ok = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ])
        .args([
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?
        .status
        .success();
    ok.then_some((cert, key))
}

/// Serves one connection: records the request, answers `answer` raw.
fn serve(
    cert: &PathBuf,
    key: &PathBuf,
    answer: &'static [u8],
) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let certs = vec![CertificateDer::from_pem_file(cert).unwrap()];
    let key = PrivateKeyDer::from_pem_file(key).unwrap();
    let config = ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), tcp);
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        // Read the head and, if any, the body announced by Content-Length.
        while let Ok(n) = tls.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                if got.len() >= end + 4 + len {
                    break;
                }
            }
        }
        let _ = tls.write_all(answer);
        tls.conn.send_close_notify();
        let _ = tls.flush();
        got
    });
    (port, handle)
}

fn trusting(cert: &PathBuf) -> HttpsClient {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(cert).unwrap())
        .unwrap();
    HttpsClient::with_roots(roots)
}

#[test]
fn posts_and_reads_the_answer() {
    let Some((cert, key)) = certificate("post") else {
        eprintln!("openssl not found: skipped");
        return;
    };
    let (port, server) = serve(&cert, &key, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"isValid\":true}");
    let r = trusting(&cert)
        .send(&HttpsRequest {
            method: "POST",
            url: format!("https://127.0.0.1:{port}/verify"),
            headers: vec![("Authorization".into(), "Bearer k".into())],
            body: b"{\"a\":1}".to_vec(),
        })
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"{\"isValid\":true");
    let sent = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(sent.starts_with("POST /verify HTTP/1.1\r\n"), "{sent}");
    assert!(
        sent.contains("\r\nAuthorization: Bearer k\r\n")
            && sent.contains("\r\nContent-Length: 7\r\n")
            && sent.ends_with("{\"a\":1}"),
        "{sent}"
    );
}

#[test]
fn a_redirect_is_returned_not_followed() {
    let Some((cert, key)) = certificate("redirect") else {
        return;
    };
    let (port, server) = serve(&cert, &key, b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.test/settle\r\nContent-Length: 0\r\n\r\n");
    let r = trusting(&cert)
        .send(&HttpsRequest {
            method: "GET",
            url: format!("https://127.0.0.1:{port}/settle"),
            headers: vec![],
            body: vec![],
        })
        .unwrap();
    assert_eq!(r.status, 302);
    server.join().unwrap();
}

#[test]
fn an_untrusted_certificate_is_refused() {
    let Some((cert, key)) = certificate("untrusted") else {
        return;
    };
    let (port, _server) = serve(&cert, &key, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    // The shipped Mozilla roots do not trust a self-signed certificate.
    let r = HttpsClient::new().send(&HttpsRequest {
        method: "GET",
        url: format!("https://127.0.0.1:{port}/"),
        headers: vec![],
        body: vec![],
    });
    assert!(r.is_err());
}

#[test]
fn plain_http_is_refused_before_connecting() {
    let r = HttpsClient::new().send(&HttpsRequest {
        method: "GET",
        url: "http://127.0.0.1:9/".into(),
        headers: vec![],
        body: vec![],
    });
    assert!(r.is_err());
}

struct NoWait;
impl Sleep for NoWait {
    fn sleep(&self, _seconds: u64) {}
}

/// The facilitator over real TLS: the core's HttpFacilitator, this client, a local server.
#[test]
fn the_facilitator_verifies_over_tls() {
    let Some((cert, key)) = certificate("facilitator") else {
        return;
    };
    let (port, server) = serve(&cert, &key, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"isValid\":true}\r\n0\r\n\r\n");
    let client = trusting(&cert);
    let facilitator =
        HttpFacilitator::new(&client, &NoWait, &format!("https://127.0.0.1:{port}"), None).unwrap();
    let out = facilitator
        .verify(
            &json!({ "x402Version": 2 }),
            &json!({ "network": "eip155:84532" }),
        )
        .unwrap();
    assert_eq!(out, json!({ "isValid": true }));
    let sent = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(sent.starts_with("POST /verify HTTP/1.1\r\n"), "{sent}");
}
