//! M0: does the minimum the product needs run on QNX 8.0?
//!
//! It does not talk to a network service. It checks the pieces the seller and the gateway stand on:
//! `std`, threads, TCP loopback, files with fsync and rename, the `no_std` core, the shipped OFAC list,
//! a TLS client and the WebSocket crate. Run it on the target and read the PASS/FAIL lines.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quebracho_x402::ports::{Https, HttpsRequest};
use quebracho_x402::signer;
use quebracho_x402_qnx::HttpsClient;

fn main() {
    println!(
        "qnx-m0: os={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let mut failures = 0;

    failures += check("clock", || {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "before the epoch".to_string())?
            .as_secs();
        if now < 1_700_000_000 {
            return Err(format!("clock reads {now}; is it set?"));
        }
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        if start.elapsed() < Duration::from_millis(5) {
            return Err("Instant does not advance".into());
        }
        Ok(format!("{now}"))
    });

    failures += check("thread", || {
        let value = std::thread::spawn(|| 21 * 2)
            .join()
            .map_err(|_| "thread panicked".to_string())?;
        if value != 42 {
            return Err(format!("thread returned {value}"));
        }
        Ok("spawn/join".into())
    });

    failures += check("tcp-loopback", || {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let address = listener
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))?;
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer)?;
            stream.write_all(b"pong")?;
            Ok::<_, std::io::Error>(())
        });
        let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .map_err(|e| format!("connect: {e}"))?;
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| format!("read timeout: {e}"))?;
        client
            .write_all(b"ping")
            .map_err(|e| format!("write: {e}"))?;
        let mut answer = [0u8; 4];
        client
            .read_exact(&mut answer)
            .map_err(|e| format!("read: {e}"))?;
        handle
            .join()
            .map_err(|_| "server thread panicked".to_string())?
            .map_err(|e| format!("server: {e}"))?;
        if &answer != b"pong" {
            return Err(format!("answer {:?}", answer));
        }
        Ok("127.0.0.1".into())
    });

    failures += check("files", || {
        let dir = PathBuf::from("qnx-m0-tmp");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
        let tmp = dir.join("state.tmp");
        let final_path = dir.join("state.json");
        let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create: {e}"))?;
        file.write_all(br#"{"status":"settled"}"#)
            .map_err(|e| format!("write: {e}"))?;
        file.sync_all().map_err(|e| format!("fsync: {e}"))?;
        drop(file);
        std::fs::rename(&tmp, &final_path).map_err(|e| format!("rename: {e}"))?;
        let text = std::fs::read_to_string(&final_path).map_err(|e| format!("read: {e}"))?;
        std::fs::remove_dir_all(&dir).map_err(|e| format!("cleanup: {e}"))?;
        if !text.contains("settled") {
            return Err("content lost".into());
        }
        Ok("fsync + rename".into())
    });

    failures += check("core-ecrecover", || {
        // The "good" vector from conformance/vectors/recover.json.
        let digest = hex32("c1fc0435a5d67fc9a0d26e0414991c2e354e708b910afffb6fa01053878c8136")?;
        let signature = "0x465ec799a96fb510dc04f91976657e8cbadf8ef8b6e2244831de50d55d034f5055516239731ec8e096c82e1201959829152d2a0696c03214711ab859e9522a2a1c";
        let recovered =
            signer::recover_hex(&digest, signature).ok_or_else(|| "no signer".to_string())?;
        let expected = signer::parse_address("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23")
            .ok_or_else(|| "bad address".to_string())?;
        if recovered != expected {
            return Err("recovered another address".into());
        }
        Ok("keccak + ecrecover".into())
    });

    failures += check("screening-ofac", || {
        let ofac = quebracho_x402_screening::ofac::bundled();
        let reason = ofac.reason("0x0330070fd38ec3bb94f58fa55d40368271e9e54a");
        if reason != Some("address_sanctioned") {
            return Err(format!("reason {reason:?}"));
        }
        if ofac.published().is_none() {
            return Err("no published date".into());
        }
        Ok("bundled SDN".into())
    });

    failures += check("websocket-crate", || {
        // Construct a WebSocket over an in-memory stream: proves the crate compiles and links.
        let stream = std::io::Cursor::new(Vec::<u8>::new());
        let _socket = tungstenite::WebSocket::from_raw_socket(
            stream,
            tungstenite::protocol::Role::Server,
            None,
        );
        Ok("tungstenite".into())
    });

    if std::env::args().any(|argument| argument == "--tls") {
        failures += check("tls-client", || {
            let client = HttpsClient::new();
            let request = HttpsRequest {
                method: "GET",
                url: "https://example.com/".into(),
                headers: Vec::new(),
                body: Vec::new(),
            };
            let response = client
                .send(&request)
                .map_err(|_| "handshake or request failed".to_string())?;
            if response.status != 200 {
                return Err(format!("status {}", response.status));
            }
            Ok("rustls + rustls-rustcrypto".into())
        });
    } else {
        println!("skip tls-client (pass --tls to try https://example.com/)");
    }

    if failures == 0 {
        println!("qnx-m0: all checks passed");
    } else {
        eprintln!("qnx-m0: {failures} check(s) failed");
        std::process::exit(1);
    }
}

fn check(name: &str, body: impl FnOnce() -> Result<String, String>) -> usize {
    match body() {
        Ok(detail) => {
            println!("PASS {name}: {detail}");
            0
        }
        Err(error) => {
            println!("FAIL {name}: {error}");
            1
        }
    }
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != 64 {
        return Err(format!("expected 64 hex digits, got {}", text.len()));
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "not hex".to_string())?;
    }
    Ok(out)
}
