//! HttpFacilitator against PHP: the same scripted HTTP answers, the same requests sent and the same
//! results (`conformance/vectors/facilitator.json`).

use std::cell::{Cell, RefCell};

use quebracho_x402::http_facilitator::{HttpFacilitator, NotHttps};
use quebracho_x402::ports::{
    Facilitator, Https, HttpsRequest, HttpsResponse, HttpsUnavailable, Sleep,
};
use serde_json::{Value, json};

struct Scripted {
    answers: RefCell<Vec<Value>>,
    sent: RefCell<Vec<Value>>,
}

impl Https for Scripted {
    fn send(&self, r: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable> {
        let header = |name: &str| {
            r.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| json!(v))
                .unwrap_or(Value::Null)
        };
        self.sent.borrow_mut().push(json!({
            "method": r.method,
            "url": r.url,
            "authorization": header("Authorization"),
            "content_type": header("Content-Type"),
            "body": if r.body.is_empty() { Value::Null } else { serde_json::from_slice::<Value>(&r.body).unwrap() },
        }));
        let mut answers = self.answers.borrow_mut();
        let a = if answers.is_empty() {
            json!({ "down": true })
        } else {
            answers.remove(0)
        };
        if a.get("down").is_some() {
            return Err(HttpsUnavailable);
        }
        Ok(HttpsResponse {
            status: a["status"].as_u64().unwrap() as u16,
            headers: vec![],
            body: a["body"].as_str().unwrap().as_bytes().to_vec(),
        })
    }
}

#[derive(Default)]
struct Waits(Cell<u32>);
impl Sleep for Waits {
    fn sleep(&self, _seconds: u64) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn http_facilitator_matches_php() {
    let doc: Value = serde_json::from_str(include_str!(
        "../../../conformance/vectors/facilitator.json"
    ))
    .unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 50);
    for c in cases {
        let at = format!("{} {} (bearer {})", c["op"], c["name"], c["bearer"]);
        let http = Scripted {
            answers: RefCell::new(c["answers"].as_array().unwrap().clone()),
            sent: RefCell::default(),
        };
        let waits = Waits::default();
        let f = HttpFacilitator::new(
            &http,
            &waits,
            "https://facilitator.test/x402/",
            c["bearer"].as_str(),
        )
        .unwrap()
        .polling(3, 0);
        let got = match c["op"].as_str().unwrap() {
            "verify" => f.verify(&c["payment"], &c["req"]),
            "settle" => f.settle(&c["payment"], &c["req"]),
            _ => f.supported().map(Value::Array),
        };
        match got {
            Ok(answer) => assert_eq!(answer, c["answer"], "{at}: answer"),
            Err(_) => assert_eq!(
                c["unavailable"],
                json!(true),
                "{at}: Rust says unavailable, PHP answered {}",
                c["answer"]
            ),
        }
        assert_eq!(
            Value::Array(http.sent.borrow().clone()),
            c["sent"],
            "{at}: requests sent"
        );
        // The delay sits only between two /status queries, never before the first.
        let polls = http
            .sent
            .borrow()
            .iter()
            .filter(|s| s["url"].as_str().unwrap().contains("/status/"))
            .count() as u32;
        assert_eq!(waits.0.get(), polls.saturating_sub(1), "{at}: waits");
    }
}

#[test]
fn only_https_urls() {
    let http = Scripted {
        answers: RefCell::default(),
        sent: RefCell::default(),
    };
    let w = Waits::default();
    for bad in [
        "http://facilitator.test",
        "https://",
        "ftp://x",
        "facilitator.test",
    ] {
        assert_eq!(
            HttpFacilitator::new(&http, &w, bad, None).err(),
            Some(NotHttps),
            "{bad}"
        );
    }
    assert!(HttpFacilitator::new(&http, &w, "https://x402.org/facilitator", None).is_ok());
}
