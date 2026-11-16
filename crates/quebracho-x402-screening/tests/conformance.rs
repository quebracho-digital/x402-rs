//! The screening providers against PHP (`conformance/vectors/screening.json`): the same scripted HTTP
//! answers, the same requests sent, the same reasons, and the same lists parsed.

use std::cell::{Cell, RefCell};

use quebracho_x402::ports::{
    AddressListener, Event, Events, Https, HttpsRequest, HttpsResponse, HttpsUnavailable,
};
use quebracho_x402::screening::{self, AddressList, Ofac};
use quebracho_x402_screening::chainalysis::{Api, Oracle};
use quebracho_x402_screening::token_blacklist::{RPCS, TOKENS};
use quebracho_x402_screening::{Lists, TokenBlacklist, sync};
use serde_json::{Value, json};

fn vectors() -> Value {
    serde_json::from_str::<Value>(include_str!("../../../conformance/vectors/screening.json"))
        .unwrap()["cases"]
        .clone()
}

struct Script {
    answers: RefCell<Vec<Value>>,
    sent: RefCell<Vec<Value>>,
}

impl Script {
    fn new(answers: &Value) -> Self {
        Self {
            answers: RefCell::new(answers.as_array().cloned().unwrap_or_default()),
            sent: RefCell::default(),
        }
    }
}

impl Https for Script {
    fn send(&self, r: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable> {
        let key = r
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("X-API-Key"))
            .map(|(_, v)| json!(v))
            .unwrap_or(Value::Null);
        self.sent.borrow_mut().push(json!({
            "method": r.method,
            "url": r.url,
            "api_key": key,
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
struct Skips(Cell<u32>);
impl Events for Skips {
    fn report(&self, e: &Event<'_>) {
        if matches!(e, Event::ScreeningSkipped { .. }) {
            self.0.set(self.0.get() + 1);
        }
    }
}

#[test]
fn listeners_match_php() {
    let cases = vectors()["listeners"].as_array().unwrap().clone();
    assert!(cases.len() >= 30);
    for c in &cases {
        let at = format!("{} / {}", c["kind"], c["name"]);
        let https = Script::new(&c["answers"]);
        let skips = Skips::default();
        let opts = &c["options"];
        let fail_open = opts["failOpen"] == json!(true);
        let listener: Box<dyn AddressListener> = match c["kind"].as_str().unwrap() {
            "token_blacklist" => {
                let mut l = TokenBlacklist::new(&https);
                if let Some(Value::Object(tokens)) = opts.get("tokens") {
                    for (key, f) in tokens {
                        let (network, asset) = key.split_once('|').unwrap();
                        l = l.token(network, asset, f.as_str().unwrap()).unwrap();
                    }
                }
                Box::new(if fail_open {
                    l.fail_open(Some(&skips))
                } else {
                    l
                })
            }
            "chainalysis_oracle" => {
                let mut l = Oracle::new(&https);
                if let Some(rpc) = opts["rpc"].as_str() {
                    l = l.rpc(rpc);
                }
                Box::new(if fail_open {
                    l.fail_open(Some(&skips))
                } else {
                    l
                })
            }
            "chainalysis_api" => {
                let l = Api::new(&https, "test-api-key").unwrap();
                Box::new(if fail_open {
                    l.fail_open(Some(&skips))
                } else {
                    l
                })
            }
            _ => {
                let mut l = Lists::new(
                    c["allow"].as_str().unwrap_or_default(),
                    c["deny"].as_str().unwrap_or_default(),
                );
                if c["api"] == json!(true) {
                    l = l.api(Api::new(&https, "test-api-key").unwrap());
                }
                Box::new(l)
            }
        };
        let listeners: [&dyn AddressListener; 1] = [listener.as_ref()];
        let reason = screening::check(
            &Ofac::off(),
            &listeners,
            Some(&skips),
            screening::PAYER,
            c["address"].as_str(),
            &c["req"],
        );
        assert_eq!(
            reason.map(Value::String).unwrap_or(Value::Null),
            c["reason"],
            "{at}: reason"
        );
        assert_eq!(
            Value::Array(https.sent.borrow().clone()),
            c["sent"],
            "{at}: requests"
        );
        assert_eq!(json!(skips.0.get()), c["skipped"], "{at}: skipped");
    }
}

#[test]
fn lists_and_dates_parse_as_in_php() {
    let v = vectors();
    for l in v["lists"].as_array().unwrap() {
        let text = l["text"].as_str().unwrap();
        assert_eq!(
            json!(AddressList::parse(text, "").addresses()),
            l["addresses"],
            "{text:?}"
        );
        assert_eq!(
            screening::updated(text)
                .map(Value::String)
                .unwrap_or(Value::Null),
            l["updated"],
            "{text:?}"
        );
    }
    for d in v["dates"].as_array().unwrap() {
        let text = d["text"].as_str().unwrap();
        assert_eq!(
            screening::updated(text)
                .map(Value::String)
                .unwrap_or(Value::Null),
            d["updated"],
            "{text:?}"
        );
    }
}

#[test]
fn sdn_csv_parses_as_in_php() {
    let sdn = &vectors()["sdn"];
    assert_eq!(
        json!(sync::parse_sdn(sdn["csv"].as_str().unwrap())),
        sdn["addresses"]
    );
}

#[test]
fn the_token_and_rpc_tables_are_php_s() {
    let v = vectors();
    let tokens: serde_json::Map<String, Value> = TOKENS
        .iter()
        .map(|(k, f)| ((*k).into(), json!(f)))
        .collect();
    assert_eq!(Value::Object(tokens), v["tokens"]);
    for r in v["rpc"].as_array().unwrap() {
        let ours = RPCS
            .iter()
            .find(|(n, _)| *n == r["network"].as_str().unwrap())
            .map(|(_, u)| json!(u));
        assert_eq!(ours.unwrap_or(Value::Null), r["rpc"], "{}", r["network"]);
    }
}

/// The sync rules: too few addresses keeps the copy, a younger copy wins, redirects are followed by hand,
/// HTTPS only.
#[test]
fn syncs_keep_the_copy_unless_the_new_list_is_good_and_not_older() {
    let row = |i: usize| {
        format!(
            "{i},\"X\",-0- ,\"CYBER2\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"Digital Currency Address - ETH 0x{i:040x}\"\n"
        )
    };
    let full: String = (1..=120).map(row).collect();
    let few: String = (1..=5).map(row).collect();
    assert!(sync::ofac_snapshot(&few, "2026-11-10T00:00:00Z", None).is_err());
    let fresh = sync::ofac_snapshot(&full, "2026-11-10T00:00:00Z", None).unwrap();
    assert_eq!((fresh.count, fresh.replaced()), (120, true));
    let written = fresh.content.unwrap();
    assert!(matches!(Ofac::from_snapshot(&written), Ofac::List { .. }));
    let older = sync::ofac_snapshot(&full, "2026-11-01T00:00:00Z", Some(&written)).unwrap();
    assert_eq!(
        (older.replaced(), older.updated.as_str()),
        (false, "2026-11-10T00:00:00Z")
    );

    let redirect = Script::new(&json!([
        { "status": 302, "body": "" },
    ]));
    // A redirect without an https Location is refused.
    assert!(sync::ofac(&redirect, 0, None).is_err());

    let list = Script::new(
        &json!([{ "status": 200, "body": "# updated: 2026-11-12T00:00:00Z\n0xAA00000000000000000000000000000000000001\n" }]),
    );
    let r = sync::list(&list, "https://lists.example.org/denied.txt", 1, 0, None).unwrap();
    assert_eq!(
        r.content.as_deref(),
        Some(
            "# source: https://lists.example.org/denied.txt\n# updated: 2026-11-12T00:00:00Z\n0xaa00000000000000000000000000000000000001\n"
        )
    );
    assert!(sync::list(&list, "http://lists.example.org/denied.txt", 1, 0, None).is_err());
}
