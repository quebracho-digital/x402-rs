//! Property tests: what reads untrusted input never panics, and keeps its rules for any input, not only the
//! PHP vectors. Thousands of generated inputs per property.

use proptest::prelude::*;
use quebracho_x402::field::{self, Rule};
use quebracho_x402::ports::{Clock, Facilitator, FacilitatorError, Ledger, LedgerUnavailable};
use quebracho_x402::screening::{self, AddressList, Ofac};
use quebracho_x402::seller::{Request, Response, Seller};
use quebracho_x402::{dates, eip712, evm_exact, headers, settlement, signer};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// Any JSON value, a few levels deep.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(|f| json!(f)),
        ".{0,80}".prop_map(Value::String),
        "0x[0-9a-fA-F]{0,140}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(
                prop_oneof![
                    Just("payload".to_string()),
                    Just("authorization".to_string()),
                    Just("accepted".to_string()),
                    Just("x402Version".to_string()),
                    Just("signature".to_string()),
                    "[a-zA-Z]{1,12}"
                ],
                inner,
                0..6
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

fn offer() -> Value {
    json!({
        "scheme": "exact", "network": "eip155:84532", "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo": "0x000000000000000000000000000000000000dEaD", "maxTimeoutSeconds": 300,
        "extra": { "name": "USDC", "version": "2" }
    })
}

/// A spelling rule written the obvious way, to compare `field::is` against.
fn reference(rule: Rule, v: &str) -> bool {
    let hex = |n: usize| {
        v.len() == n + 2 && v.starts_with("0x") && v[2..].chars().all(|c| c.is_ascii_hexdigit())
    };
    let dec = |max: usize, zero: bool| {
        (v == "0" && zero)
            || (!v.is_empty()
                && v.len() <= max
                && !v.starts_with('0')
                && v.chars().all(|c| c.is_ascii_digit()))
    };
    match rule {
        Rule::Address => hex(40),
        Rule::Bytes32 | Rule::PrivateKey => hex(64),
        Rule::Signature => hex(130),
        Rule::Uint256 => dec(78, true),
        Rule::Amount => dec(78, false),
        Rule::Timestamp => dec(19, true),
        Rule::EvmNetwork => v.strip_prefix("eip155:").is_some_and(|id| {
            !id.is_empty() && !id.starts_with('0') && id.chars().all(|c| c.is_ascii_digit())
        }),
        Rule::PaymentId => {
            (1..=128).contains(&v.len())
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        }
    }
}

const RULES: [Rule; 9] = [
    Rule::Address,
    Rule::Bytes32,
    Rule::Signature,
    Rule::PrivateKey,
    Rule::Uint256,
    Rule::Amount,
    Rule::Timestamp,
    Rule::EvmNetwork,
    Rule::PaymentId,
];

struct MemLedger(RefCell<BTreeMap<String, Value>>);
impl Ledger for MemLedger {
    fn claim(&self, k: &str, _t: u64) -> Result<bool, LedgerUnavailable> {
        let mut m = self.0.borrow_mut();
        Ok(!m.contains_key(k) && m.insert(k.into(), json!({"status": "claimed"})).is_none())
    }
    fn get(&self, k: &str) -> Result<Option<Value>, LedgerUnavailable> {
        Ok(self.0.borrow().get(k).cloned())
    }
    fn put(&self, k: &str, s: &Value, _t: u64) -> Result<(), LedgerUnavailable> {
        self.0.borrow_mut().insert(k.into(), s.clone());
        Ok(())
    }
    fn release(&self, k: &str) -> Result<(), LedgerUnavailable> {
        self.0.borrow_mut().remove(k);
        Ok(())
    }
    fn open(&self, _k: &str, _r: &Value, _t: u64) -> Result<(), LedgerUnavailable> {
        Ok(())
    }
    fn open_keys(&self, _l: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
        Ok(vec![])
    }
    fn close(&self, _k: &str) -> Result<(), LedgerUnavailable> {
        Ok(())
    }
}
struct Now;
impl Clock for Now {
    fn now(&self) -> u64 {
        1_800_000_000
    }
}
struct Never;
impl Facilitator for Never {
    fn verify(&self, _p: &Value, _r: &Value) -> Result<Value, FacilitatorError> {
        Ok(json!({ "isValid": true }))
    }
    fn settle(&self, _p: &Value, _r: &Value) -> Result<Value, FacilitatorError> {
        Ok(
            json!({ "success": true, "transaction": format!("0x{}", "ab".repeat(32)), "network": "eip155:84532" }),
        )
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn field_rules_match_their_definition(v in prop_oneof![".{0,140}", "0x[0-9a-fA-F]{38,132}", "[0-9]{0,80}", "eip155:[0-9]{0,6}", "[A-Za-z0-9_-]{0,130}"]) {
        for rule in RULES {
            prop_assert_eq!(field::is(rule, &v), reference(rule, &v), "{:?} {:?}", rule, v);
        }
    }

    #[test]
    fn uint256_is_the_number(n in any::<u128>()) {
        let w = eip712::uint256(&n.to_string()).unwrap();
        prop_assert_eq!(&w[..16], &[0u8; 16][..]);
        prop_assert_eq!(u128::from_be_bytes(w[16..].try_into().unwrap()), n);
    }

    #[test]
    fn uint256_never_panics(s in ".{0,100}") {
        let _ = eip712::uint256(&s);
    }

    #[test]
    fn headers_round_trip_and_never_panic(v in any_json(), junk in ".{0,200}") {
        if v.is_object() || v.is_array() {
            prop_assert_eq!(headers::decode(&headers::encode(&v)), Some(v));
        }
        let _ = headers::decode(&junk);
    }

    #[test]
    fn verify_never_panics_and_never_accepts_garbage(payment in any_json(), now in any::<u64>()) {
        // A random payment can never carry a valid signature for this offer.
        prop_assert!(evm_exact::verify(&payment, &offer(), now).is_err());
    }

    #[test]
    fn settlement_helpers_never_panic(payment in any_json(), receipt in any_json(), accepts in prop::collection::vec(any_json(), 0..4)) {
        let _ = settlement::key(&payment);
        let _ = settlement::ttl(&payment, Some(&receipt), 1_800_000_000);
        let _ = settlement::offer(&accepts, Some(&payment));
        let s = settlement::settled(&receipt);
        prop_assert_eq!(&s["success"], &json!(true));
    }

    #[test]
    fn recover_never_panics(digest in any::<[u8; 32]>(), sig in prop::collection::vec(any::<u8>(), 65), text in ".{0,140}") {
        let _ = signer::recover(&digest, &sig.try_into().unwrap());
        let _ = signer::recover_hex(&digest, &text);
    }

    #[test]
    fn dates_round_trip(t in 0i64..253_402_300_799) {
        prop_assert_eq!(dates::parse_iso(&dates::iso(t)), Some(t));
    }

    #[test]
    fn date_parsers_never_panic(s in ".{0,40}") {
        let _ = dates::parse_iso(&s);
        let _ = dates::parse_http(&s);
        let _ = screening::updated(&s);
    }

    #[test]
    fn lists_never_panic_and_find_what_they_hold(text in ".{0,400}", a in "0x[0-9a-fA-F]{40}") {
        let _ = AddressList::parse(&text, "x");
        let l = AddressList::parse(&format!("{text}\n{a} note\n"), "x");
        prop_assert!(l.contains(&a.to_ascii_lowercase()) && l.contains(&a.to_ascii_uppercase().replacen("0X", "0x", 1)));
        let _ = Ofac::from_snapshot(&text);
    }

    /// The whole seller with a random header: never panics, never runs the handler, never claims.
    #[test]
    fn the_seller_never_runs_or_claims_for_garbage(payment in any_json(), raw in ".{0,300}") {
        let ledger = MemLedger(RefCell::default());
        let ofac = Ofac::off();
        let seller = Seller { ledger: &ledger, facilitator: &Never, clock: &Now, ofac: &ofac, listeners: &[], events: None, lookup: None, stop: None };
        let offers = [offer()];
        for header in [headers::encode(&payment), raw.clone()] {
            let r = seller.process(&Request { accepts: Some(&offers), resource: &json!({}), payment: Some(&header), keep: true }, || Ok(Response::new(200, "secret")));
            let r = r.unwrap();
            prop_assert!(r.status == 400 || r.status == 402, "status {}", r.status);
            prop_assert!(r.body != b"secret");
        }
        prop_assert!(ledger.0.borrow().is_empty());
    }
}
