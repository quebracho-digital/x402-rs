//! `settlement` against PHP's `Settlement` (`conformance/vectors/settlement.json`): receipt normalization,
//! reading a settle answer, the online verify reason, offer matching, the payment key and mock mode.

use quebracho_x402::ports::{Facilitator, FacilitatorError};
use quebracho_x402::settlement::{self, MockFacilitator};
use serde_json::{Value, json};

fn cases() -> Value {
    serde_json::from_str::<Value>(include_str!("../../../conformance/vectors/settlement.json"))
        .unwrap()["cases"]
        .clone()
}

/// A facilitator that answers one scripted way.
struct Answers(Value);
impl Facilitator for Answers {
    fn verify(&self, _p: &Value, _r: &Value) -> Result<Value, FacilitatorError> {
        Ok(self.0["answer"].clone())
    }
    fn settle(&self, _p: &Value, _r: &Value) -> Result<Value, FacilitatorError> {
        if self.0.get("unavailable").is_some() {
            return Err(FacilitatorError::Unavailable);
        }
        if self.0.get("throws").is_some() {
            return Err(FacilitatorError::Other);
        }
        Ok(self.0["answer"].clone())
    }
}

#[test]
fn settled_receipts_match_php() {
    for c in cases()["settled"].as_array().unwrap() {
        assert_eq!(
            settlement::settled(&c["receipt"]),
            c["settled"],
            "{}",
            c["name"]
        );
    }
}

#[test]
fn settle_answers_are_read_as_php() {
    for c in cases()["run"].as_array().unwrap() {
        let got = settlement::run(
            &Answers(c.clone()),
            &json!({}),
            &json!({ "network": "eip155:84532" }),
        );
        assert_eq!(got, c["receipt"], "{}", c["name"]);
    }
}

#[test]
fn verify_reasons_match_php() {
    for c in cases()["verifier"].as_array().unwrap() {
        let got = settlement::verify_online(
            &Answers(c.clone()),
            &json!({}),
            &json!({ "network": "eip155:84532" }),
        );
        assert_eq!(
            got.map(Value::String).unwrap_or(Value::Null),
            c["reason"],
            "{}",
            c["name"]
        );
    }
}

#[test]
fn offers_are_matched_as_php() {
    for c in cases()["offer"].as_array().unwrap() {
        let accepts = c["accepts"].as_array().unwrap().clone();
        let accepted = (!c["accepted"].is_null()).then_some(&c["accepted"]);
        let got = settlement::offer(&accepts, accepted)
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(got, c["offer"], "{}", c["name"]);
    }
}

/// The key of every payment that can reach a claim (an EIP-3009 authorization) is PHP's. Without an
/// authorization PHP hashes the whole payload; such a payment never verifies, so Rust gives no key.
#[test]
fn payment_keys_match_php() {
    let mut keyed = 0;
    for c in cases()["key"].as_array().unwrap() {
        let has_auth = c["payment"]
            .pointer("/payload/authorization")
            .is_some_and(Value::is_object);
        match settlement::key(&c["payment"]) {
            Some(k) => {
                assert_eq!(json!(k), c["key"]);
                keyed += 1;
            }
            None => assert!(!has_auth, "a payment with an authorization must have a key"),
        }
    }
    assert!(keyed >= 2);
}

#[test]
fn mock_mode_matches_php() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/evm_exact.json")).unwrap();
    let base = &doc["cases"][0];
    let got = MockFacilitator
        .settle(&base["payment"], &base["req"])
        .unwrap();
    assert_eq!(got, cases()["mock"]);
    assert_eq!(
        MockFacilitator
            .verify(&base["payment"], &base["req"])
            .unwrap(),
        json!({ "isValid": true })
    );
}

#[test]
fn ttl_follows_expiry_and_references() {
    let p = json!({ "payload": { "authorization": { "validBefore": "1000300" } } });
    assert_eq!(settlement::ttl(&p, None, 1_000_000), 300);
    assert_eq!(settlement::ttl(&p, None, 999_000), settlement::TTL);
    assert_eq!(settlement::ttl(&p, None, 2_000_000), 1);
    assert_eq!(settlement::ttl(&json!({}), None, 0), settlement::TTL);
    let referenced = json!({ "status": "pending", "receipt": { "transaction": "0xab" } });
    assert_eq!(
        settlement::ttl(&p, Some(&referenced), 1_000_000),
        settlement::REFERENCED_TTL
    );
    let unreferenced = json!({ "status": "pending", "receipt": { "transaction": "" } });
    assert_eq!(settlement::ttl(&p, Some(&unreferenced), 1_000_000), 300);
}
