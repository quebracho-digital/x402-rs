//! A payment's identity, its TTLs, the offer it took, and reading a facilitator's settle answer without
//! trusting its shape (port of `Settlement`).

use alloc::string::String;
use alloc::vec::Vec;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::hex;
use crate::php::{at, get};
use crate::ports::{Facilitator, FacilitatorError};

pub const UNAVAILABLE: &str = "facilitator_unavailable";
pub const UNEXPECTED_VERIFY: &str = "unexpected_verify_error";
/// How long a claim or a state lives, at most: seconds.
pub const TTL: u64 = 600;
/// A `settling` or `pending` state that holds a transaction lives a day, to reconcile it.
pub const REFERENCED_TTL: u64 = 86_400;
/// An open entry lives three days, so a reconciler still sees it after the day it may resolve it.
pub const OPEN_TTL: u64 = 259_200;
/// The largest response body kept in the ledger, in bytes.
pub const MAX_BODY: usize = 1_048_576;
/// Prefix of the claim one retry holds while it runs an upfront handler that has not delivered.
pub const RUN: &str = "run:";
/// Settle failures after which the money may still move: the claim is kept for these (and for any failure
/// that carries a transaction). Every other failure moved nothing.
pub const MAY_HAVE_MOVED: [&str; 4] = [
    "settlement_pending",
    UNAVAILABLE,
    "unexpected_settle_error",
    "invalid_settle_response",
];

/// The payment's key in the claim and the ledger: SHA-256 (hex) of the JSON list `[network, payer, nonce]`,
/// payer and nonce in lower case, so `0xAB…` and `0xab…` make one claim. The same key as PHP's
/// `Settlement::key` for an EVM payment. `None` when the payment carries no EIP-3009 authorization (it never
/// verified, so it never gets this far).
pub fn key(payment: &Value) -> Option<String> {
    let auth = at(payment, &["payload", "authorization"]).filter(|a| a.is_object())?;
    fn text(v: Option<&Value>) -> &str {
        v.and_then(Value::as_str).unwrap_or_default()
    }
    let id = Value::Array(Vec::from([
        Value::String(text(at(payment, &["accepted", "network"])).into()),
        Value::String(text(get(auth, "from")).to_ascii_lowercase()),
        Value::String(text(get(auth, "nonce")).to_ascii_lowercase()),
    ]));
    let json = serde_json::to_string(&id).ok()?;
    Some(hex::encode(&Sha256::digest(json.as_bytes())))
}

/// How long a claim or state lives: until the payment expires (`validBefore`), at most [`TTL`]; a
/// `settling` or `pending` state with a transaction, [`REFERENCED_TTL`].
pub fn ttl(payment: &Value, state: Option<&Value>, now: u64) -> u64 {
    let expires = at(payment, &["payload", "authorization", "validBefore"])
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u64>().ok());
    ttl_until(expires, state, now)
}

/// [`ttl`] for a payment known only by its expiry.
pub fn ttl_until(expires_at: Option<u64>, state: Option<&Value>, now: u64) -> u64 {
    if let Some(state) = state {
        let tx = at(state, &["receipt", "transaction"])
            .and_then(Value::as_str)
            .unwrap_or_default();
        let status = get(state, "status").and_then(Value::as_str);
        if matches!(status, Some("settling" | "pending")) && !tx.is_empty() {
            return REFERENCED_TTL;
        }
    }
    match expires_at {
        None => TTL,
        Some(e) => TTL.min((e.saturating_sub(now)).max(1)),
    }
}

/// The seller's own offer the buyer says it took (`accepted`), or `None`. Always one of `accepts`, never
/// the buyer's copy. By scheme and network; with several on one network, by asset (EVM hex in any case).
pub fn offer<'a>(accepts: &'a [Value], accepted: Option<&Value>) -> Option<&'a Value> {
    let accepted = accepted.filter(|a| a.is_object());
    let field =
        |v: Option<&Value>, k: &str| v.and_then(|v| get(v, k)).cloned().unwrap_or(Value::Null);
    let same: Vec<&Value> = accepts
        .iter()
        .filter(|a| {
            field(Some(a), "scheme") == field(accepted, "scheme")
                && field(Some(a), "network") == field(accepted, "network")
        })
        .collect();
    let first = *same.first()?;
    if same.len() > 1
        && let Some(asset) = accepted
            .and_then(|a| get(a, "asset"))
            .and_then(Value::as_str)
    {
        let evm = get(first, "network")
            .and_then(Value::as_str)
            .is_some_and(|n| n.starts_with("eip155:"));
        for o in &same {
            if let Some(own) = get(o, "asset").and_then(Value::as_str)
                && if evm {
                    own.eq_ignore_ascii_case(asset)
                } else {
                    own == asset
                }
            {
                return Some(o);
            }
        }
    }
    Some(first)
}

/// Mock mode, by name only: signatures are verified for real, nothing moves on chain, the receipt has no
/// transaction and says `extensions.mock`.
pub struct MockFacilitator;

impl Facilitator for MockFacilitator {
    fn verify(&self, _payment: &Value, _req: &Value) -> Result<Value, FacilitatorError> {
        Ok(serde_json::json!({ "isValid": true }))
    }

    fn settle(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError> {
        Ok(serde_json::json!({
            "success": true,
            "transaction": "",
            "network": get(req, "network").cloned().unwrap_or(Value::Null),
            "payer": at(payment, &["payload", "authorization", "from"]).cloned().unwrap_or(Value::Null),
            "extensions": { "mock": true },
        }))
    }
}

/// The online check from a facilitator: `None` when `/verify` says good, else its reason
/// (`invalid_payment` when it gives none); unreachable is [`UNAVAILABLE`], anything else
/// [`UNEXPECTED_VERIFY`].
pub fn verify_online(
    facilitator: &dyn Facilitator,
    payment: &Value,
    req: &Value,
) -> Option<String> {
    match facilitator.verify(payment, req) {
        Err(FacilitatorError::Unavailable) => Some(UNAVAILABLE.into()),
        Err(FacilitatorError::Other) => Some(UNEXPECTED_VERIFY.into()),
        Ok(out) if get(&out, "isValid") == Some(&Value::Bool(true)) => None,
        Ok(out) => Some(match get(&out, "invalidReason").and_then(Value::as_str) {
            Some(r) if !r.is_empty() => r.into(),
            _ => "invalid_payment".into(),
        }),
    }
}

/// Settles and reads the answer: a normalized receipt; success only when the facilitator said
/// `success: true`.
pub fn run(facilitator: &dyn Facilitator, payment: &Value, req: &Value) -> Value {
    let receipt = match facilitator.settle(payment, req) {
        Ok(r) => Some(r),
        Err(FacilitatorError::Unavailable) => {
            Some(serde_json::json!({ "success": false, "errorReason": UNAVAILABLE }))
        }
        Err(FacilitatorError::Other) => None,
    };
    if let Some(r) = receipt
        .as_ref()
        .filter(|r| get(r, "success") == Some(&Value::Bool(true)))
    {
        return settled(r);
    }
    let text = |k: &str| {
        receipt
            .as_ref()
            .and_then(|r| get(r, k))
            .and_then(Value::as_str)
            .map(String::from)
    };
    let mut failed = Map::new();
    failed.insert("success".into(), Value::Bool(false));
    failed.insert(
        "errorReason".into(),
        Value::String(text("errorReason").unwrap_or_else(|| "unexpected_settle_error".into())),
    );
    // Kept so a broadcast that has not confirmed yet can be reconciled.
    failed.insert(
        "transaction".into(),
        Value::String(text("transaction").unwrap_or_default()),
    );
    failed.insert(
        "network".into(),
        get(req, "network").cloned().unwrap_or(Value::Null),
    );
    if let Some(id) = text("paymentId") {
        failed.insert("paymentId".into(), Value::String(id));
    }
    Value::Object(failed)
}

/// A settled receipt with the spec's fields, each of its type: a field of another type is dropped.
pub fn settled(receipt: &Value) -> Value {
    let mut out = Map::new();
    out.insert("success".into(), Value::Bool(true));
    for f in ["transaction", "network"] {
        if let Some(Value::String(s)) = get(receipt, f) {
            out.insert(f.into(), Value::String(s.clone()));
        }
    }
    if let Value::Object(m) = receipt {
        match m.get("payer") {
            Some(Value::String(s)) => {
                out.insert("payer".into(), Value::String(s.clone()));
            }
            Some(Value::Null) => {
                out.insert("payer".into(), Value::Null);
            }
            _ => {}
        }
    }
    for f in ["errorReason", "errorMessage", "paymentId"] {
        if let Some(Value::String(s)) = get(receipt, f) {
            out.insert(f.into(), Value::String(s.clone()));
        }
    }
    // Atomic units: a non-negative integer as a string.
    if let Some(Value::String(a)) = get(receipt, "amount")
        && !a.is_empty()
        && a.bytes().all(|c| c.is_ascii_digit())
    {
        out.insert("amount".into(), Value::String(a.clone()));
    }
    if let Value::Object(m) = receipt
        && let Some(ext) = m.get("extensions")
    {
        out.insert("extensions".into(), ext.clone());
    }
    Value::Object(out)
}
