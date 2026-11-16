//! JSON-RPC over the core's [`Https`] port: what the on-chain lists ask a node (port of `Rpc.php`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use quebracho_x402::field::{self, Rule};
use quebracho_x402::ports::{Https, HttpsRequest};
use serde_json::{Value, json};

/// Why a call did not answer: unreachable, not JSON-RPC, an `error`, or no `result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcFailed(pub String);

/// One JSON-RPC call to `url`. A `null` result is an answer.
pub fn call(https: &dyn Https, url: &str, method: &str, params: Value) -> Result<Value, RpcFailed> {
    let body = serde_json::to_vec(
        &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
    )
    .unwrap_or_default();
    let request = HttpsRequest {
        method: "POST",
        url: url.to_string(),
        headers: Vec::from([("Content-Type".into(), "application/json".into())]),
        body,
    };
    let response = https
        .send(&request)
        .map_err(|_| RpcFailed(format!("{method}: unreachable")))?;
    let Ok(Value::Object(answer)) = serde_json::from_slice::<Value>(&response.body) else {
        return Err(RpcFailed(format!("{method}: not a JSON-RPC answer")));
    };
    if answer.get("error").is_some_and(|e| !e.is_null()) {
        return Err(RpcFailed(format!("{method}: error")));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| RpcFailed(format!("{method}: no result")))
}

/// A 20-byte address as the 32-byte ABI word, lower-case hex without `0x`.
pub fn word(address: &str) -> String {
    let hex = address
        .strip_prefix("0x")
        .unwrap_or(address)
        .to_ascii_lowercase();
    format!("{hex:0>64}")
}

/// `eth_call` of a `(address) returns (bool)` function: whether it answered true. Anything that is not
/// one ABI word is a failure.
pub fn ask_bool(
    https: &dyn Https,
    url: &str,
    contract: &str,
    selector: &str,
    address: &str,
) -> Result<bool, RpcFailed> {
    let data = format!("{selector}{}", word(address));
    let answer = call(
        https,
        url,
        "eth_call",
        json!([{ "to": contract, "data": data }, "latest"]),
    )?;
    match answer.as_str() {
        Some(w) if field::is(Rule::Bytes32, w) => Ok(w[2..].bytes().any(|c| c != b'0')),
        _ => Err(RpcFailed("not a bool".into())),
    }
}
