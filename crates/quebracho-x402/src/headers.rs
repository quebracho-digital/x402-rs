//! The x402 v2 HTTP headers: standard padded base64 of a JSON object (port of `PaymentHeaders`).

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::Value;

pub const REQUIRED: &str = "PAYMENT-REQUIRED";
pub const SIGNATURE: &str = "PAYMENT-SIGNATURE";
pub const RESPONSE: &str = "PAYMENT-RESPONSE";

/// Encodes with padding; reads with or without it (PHP's strict `base64_decode` does too).
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// A header value: JSON, then padded base64.
pub fn encode(data: &Value) -> String {
    B64.encode(serde_json::to_vec(data).unwrap_or_default())
}

/// The JSON a header holds, or `None` when it is not base64 of a JSON object or list (PHP's arrays).
pub fn decode(header: &str) -> Option<Value> {
    let bytes: Vec<u8> = B64.decode(header).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    matches!(value, Value::Object(_) | Value::Array(_)).then_some(value)
}

/// Raw bytes as standard padded base64 (stored response bodies).
pub fn base64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Standard base64 back to bytes.
pub fn unbase64(text: &str) -> Option<Vec<u8>> {
    B64.decode(text).ok()
}
