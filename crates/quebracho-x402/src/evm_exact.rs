//! Offline verification of an x402 v2 `exact` payment on an EVM chain: an EIP-3009
//! `TransferWithAuthorization` (port of `EvmExact::verify`).
//!
//! The checks run in the PHP order, so the first failing one gives the same reason code. Inputs are
//! the decoded JSON of the buyer's payment (`PAYMENT-SIGNATURE`) and of our own offer (one entry of
//! `accepts`). Where PHP casts loosely (`(string)`, `(int)`, `empty()`), the helpers at the bottom
//! reproduce what the cast does to JSON values.
//!
//! One deliberate difference: PHP reads the chain id with `(int) explode(':', $network)[1]`; here an
//! offer whose network is not in [`Rule::EvmNetwork`] spelling is `invalid_payment_requirements`.
//! It is our own offer, so it never reaches a buyer.

use serde_json::Value;

use crate::eip712::{self, Domain, TransferWithAuthorization};
use crate::field::{self, Rule};
use crate::hex;
use crate::signer;

/// Seconds a signature must still be valid when verified, so it does not expire on its way into a block.
pub const SLACK: u64 = 6;
/// Clock skew allowed on top of the offer's `maxTimeoutSeconds` for `validBefore`.
pub const SKEW: i128 = 60;

/// Why a payment is refused: the reason codes of the x402 v2 spec §9, which clients match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    InvalidPayload,
    InvalidX402Version,
    InvalidScheme,
    InvalidNetwork,
    InvalidPaymentRequirements,
    RecipientMismatch,
    ValueMismatch,
    ValidAfter,
    ValidBefore,
    Signature,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidX402Version => "invalid_x402_version",
            Self::InvalidScheme => "invalid_scheme",
            Self::InvalidNetwork => "invalid_network",
            Self::InvalidPaymentRequirements => "invalid_payment_requirements",
            Self::RecipientMismatch => "invalid_exact_evm_payload_recipient_mismatch",
            Self::ValueMismatch => "invalid_exact_evm_payload_authorization_value_mismatch",
            Self::ValidAfter => "invalid_exact_evm_payload_authorization_valid_after",
            Self::ValidBefore => "invalid_exact_evm_payload_authorization_valid_before",
            Self::Signature => "invalid_exact_evm_payload_signature",
        }
    }
}

/// The EIP-3009 fields and their one spelling: anything else is `invalid_payload`.
const AUTHORIZATION: [(&str, Rule); 6] = [
    ("from", Rule::Address),
    ("to", Rule::Address),
    ("nonce", Rule::Bytes32),
    ("value", Rule::Uint256),
    ("validAfter", Rule::Timestamp),
    ("validBefore", Rule::Timestamp),
];

/// `Ok(())` when `payment` pays `req` at Unix time `now`, or the first reason it does not.
pub fn verify(payment: &Value, req: &Value, now: u64) -> Result<(), Reason> {
    use Reason::*;
    let auth = at(payment, &["payload", "authorization"]);
    let signature = at(payment, &["payload", "signature"]);
    let accepted = at(payment, &["accepted"]).unwrap_or(&EMPTY);
    let fail = |bad: bool, reason: Reason| if bad { Err(reason) } else { Ok(()) };

    let (Some(auth), Some(Value::String(signature))) = (auth.filter(|a| is_array(a)), signature)
    else {
        return Err(InvalidPayload);
    };
    fail(!is_array(accepted), InvalidPayload)?;
    // One spelling per value: a looser format would let one signature claim several deliveries.
    let canonical = AUTHORIZATION.iter().all(
        |(name, rule)| matches!(get(auth, name), Some(Value::String(s)) if field::is(*rule, s)),
    );
    fail(
        !canonical || !field::is(Rule::Signature, signature),
        InvalidPayload,
    )?;
    fail(
        !matches!(get(payment, "x402Version"), Some(Value::Number(n)) if !n.is_f64() && n.as_i64() == Some(2)),
        InvalidX402Version,
    )?;
    fail(
        get(accepted, "scheme").and_then(Value::as_str) != Some("exact"),
        InvalidScheme,
    )?;
    fail(
        get(accepted, "network").unwrap_or(&Value::Null)
            != get(req, "network").unwrap_or(&Value::Null),
        InvalidNetwork,
    )?;
    let extra = get(req, "extra");
    let (name, version) = (
        extra.and_then(|e| get(e, "name")),
        extra.and_then(|e| get(e, "version")),
    );
    fail(
        php_empty(name) || php_empty(version),
        InvalidPaymentRequirements,
    )?;
    let amount = php_string(get(req, "amount").unwrap_or(&EMPTY_STRING));
    let Some(amount) = amount.filter(|a| field::is(Rule::Amount, a)) else {
        return Err(InvalidPaymentRequirements);
    };
    let (Some(Value::String(asset)), Some(Value::String(pay_to))) =
        (get(req, "asset"), get(req, "payTo"))
    else {
        return Err(InvalidPaymentRequirements);
    };
    fail(
        !field::is(Rule::Address, asset) || !field::is(Rule::Address, pay_to),
        InvalidPaymentRequirements,
    )?;
    // The buyer echoes the offer it took; a different echo is not that offer.
    let echo = |key| php_string(get(accepted, key).unwrap_or(&EMPTY_STRING));
    let same_ci =
        |a: Option<alloc::string::String>, b: &str| a.is_some_and(|a| a.eq_ignore_ascii_case(b));
    fail(
        !same_ci(echo("asset"), asset)
            || !same_ci(echo("payTo"), pay_to)
            || echo("amount").as_deref() != Some(amount.as_str()),
        InvalidPayload,
    )?;

    // From here every authorization field is a canonical string.
    let text = |name| get(auth, name).and_then(Value::as_str).unwrap_or_default();
    fail(!text("to").eq_ignore_ascii_case(pay_to), RecipientMismatch)?;
    fail(text("value") != amount, ValueMismatch)?;
    // Timestamps are at most 19 digits, so they fit in u64.
    let (valid_after, valid_before) = (
        text("validAfter")
            .parse::<u64>()
            .map_err(|_| InvalidPayload)?,
        text("validBefore")
            .parse::<u64>()
            .map_err(|_| InvalidPayload)?,
    );
    fail(valid_after > now, ValidAfter)?;
    fail(valid_before < now.saturating_add(SLACK), ValidBefore)?;
    // No longer than the offer allows (+60 s skew): bounds replay windows and claim storage.
    let timeout = php_int(get(req, "maxTimeoutSeconds"));
    fail(
        i128::from(valid_before) > i128::from(now) + i128::from(timeout) + SKEW,
        ValidBefore,
    )?;

    let network = get(req, "network")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let chain_id = match network.strip_prefix("eip155:") {
        Some(id) if field::is(Rule::EvmNetwork, network) => {
            id.parse::<u64>().map_err(|_| InvalidPaymentRequirements)?
        }
        _ => return Err(InvalidPaymentRequirements),
    };
    let (Some(name), Some(version)) = (name.and_then(php_string), version.and_then(php_string))
    else {
        return Err(InvalidPaymentRequirements);
    };
    let domain = Domain {
        name: &name,
        version: &version,
        chain_id,
        verifying_contract: hex::decode(asset).ok_or(InvalidPaymentRequirements)?,
    };
    let word = |name| eip712::uint256(text(name));
    let message = TransferWithAuthorization {
        from: hex::decode(text("from")).ok_or(InvalidPayload)?,
        to: hex::decode(text("to")).ok_or(InvalidPayload)?,
        // A canonical uint256 can still have more than 256 bits; PHP's digest then matches no
        // signature, so it ends as a bad signature here too.
        value: word("value").ok_or(Signature)?,
        valid_after: word("validAfter").ok_or(Signature)?,
        valid_before: word("validBefore").ok_or(Signature)?,
        nonce: hex::decode(text("nonce")).ok_or(InvalidPayload)?,
    };
    let signer = signer::recover_hex(&eip712::digest(&domain, &message), signature);
    fail(signer != Some(message.from), Signature)
}

use crate::php::{EMPTY, EMPTY_STRING, at, get, is_array, php_empty, php_int, php_string};
