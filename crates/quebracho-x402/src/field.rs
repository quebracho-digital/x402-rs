//! The one spelling of each value read from outside (port of `Field.php`).
//!
//! Why one spelling: the encoder reads `0xAB`, `0xab` and `ab` as the same bytes, so a looser format
//! would let one signature count as several payments, or show screening an address in one form and
//! settle for it in another. Each rule takes the whole string: nothing before, nothing after (PHP's
//! `\A…\z`; a trailing newline does not pass). ASCII only.
//!
//! Only the rules the EVM `exact` scheme uses are ported so far; each has conformance vectors.

/// A spelling rule. The names match the PHP constants' values (`Field::ADDRESS` is `"address"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// `0x` and 40 hex digits, any case (EIP-55's case is a checksum, not another address).
    Address,
    /// `0x` and 64 hex digits: an EIP-3009 nonce, a transaction hash.
    Bytes32,
    /// An EOA signature r ‖ s ‖ v: `0x` and 130 hex digits.
    Signature,
    /// `0x` and 64 hex digits.
    PrivateKey,
    /// Decimal: `0`, or up to 78 digits with no leading zero. No sign, exponent or hex.
    Uint256,
    /// A [`Rule::Uint256`] above zero.
    Amount,
    /// Unix seconds in decimal: `0`, or up to 19 digits with no leading zero.
    Timestamp,
    /// CAIP-2 EVM network: `eip155:` and a chain id above zero, no leading zero.
    EvmNetwork,
    /// A facilitator's payment id, safe in a URL path: letters, digits, `_` and `-`, 1 to 128.
    PaymentId,
}

impl Rule {
    /// The rule named as in PHP (`"address"`, `"bytes32"`, …).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "address" => Self::Address,
            "bytes32" => Self::Bytes32,
            "signature" => Self::Signature,
            "private_key" => Self::PrivateKey,
            "uint256" => Self::Uint256,
            "amount" => Self::Amount,
            "timestamp" => Self::Timestamp,
            "evm_network" => Self::EvmNetwork,
            "payment_id" => Self::PaymentId,
            _ => return None,
        })
    }
}

/// Whether `value` is in the rule's one spelling.
pub fn is(rule: Rule, value: &str) -> bool {
    match rule {
        Rule::Address => hex_prefixed(value, 40),
        Rule::Bytes32 | Rule::PrivateKey => hex_prefixed(value, 64),
        Rule::Signature => hex_prefixed(value, 130),
        Rule::Uint256 => decimal(value, 78, true),
        Rule::Amount => decimal(value, 78, false),
        Rule::Timestamp => decimal(value, 19, true),
        Rule::PaymentId => {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        }
        Rule::EvmNetwork => value
            .strip_prefix("eip155:")
            .is_some_and(|id| decimal(id, usize::MAX, false)),
    }
}

fn hex_prefixed(value: &str, digits: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|h| h.len() == digits && h.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// `0` (if allowed) or `[1-9][0-9]{0,max-1}`.
fn decimal(value: &str, max: usize, zero: bool) -> bool {
    let b = value.as_bytes();
    if b == b"0" {
        return zero;
    }
    !b.is_empty() && b.len() <= max && b[0] != b'0' && b.iter().all(u8::is_ascii_digit)
}
