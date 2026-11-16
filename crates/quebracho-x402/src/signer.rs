//! EVM addresses and ecrecover (port of the verifying half of `Signer.php`).
//!
//! The seller side never signs, so there is no private key here.

use alloc::string::String;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::field::{self, Rule};
use crate::{hex, keccak256};

/// The address of an uncompressed secp256k1 public key (`0x04 ‖ x ‖ y`).
pub fn address_of(public_key: &VerifyingKey) -> [u8; 20] {
    let point = public_key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// The address that signed `digest`, or `None` when the signature is malformed or recovers nothing.
///
/// `signature` is r ‖ s ‖ v with v = 27 or 28. As in PHP: 0 < r < n, and **low s only**
/// (0 < s ≤ n/2, EIP-2), since (r, n−s) is the same signature malleated.
pub fn recover(digest: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 20]> {
    let v = match signature[64] {
        27 => 0,
        28 => 1,
        _ => return None,
    };
    // Rejects r or s equal to zero or not below n.
    let sig = Signature::from_slice(&signature[..64]).ok()?;
    if sig.normalize_s().is_some() {
        return None; // s > n/2
    }
    let key = VerifyingKey::recover_from_prehash(digest, &sig, RecoveryId::from_byte(v)?).ok()?;
    Some(address_of(&key))
}

/// [`recover`] on a `0x`-hex signature in its one spelling ([`Rule::Signature`]).
pub fn recover_hex(digest: &[u8; 32], signature: &str) -> Option<[u8; 20]> {
    if !field::is(Rule::Signature, signature) {
        return None;
    }
    recover(digest, &hex::decode::<65>(signature)?)
}

/// EIP-55: each hex letter upper-cased where the same nibble of keccak(lower-case hex) is ≥ 8.
pub fn checksum(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// A `0x`-hex address in its one spelling ([`Rule::Address`]), as bytes.
pub fn parse_address(address: &str) -> Option<[u8; 20]> {
    if !field::is(Rule::Address, address) {
        return None;
    }
    hex::decode(address)
}
