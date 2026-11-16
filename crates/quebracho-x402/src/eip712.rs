//! The EIP-712 digest of an EIP-3009 `TransferWithAuthorization` (port of the part of `Eip712.php`
//! and `Authorization::digest` that x402 `exact` on EVM uses).
//!
//! Type hashes are computed from their type strings, never typed in as constants: the conformance
//! vectors check them against PHP.

use crate::keccak256;

/// The EIP-712 domain type, in the field order `Eip712.php` builds when all four are present.
pub const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// The EIP-3009 authorization type x402 signs.
pub const TRANSFER_WITH_AUTHORIZATION_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// The token's EIP-712 domain: `extra.name`, `extra.version`, the chain id and the token (`asset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

impl Domain<'_> {
    /// `hashStruct(EIP712Domain)`.
    pub fn separator(&self) -> [u8; 32] {
        let mut enc = [0u8; 32 * 5];
        enc[0..32].copy_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
        enc[32..64].copy_from_slice(&keccak256(self.name.as_bytes()));
        enc[64..96].copy_from_slice(&keccak256(self.version.as_bytes()));
        enc[120..128].copy_from_slice(&self.chain_id.to_be_bytes());
        enc[140..160].copy_from_slice(&self.verifying_contract);
        keccak256(&enc)
    }
}

/// An EIP-3009 authorization, its integers already as 32-byte big-endian words (see [`uint256`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferWithAuthorization {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: [u8; 32],
    pub valid_after: [u8; 32],
    pub valid_before: [u8; 32],
    pub nonce: [u8; 32],
}

impl TransferWithAuthorization {
    /// `hashStruct(TransferWithAuthorization)`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut enc = [0u8; 32 * 7];
        enc[0..32].copy_from_slice(&keccak256(TRANSFER_WITH_AUTHORIZATION_TYPE.as_bytes()));
        enc[44..64].copy_from_slice(&self.from);
        enc[76..96].copy_from_slice(&self.to);
        enc[96..128].copy_from_slice(&self.value);
        enc[128..160].copy_from_slice(&self.valid_after);
        enc[160..192].copy_from_slice(&self.valid_before);
        enc[192..224].copy_from_slice(&self.nonce);
        keccak256(&enc)
    }
}

/// The digest to sign: `keccak(0x1901 ‖ domainSeparator ‖ hashStruct(message))`.
pub fn digest(domain: &Domain<'_>, auth: &TransferWithAuthorization) -> [u8; 32] {
    let mut enc = [0u8; 66];
    enc[0] = 0x19;
    enc[1] = 0x01;
    enc[2..34].copy_from_slice(&domain.separator());
    enc[34..66].copy_from_slice(&auth.struct_hash());
    keccak256(&enc)
}

/// A decimal string of ASCII digits as a 32-byte big-endian word, or `None` if it is not digits or
/// does not fit in 256 bits. Spelling (leading zeros, length) is [`crate::field`]'s job.
pub fn uint256(decimal: &str) -> Option<[u8; 32]> {
    if decimal.is_empty() {
        return None;
    }
    let mut word = [0u8; 32];
    for c in decimal.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        // word = word * 10 + digit, from the least significant byte up.
        let mut carry = u16::from(c - b'0');
        for byte in word.iter_mut().rev() {
            let v = u16::from(*byte) * 10 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(word)
}
