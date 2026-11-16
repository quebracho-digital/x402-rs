//! # quebracho-x402
//!
//! The `no_std` core of the Rust port of the PHP library `quebracho/x402`: what a device needs to
//! **charge** with x402. A seller only verifies, so this crate holds no key and needs no entropy.
//!
//! What is here (each module names its PHP origin):
//! - [`field`]: the one spelling of each value read from outside (`Field.php`).
//! - [`keccak256`] and [`eip712`]: the EIP-3009 `TransferWithAuthorization` digest (`Eip712.php`, `Authorization.php`).
//! - [`signer`]: ecrecover with low-s only, and EIP-55 addresses (`Signer.php`).
//! - [`evm_exact`]: offline verification of an `exact` EVM payment, with the x402 v2 reason codes (`EvmExact.php`).
//!
//! Every behaviour is checked against vectors exported from the PHP library (`conformance/`).
//! Not here yet: settlement keys, claims, ledger, screening, the sale (see `planning/DESIGN.md`).

#![no_std]

extern crate alloc;

pub mod eip712;
pub mod evm_exact;
pub mod field;
pub mod headers;
mod hex;
mod php;
pub mod ports;
pub mod screening;
pub mod seller;
pub mod settlement;
pub mod signer;

use sha3::{Digest, Keccak256};

/// Keccak-256 (Ethereum's, not SHA3-256) of raw bytes.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
