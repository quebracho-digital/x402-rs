//! # quebracho-x402-screening
//!
//! Who may pay or be paid: the address screening of `quebracho-x402`, port of the PHP library's
//! `OfacSdn`, `TokenBlacklist`, `ChainalysisOracle`, `ChainalysisApi`, `Screening` and the list syncs.
//!
//! The core asks OFAC's list first, always, and then each [`AddressListener`] in order; the first refusal
//! wins, and a list that cannot answer refuses (fail closed) unless built to fail open, which is reported.
//! Pick what you need:
//!
//! | Piece | What it asks | Refuses with | Feature |
//! |---|---|---|---|
//! | [`ofac::bundled`] | OFAC's SDN list, shipped in the binary | `address_sanctioned` | `ofac` (default) |
//! | [`TokenBlacklist`] | the token's own blacklist on chain (USDC, USDT freeze) | `address_blacklisted` | |
//! | [`chainalysis::Oracle`] | Chainalysis' on-chain sanctions oracle (Ethereum) | `address_sanctioned` | |
//! | [`chainalysis::Api`] | Chainalysis' sanctions API (needs a key) | `address_sanctioned` | |
//! | [`Lists`] | your own allow and deny lists, then the API | `address_denied` | |
//! | [`quebracho_x402::screening::AddressList`] | any plain-text list | the reason you give | |
//! | [`sync`] | keeps OFAC's and published lists fresh | | `std` to write files |
//!
//! Everything goes through the core's ports (`Https`, `Events`): no I/O of its own, `no_std` + `alloc`.
//!
//! [`AddressListener`]: quebracho_x402::ports::AddressListener

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod chainalysis;
mod lists;
#[cfg(feature = "ofac")]
pub mod ofac;
pub mod rpc;
pub mod sync;
pub mod token_blacklist;

pub use lists::Lists;
pub use token_blacklist::TokenBlacklist;
