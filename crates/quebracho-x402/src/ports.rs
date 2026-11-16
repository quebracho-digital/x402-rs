//! Ports: everything the core needs from the world enters through these traits (`planning/DESIGN.md` §5).
//! The core does no I/O. A device wires adapters (files, HTTP, slog2); tests wire scripts.
//!
//! States, receipts and references are JSON values with the same fields as in the PHP library, so a
//! ledger written by one can be read by the other.

use alloc::string::String;
use alloc::vec::Vec;

use serde_json::Value;

/// A store that cannot answer. Before the handler runs nothing is charged (`503 ledger_unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerUnavailable;

/// What each payment has become, kept across requests and processes (port of `PaymentLedger`).
///
/// `status` is `claimed`, `settling`, `handling`, `settled`, `delivered` or `pending`. Every state expires
/// after its TTL in seconds.
pub trait Ledger {
    /// Stores a `claimed` state unless the key holds a live one. **Atomic**: of N concurrent calls exactly
    /// one returns `true`.
    fn claim(&self, key: &str, ttl: u64) -> Result<bool, LedgerUnavailable>;
    /// The stored state, or `None` (none, or expired).
    fn get(&self, key: &str) -> Result<Option<Value>, LedgerUnavailable>;
    /// Replaces the state and renews the TTL.
    fn put(&self, key: &str, state: &Value, ttl: u64) -> Result<(), LedgerUnavailable>;
    /// Deletes the key and its open entry: a payment that charged nothing is good again.
    fn release(&self, key: &str) -> Result<(), LedgerUnavailable>;
    /// Lists the key as open (to reconcile against the chain) with `reference`: never a signature or a body.
    /// The ledger sets `opened` (Unix seconds) on the first open of a key and keeps it after.
    fn open(&self, key: &str, reference: &Value, ttl: u64) -> Result<(), LedgerUnavailable>;
    /// Up to `limit` live open entries, key and reference.
    fn open_keys(&self, limit: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable>;
    /// Removes the key from the open entries; its state is not touched.
    fn close(&self, key: &str) -> Result<(), LedgerUnavailable>;
}

/// Why a facilitator call did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FacilitatorError {
    /// Unreachable or not answering (PHP's `FacilitatorException`): not the buyer's fault, 502. On settle
    /// the claim is kept, since it may have sent the transaction.
    Unavailable,
    /// Anything else that went wrong (PHP: any other throwable).
    Other,
}

/// Verifies online and settles (port of `Facilitator`). Answers are the facilitator's JSON as it is: the
/// core reads them without trusting their shape.
pub trait Facilitator {
    /// `/verify`: `{"isValid": true}` or `{"isValid": false, "invalidReason": "..."}`.
    fn verify(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError>;
    /// `/settle`: a SettlementResponse (`success`, `transaction`, `network`, `payer`, `errorReason`...).
    fn settle(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError>;
}

/// Asks what became of a `pending` payment (port of the `lookup` closure, e.g. `ReceiptLookup`): a receipt
/// with `success: true` settles it, `success: false` frees it, `None` keeps it pending. An `Err` counts as
/// `None`.
/// A lookup that could not answer (counts as "still pending").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupFailed;

pub trait Lookup {
    fn lookup(
        &self,
        state: &Value,
        payment: &Value,
        req: &Value,
    ) -> Result<Option<Value>, LookupFailed>;
}

/// The time. `reliable` is the fail-closed rule of `THREATS.md` T6 (not in PHP): without a trusted clock no
/// new payment is admitted.
pub trait Clock {
    /// Unix seconds.
    fn now(&self) -> u64;
    fn reliable(&self) -> bool {
        true
    }
}

/// One more screening list, asked about an address OFAC's list passed (port of an `AddressCheck`
/// listener). `Ok(Some(reason))` rejects; `Err` rejects as `address_check_failed` (fail closed).
/// A list that could not answer: the address is refused (`address_check_failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListFailed;

pub trait AddressListener {
    fn check(
        &self,
        role: &str,
        network: &str,
        address: &str,
        req: &Value,
    ) -> Result<Option<String>, ListFailed>;
}

/// The stop switch (port of `Stop`): while engaged, nothing new is verified, claimed, run or charged.
pub trait Pause {
    fn engaged(&self) -> bool;
}

/// What the seller reports. Reporting never changes an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// Once per paid request: `settled`, `not_settled`, `failed`, `rejected`, `failed_after_settle`.
    Outcome {
        status: &'a str,
        reason: Option<&'a str>,
        key: Option<&'a str>,
    },
    /// Before a settle is sent or an upfront handler runs (`settling`, `handling`).
    Intent { status: &'a str, key: &'a str },
    /// The ledger could not do something and the sale went on: `intend`, `record`, `release`,
    /// `release_run`, `close`, `lookup`.
    Fault { op: &'a str, key: &'a str },
    /// The screening refused an address.
    AddressRejected {
        role: &'a str,
        address: &'a str,
        reason: &'a str,
    },
}

/// Where events go: a log (slog2 on QNX), a file of records.
pub trait Events {
    fn report(&self, event: &Event<'_>);
}

/// One HTTP request, as the core builds it. The adapter sends it over TLS (`rustls`) and must not follow
/// redirects, so a signed payment reaches only the host it was meant for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What came back: the status and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The request did not complete (connection, TLS, timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsUnavailable;

/// A blocking HTTPS client (port of PSR-18). TLS is mandatory (decision of Leo): an adapter must refuse
/// any URL that is not `https://`, verify the server certificate and never follow redirects. No async:
/// threads and messages, as QNX is organized.
pub trait Https {
    fn send(&self, request: &HttpsRequest) -> Result<HttpsResponse, HttpsUnavailable>;
}

/// Waiting between two polls. A device that must not block passes a sleeper that returns at once and
/// polls zero times.
pub trait Sleep {
    fn sleep(&self, seconds: u64);
}
