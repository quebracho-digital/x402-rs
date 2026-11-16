//! Chainalysis' copies of the sanctions lists, a second opinion next to OFAC's own (port of
//! `ChainalysisOracle.php` and `ChainalysisApi.php`). Either may lag OFAC's list either way.
//!
//! - [`Oracle`]: their on-chain sanctions oracle on Ethereum, one free `eth_call`, EVM addresses only.
//! - [`Api`]: their free sanctions API, any address form, needs a key.
//!
//! Both refuse (`address_check_failed`) when they cannot answer, unless built to fail open (reported as
//! [`Event::ScreeningSkipped`]). The API's 4xx (a wrong key) never fails open.
//!
//! PHP asks them deferred (while the handler runs, read before settling); here they are asked in line,
//! before the claim: same verdict, the latency is paid up front.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use quebracho_x402::field::{self, Rule};
use quebracho_x402::ports::{AddressListener, Event, Events, Https, HttpsRequest, ListFailed};
use serde_json::Value;

use crate::rpc;
use crate::token_blacklist::default_rpc;

/// The oracle contract on Ethereum mainnet.
pub const ORACLE: &str = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb";
const IS_SANCTIONED: &str = "0xdf592f7d";
/// The API's address endpoint (`%s` is the address, URL-encoded).
pub const API_URL: &str = "https://public.chainalysis.com/api/v1/address/";

/// Why a check could not be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// May fail open.
    Unavailable,
    /// Our own mistake (a wrong key): never fails open.
    Ours,
}

fn skipped(events: Option<&dyn Events>, role: &str, address: &str, by: &str) {
    if let Some(e) = events {
        e.report(&Event::ScreeningSkipped { role, address, by });
    }
}

pub struct Oracle<'a> {
    https: &'a dyn Https,
    rpc: String,
    fail_open: bool,
    events: Option<&'a dyn Events>,
}

impl<'a> Oracle<'a> {
    /// Asks the oracle through a public Ethereum node; fails closed.
    pub fn new(https: &'a dyn Https) -> Self {
        Self {
            https,
            rpc: default_rpc("eip155:1").unwrap_or_default(),
            fail_open: false,
            events: None,
        }
    }

    /// Your own Ethereum node.
    pub fn rpc(mut self, url: &str) -> Self {
        self.rpc = url.into();
        self
    }

    pub fn fail_open(mut self, events: Option<&'a dyn Events>) -> Self {
        self.fail_open = true;
        self.events = events;
        self
    }

    /// Whether the oracle lists `address`.
    pub fn sanctioned(&self, address: &str) -> Result<bool, ListFailed> {
        rpc::ask_bool(self.https, &self.rpc, ORACLE, IS_SANCTIONED, address).map_err(|_| ListFailed)
    }
}

impl AddressListener for Oracle<'_> {
    fn check(
        &self,
        role: &str,
        _network: &str,
        address: &str,
        _req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        if !field::is(Rule::Address, address) {
            return Ok(None);
        }
        match self.sanctioned(address) {
            Ok(true) => Ok(Some("address_sanctioned".into())),
            Ok(false) => Ok(None),
            Err(_) if self.fail_open => {
                skipped(self.events, role, address, "ChainalysisOracle");
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

pub struct Api<'a> {
    https: &'a dyn Https,
    key: String,
    fail_open: bool,
    events: Option<&'a dyn Events>,
}

/// The API needs a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoKey;

impl<'a> Api<'a> {
    pub fn new(https: &'a dyn Https, key: &str) -> Result<Self, NoKey> {
        if key.is_empty() {
            return Err(NoKey);
        }
        Ok(Self {
            https,
            key: key.into(),
            fail_open: false,
            events: None,
        })
    }

    pub fn fail_open(mut self, events: Option<&'a dyn Events>) -> Self {
        self.fail_open = true;
        self.events = events;
        self
    }

    fn ask(&self, address: &str) -> Result<bool, Failure> {
        let request = HttpsRequest {
            method: "GET",
            url: format!("{API_URL}{}", url_encode(address)),
            headers: Vec::from([
                ("X-API-Key".into(), self.key.clone()),
                ("Accept".into(), "application/json".into()),
            ]),
            body: Vec::new(),
        };
        let response = self
            .https
            .send(&request)
            .map_err(|_| Failure::Unavailable)?;
        if (400..500).contains(&response.status) {
            return Err(Failure::Ours);
        }
        let body: Option<Value> = (response.status == 200)
            .then(|| serde_json::from_slice(&response.body).ok())
            .flatten();
        match body.as_ref().and_then(|b| b.get("identifications")) {
            Some(Value::Array(ids)) => Ok(!ids.is_empty()),
            _ => Err(Failure::Unavailable),
        }
    }

    /// The verdict for the [`crate::Lists`] listener: `Ok(None)` passes, a failure follows this API's policy.
    pub(crate) fn verdict(&self, role: &str, address: &str) -> Result<Option<String>, ListFailed> {
        match self.ask(address) {
            Ok(true) => Ok(Some("address_sanctioned".into())),
            Ok(false) => Ok(None),
            Err(Failure::Unavailable) if self.fail_open => {
                skipped(self.events, role, address, "ChainalysisApi");
                Ok(None)
            }
            Err(_) => Err(ListFailed),
        }
    }
}

impl AddressListener for Api<'_> {
    fn check(
        &self,
        role: &str,
        _network: &str,
        address: &str,
        _req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        self.verdict(role, address)
    }
}

/// PHP's `rawurlencode`: everything but letters, digits and `-._~` as `%XX`.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out.to_string()
}
