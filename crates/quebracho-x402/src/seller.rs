//! Charging for one request: 402 → verify → claim → run → settle (port of `X402Middleware` and `Sale`).
//!
//! Transport-agnostic: the caller hands over the `PAYMENT-SIGNATURE` header, the
//! offers and a handler, and gets back a [`Response`] to write in its own transport. HTTP status codes and
//! JSON bodies are the PHP middleware's, checked against `conformance/vectors/sale.json`.
//!
//! What is not ported, on purpose: the claims-only mode (a [`Ledger`] is always required), deferred
//! address lookups, `ChainFacilitator`'s reference callback (no self-facilitation, decision of Leo) and the
//! MCP transport. Added, not in PHP: an unreliable [`Clock`] refuses new payments (`clock_unreliable`, 503).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::Cell;

use serde_json::{Map, Value, json};

use crate::evm_exact;
use crate::headers;
use crate::php::{at, get};
use crate::ports::{
    AddressListener, Clock, Event, Events, Facilitator, Ledger, LedgerUnavailable, Lookup, Pause,
};
use crate::screening::{self, Ofac};
use crate::settlement::{self, MAX_BODY, MAY_HAVE_MOVED, OPEN_TTL, RUN, UNAVAILABLE};

/// The reason a paused seller answers with.
pub const PAUSED: &str = "payments_paused";
/// Added in the port: no trusted time, no new payment (threat T6, `docs/THREATS.md`).
pub const CLOCK_UNRELIABLE: &str = "clock_unreliable";

/// What goes back to the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            headers: alloc::vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The handler failed without an answer (PHP: it threw). The seller has recorded what it must; the
/// transport answers as it does for any crash (500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerFailed;

/// One seller: the ports it charges through. Build it once; [`Seller::process`] each request.
pub struct Seller<'a> {
    pub ledger: &'a dyn Ledger,
    pub facilitator: &'a dyn Facilitator,
    pub clock: &'a dyn Clock,
    /// Required: OFAC is on unless turned off by name ([`Ofac::off`]).
    pub ofac: &'a Ofac,
    pub listeners: &'a [&'a dyn AddressListener],
    pub events: Option<&'a dyn Events>,
    pub lookup: Option<&'a dyn Lookup>,
    pub stop: Option<&'a dyn Pause>,
}

/// One paid request.
pub struct Request<'r> {
    /// The offers for this request; `None` when it is free.
    pub accepts: Option<&'r [Value]>,
    /// The 402's `resource` (url, description, mimeType).
    pub resource: &'r Value,
    /// The `PAYMENT-SIGNATURE` header, if any.
    pub payment: Option<&'r str>,
    /// `false` for a sensitive request: its state is kept, its body never is.
    pub keep: bool,
}

impl Seller<'_> {
    /// Charges for one request. `handler` runs at most once.
    pub fn process(
        &self,
        request: &Request<'_>,
        handler: impl FnOnce() -> Result<Response, HandlerFailed>,
    ) -> Result<Response, HandlerFailed> {
        let Some(accepts) = request.accepts else {
            return handler();
        };
        let required = |reason: &str| required(accepts, request.resource, reason);
        let header = request.payment.unwrap_or_default();
        if header.is_empty() {
            // Paused: say so now, so the buyer does not sign a payment this seller would not take.
            if self.paused() {
                return Ok(paused());
            }
            return Ok(required("PAYMENT-SIGNATURE header is required"));
        }
        let Some(payment) = headers::decode(header) else {
            return Ok(Response::json(
                400,
                &json!({ "error": "The payment header is not base64-encoded JSON." }),
            ));
        };
        // The offer the buyer says it took, among ours: never its own copy.
        let Some(req) = settlement::offer(accepts, get(&payment, "accepted")) else {
            return Ok(required("The payment matches none of the accepted offers"));
        };
        let sale = Sale::new(self, &payment, req);

        let run = match self.before_handler(&sale) {
            Err(LedgerUnavailable) => {
                return Ok(Response::json(
                    503,
                    &json!({ "error": "ledger_unavailable" }),
                ));
            }
            Ok(Early::Refuse(code)) => return Ok(Response::json(409, &json!({ "error": code }))),
            Ok(Early::Replay(state)) => return Ok(replay(&state)),
            Ok(Early::Paused) => return Ok(paused()),
            Ok(Early::ClockUnreliable) => {
                return Ok(Response::json(503, &json!({ "error": CLOCK_UNRELIABLE })));
            }
            Ok(Early::Rejected(r)) if r == UNAVAILABLE => {
                return Ok(Response::json(502, &json!({ "error": r })));
            }
            Ok(Early::Rejected(r)) => return Ok(required(&r)),
            Ok(Early::Run(state)) => Some(state),
            Ok(Early::Admitted) => None,
        };

        if let Some(state) = run {
            let receipt = get(&state, "receipt").cloned().unwrap_or(Value::Null);
            let out = self.deliver_upfront(&sale, &receipt, request.keep, handler);
            // After the outcome is written, whatever it was: the next retry finds it.
            sale.end_run();
            return out;
        }
        if sale.upfront() {
            // The intention is stored before the money can move: if the store refuses it, nothing is sent.
            if !sale.intend(&json!({ "status": "settling" })) {
                sale.abandon(None);
                return Ok(Response::json(
                    503,
                    &json!({ "error": "ledger_unavailable" }),
                ));
            }
            if self.paused() {
                sale.abandon(None);
                return Ok(paused());
            }
            // Money first; once it moved, the receipt goes with whatever the handler answers.
            let receipt = sale.settle(None);
            sale.record(&receipt, None, false);
            if receipt["success"] != Value::Bool(true) {
                return Ok(failed(accepts, request.resource, &receipt));
            }
            return self.deliver_upfront(&sale, &receipt, request.keep, handler);
        }

        let response = match handler() {
            Ok(r) => r,
            Err(e) => {
                sale.abandon(None);
                return Err(e);
            }
        };
        if !response.ok() {
            // Nothing delivered, nothing charged.
            sale.abandon(Some(response.status));
            return Ok(response);
        }
        if self.paused() {
            // Switched on while the handler ran: nothing charged, its answer is withheld.
            sale.abandon(Some(response.status));
            return Ok(paused());
        }
        if !sale.intend(&json!({ "status": "settling" })) {
            // Refused before the settle: nothing charged, the handler's answer is withheld.
            sale.abandon(Some(response.status));
            return Ok(Response::json(
                503,
                &json!({ "error": "ledger_unavailable" }),
            ));
        }
        let receipt = sale.settle(Some(response.status));
        sale.record(&receipt, request.keep.then_some(&response), true);
        if receipt["success"] != Value::Bool(true) {
            return Ok(failed(accepts, request.resource, &receipt));
        }
        Ok(response.with_header(headers::RESPONSE, &headers::encode(&receipt)))
    }

    /// Upfront, the money has moved: runs the handler and stores its answer with the receipt. A handler
    /// that does not deliver leaves the state `settled` with `handler_ran: false`, so a retry runs it again
    /// with no second settle.
    fn deliver_upfront(
        &self,
        sale: &Sale<'_>,
        receipt: &Value,
        keep: bool,
        handler: impl FnOnce() -> Result<Response, HandlerFailed>,
    ) -> Result<Response, HandlerFailed> {
        let encoded = headers::encode(receipt);
        // Written before the handler: if the process dies inside it, a retry finds `handling` and does not run it again.
        if !sale.intend(&json!({ "status": "handling", "receipt": receipt, "handler_ran": true })) {
            sale.ran(503);
            return Ok(
                Response::json(503, &json!({ "error": "ledger_unavailable" }))
                    .with_header(headers::RESPONSE, &encoded),
            );
        }
        let response = match handler() {
            Ok(r) => r,
            Err(e) => {
                // Paid and failed: recorded, so the seller can refund by hand; the buyer's retry runs it again.
                sale.record(receipt, None, false);
                sale.ran(500);
                return Err(e);
            }
        };
        sale.ran(response.status);
        let delivered = response.ok();
        sale.record(receipt, (delivered && keep).then_some(&response), delivered);
        Ok(response.with_header(headers::RESPONSE, &encoded))
    }

    /// Everything before the handler: what the ledger already holds, the stop switch, the clock, then
    /// admission. A ledger that cannot answer here charges nothing.
    fn before_handler(&self, sale: &Sale<'_>) -> Result<Early, LedgerUnavailable> {
        match sale.stored()? {
            Some(Stored::Refuse(code)) => return Ok(Early::Refuse(code)),
            Some(Stored::Replay(state)) => return Ok(Early::Replay(state)),
            // Paid upfront, handler never ran: run it now, no second settle.
            Some(Stored::Run(state)) => return Ok(Early::Run(state)),
            None => {}
        }
        // Stopped by hand: nothing new is verified, claimed, run or charged. A payment the ledger already
        // holds (above) is still delivered: it was paid.
        if self.paused() {
            return Ok(Early::Paused);
        }
        if !self.clock.reliable() {
            return Ok(Early::ClockUnreliable);
        }
        Ok(match sale.admit()? {
            Some(reason) => Early::Rejected(reason),
            None => Early::Admitted,
        })
    }

    fn paused(&self) -> bool {
        self.stop.is_some_and(|s| s.engaged())
    }
}

/// How a request ends before the handler, or that it goes on.
enum Early {
    Refuse(&'static str),
    Replay(Value),
    Run(Value),
    Paused,
    ClockUnreliable,
    Rejected(String),
    Admitted,
}

fn paused() -> Response {
    Response::json(503, &json!({ "error": PAUSED })).with_header("Retry-After", "300")
}

fn required(accepts: &[Value], resource: &Value, error: &str) -> Response {
    let body =
        json!({ "x402Version": 2, "error": error, "resource": resource, "accepts": accepts });
    Response::json(402, &body).with_header(headers::REQUIRED, &headers::encode(&body))
}

/// Settle failed: a 402 with the failed receipt; 502 when the facilitator was unreachable.
fn failed(accepts: &[Value], resource: &Value, receipt: &Value) -> Response {
    let reason = receipt["errorReason"].as_str().unwrap_or_default();
    let response = match reason {
        UNAVAILABLE => Response::json(502, &json!({ "error": UNAVAILABLE })),
        "reference_unavailable" => Response::json(503, &json!({ "error": "ledger_unavailable" })),
        _ => required(accepts, resource, reason),
    };
    response.with_header(headers::RESPONSE, &headers::encode(receipt))
}

/// A stored delivered answer, sent again with its receipt.
fn replay(state: &Value) -> Response {
    let stored = &state["response"];
    let mut response = Response::new(
        stored["status"].as_u64().unwrap_or(200) as u16,
        headers::unbase64(stored["body"].as_str().unwrap_or_default()).unwrap_or_default(),
    );
    if let Some(Value::Object(h)) = stored.get("headers") {
        for (name, value) in h {
            response
                .headers
                .push((name.clone(), value.as_str().unwrap_or_default().into()));
        }
    }
    response.with_header(headers::RESPONSE, &headers::encode(&state["receipt"]))
}

/// What the ledger already holds for a payment.
enum Stored {
    /// Replay this delivered state.
    Replay(Value),
    /// Charged upfront, never delivered: run the handler (the run claim is held).
    Run(Value),
    /// Answer 409 with this reason.
    Refuse(&'static str),
}

/// One paid request's steps (port of `Sale`).
struct Sale<'a> {
    seller: &'a Seller<'a>,
    payment: &'a Value,
    req: &'a Value,
    key: String,
    claimed: Cell<bool>,
    running: Cell<bool>,
    ledger_error: Cell<bool>,
}

impl<'a> Sale<'a> {
    fn new(seller: &'a Seller<'a>, payment: &'a Value, req: &'a Value) -> Self {
        Self {
            seller,
            payment,
            req,
            key: settlement::key(payment).unwrap_or_default(),
            claimed: Cell::new(false),
            running: Cell::new(false),
            ledger_error: Cell::new(false),
        }
    }

    fn now(&self) -> u64 {
        self.seller.clock.now()
    }

    fn upfront(&self) -> bool {
        at(self.req, &["extra", "paymentFlow"]).and_then(Value::as_str) == Some("upfront")
    }

    fn payer(&self) -> Option<&str> {
        at(self.payment, &["payload", "authorization", "from"]).and_then(Value::as_str)
    }

    fn verify_offline(&self) -> Option<&'static str> {
        let network = get(self.req, "network")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !network.starts_with("eip155:") {
            return Some("unsupported_scheme");
        }
        evm_exact::verify(self.payment, self.req, self.now())
            .err()
            .map(|r| r.as_str())
    }

    fn ttl(&self, state: Option<&Value>) -> u64 {
        settlement::ttl(self.payment, state, self.now())
    }

    /// Why the payment cannot buy this, or `None` once it is claimed.
    fn admit(&self) -> Result<Option<String>, LedgerUnavailable> {
        let s = self.seller;
        // Offline first: a bad payment costs no facilitator round trip.
        let mut reason = self.verify_offline().map(String::from);
        // Screened once the signature proved who pays, before anything is spent.
        if reason.is_none() {
            reason = screening::check(
                s.ofac,
                s.listeners,
                s.events,
                screening::PAYER,
                self.payer(),
                self.req,
            );
        }
        // Online (balance, nonce unused): a bad payment runs nothing and takes no claim.
        if reason.is_none() {
            reason = settlement::verify_online(s.facilitator, self.payment, self.req);
        }
        // Spent before it runs: N concurrent copies get one delivery.
        if reason.is_none() {
            if s.ledger.claim(&self.key, self.ttl(None))? {
                self.claimed.set(true);
            } else {
                reason = Some("duplicate_settlement".into());
            }
        }
        if let Some(r) = &reason {
            self.outcome("rejected", Some(r));
        }
        Ok(reason)
    }

    /// What this payment already bought, read only once its signature proves who paid (a forged copy costs
    /// no read).
    fn stored(&self) -> Result<Option<Stored>, LedgerUnavailable> {
        if self.verify_offline().is_some() {
            return Ok(None);
        }
        let ledger = self.seller.ledger;
        let answer = match ledger.get(&self.key)? {
            None => None,
            Some(state) => self.classify(state)?,
        };
        if !matches!(answer, Some(Stored::Run(_))) {
            return Ok(answer);
        }
        // Charged upfront, never delivered: of N concurrent retries one runs the handler, the rest wait.
        let run_key = alloc::format!("{RUN}{}", self.key);
        if !ledger.claim(&run_key, self.ttl(None))? {
            return Ok(Some(Stored::Refuse("in_progress")));
        }
        self.running.set(true);
        // Read again under the claim: a retry that finished in between already ran it.
        let again = match ledger.get(&self.key) {
            Ok(None) => Ok(None),
            Ok(Some(state)) => self.classify(state),
            Err(e) => Err(e),
        };
        match again {
            Err(e) => {
                self.end_run();
                Err(e)
            }
            Ok(answer) => {
                if !matches!(answer, Some(Stored::Run(_))) {
                    self.end_run();
                }
                Ok(answer)
            }
        }
    }

    fn end_run(&self) {
        if !self.running.get() {
            return;
        }
        if self
            .seller
            .ledger
            .release(&alloc::format!("{RUN}{}", self.key))
            .is_err()
        {
            self.fault("release_run");
        }
        self.running.set(false);
    }

    fn classify(&self, state: Value) -> Result<Option<Stored>, LedgerUnavailable> {
        Ok(match get(&state, "status").and_then(Value::as_str) {
            Some("delivered" | "settled") => Some(answer(state)),
            Some("pending") => self.confirm(state, "settlement_pending")?,
            Some("settling") => {
                let refs = ["transaction", "paymentId"].iter().any(|f| {
                    at(&state, &["receipt", f])
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.is_empty())
                });
                if refs {
                    self.confirm(state, "settlement_unknown")?
                } else {
                    Some(Stored::Refuse("settlement_unknown"))
                }
            }
            // Upfront, the handler started and never closed: it may have had effects, so it never runs again.
            Some("handling") => Some(if state.get("response").is_some() {
                Stored::Replay(state)
            } else {
                Stored::Refuse("needs_review")
            }),
            Some("claimed") => Some(Stored::Refuse("in_progress")),
            // Unknown: never admit it again.
            _ => Some(Stored::Refuse("already_settled")),
        })
    }

    /// A pending payment: asks the lookup what the chain did. Confirmed, it becomes settled; refuted, it is
    /// freed (`None`: admitted as new); unknown, it stays.
    fn confirm(
        &self,
        mut state: Value,
        unknown: &'static str,
    ) -> Result<Option<Stored>, LedgerUnavailable> {
        let receipt = match self
            .seller
            .lookup
            .map(|l| l.lookup(&state, self.payment, self.req))
        {
            None => None,
            Some(Ok(r)) => r,
            Some(Err(_)) => {
                self.fault("lookup");
                None
            }
        };
        let success = receipt.as_ref().and_then(|r| get(r, "success"));
        if success == Some(&Value::Bool(false)) {
            self.seller.ledger.release(&self.key)?;
            return Ok(None);
        }
        let Some(receipt) = receipt
            .filter(|r| get(r, "success") == Some(&Value::Bool(true)) && self.same(&state, r))
        else {
            return Ok(Some(Stored::Refuse(unknown)));
        };
        state["receipt"] = settlement::settled(&receipt);
        if get(&state, "status").and_then(Value::as_str) == Some("settling") && self.upfront() {
            // Upfront, a settling state is written before the handler: confirmed, the handler has not run yet.
            state["handler_ran"] = Value::Bool(false);
        }
        state["status"] = Value::String(
            if state.get("response").is_some() {
                "delivered"
            } else {
                "settled"
            }
            .into(),
        );
        self.seller
            .ledger
            .put(&self.key, &state, self.ttl(Some(&state)))?;
        self.track(&state)?;
        Ok(Some(answer(state)))
    }

    /// Whether a lookup's receipt is about this payment: network, stored transaction and paymentId, payer.
    fn same(&self, state: &Value, receipt: &Value) -> bool {
        let eq = |a: Option<&Value>, b: Option<&Value>| matches!((a, b), (Some(Value::String(a)), Some(Value::String(b))) if a.eq_ignore_ascii_case(b));
        let known = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        let stored_tx = at(state, &["receipt", "transaction"]);
        let stored_id = at(state, &["receipt", "paymentId"]);
        get(receipt, "network") == get(self.req, "network")
            && (!known(stored_tx) || eq(get(receipt, "transaction"), stored_tx))
            && (!known(stored_id)
                || get(receipt, "paymentId").is_none()
                || eq(get(receipt, "paymentId"), stored_id))
            && (get(receipt, "payer").is_none()
                || eq(
                    get(receipt, "payer"),
                    at(self.payment, &["payload", "authorization", "from"]),
                ))
    }

    /// Write-ahead: records an intention before the money (or the handler) can move. `false` when the
    /// store refused it; the caller must not go on.
    fn intend(&self, state: &Value) -> bool {
        if let Some(e) = self.seller.events {
            e.report(&Event::Intent {
                status: state["status"].as_str().unwrap_or_default(),
                key: &self.key,
            });
        }
        if self.remember(state.clone(), None).is_err() {
            self.ledger_error.set(true);
            self.fault("intend");
            return false;
        }
        true
    }

    /// Records this payment's outcome; a settled state becomes `delivered` when a response is kept.
    fn remember(
        &self,
        mut state: Value,
        response: Option<&Response>,
    ) -> Result<(), LedgerUnavailable> {
        if let Some(kept) = response.and_then(capture) {
            state["response"] = kept;
            if state["status"] == "settled" {
                state["status"] = "delivered".into();
            }
        }
        self.seller
            .ledger
            .put(&self.key, &state, self.ttl(Some(&state)))?;
        self.track(&state)
    }

    /// Keeps the open entries in step: `settling` and `pending` are opened (money may have moved), `settled`
    /// and `delivered` closed. An open that fails fails the write; a close that fails is reported.
    fn track(&self, state: &Value) -> Result<(), LedgerUnavailable> {
        match state["status"].as_str() {
            Some("settling" | "pending") => {
                self.seller
                    .ledger
                    .open(&self.key, &self.reference(state), OPEN_TTL)
            }
            Some("settled" | "delivered") => {
                if self.seller.ledger.close(&self.key).is_err() {
                    self.fault("close");
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// What a reconciler needs to ask the chain about this payment: never the signature nor a body.
    fn reference(&self, state: &Value) -> Value {
        let text = |v: Option<&Value>| {
            v.and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map_or(Value::Null, |s| Value::String(s.into()))
        };
        let valid_before = at(self.payment, &["payload", "authorization", "validBefore"])
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());
        json!({
            "network": get(self.req, "network"),
            "asset": get(self.req, "asset"),
            "from": self.payer(),
            "nonce": text(at(self.payment, &["payload", "authorization", "nonce"])),
            "payTo": get(self.req, "payTo"),
            "amount": get(self.req, "amount"),
            "validBefore": valid_before,
            "transaction": text(at(state, &["receipt", "transaction"])),
            "paymentId": text(at(state, &["receipt", "paymentId"])),
            "status": state["status"],
            "upfront": self.upfront(),
        })
    }

    /// Settles; a failure that moved nothing frees the claim.
    fn settle(&self, handler_status: Option<u16>) -> Value {
        let receipt = settlement::run(self.seller.facilitator, self.payment, self.req);
        if receipt["success"] == Value::Bool(true) {
            self.outcome("settled", None);
        } else {
            let reason = receipt["errorReason"].as_str().unwrap_or_default();
            // A transaction may still land: keep the claim. Only a clear refusal frees it.
            if receipt["transaction"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
                && !MAY_HAVE_MOVED.contains(&reason)
            {
                self.free();
            }
            self.outcome("not_settled", Some(reason));
        }
        let _ = handler_status;
        receipt
    }

    /// Stores what happened: a settled payment (with the response, if any), or a pending one whose claim
    /// was kept. A store that fails here comes after the money may have moved: reported, never an error.
    fn record(&self, receipt: &Value, response: Option<&Response>, handler_ran: bool) {
        let mut state = Map::new();
        let success = receipt["success"] == Value::Bool(true);
        if !success && !self.claimed.get() {
            return;
        }
        state.insert(
            "status".into(),
            Value::String(if success { "settled" } else { "pending" }.into()),
        );
        state.insert("receipt".into(), receipt.clone());
        if !handler_ran {
            state.insert("handler_ran".into(), Value::Bool(false));
        }
        if self.remember(Value::Object(state), response).is_err() {
            self.fault("record");
        }
    }

    /// The handler delivered nothing, or the ledger refused the intention: nothing charged.
    fn abandon(&self, _handler_status: Option<u16>) {
        self.free();
        self.outcome(
            "failed",
            self.ledger_error.get().then_some("ledger_unavailable"),
        );
    }

    /// Upfront: money moved before the handler; a handler that then failed is recorded for a refund by hand.
    fn ran(&self, handler_status: u16) {
        if !(200..300).contains(&handler_status) {
            self.outcome(
                "failed_after_settle",
                self.ledger_error.get().then_some("ledger_unavailable"),
            );
        }
    }

    fn free(&self) {
        if self.claimed.get() {
            if self.seller.ledger.release(&self.key).is_err() {
                // The claim stays until its TTL: the buyer waits but cannot pay twice.
                self.fault("release");
                return;
            }
            self.claimed.set(false);
        }
    }

    fn outcome(&self, status: &str, reason: Option<&str>) {
        if let Some(e) = self.seller.events {
            e.report(&Event::Outcome {
                status,
                reason,
                key: (!self.key.is_empty()).then_some(self.key.as_str()),
            });
        }
    }

    fn fault(&self, op: &str) {
        if let Some(e) = self.seller.events {
            e.report(&Event::Fault { op, key: &self.key });
        }
    }
}

/// A stored settled state's answer: its response replays; without one, run when the handler never ran
/// (upfront), else refused.
fn answer(state: Value) -> Stored {
    if state.get("response").is_some() {
        Stored::Replay(state)
    } else if get(&state, "handler_ran") == Some(&Value::Bool(false)) {
        Stored::Run(state)
    } else {
        Stored::Refuse("already_settled")
    }
}

/// The response kept in the ledger: only a 2xx of at most [`MAX_BODY`] bytes, body as base64.
fn capture(response: &Response) -> Option<Value> {
    if !response.ok() || response.body.len() > MAX_BODY {
        return None;
    }
    let mut headers = Map::new();
    for (name, value) in &response.headers {
        let joined = match headers.get(name).and_then(Value::as_str) {
            Some(prev) => alloc::format!("{prev}, {value}"),
            None => value.to_string(),
        };
        headers.insert(name.clone(), Value::String(joined));
    }
    Some(
        json!({ "status": response.status, "headers": headers, "body": headers::base64(&response.body) }),
    )
}

#[cfg(test)]
mod tests {
    //! What PHP's scenarios cannot reach: races between two ledger reads, and the guards that keep a sale
    //! from releasing what it does not hold.

    use super::*;
    use crate::ports::{FacilitatorError, LedgerUnavailable};
    use crate::screening::Ofac;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    /// A ledger whose `get` answers from a script, one answer per call, then from its own states.
    #[derive(Default)]
    struct Racy {
        gets: RefCell<Vec<Option<Value>>>,
        states: RefCell<BTreeMap<String, Value>>,
        releases: RefCell<Vec<String>>,
    }
    impl Ledger for Racy {
        fn claim(&self, k: &str, _t: u64) -> Result<bool, LedgerUnavailable> {
            let mut s = self.states.borrow_mut();
            if s.contains_key(k) {
                return Ok(false);
            }
            s.insert(k.into(), json!({ "status": "claimed" }));
            Ok(true)
        }
        fn get(&self, k: &str) -> Result<Option<Value>, LedgerUnavailable> {
            let mut g = self.gets.borrow_mut();
            if !g.is_empty() {
                return Ok(g.remove(0));
            }
            Ok(self.states.borrow().get(k).cloned())
        }
        fn put(&self, k: &str, s: &Value, _t: u64) -> Result<(), LedgerUnavailable> {
            self.states.borrow_mut().insert(k.into(), s.clone());
            Ok(())
        }
        fn release(&self, k: &str) -> Result<(), LedgerUnavailable> {
            self.releases.borrow_mut().push(k.into());
            self.states.borrow_mut().remove(k);
            Ok(())
        }
        fn open(&self, _k: &str, _r: &Value, _t: u64) -> Result<(), LedgerUnavailable> {
            Ok(())
        }
        fn open_keys(&self, _l: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
            Ok(Vec::new())
        }
        fn close(&self, _k: &str) -> Result<(), LedgerUnavailable> {
            Ok(())
        }
    }

    struct Ok200;
    impl Facilitator for Ok200 {
        fn verify(&self, _p: &Value, _r: &Value) -> Result<Value, FacilitatorError> {
            Ok(json!({ "isValid": true }))
        }
        fn settle(&self, p: &Value, r: &Value) -> Result<Value, FacilitatorError> {
            Ok(
                json!({ "success": true, "transaction": alloc::format!("0x{}", "ab".repeat(32)), "network": r["network"], "payer": p["payload"]["authorization"]["from"] }),
            )
        }
    }
    struct At(u64);
    impl Clock for At {
        fn now(&self) -> u64 {
            self.0
        }
    }

    /// The upfront payment of the PHP scenarios (nonce 30), its offer and its ledger key.
    fn upfront() -> (Value, Value, String) {
        let doc: Value =
            serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
        let case = doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "upfront retry: run claim not released afterwards")
            .unwrap();
        let header = case["steps"][0]["step"]["header"].as_str().unwrap();
        let payment = headers::decode(header).unwrap();
        let key = settlement::key(&payment).unwrap();
        (Value::String(header.into()), case["offers"][0].clone(), key)
    }

    fn charged_not_run() -> Value {
        json!({ "status": "settled", "receipt": { "success": true, "transaction": alloc::format!("0x{}", "cd".repeat(32)), "network": "eip155:84532" }, "handler_ran": false })
    }

    fn run(ledger: &Racy, header: &Value, offer: &Value, runs: &Rc<RefCell<u32>>) -> Response {
        let ofac = Ofac::off();
        let seller = Seller {
            ledger,
            facilitator: &Ok200,
            clock: &At(1_800_000_000),
            ofac: &ofac,
            listeners: &[],
            events: None,
            lookup: None,
            stop: None,
        };
        let offers = [offer.clone()];
        let runs = runs.clone();
        seller
            .process(
                &Request {
                    accepts: Some(&offers),
                    resource: &json!({}),
                    payment: header.as_str(),
                    keep: true,
                },
                move || {
                    *runs.borrow_mut() += 1;
                    Ok(Response::new(200, "energy"))
                },
            )
            .unwrap()
    }

    /// Charged upfront, but by the second read (under the run claim) the state is gone (expired): the
    /// payment is admitted as new, and the run claim is let go.
    #[test]
    fn the_state_vanishes_between_the_two_reads() {
        let (header, offer, key) = upfront();
        let ledger = Racy::default();
        *ledger.gets.borrow_mut() = alloc::vec![Some(charged_not_run()), None];
        let runs = Rc::new(RefCell::new(0));
        let r = run(&ledger, &header, &offer, &runs);
        assert_eq!(r.status, 200);
        assert_eq!(*runs.borrow(), 1);
        assert!(
            ledger
                .releases
                .borrow()
                .contains(&alloc::format!("{RUN}{key}")),
            "run claim released"
        );
    }

    /// By the second read another retry already delivered: replayed, the handler does not run again.
    #[test]
    fn another_retry_delivered_in_between() {
        let (header, offer, key) = upfront();
        let ledger = Racy::default();
        let mut delivered = charged_not_run();
        delivered["status"] = json!("delivered");
        delivered["response"] =
            json!({ "status": 200, "headers": {}, "body": headers::base64(b"kept") });
        *ledger.gets.borrow_mut() = alloc::vec![Some(charged_not_run()), Some(delivered)];
        let runs = Rc::new(RefCell::new(0));
        let r = run(&ledger, &header, &offer, &runs);
        assert_eq!((r.status, r.body.as_slice()), (200, b"kept".as_slice()));
        assert_eq!(*runs.borrow(), 0);
        assert!(
            ledger
                .releases
                .borrow()
                .contains(&alloc::format!("{RUN}{key}"))
        );
    }

    /// A sale releases only what it holds: no run claim, no payment claim.
    #[test]
    fn a_sale_releases_only_what_it_holds() {
        let (header, offer, _) = upfront();
        let ledger = Racy::default();
        let ofac = Ofac::off();
        let seller = Seller {
            ledger: &ledger,
            facilitator: &Ok200,
            clock: &At(1_800_000_000),
            ofac: &ofac,
            listeners: &[],
            events: None,
            lookup: None,
            stop: None,
        };
        let payment = headers::decode(header.as_str().unwrap()).unwrap();
        let sale = Sale::new(&seller, &payment, &offer);
        sale.end_run();
        sale.free();
        sale.abandon(None);
        assert!(ledger.releases.borrow().is_empty());
    }

    /// An offer on a chain family this seller does not verify (PHP throws a LogicException, a 500).
    #[test]
    fn an_offer_no_scheme_verifies_is_refused() {
        let (header, mut offer, _) = upfront();
        offer["network"] = json!("solana:devnet");
        let ledger = Racy::default();
        let header_value = {
            let mut p = headers::decode(header.as_str().unwrap()).unwrap();
            p["accepted"]["network"] = json!("solana:devnet");
            Value::String(headers::encode(&p))
        };
        let runs = Rc::new(RefCell::new(0));
        let r = run(&ledger, &header_value, &offer, &runs);
        assert_eq!(r.status, 402);
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["error"],
            "unsupported_scheme"
        );
        assert_eq!(*runs.borrow(), 0);
    }
}
