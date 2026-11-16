//! The seller against PHP's own answers: each scenario in `conformance/vectors/sale.json` was run through
//! the PHP `X402Middleware` with a scripted facilitator, handler and ledger. Same scripts here, same
//! answers expected: status, error, headers, which callbacks ran, the outcome events and the ledger after.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use quebracho_x402::headers;
use quebracho_x402::ports::{
    AddressListener, Clock, Event, Events, Facilitator, FacilitatorError, Ledger,
    LedgerUnavailable, ListFailed, Lookup, LookupFailed, Pause,
};
use quebracho_x402::screening::Ofac;
use quebracho_x402::seller::{HandlerFailed, Request, Response, Seller};
use serde_json::{Value, json};

#[derive(Default)]
struct ScriptedLedger {
    states: RefCell<BTreeMap<String, Value>>,
    open: RefCell<BTreeMap<String, Value>>,
    fail: RefCell<Vec<Value>>,
    /// Writing a state with this status engages the stop switch (a person pressing it mid-sale).
    stop_on: RefCell<Option<Value>>,
    stop: Rc<Cell<bool>>,
}

impl ScriptedLedger {
    fn failing(&self, op: &str, state: Option<&Value>) -> Result<(), LedgerUnavailable> {
        for f in self.fail.borrow_mut().iter_mut() {
            if f["op"] == op
                && (f.get("status").is_none() || state.map(|s| &s["status"]) == f.get("status"))
            {
                // 'skip': let that many matching calls through first.
                let skip = f.get("skip").and_then(Value::as_u64).unwrap_or(0);
                if skip > 0 {
                    f["skip"] = json!(skip - 1);
                    continue;
                }
                return Err(LedgerUnavailable);
            }
        }
        Ok(())
    }
}

impl Ledger for ScriptedLedger {
    fn claim(&self, key: &str, _ttl: u64) -> Result<bool, LedgerUnavailable> {
        self.failing("claim", None)?;
        let mut s = self.states.borrow_mut();
        if s.contains_key(key) {
            return Ok(false);
        }
        s.insert(key.into(), json!({ "status": "claimed" }));
        Ok(true)
    }
    fn get(&self, key: &str) -> Result<Option<Value>, LedgerUnavailable> {
        self.failing("get", None)?;
        Ok(self.states.borrow().get(key).cloned())
    }
    fn put(&self, key: &str, state: &Value, _ttl: u64) -> Result<(), LedgerUnavailable> {
        self.failing("put", Some(state))?;
        self.states.borrow_mut().insert(key.into(), state.clone());
        if self.stop_on.borrow().as_ref() == Some(&state["status"]) {
            self.stop.set(true);
        }
        Ok(())
    }
    fn release(&self, key: &str) -> Result<(), LedgerUnavailable> {
        self.failing("release", None)?;
        self.states.borrow_mut().remove(key);
        self.open.borrow_mut().remove(key);
        Ok(())
    }
    fn open(&self, key: &str, reference: &Value, _ttl: u64) -> Result<(), LedgerUnavailable> {
        self.failing("open", None)?;
        self.open.borrow_mut().insert(key.into(), reference.clone());
        Ok(())
    }
    fn open_keys(&self, limit: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
        Ok(self
            .open
            .borrow()
            .iter()
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
    fn close(&self, key: &str) -> Result<(), LedgerUnavailable> {
        self.failing("close", None)?;
        self.open.borrow_mut().remove(key);
        Ok(())
    }
}

#[derive(Default)]
struct ScriptedFacilitator {
    verify: RefCell<Value>,
    settle: RefCell<Value>,
    verifies: Cell<u32>,
    settles: Cell<u32>,
}

impl Facilitator for ScriptedFacilitator {
    fn verify(&self, _payment: &Value, _req: &Value) -> Result<Value, FacilitatorError> {
        self.verifies.set(self.verifies.get() + 1);
        match &*self.verify.borrow() {
            Value::Null => Ok(json!({ "isValid": true })),
            Value::String(s) if s == "unavailable" => Err(FacilitatorError::Unavailable),
            Value::String(s) if s == "throw" => Err(FacilitatorError::Other),
            reason => Ok(json!({ "isValid": false, "invalidReason": reason })),
        }
    }
    fn settle(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError> {
        self.settles.set(self.settles.get() + 1);
        match &*self.settle.borrow() {
            Value::String(s) if s == "unavailable" => Err(FacilitatorError::Unavailable),
            Value::String(s) if s == "throw" => Err(FacilitatorError::Other),
            Value::String(s) if s == "mock" => Ok(json!({
                "success": true,
                "transaction": format!("0x{}", "ab".repeat(32)),
                "network": req["network"],
                "payer": payment["payload"]["authorization"]["from"],
            })),
            receipt => Ok(receipt.clone()),
        }
    }
}

struct FixedClock(u64);
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

#[derive(Default)]
struct Switch(Rc<Cell<bool>>);
impl Pause for Switch {
    fn engaged(&self) -> bool {
        self.0.get()
    }
}

#[derive(Default)]
struct ScriptedLookup(RefCell<Value>);
impl Lookup for ScriptedLookup {
    fn lookup(
        &self,
        _state: &Value,
        _payment: &Value,
        _req: &Value,
    ) -> Result<Option<Value>, LookupFailed> {
        if *self.0.borrow() == json!("throw") {
            return Err(LookupFailed);
        }
        Ok(Some(self.0.borrow().clone()).filter(|v| !v.is_null()))
    }
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Value>>);
impl Events for Recorder {
    fn report(&self, event: &Event<'_>) {
        match event {
            Event::Outcome { status, reason, .. } => self
                .0
                .borrow_mut()
                .push(json!({ "status": status, "reason": reason })),
            Event::Fault { op, .. } => self
                .0
                .borrow_mut()
                .push(json!({ "status": "fault", "reason": op })),
            _ => {}
        }
    }
}

struct Deny(String);
impl AddressListener for Deny {
    fn check(
        &self,
        _role: &str,
        _network: &str,
        _address: &str,
        _req: &Value,
    ) -> Result<Option<String>, ListFailed> {
        Ok(Some(self.0.clone()))
    }
}

/// A body as PHP's scenario recorded it: over 4 KiB as its SHA-256 and length.
fn recorded(bytes: &[u8]) -> Value {
    if bytes.len() > 4096 {
        let hash: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return json!({ "sha256": hash, "length": bytes.len() });
    }
    body(bytes)
}

/// The body as JSON when it is JSON, else as text: PHP and serde order keys differently.
fn body(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).into()))
}

#[test]
fn sale_scenarios_match_php() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
    let mut scenarios = 0;
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ledger = ScriptedLedger::default();
        for p in case["preset"].as_array().unwrap() {
            ledger
                .states
                .borrow_mut()
                .insert(p["slot"].as_str().unwrap().into(), p["state"].clone());
        }
        let facilitator = ScriptedFacilitator::default();
        let clock = FixedClock(case["now"].as_u64().unwrap());
        let sanctioned: Vec<&str> = case["sanctioned"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let ofac = Ofac::from_snapshot(
            &json!({ "published": "2999-01-01T00:00:00Z", "addresses": { "ETH": sanctioned } })
                .to_string(),
        );
        let deny = case["deny"].as_str().map(|r| Deny(r.into()));
        let listeners: Vec<&dyn AddressListener> =
            deny.iter().map(|d| d as &dyn AddressListener).collect();
        let events = Recorder::default();
        let lookup = ScriptedLookup::default();
        let stop = Switch(ledger.stop.clone());
        let offers: Vec<Value> = case["offers"].as_array().unwrap().clone();

        for (i, expected) in case["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name}, step {}", i + 1);
            let step = &expected["step"];
            *facilitator.verify.borrow_mut() = step.get("verify").cloned().unwrap_or(Value::Null);
            *facilitator.settle.borrow_mut() = step.get("settle").cloned().unwrap_or(json!("mock"));
            *ledger.fail.borrow_mut() = step
                .get("fail")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            *lookup.0.borrow_mut() = step["lookup"].clone();
            *ledger.stop_on.borrow_mut() = step.get("stop_on").cloned();
            // PHP passes no lookup at all when the step has none.
            let seller = Seller {
                ledger: &ledger,
                facilitator: &facilitator,
                clock: &clock,
                ofac: &ofac,
                listeners: &listeners,
                events: Some(&events),
                lookup: (!step["lookup"].is_null()).then_some(&lookup as &dyn Lookup),
                stop: Some(&stop),
            };
            stop.0
                .set(step.get("stop").and_then(Value::as_bool).unwrap_or(false));
            events.0.borrow_mut().clear();
            let (v0, s0) = (facilitator.verifies.get(), facilitator.settles.get());
            let handler_calls = Cell::new(0);
            let script = &step["handler"];
            let handler = || {
                handler_calls.set(handler_calls.get() + 1);
                if script.get("stop").is_some() {
                    stop.0.set(true);
                }
                if script.get("throw").is_some() {
                    return Err(HandlerFailed);
                }
                let content = if script.get("big").is_some() {
                    vec![b'x'; 1_048_577]
                } else {
                    script["body"].as_str().unwrap().as_bytes().to_vec()
                };
                let mut r = Response::new(script["status"].as_u64().unwrap() as u16, content)
                    .with_header("Content-Type", "application/json");
                if let Some(Value::Object(h)) = script.get("headers") {
                    for (name, values) in h {
                        for v in values
                            .as_array()
                            .cloned()
                            .unwrap_or_else(|| vec![values.clone()])
                        {
                            r.headers.push((name.clone(), v.as_str().unwrap().into()));
                        }
                    }
                }
                Ok(r)
            };
            let request = Request {
                accepts: Some(&offers),
                resource: &case["resource"],
                payment: step.get("header").and_then(Value::as_str),
                keep: step.get("keep").and_then(Value::as_bool).unwrap_or(true),
            };
            let result = seller.process(&request, handler);
            let want = &expected["result"];
            match result {
                Err(HandlerFailed) => assert_eq!(
                    want["threw"],
                    json!(true),
                    "{at}: Rust failed, PHP answered {want}"
                ),
                Ok(r) => {
                    assert_eq!(json!(r.status), want["status"], "{at}: status");
                    let want_body = match &want["body"] {
                        Value::String(text) => body(text.as_bytes()),
                        other => other.clone(),
                    };
                    assert_eq!(recorded(&r.body), want_body, "{at}: body");
                    let decoded = |h: &str| {
                        r.header(h)
                            .map(|v| headers::decode(v).expect("decodes"))
                            .unwrap_or(Value::Null)
                    };
                    assert_eq!(
                        decoded(headers::REQUIRED),
                        want["payment_required"],
                        "{at}: PAYMENT-REQUIRED"
                    );
                    assert_eq!(
                        decoded(headers::RESPONSE),
                        want["payment_response"],
                        "{at}: PAYMENT-RESPONSE"
                    );
                    assert_eq!(
                        r.header("Retry-After")
                            .map(String::from)
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                        want["retry_after"],
                        "{at}: Retry-After"
                    );
                }
            }
            assert_eq!(
                json!(handler_calls.get()),
                expected["handler_calls"],
                "{at}: handler calls"
            );
            assert_eq!(
                json!(facilitator.verifies.get() - v0),
                expected["verify_calls"],
                "{at}: verify calls"
            );
            assert_eq!(
                json!(facilitator.settles.get() - s0),
                expected["settle_calls"],
                "{at}: settle calls"
            );
            assert_eq!(
                Value::Array(events.0.borrow().clone()),
                expected["outcomes"],
                "{at}: events"
            );
            let view: serde_json::Map<String, Value> = ledger
                .states
                .borrow()
                .iter()
                .map(|(k, s)| {
                    (k.clone(), json!({
                        "status": s["status"],
                        "response": s.get("response").is_some(),
                        "handler_ran": s.get("handler_ran").cloned().unwrap_or(Value::Null),
                        "receipt_success": s.pointer("/receipt/success").cloned().unwrap_or(Value::Null),
                    }))
                })
                .collect();
            assert_eq!(Value::Object(view), expected["ledger"], "{at}: ledger");
            let open: Vec<Value> = ledger.open.borrow().keys().map(|k| json!(k)).collect();
            assert_eq!(Value::Array(open), expected["open"], "{at}: open entries");
        }
        scenarios += 1;
    }
    assert!(scenarios >= 30);
}

#[test]
fn a_free_request_runs_the_handler_untouched() {
    let ledger = ScriptedLedger::default();
    let ofac = Ofac::off();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &ScriptedFacilitator::default(),
        clock: &FixedClock(0),
        ofac: &ofac,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let r = seller
        .process(
            &Request {
                accepts: None,
                resource: &Value::Null,
                payment: None,
                keep: true,
            },
            || Ok(Response::new(200, "free")),
        )
        .unwrap();
    assert_eq!(r.body, b"free");
    assert!(ledger.states.borrow().is_empty());
}

#[test]
fn an_unreliable_clock_admits_nothing() {
    struct Unsure;
    impl Clock for Unsure {
        fn now(&self) -> u64 {
            1_800_000_000
        }
        fn reliable(&self) -> bool {
            false
        }
    }
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "paid: delivered once, the retry is replayed")
        .unwrap();
    let ledger = ScriptedLedger::default();
    let facilitator = ScriptedFacilitator::default();
    *facilitator.settle.borrow_mut() = json!("mock");
    let ofac = Ofac::off();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &Unsure,
        ofac: &ofac,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let offers = case["offers"].as_array().unwrap().clone();
    let request = Request {
        accepts: Some(&offers),
        resource: &case["resource"],
        payment: case["steps"][0]["step"]["header"].as_str(),
        keep: true,
    };
    let r = seller
        .process(&request, || panic!("the handler must not run"))
        .unwrap();
    assert_eq!(r.status, 503);
    assert_eq!(facilitator.verifies.get(), 0);
    assert!(ledger.states.borrow().is_empty());
}

/// Two copies of one payment racing: both read an empty ledger, only one wins the atomic claim. The loser
/// is refused (`duplicate_settlement`) and its handler never runs (threat T1).
#[test]
fn a_racing_copy_loses_the_claim_and_runs_nothing() {
    struct Raced(ScriptedLedger);
    impl Ledger for Raced {
        fn claim(&self, _key: &str, _ttl: u64) -> Result<bool, LedgerUnavailable> {
            Ok(false) // the other copy claimed it between our read and our claim
        }
        fn get(&self, _key: &str) -> Result<Option<Value>, LedgerUnavailable> {
            Ok(None)
        }
        fn put(&self, k: &str, s: &Value, t: u64) -> Result<(), LedgerUnavailable> {
            self.0.put(k, s, t)
        }
        fn release(&self, k: &str) -> Result<(), LedgerUnavailable> {
            self.0.release(k)
        }
        fn open(&self, k: &str, r: &Value, t: u64) -> Result<(), LedgerUnavailable> {
            self.0.open(k, r, t)
        }
        fn open_keys(&self, l: usize) -> Result<Vec<(String, Value)>, LedgerUnavailable> {
            self.0.open_keys(l)
        }
        fn close(&self, k: &str) -> Result<(), LedgerUnavailable> {
            self.0.close(k)
        }
    }
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "paid: delivered once, the retry is replayed")
        .unwrap();
    let ledger = Raced(ScriptedLedger::default());
    let facilitator = ScriptedFacilitator::default();
    let ofac = Ofac::off();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &FixedClock(1_800_000_000),
        ofac: &ofac,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let offers = case["offers"].as_array().unwrap().clone();
    let request = Request {
        accepts: Some(&offers),
        resource: &case["resource"],
        payment: case["steps"][0]["step"]["header"].as_str(),
        keep: true,
    };
    let r = seller
        .process(&request, || {
            panic!("the losing copy must not run the handler")
        })
        .unwrap();
    assert_eq!(r.status, 402);
    assert_eq!(body(&r.body)["error"], "duplicate_settlement");
    assert_eq!(facilitator.settles.get(), 0);
}
