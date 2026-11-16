//! Any x402 facilitator by URL: `/verify`, `/settle`, `/supported` (port of `HttpFacilitator.php`).
//!
//! A settle counts only when it is consistent: a 2xx, `success: true`, a transaction (`0x` + 64 hex on
//! EVM), our network and, when the facilitator names one, the payer who signed. A settle that comes back
//! pending with a `paymentId` (Circle) is polled at `/status/{id}`.
//!
//! Checked against `conformance/vectors/facilitator.json`. Not ported: the deprecated `$seller` argument
//! and the `$headers` hook (both serve Circle's keyless mode, a later crate).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{Value, json};

use crate::field::{self, Rule};
use crate::php::{at, get};
use crate::ports::{Facilitator, FacilitatorError, Https, HttpsRequest, Sleep};

pub struct HttpFacilitator<'a> {
    http: &'a dyn Https,
    sleep: &'a dyn Sleep,
    url: String,
    bearer: Option<String>,
    poll_attempts: u32,
    poll_delay_seconds: u64,
}

/// The URL is not `https://` with a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotHttps;

impl<'a> HttpFacilitator<'a> {
    /// `url` is the facilitator's base URL, https only; `bearer` its API key, if it has one. A pending
    /// settle is polled 5 times, 1 second apart (PHP's defaults): change it with [`Self::polling`].
    pub fn new(
        http: &'a dyn Https,
        sleep: &'a dyn Sleep,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<Self, NotHttps> {
        let host = url
            .strip_prefix("https://")
            .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
        if host.is_none_or(str::is_empty) {
            return Err(NotHttps);
        }
        Ok(Self {
            http,
            sleep,
            url: url.trim_end_matches('/').to_string(),
            bearer: bearer.map(String::from),
            poll_attempts: 5,
            poll_delay_seconds: 1,
        })
    }

    /// How many `/status` queries at most, and the seconds between two. `attempts` 0 never waits: the
    /// payment stays `settlement_pending` with its `paymentId`, for the reconciler.
    pub fn polling(mut self, attempts: u32, delay_seconds: u64) -> Self {
        self.poll_attempts = attempts;
        self.poll_delay_seconds = delay_seconds;
        self
    }

    /// The `kinds` of `/supported`.
    pub fn supported(&self) -> Result<Vec<Value>, FacilitatorError> {
        match self.call("GET", "/supported", None)?.get("kinds") {
            Some(Value::Array(kinds)) => Ok(kinds.clone()),
            _ => Err(FacilitatorError::Unavailable),
        }
    }

    fn body(payment: &Value, req: &Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({ "x402Version": 2, "paymentPayload": payment, "paymentRequirements": req }),
        )
        .unwrap_or_default()
    }

    /// The facilitator's JSON. A non-2xx is an answer only when it says `isValid`/`success` false (a
    /// refusal); anything else is [`FacilitatorError::Unavailable`].
    fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Value, FacilitatorError> {
        let mut headers = Vec::new();
        if let Some(b) = &self.bearer {
            headers.push(("Authorization".into(), format!("Bearer {b}")));
        }
        if body.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        let request = HttpsRequest {
            method,
            url: format!("{}{path}", self.url),
            headers,
            body: body.unwrap_or_default(),
        };
        let response = self
            .http
            .send(&request)
            .map_err(|_| FacilitatorError::Unavailable)?;
        let out: Option<Value> = serde_json::from_slice(&response.body)
            .ok()
            .filter(|v: &Value| v.is_object() || v.is_array());
        match out {
            Some(out) if (200..300).contains(&response.status) => Ok(out),
            Some(out)
                if get(&out, "isValid") == Some(&Value::Bool(false))
                    || get(&out, "success") == Some(&Value::Bool(false)) =>
            {
                Ok(out)
            }
            _ => Err(FacilitatorError::Unavailable),
        }
    }

    /// Follows a pending answer (success not true, with a `paymentId`) at `/status`, then checks it.
    fn poll(&self, mut out: Value, payment: &Value, req: &Value) -> Value {
        let network = get(req, "network").cloned().unwrap_or(Value::Null);
        let id = at(&out, &["extensions", "settlement-status", "paymentId"])
            .and_then(Value::as_str)
            .map(String::from);
        let mut i = 0;
        while get(&out, "success") != Some(&Value::Bool(true))
            && id
                .as_deref()
                .is_some_and(|id| field::is(Rule::PaymentId, id))
            && i < self.poll_attempts
        {
            if i > 0 {
                self.sleep.sleep(self.poll_delay_seconds);
            }
            i += 1;
            let Ok(status) = self.call(
                "GET",
                &format!("/status/{}", id.as_deref().unwrap_or_default()),
                None,
            ) else {
                // Settled or not, the facilitator knows it by this id.
                break;
            };
            match get(&status, "status").and_then(Value::as_str) {
                Some("completed") => {
                    out = json!({
                        "success": true,
                        "transaction": get(&status, "transaction").cloned().unwrap_or(Value::Null),
                        "network": get(&status, "network").cloned().unwrap_or_else(|| network.clone()),
                        "payer": get(&status, "payer").or_else(|| get(&out, "payer")).cloned().unwrap_or(Value::Null),
                    });
                }
                Some("failed") => {
                    let reason = get(&status, "reason")
                        .and_then(Value::as_str)
                        .unwrap_or("settlement_failed");
                    return json!({ "success": false, "errorReason": reason, "transaction": "", "network": network });
                }
                _ => {}
            }
        }
        if get(&out, "success") != Some(&Value::Bool(true))
            && let Some(id) = id
        {
            // Still pending after polling: its id is what reconciles it.
            let tx = get(&out, "transaction")
                .and_then(Value::as_str)
                .unwrap_or_default();
            return json!({ "success": false, "errorReason": "settlement_pending", "transaction": tx, "network": network, "paymentId": id });
        }
        check_settle(out, payment, req)
    }
}

/// The consistency rule for a settle's answer; a refusal (success not true) comes back as it is.
pub fn check_settle(out: Value, payment: &Value, req: &Value) -> Value {
    if get(&out, "success") != Some(&Value::Bool(true)) {
        return out;
    }
    let network = get(req, "network")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tx = get(&out, "transaction").and_then(Value::as_str);
    let from = at(payment, &["payload", "authorization", "from"]);
    let payer = get(&out, "payer");
    let tx_ok = tx.is_some_and(|t| {
        if network.starts_with("eip155:") {
            field::is(Rule::Bytes32, t)
        } else {
            !t.is_empty()
        }
    });
    let payer_ok = match (payer, from) {
        (Some(p), Some(f)) => {
            crate::php::php_string(p).eq_ignore_ascii_case(&crate::php::php_string(f))
        }
        _ => true,
    };
    if tx_ok && get(&out, "network").and_then(Value::as_str) == Some(network) && payer_ok {
        return out;
    }
    json!({ "success": false, "errorReason": "invalid_settle_response", "transaction": tx.unwrap_or_default(), "network": network })
}

impl Facilitator for HttpFacilitator<'_> {
    fn verify(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError> {
        let out = self.call("POST", "/verify", Some(Self::body(payment, req)))?;
        if !matches!(get(&out, "isValid"), Some(Value::Bool(_))) {
            return Err(FacilitatorError::Unavailable);
        }
        Ok(out)
    }

    fn settle(&self, payment: &Value, req: &Value) -> Result<Value, FacilitatorError> {
        let out = self.call("POST", "/settle", Some(Self::body(payment, req)))?;
        Ok(self.poll(out, payment, req))
    }
}
