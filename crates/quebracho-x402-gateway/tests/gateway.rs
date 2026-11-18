//! The gateway against the PHP conformance vectors: a real signed payment, and the failures that
//! matter. Each test starts from a vector case so the payment is the same one PHP produced.

use quebracho_x402::headers;
use quebracho_x402::ports::{Clock, Facilitator, FacilitatorError, Pause};
use quebracho_x402::screening::Ofac;
use quebracho_x402::seller::Seller;
use quebracho_x402::settlement::MockFacilitator;
use quebracho_x402_gateway::{
    ChargeOutcome, ChargePoint, ChargeRequest, ConfigError, ConnectorStatus, Gateway,
    GatewayConfig, MAX_KWH, MemoryLedger, RateLimit, SessionState, SimulatedChargePoint,
    StopReason,
};
use serde_json::{Value, json};

const HAPPY: &str = "paid: delivered once, the retry is replayed";

fn case(name: &str) -> Value {
    let doc: Value =
        serde_json::from_str(include_str!("../../../conformance/vectors/sale.json")).unwrap();
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

fn offer(case: &Value) -> &Value {
    &case["offers"][0]
}

fn header(case: &Value) -> &str {
    case["steps"][0]["step"]["header"].as_str().unwrap()
}

fn now(case: &Value) -> u64 {
    case["now"].as_u64().unwrap()
}

fn config(offer: &Value) -> GatewayConfig {
    GatewayConfig {
        network: offer["network"].as_str().unwrap().into(),
        asset: offer["asset"].as_str().unwrap().into(),
        pay_to: offer["payTo"].as_str().unwrap().into(),
        token_name: offer["extra"]["name"].as_str().unwrap().into(),
        token_version: offer["extra"]["version"].as_str().unwrap().into(),
        price_per_kwh: offer["amount"].as_str().unwrap().parse().unwrap(),
        max_timeout_seconds: offer["maxTimeoutSeconds"].as_u64().unwrap(),
        resource_url: "https://device.test/charging/1".into(),
    }
}

struct Parts<'a> {
    case: &'a Value,
    ledger: &'a MemoryLedger,
    facilitator: &'a dyn Facilitator,
    clock: &'a At,
    ofac: &'a Ofac,
    charge_point: &'a SimulatedChargePoint,
    stop: Option<&'a dyn Pause>,
    rate: Option<&'a dyn RateLimit>,
}

fn gateway(parts: Parts<'_>) -> Gateway<'_> {
    let seller = Seller {
        ledger: parts.ledger,
        facilitator: parts.facilitator,
        clock: parts.clock,
        ofac: parts.ofac,
        listeners: &[],
        events: None,
        lookup: None,
        stop: parts.stop,
    };
    let gateway = Gateway::new(
        seller,
        parts.charge_point,
        parts.clock,
        config(offer(parts.case)),
    );
    match parts.rate {
        Some(rate) => gateway.with_rate_limit(rate),
        None => gateway,
    }
}

fn setup<'a>(
    case: &'a Value,
    ledger: &'a MemoryLedger,
    facilitator: &'a dyn Facilitator,
    clock: &'a At,
    ofac: &'a Ofac,
    charge_point: &'a SimulatedChargePoint,
) -> Gateway<'a> {
    gateway(Parts {
        case,
        ledger,
        facilitator,
        clock,
        ofac,
        charge_point,
        stop: None,
        rate: None,
    })
}

struct At(u64);

impl Clock for At {
    fn now(&self) -> u64 {
        self.0
    }
}

struct FailingFacilitator;

impl Facilitator for FailingFacilitator {
    fn verify(&self, _payment: &Value, _req: &Value) -> Result<Value, FacilitatorError> {
        Ok(json!({ "isValid": true }))
    }

    fn settle(&self, _payment: &Value, _req: &Value) -> Result<Value, FacilitatorError> {
        Ok(json!({ "success": false, "errorReason": "insufficient_funds" }))
    }
}

struct Engaged(bool);

impl Pause for Engaged {
    fn engaged(&self) -> bool {
        self.0
    }
}

struct DenyAll;

impl RateLimit for DenyAll {
    fn allow(&self, _key: &str, _now: u64) -> bool {
        false
    }
}

fn error_of(response: &quebracho_x402::seller::Response) -> String {
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    body["error"].as_str().unwrap_or_default().into()
}

fn started() -> SimulatedChargePoint {
    let cp = SimulatedChargePoint::new(1);
    cp.plug(1);
    cp
}

#[test]
fn a_paid_charge_starts_meters_and_stops_at_the_block() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Charging { session, response } = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 200);
    assert!(
        response.header(headers::RESPONSE).is_some(),
        "the receipt goes back to the buyer"
    );
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Charging));
    assert_eq!(session.limit_wh, 1_000);
    assert_eq!(session.amount, "10000");
    assert_eq!(session.payer, "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");

    cp.advance(1, 1_000);
    assert!(gateway.should_stop(&session).unwrap());
    let mut session = session;
    let ack = gateway
        .stop(&mut session, StopReason::FullyCharged)
        .unwrap();
    assert_eq!(ack.energy_wh, 1_000);
    assert_eq!(session.state, SessionState::Closed);
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
}

#[test]
fn a_retry_after_the_charge_is_replayed_without_starting_again() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Charging { mut session, .. } = outcome else {
        panic!("{outcome:?}")
    };
    cp.advance(1, 1_000);
    gateway
        .stop(&mut session, StopReason::FullyCharged)
        .unwrap();
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Replayed { response } = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 200);
    assert!(
        response.header(headers::RESPONSE).is_some(),
        "the original receipt is replayed"
    );
    assert_eq!(
        cp.status(1),
        Ok(ConnectorStatus::Preparing),
        "no second charge"
    );
    assert_eq!(cp.meter(1).unwrap().energy_wh, 1_000);
}

#[test]
fn no_payment_is_a_402_and_nothing_starts() {
    let case = case(HAPPY);
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: None,
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 402);
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
    assert_eq!(cp.meter(1).unwrap().energy_wh, 0);
}

#[test]
fn a_tampered_amount_is_refused_offline() {
    let case = case("tampered amount: refused offline");
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 402);
    assert_eq!(
        error_of(&response),
        "invalid_exact_evm_payload_authorization_value_mismatch"
    );
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
}

#[test]
fn a_sanctioned_payer_is_refused_before_the_charger() {
    let case = case("sanctioned payer");
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::from_snapshot(
        r#"{"published":"2026-01-01T00:00:00Z","addresses":{"ETH":["0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"]}}"#,
    );
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 402);
    assert_eq!(error_of(&response), "address_sanctioned");
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
}

#[test]
fn a_charger_that_rejects_the_start_frees_the_claim() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    cp.reject_start(1, true);
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Failed {
        session,
        response,
        reason,
    } = outcome
    else {
        panic!("{outcome:?}")
    };
    assert!(session.is_none());
    assert_eq!(response.status, 502);
    assert_eq!(reason, "charge_point_rejected");
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
    assert!(
        ledger.is_empty(),
        "a start that never happened frees the claim"
    );
}

#[test]
fn a_failed_settle_stops_the_charge() {
    let case = case("settle refused clearly: withheld, claim freed");
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = FailingFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Failed {
        session,
        response,
        reason,
    } = outcome
    else {
        panic!("{outcome:?}")
    };
    let session = session.expect("the charge started before the settle");
    assert_eq!(session.state, SessionState::Closed);
    assert_eq!(response.status, 402);
    assert_eq!(reason, "settlement_failed");
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
    assert!(ledger.is_empty(), "a clear refusal frees the claim");
}

#[test]
fn the_emergency_stop_refuses_before_the_charger() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let pause = Engaged(true);
    let gateway = gateway(Parts {
        case: &case,
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &ofac,
        charge_point: &cp,
        stop: Some(&pause),
        rate: None,
    });

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 503);
    assert_eq!(error_of(&response), "payments_paused");
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
}

#[test]
fn a_rate_limited_payer_never_reaches_the_seller() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let limit = DenyAll;
    let gateway = gateway(Parts {
        case: &case,
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &ofac,
        charge_point: &cp,
        stop: None,
        rate: Some(&limit),
    });

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 429);
    assert_eq!(error_of(&response), "rate_limited");
    assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
    assert!(ledger.is_empty());
}

#[test]
fn a_busy_connector_is_a_409() {
    let case = case(HAPPY);
    let header = header(&case).to_string();
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    cp.start(1, "already", 1_000).unwrap();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(&header),
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 409);
    assert_eq!(error_of(&response), "connector_busy");
}

#[test]
fn zero_kwh_is_refused_before_anything_else() {
    let case = case(HAPPY);
    let ledger = MemoryLedger::default();
    let facilitator = MockFacilitator;
    let clock = At(now(&case));
    let ofac = Ofac::off();
    let cp = started();
    let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 0,
        payment: None,
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(response.status, 400);
    assert_eq!(error_of(&response), "kwh_must_be_positive");
    assert!(ledger.is_empty());
}

/// Inputs that cross the gateway boundary, one test per rule. A payment that is not canonical or not
/// the one the seller offered never reaches the charger and never writes the ledger.
mod sanitization {
    use std::cell::Cell;

    use super::*;

    fn payment_of(case: &Value) -> Value {
        headers::decode(header(case)).expect("the vector header decodes")
    }

    fn assert_refused(name: &str, mutate: impl FnOnce(&mut Value), status: u16, error: &str) {
        let case = case(HAPPY);
        let mut payment = payment_of(&case);
        mutate(&mut payment);
        let header = headers::encode(&payment);
        let ledger = MemoryLedger::default();
        let facilitator = MockFacilitator;
        let clock = At(now(&case));
        let ofac = Ofac::off();
        let cp = started();
        let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some(&header),
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{name}: {outcome:?}");
        };
        assert_eq!(response.status, status, "{name}");
        assert_eq!(error_of(&response), error, "{name}");
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing), "{name}");
        assert!(ledger.is_empty(), "{name}");
    }

    fn assert_charging(name: &str, mutate: impl FnOnce(&mut Value)) {
        let case = case(HAPPY);
        let mut payment = payment_of(&case);
        mutate(&mut payment);
        let header = headers::encode(&payment);
        let ledger = MemoryLedger::default();
        let facilitator = MockFacilitator;
        let clock = At(now(&case));
        let ofac = Ofac::off();
        let cp = started();
        let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some(&header),
        });
        let ChargeOutcome::Charging { session, .. } = outcome else {
            panic!("{name}: {outcome:?}");
        };
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Charging), "{name}");
        assert_eq!(session.amount, "10000", "{name}");
        assert_eq!(session.limit_wh, 1_000, "{name}");
    }

    struct CountingRateLimit {
        calls: Cell<u32>,
    }

    impl RateLimit for CountingRateLimit {
        fn allow(&self, _key: &str, _now: u64) -> bool {
            self.calls.set(self.calls.get() + 1);
            true
        }
    }

    #[test]
    fn the_config_is_validated_once() {
        let case = case(HAPPY);
        let good = config(offer(&case));
        assert_eq!(good.validate(), Ok(()));

        let mut bad = good.clone();
        bad.network = "solana:devnet".into();
        assert_eq!(bad.validate(), Err(ConfigError::Network));
        bad.network = "eip155:0".into();
        assert_eq!(bad.validate(), Err(ConfigError::Network));
        bad.network = "eip155:084532".into();
        assert_eq!(bad.validate(), Err(ConfigError::Network));

        let mut bad = good.clone();
        bad.asset = "0x123".into();
        assert_eq!(bad.validate(), Err(ConfigError::Asset));

        let mut bad = good.clone();
        bad.pay_to = "000000000000000000000000000000000000dEaD".into();
        assert_eq!(bad.validate(), Err(ConfigError::PayTo));

        for name in [
            "".to_string(),
            " USDC".to_string(),
            "USDC ".to_string(),
            "x".repeat(65),
        ] {
            let mut bad = good.clone();
            bad.token_name = name.clone();
            assert_eq!(bad.validate(), Err(ConfigError::TokenName), "{name:?}");
        }
        for version in [
            "".to_string(),
            " 2".to_string(),
            "2 ".to_string(),
            "x".repeat(65),
        ] {
            let mut bad = good.clone();
            bad.token_version = version.clone();
            assert_eq!(
                bad.validate(),
                Err(ConfigError::TokenVersion),
                "{version:?}"
            );
        }

        let mut bad = good.clone();
        bad.price_per_kwh = 0;
        assert_eq!(bad.validate(), Err(ConfigError::Price));

        for timeout in [0, 601] {
            let mut bad = good.clone();
            bad.max_timeout_seconds = timeout;
            assert_eq!(bad.validate(), Err(ConfigError::MaxTimeout), "{timeout}");
        }

        for url in [
            "http://device.test/charging/1",
            "https://",
            "https:///",
            "https:// device.test",
        ] {
            let mut bad = good.clone();
            bad.resource_url = url.into();
            assert_eq!(bad.validate(), Err(ConfigError::ResourceUrl), "{url}");
        }
    }

    #[test]
    fn the_transport_refuses_bad_headers_before_the_charger() {
        let case = case(HAPPY);
        let ledger = MemoryLedger::default();
        let facilitator = MockFacilitator;
        let clock = At(now(&case));
        let ofac = Ofac::off();
        let cp = started();
        let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

        let too_big = "A".repeat(headers::MAX_PAYMENT_HEADER + 1);
        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some(&too_big),
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 431);
        assert_eq!(error_of(&response), "The payment header is too large.");

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some("not base64"),
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 400);
        assert_eq!(
            error_of(&response),
            "The payment header is not base64-encoded JSON."
        );

        let array = headers::encode(&json!([1, 2, 3]));
        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some(&array),
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 402);
        assert_eq!(
            error_of(&response),
            "The payment matches none of the accepted offers"
        );

        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        assert!(ledger.is_empty());
    }

    #[test]
    fn every_bad_payment_field_is_refused_before_the_charger() {
        assert_refused(
            "x402Version",
            |p| p["x402Version"] = json!(1),
            402,
            "invalid_x402_version",
        );
        assert_refused(
            "accepted scheme",
            |p| p["accepted"]["scheme"] = json!("upto"),
            402,
            "The payment matches none of the accepted offers",
        );
        assert_refused(
            "accepted network",
            |p| p["accepted"]["network"] = json!("eip155:1"),
            402,
            "The payment matches none of the accepted offers",
        );
        assert_refused(
            "accepted amount",
            |p| p["accepted"]["amount"] = json!("1"),
            402,
            "invalid_payload",
        );
        assert_refused(
            "accepted asset",
            |p| p["accepted"]["asset"] = json!("0x0000000000000000000000000000000000000001"),
            402,
            "invalid_payload",
        );
        assert_refused(
            "accepted payTo",
            |p| p["accepted"]["payTo"] = json!("0x0000000000000000000000000000000000000001"),
            402,
            "invalid_payload",
        );
        assert_refused(
            "accepted not an object",
            |p| p["accepted"] = json!("x"),
            402,
            "The payment matches none of the accepted offers",
        );
        assert_refused(
            "accepted missing",
            |p| {
                p.as_object_mut().unwrap().remove("accepted");
            },
            402,
            "The payment matches none of the accepted offers",
        );
        assert_refused(
            "payload missing",
            |p| {
                p.as_object_mut().unwrap().remove("payload");
            },
            402,
            "invalid_payload",
        );
        assert_refused(
            "authorization missing",
            |p| {
                p["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("authorization");
            },
            402,
            "invalid_payload",
        );
        assert_refused(
            "signature short",
            |p| p["payload"]["signature"] = json!("0x1234"),
            402,
            "invalid_payload",
        );
        assert_refused(
            "nonce short",
            |p| p["payload"]["authorization"]["nonce"] = json!("0x1234"),
            402,
            "invalid_payload",
        );
        assert_refused(
            "from not an address",
            |p| p["payload"]["authorization"]["from"] = json!("x".repeat(1_000)),
            402,
            "invalid_payload",
        );
        assert_refused(
            "to another address",
            |p| {
                p["payload"]["authorization"]["to"] =
                    json!("0x0000000000000000000000000000000000000001")
            },
            402,
            "invalid_exact_evm_payload_recipient_mismatch",
        );
        assert_refused(
            "value another amount",
            |p| p["payload"]["authorization"]["value"] = json!("1"),
            402,
            "invalid_exact_evm_payload_authorization_value_mismatch",
        );
        assert_refused(
            "validAfter in the future",
            |p| p["payload"]["authorization"]["validAfter"] = json!("9999999999"),
            402,
            "invalid_exact_evm_payload_authorization_valid_after",
        );
        assert_refused(
            "validBefore too long",
            |p| p["payload"]["authorization"]["validBefore"] = json!("9999999999"),
            402,
            "invalid_exact_evm_payload_authorization_valid_before",
        );
    }

    #[test]
    fn the_buyers_echo_cannot_change_the_flow_or_the_domain() {
        assert_charging("extra name", |p| {
            p["accepted"]["extra"]["name"] = json!("EVIL")
        });
        assert_charging("extra version", |p| {
            p["accepted"]["extra"]["version"] = json!("EVIL")
        });
        assert_charging("payment flow", |p| {
            p["accepted"]["extra"]["paymentFlow"] = json!("upfront")
        });
        assert_charging("asset transfer method", |p| {
            p["accepted"]["extra"]["assetTransferMethod"] = json!("evil")
        });
    }

    #[test]
    fn an_invalid_payer_is_not_a_rate_limit_key() {
        let case = case(HAPPY);
        let mut payment = payment_of(&case);
        payment["payload"]["authorization"]["from"] = json!("x".repeat(1_000));
        let header = headers::encode(&payment);
        let ledger = MemoryLedger::default();
        let facilitator = MockFacilitator;
        let clock = At(now(&case));
        let ofac = Ofac::off();
        let cp = started();
        let limit = CountingRateLimit {
            calls: Cell::new(0),
        };
        let gateway = gateway(Parts {
            case: &case,
            ledger: &ledger,
            facilitator: &facilitator,
            clock: &clock,
            ofac: &ofac,
            charge_point: &cp,
            stop: None,
            rate: Some(&limit),
        });

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: 1,
            payment: Some(&header),
        });
        assert!(matches!(outcome, ChargeOutcome::Rejected(_)));
        assert_eq!(
            limit.calls.get(),
            0,
            "the invalid payer never becomes a key"
        );
        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        assert!(ledger.is_empty());
    }

    #[test]
    fn the_block_and_the_connector_are_sanitized() {
        let case = case(HAPPY);
        let ledger = MemoryLedger::default();
        let facilitator = MockFacilitator;
        let clock = At(now(&case));
        let ofac = Ofac::off();
        let cp = started();
        let gateway = setup(&case, &ledger, &facilitator, &clock, &ofac, &cp);

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: MAX_KWH + 1,
            payment: None,
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 400);
        assert_eq!(error_of(&response), "kwh_too_large");

        let outcome = gateway.charge(ChargeRequest {
            connector: 99,
            kwh: 1,
            payment: None,
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 503);
        assert_eq!(error_of(&response), "charge_point_unavailable");

        let outcome = gateway.charge(ChargeRequest {
            connector: 1,
            kwh: u64::MAX,
            payment: None,
        });
        let ChargeOutcome::Rejected(response) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(response.status, 400);
        assert_eq!(error_of(&response), "kwh_too_large");

        assert_eq!(cp.status(1), Ok(ConnectorStatus::Preparing));
        assert!(ledger.is_empty());
    }
}
