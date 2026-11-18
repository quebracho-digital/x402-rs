//! The paid charge, offline: no chain, no network, no keys. It uses the PHP conformance vector as the
//! buyer's signed payment, the mock facilitator and the simulated charger, so it runs anywhere.
//!
//! `cargo run -p quebracho-x402-gateway --bin demo`

use quebracho_x402::headers;
use quebracho_x402::ports::{Clock, Pause};
use quebracho_x402::screening::Ofac;
use quebracho_x402::seller::{Response, Seller};
use quebracho_x402::settlement::MockFacilitator;
use quebracho_x402_gateway::{
    ChargeOutcome, ChargePoint, ChargeRequest, ConnectorStatus, Gateway, GatewayConfig,
    MemoryLedger, SimulatedChargePoint, StopReason, TokenBucket,
};
use serde_json::Value;

const SALE: &str = include_str!("../../../../conformance/vectors/sale.json");
const HAPPY: &str = "paid: delivered once, the retry is replayed";

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

struct StopSwitch(bool);

impl Pause for StopSwitch {
    fn engaged(&self) -> bool {
        self.0
    }
}

fn show_outcome(label: &str, outcome: &ChargeOutcome) {
    match outcome {
        ChargeOutcome::Rejected(response) => show(label, response),
        other => println!("  {label}: unexpected {other:?}"),
    }
}

fn config(offer: &Value) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    Ok(GatewayConfig {
        network: offer["network"].as_str().ok_or("no network")?.into(),
        asset: offer["asset"].as_str().ok_or("no asset")?.into(),
        pay_to: offer["payTo"].as_str().ok_or("no payTo")?.into(),
        token_name: offer["extra"]["name"]
            .as_str()
            .ok_or("no token name")?
            .into(),
        token_version: offer["extra"]["version"]
            .as_str()
            .ok_or("no token version")?
            .into(),
        price_per_kwh: offer["amount"].as_str().ok_or("no amount")?.parse()?,
        max_timeout_seconds: offer["maxTimeoutSeconds"].as_u64().ok_or("no timeout")?,
        resource_url: "https://device.test/charging/1".into(),
    })
}

fn show(label: &str, response: &Response) {
    println!("  {label}: HTTP {}", response.status);
    if let Some(required) = response.header(headers::REQUIRED) {
        println!(
            "    {}: {} bytes (base64)",
            headers::REQUIRED,
            required.len()
        );
    }
    if let Some(receipt) = response.header(headers::RESPONSE) {
        match headers::decode(receipt) {
            Some(value) => println!("    {}: {}", headers::RESPONSE, value),
            None => println!("    {}: {}", headers::RESPONSE, receipt),
        }
    }
    println!(
        "    body: {}",
        String::from_utf8_lossy(&response.body).trim()
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|arg| arg == "--safety") {
        return safety();
    }
    let doc: Value = serde_json::from_str(SALE)?;
    let case = doc["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["name"] == HAPPY))
        .ok_or("the conformance vector has no happy case")?;
    let payment = case["steps"][0]["step"]["header"]
        .as_str()
        .ok_or("the case has no payment")?;
    let now = case["now"].as_u64().ok_or("the case has no clock")?;
    let offer = &case["offers"][0];

    let ledger = MemoryLedger::new();
    let facilitator = MockFacilitator;
    let clock = FixedClock(now);
    let ofac = Ofac::off();
    let charge_point = SimulatedChargePoint::new(1);
    charge_point.plug(1);

    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &ofac,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let config = config(offer)?;
    let gateway = Gateway::try_new(seller, &charge_point, &clock, config)
        .map_err(|e| format!("invalid config: {e:?}"))?;

    println!("x402 EV charging gateway: offline demo");
    println!("  vector: {HAPPY:?}");
    println!("  clock: {now}, connector 1, block 1 kWh");

    println!("\n1. A driver asks for 1 kWh without a payment");
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: None,
    });
    let ChargeOutcome::Rejected(response) = outcome else {
        return Err(format!("expected a 402, got {outcome:?}").into());
    };
    show("402", &response);
    println!("  the buyer gets the offer in {}", headers::REQUIRED);

    println!("\n2. The driver sends the signed payment");
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(payment),
    });
    let ChargeOutcome::Charging {
        mut session,
        response,
    } = outcome
    else {
        return Err(format!("expected a charge, got {outcome:?}").into());
    };
    show("200", &response);
    println!(
        "  session {}: {} Wh, amount {}, transaction {}",
        session.id, session.limit_wh, session.amount, session.transaction_id
    );
    println!(
        "  charger: {:?}",
        gateway.status(1).map_err(|e| format!("{e:?}"))?
    );

    println!("\n3. The meter runs");
    for (wh, label) in [(400, "after 400 Wh"), (600, "after 1000 Wh")] {
        charge_point.advance(1, wh);
        let meter = gateway.meter(&session).map_err(|e| format!("{e:?}"))?;
        println!(
            "  {label}: meter {} Wh, {} W, at {}",
            meter.energy_wh, meter.power_w, meter.at
        );
        println!(
            "  should stop: {}",
            gateway
                .should_stop(&session)
                .map_err(|e| format!("{e:?}"))?
        );
    }

    println!("\n4. The gateway stops at the block");
    let ack = gateway
        .stop(&mut session, StopReason::FullyCharged)
        .map_err(|e| format!("{e:?}"))?;
    println!("  delivered: {} Wh", ack.energy_wh);
    println!("  session: {:?}", session.state);
    println!(
        "  charger: {:?}",
        gateway.status(1).map_err(|e| format!("{e:?}"))?
    );

    println!("\n5. The same payment is retried");
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(payment),
    });
    match outcome {
        ChargeOutcome::Replayed { response } => {
            show("200 (replayed)", &response);
            let meter = gateway.meter(&session).map_err(|e| format!("{e:?}"))?;
            println!(
                "  no second charge; the meter still reads {} Wh",
                meter.energy_wh
            );
        }
        other => println!("  unexpected: {other:?}"),
    }

    println!(
        "\nDone. The seller verified the payment and the facilitator settled it; the seller never held a key."
    );
    Ok(())
}

/// The same valid payment under three policies: OFAC, the stop switch and the rate limit. The point is
/// that the payment is good and the charger still does not move.
fn safety() -> Result<(), Box<dyn std::error::Error>> {
    let doc: Value = serde_json::from_str(SALE)?;
    let case = doc["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["name"] == HAPPY))
        .ok_or("the conformance vector has no happy case")?;
    let payment = case["steps"][0]["step"]["header"]
        .as_str()
        .ok_or("the case has no payment")?;
    let now = case["now"].as_u64().ok_or("the case has no clock")?;
    let offer = &case["offers"][0];
    let config = config(offer)?;
    let clock = FixedClock(now);
    let facilitator = MockFacilitator;
    let charge_point = SimulatedChargePoint::new(1);
    charge_point.plug(1);

    println!("x402 gateway: safety cases");
    println!("  the payment is valid; only the policy changes");

    println!("\n1. OFAC: the payer is on the list");
    let sanctions = Ofac::from_snapshot(
        r#"{"published":"2026-01-01T00:00:00Z","addresses":{"ETH":["0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"]}}"#,
    );
    let ledger = MemoryLedger::new();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &sanctions,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let gateway = Gateway::try_new(seller, &charge_point, &clock, config.clone())
        .map_err(|e| format!("invalid config: {e:?}"))?;
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(payment),
    });
    show_outcome("OFAC", &outcome);
    assert_eq!(charge_point.status(1).unwrap(), ConnectorStatus::Preparing);
    println!("  charger: Preparing (no start)");

    println!("\n2. Emergency stop: the stop switch is engaged");
    let stop = StopSwitch(true);
    let sanctions = Ofac::off();
    let ledger = MemoryLedger::new();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &sanctions,
        listeners: &[],
        events: None,
        lookup: None,
        stop: Some(&stop),
    };
    let gateway = Gateway::try_new(seller, &charge_point, &clock, config.clone())
        .map_err(|e| format!("invalid config: {e:?}"))?;
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(payment),
    });
    show_outcome("stop", &outcome);
    assert_eq!(charge_point.status(1).unwrap(), ConnectorStatus::Preparing);
    println!("  charger: Preparing (no start)");

    println!("\n3. Rate limit: the payer has no tokens");
    let limit = TokenBucket::new(0, 0);
    let sanctions = Ofac::off();
    let ledger = MemoryLedger::new();
    let seller = Seller {
        ledger: &ledger,
        facilitator: &facilitator,
        clock: &clock,
        ofac: &sanctions,
        listeners: &[],
        events: None,
        lookup: None,
        stop: None,
    };
    let gateway = Gateway::try_new(seller, &charge_point, &clock, config)
        .map_err(|e| format!("invalid config: {e:?}"))?
        .with_rate_limit(&limit);
    let outcome = gateway.charge(ChargeRequest {
        connector: 1,
        kwh: 1,
        payment: Some(payment),
    });
    show_outcome("rate limit", &outcome);
    assert_eq!(charge_point.status(1).unwrap(), ConnectorStatus::Preparing);
    println!("  charger: Preparing (no start)");

    println!("\nNo charge started in any safety case.");
    Ok(())
}
