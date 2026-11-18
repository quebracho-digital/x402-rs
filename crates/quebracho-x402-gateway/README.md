# quebracho-x402-gateway

> **0.1, experimental.** Not audited. The OCPP wire adapter is still to come; this crate has the
> session state and the charge-point port, with a simulator for tests and the demo.

Sells EV charging with x402. The gateway is the x402 **seller** and the OCPP **server**: a driver pays
for a block of energy, the gateway starts the charger, reads the meter, stops at the block, and closes
the session with the meter reading on the receipt.

The first milestone is deliberately transport-free:

| Piece | What |
|---|---|
| [`ChargePoint`] | `status`, `start`, `stop`, `meter`. The OCPP adapter implements it; `SimulatedChargePoint` is for tests and the demo. |
| [`Session`] | One paid charge: connector, payer, amount, energy limit, transaction, start meter, state. |
| [`Gateway`] | Builds the offer, runs the core `Seller`, starts the charger, and stops it if the settle fails. |
| [`TokenBucket`] | An app-level rate limit per payer. |

The offer is always `extra.paymentFlow = "delivery"`. Charging is an effect that can be stopped, and
paying upfront with `exact` would charge a buyer if the charger rejects the start with no refund. The
energy delivered before a failed settle is bounded by the block size and the meter interval.

## Run it

```bash
cargo run -p quebracho-x402-gateway --bin demo
cargo run -p quebracho-x402-gateway --bin demo -- --safety
```

The demo is offline: it uses the happy PHP vector as the buyer's signed payment, `MockFacilitator`,
`MemoryLedger` and `SimulatedChargePoint`. It prints the 402, the paid charge, the meter, the stop at
the block, and the replay of the same payment. `--safety` prints the same valid payment refused by
OFAC, by the stop switch and by the rate limit; the charger never moves in any of them.

## The flow

```text
driver -> 402 + offer (delivery)
driver -> PAYMENT-SIGNATURE
gateway -> verify, screen, claim
gateway -> charger.start(connector, limit)
gateway -> settle
  success -> charge, meter, stop at limit, receipt
  failure -> charger.stop, claim freed if nothing moved
```

## Tests

```bash
cargo test -p quebracho-x402-gateway
```

The tests use the PHP conformance vectors for a real signed payment and cover the happy path, the
replay of a retry, no payment, a tampered amount, a sanctioned payer, a charger that rejects the
start, a settle that fails, the emergency stop, the rate limit, the block cap, the connector check,
and one rejection per bad payment field and bad header.

Every input is checked at the gateway boundary: the config once at startup, `kwh > 0` and
`kwh <= 1_000`, the header size and encoding, the offer the seller made, the canonical field
formats, and only a canonical payer address becomes a rate-limit key.

## Not yet

- The OCPP 1.6J WebSocket adapter and its simulator (the `ChargePoint` port is the seam).
- The HTTP(S) transport that exposes the paid route.
- The reconciler and the `signerd` buyer.
