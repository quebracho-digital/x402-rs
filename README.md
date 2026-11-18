# x402-rs

x402 payments in Rust for embedded and real-time devices, starting with QNX 8.0.
A port of [quebracho/x402](https://github.com/quebracho-digital/x402) (PHP).

## TL;DR

- **What:** a device (an EV charger gateway, a sensor) charges for what it does with
  [x402](https://www.x402.org/): HTTP 402, a signed USDC authorization (EIP-3009), settled by a
  facilitator. The device only *verifies*: it holds no key.
- **Safe by default:** one signature buys one delivery; paid upfront unless an offer asks for pay on
  delivery by name (`extra.paymentFlow = "delivery"`; PHP's default is the reverse); OFAC screening is on unless turned off by name;
  anything that cannot answer (a list, the ledger, the clock) refuses instead of letting a payment through.
- **Pure Rust, `no_std` core:** no C in the dependency tree, TLS with `rustls` + `rustls-rustcrypto`.
- **Checked against PHP:** every shared behaviour is compared with the PHP library it ports, through
  vectors and scripted scenarios exported from it (`conformance/`, which also lists where Rust differs on
  purpose). PHP is not needed to build or test: the vectors are committed.
- **Status:** experimental (0.1.1), no third-party audit yet (only our own reviews, see `docs/TESTING.md`). It runs on any POSIX host today; QNX 8.0 builds come next.

## What works today

| Area | What | Crate |
|---|---|---|
| Verify | EVM `exact` offline: EIP-712 / EIP-3009 digest, low-s ecrecover, one spelling per value, x402 v2 reason codes | `quebracho-x402` |
| Sell | 402 → verify → screen → claim → run → settle; upfront (default) or pay on delivery; replay from the ledger; pending lookups; stop switch | `quebracho-x402` |
| Charge | The EV gateway: a block of kWh, start/stop, meter, block cap, delivery-only, charge-point port with a simulator | `quebracho-x402-gateway` |
| Facilitator | Any x402 facilitator by URL (`/verify`, `/settle`, `/status`), with the settle consistency rule | `quebracho-x402` |
| Screening | OFAC's list shipped; the token's own blacklist (USDC/USDT freeze); Chainalysis' oracle and API; your own allow and deny lists; list syncs | `quebracho-x402-screening` |
| Platform | Ledger in files (PHP's layout, lock + fsync + rename), stop file, trusted clock, HTTPS client | `quebracho-x402-qnx` |

Next: the OCPP 1.6J wire adapter, the seller's HTTPS server, the reconciler, then the buyer and
`signerd`. What is defended and what is still to build: [docs/THREATS.md](docs/THREATS.md).

## Crates

| Crate | `no_std` | What |
|---|---|---|
| [`quebracho-x402`](crates/quebracho-x402) | yes | The core: verify, the sale, the ports (`Ledger`, `Facilitator`, `Https`, `Clock`, `Pause`, `Events`...) |
| [`quebracho-x402-screening`](crates/quebracho-x402-screening) | yes (`std` feature to write files) | Who may pay or be paid: OFAC, token blacklists, Chainalysis, your lists |
| [`quebracho-x402-qnx`](crates/quebracho-x402-qnx) | no | Adapters for QNX 8.0 and any POSIX host (not published until it runs on QNX) |
| [`quebracho-x402-gateway`](crates/quebracho-x402-gateway) | no | The EV charging gateway: charge-point port, simulator, sessions, the paid charge |

## Try it

```bash
cargo test                      # every crate, against the PHP vectors
cargo run -p quebracho-x402-gateway --bin demo            # the EV charge, offline
cargo run -p quebracho-x402-gateway --bin demo -- --safety # OFAC, stop, rate limit
conformance/export.sh           # regenerate the vectors from the PHP library (needs Docker)
```

The demo is offline: the PHP vector is the buyer's signed payment, and the facilitator, ledger and
charger are mocks. It prints the 402, the paid charge, the meter, the stop at the block, and the replay
of the same payment. `--safety` runs the same valid payment against OFAC, the stop switch and the rate
limit; the charger never starts. The OCPP wire adapter and the real HTTP transport are next; the
gateway calls the charge-point port directly.

| Path | What |
|---|---|
| `conformance/` | The vectors and the scripts that export them from PHP ([README](conformance/README.md)) |
| `docs/THREATS.md` | The threat model |
| `docs/TESTING.md` | How it is tested, and the mutants left on purpose |
| `SECURITY.md` | How to report a vulnerability |

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
