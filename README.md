# x402-rs

x402 payments in Rust for embedded and real-time devices, starting with QNX 8.0.
A port of [quebracho/x402](https://github.com/quebracho-digital/x402) (PHP).

## TL;DR

- **What:** a device (an EV charger gateway, a sensor) charges for what it does with
  [x402](https://www.x402.org/): HTTP 402, a signed USDC authorization (EIP-3009), settled by a
  facilitator. The device only *verifies*: it holds no key.
- **Safe by default:** one signature buys one delivery; OFAC screening is on unless turned off by name;
  anything that cannot answer (a list, the ledger, the clock) refuses instead of letting a payment through.
- **Pure Rust, `no_std` core:** no C in the dependency tree, TLS with `rustls` + `rustls-rustcrypto`.
- **Checked against PHP:** every behaviour is compared with the PHP library it ports, through vectors and
  scripted scenarios exported from it (`conformance/`).
- **Status:** experimental (0.1), not audited. It runs on any POSIX host today; QNX 8.0 builds come next.

## What works today

| Area | What | Crate |
|---|---|---|
| Verify | EVM `exact` offline: EIP-712 / EIP-3009 digest, low-s ecrecover, one spelling per value, x402 v2 reason codes | `quebracho-x402` |
| Sell | 402 → verify → screen → claim → run → settle; pay on delivery or upfront; replay from the ledger; pending lookups; stop switch | `quebracho-x402` |
| Facilitator | Any x402 facilitator by URL (`/verify`, `/settle`, `/status`), with the settle consistency rule | `quebracho-x402` |
| Screening | OFAC's list shipped; the token's own blacklist (USDC/USDT freeze); Chainalysis' oracle and API; your own allow and deny lists; list syncs | `quebracho-x402-screening` |
| Platform | Ledger in files (PHP's layout, lock + fsync + rename), stop file, trusted clock, HTTPS client | `quebracho-x402-qnx` |

Next: the reconciler, the seller's HTTPS server, the OCPP gateway for EV chargers, then the buyer and
`signerd`. What is defended and what is still to build: [docs/THREATS.md](docs/THREATS.md).

## Crates

| Crate | `no_std` | What |
|---|---|---|
| [`quebracho-x402`](crates/quebracho-x402) | yes | The core: verify, the sale, the ports (`Ledger`, `Facilitator`, `Https`, `Clock`, `Pause`, `Events`...) |
| [`quebracho-x402-screening`](crates/quebracho-x402-screening) | yes (`std` feature to write files) | Who may pay or be paid: OFAC, token blacklists, Chainalysis, your lists |
| [`quebracho-x402-qnx`](crates/quebracho-x402-qnx) | no | Adapters for QNX 8.0 and any POSIX host (not published until it runs on QNX) |

## Try it

```bash
cargo test                      # every crate, against the PHP vectors
conformance/export.sh           # regenerate the vectors from the PHP library (needs Docker)
```

| Path | What |
|---|---|
| `conformance/` | The vectors and the scripts that export them from PHP ([README](conformance/README.md)) |
| `docs/THREATS.md` | The threat model |
| `SECURITY.md` | How to report a vulnerability |

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
