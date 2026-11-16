# x402-rs

x402 payments in Rust for embedded and real-time devices, starting with QNX 8.0.
A port of [quebracho/x402](https://github.com/quebracho-digital/x402) (PHP).

**Status:** in development. Today it charges for a request end to end on any
POSIX host: offline EVM `exact` verification (EIP-712 / EIP-3009, low-s
ecrecover), OFAC screening on by default, one signature = one delivery, pay on
delivery or upfront, a payment ledger in files with replay and crash recovery,
a stop switch. Every step is checked against vectors and sale scenarios
exported from the PHP library. Next: the reconciler, the seller's HTTPS server, the OCPP
gateway, then the buyer and `signerd`.

| Path | What |
|---|---|
| `crates/quebracho-x402` | The `no_std` core: verify, screen, sell ([README](crates/quebracho-x402/README.md)) |
| `crates/quebracho-x402-ofac` | OFAC's SDN list, shipped |
| `crates/quebracho-x402-qnx` | Platform adapters (std/POSIX): file ledger, stop switch, clock, HTTPS client (rustls, pure Rust) |
| `conformance/` | Vectors exported from the PHP library, and the exporter ([README](conformance/README.md)) |
| `docs/THREATS.md` | The threat model: what is defended, what is still to build |

```bash
cargo test
```

## License

MIT. See [LICENSE](LICENSE).
