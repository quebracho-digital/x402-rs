# quebracho-x402

> **0.1, experimental.** Not audited. The API will change before 1.0. Test on testnets first.

The `no_std` + `alloc` core of the Rust port of [quebracho/x402](https://github.com/quebracho-digital/x402):
what a device needs to **charge** with x402. A seller only verifies, so this crate holds no key and
needs no entropy.

| Module | Does | Port of |
|---|---|---|
| `field` | One spelling per value read from outside | `Field.php` |
| `keccak256`, `eip712` | EIP-3009 `TransferWithAuthorization` digest | `Eip712.php`, `Authorization::digest` |
| `signer` | ecrecover (low-s only), EIP-55 addresses | `Signer.php` (verifying half) |
| `evm_exact` | Offline verify of an `exact` EVM payment, x402 v2 reason codes | `EvmExact::verify` |
| `settlement`, `headers` | Payment key, TTLs, offer matching, reading a settle answer, `PAYMENT-*` headers | `Settlement`, `PaymentHeaders` |
| `screening` | OFAC (on unless turned off by name), the listener chain, fail closed, the list format; the providers are in `quebracho-x402-screening` | `OfacSdn`, `AddressCheck`, `AddressList` |
| `dates` | ISO 8601 and HTTP dates, UTC, no time zone database | (`strtotime`, `gmdate`) |
| `ports` | `Ledger`, `Facilitator`, `Lookup`, `Clock`, `AddressListener`, `Pause`, `Events` | `PaymentLedger`, `Facilitator`, ... |
| `http_facilitator` | Any x402 facilitator by URL over the `Http` port; settle consistency rule, /status polling | `HttpFacilitator` |
| `seller` | One paid request: 402, verify, claim, run, settle; upfront; ledger replay | `X402Middleware`, `Sale` |

```rust
use quebracho_x402::evm_exact;

// payment: the decoded PAYMENT-SIGNATURE; req: our offer (one entry of `accepts`).
match evm_exact::verify(&payment, &req, now_unix_seconds) {
    Ok(()) => { /* next: claim, then run or settle */ }
    Err(reason) => { /* answer 402 with reason.as_str() */ }
}
```

## Tests

```bash
cargo test -p quebracho-x402                                   # conformance vectors from PHP
cargo build -p quebracho-x402 --target wasm32-unknown-unknown  # checks it stays no_std
```

## Not yet

The TLS transport (an adapter), the reconciler, job mode, the buyer and MCP.
