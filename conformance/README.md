# Conformance vectors

The Rust core must reproduce the PHP library [quebracho/x402](https://github.com/quebracho-digital/x402)
byte for byte. Every expected value in `vectors/` is computed by the PHP code, never typed by hand.

| File | What it pins | PHP source |
|---|---|---|
| `keccak.json` | Keccak-256, including the EIP-712 type strings | `Eip712::keccak` |
| `field.json` | The one spelling of each value (address, bytes32, uint256, ...) | `Field::is` |
| `signer.json` | Key → EIP-55 address, and checksum spelling | `Signer` |
| `digest.json` | EIP-3009 `TransferWithAuthorization` digests and signatures | `Authorization::digest` |
| `recover.json` | ecrecover: low-s only, v = 27/28, r and s ranges | `Signer::recover` |
| `evm_exact.json` | Payment + offer + clock → x402 v2 reason code | `EvmExact::verify` |
| `facilitator.json` | 52 scripted HTTP answers to verify, settle (with /status polling) and supported: requests sent and results | `HttpFacilitator` (`facilitator.php`) |
| `sale.json` | 34 scripted sales (facilitator, handler, ledger failures, stop, lookup, upfront): status, headers, callbacks, events, ledger after | `X402Middleware` (`scenarios.php`) |

Each file names the library commit it came from (`source`).

## Regenerate

```bash
conformance/export.sh                          # the library at the commit pinned in conformance/Dockerfile
X402_REF=<commit> conformance/export.sh        # another commit of the public repository
X402_LIB=/path/to/x402 conformance/export.sh   # a local checkout (its vendor/ installed)
cargo test
```

Only Docker is needed. `Dockerfile` builds PHP 8.3 with `gmp`, clones the public
[quebracho/x402](https://github.com/quebracho-digital/x402) at a pinned commit and installs its
dependencies, so anyone gets the same vectors. Bumping `X402_REF` and rerunning shows what changed in
PHP; `cargo test` then says whether Rust still agrees.

The key `0x4c08…2318` is the well-known web3.js test key, never funded. The `eip155:4689` digest uses
a placeholder token: it pins the domain math only and makes no claim about USDC on IoTeX.

## File ledger interop (by hand)

`quebracho-x402-qnx`'s `FileLedger` uses PHP's file layout. Checked on 2026-11-16: a ledger written by Rust
(`cargo test -p quebracho-x402-qnx --test adapters write_a_ledger_for_php -- --ignored`, with
`X402_INTEROP_DIR`) is read by PHP's `FileLedger` (state, open entry, and a refused second claim).
