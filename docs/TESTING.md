# Testing

The rule: no code without a test, and a test that fails is fixed in the code, never by editing the test.

| Layer | What | Where |
|---|---|---|
| Conformance | Expected answers exported from the PHP library itself (vectors and scripted sale, facilitator and screening scenarios) | `conformance/`, `*/tests/conformance.rs`, `sale.rs`, `settlement.rs` |
| Properties | Thousands of generated inputs per property: no panic and no admission on hostile input, rules against their definition | `crates/quebracho-x402/tests/properties.rs` |
| Units | Edges no vector reaches (calendar, casts checked with `php -r`, races between ledger reads) | `units.rs`, `#[cfg(test)]` modules |
| Platform | A real TLS server (rustls) and real files: truncation, dripping servers, size caps, permissions, concurrent claims | `crates/quebracho-x402-qnx/tests/` |
| Coverage | `cargo llvm-cov --workspace --all-features`: every production line runs (99%+; the rest is test scaffolding) | |
| Mutation | `cargo mutants --test-workspace=true`: each surviving mutant gets a test, or is listed below | CI, weekly |
| Dependencies | `cargo deny check`: RustSec advisories, licenses, sources | `deny.toml`, CI |
| Secrets | gitleaks against `.gitleaks-baseline.json` | CI |

## Equivalent mutants

These change no observable result, so no test can tell them apart; they are left on purpose.

| Mutant | Why it is equivalent |
|---|---|
| `hex.rs`: `\|` → `^` joining two nibbles | The high and low nibbles never share a bit |
| `php.rs`: `<` → `<=` on the exponent sign | That branch never sees exponent 0 |
| `php.rs`: `>` → `>=` in `libm_floor` | One more multiple of 2^64 is removed again by the modulo |
| `settlement.rs`: `len() > 1` → `>= 1` | With one match the asset search falls back to that same match |
| `sync.rs`: `!` on the last CSV field | A one-field row has no remarks column |
| `https.rs`: read buffer size | Smaller reads, same bytes |
| `https.rs`: `>` → `>=` on the elapsed deadline | Not observable at clock resolution |
| `https.rs`: EINTR retry arm | An interrupted read cannot be staged in a test |
| `https.rs`: early head detection, completeness pre-check, `<=` on an exact chunk | Performance only: a wrong "maybe whole" costs one parse that says "not yet" |

## Run it

```bash
cargo test --all --all-features
cargo llvm-cov --workspace --all-features --summary-only
cargo mutants --test-workspace=true --all-features -p quebracho-x402
cargo deny check
conformance/export.sh && git diff --exit-code conformance/vectors
```
