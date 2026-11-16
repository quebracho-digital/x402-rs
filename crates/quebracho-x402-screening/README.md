# quebracho-x402-screening

> **0.1, experimental.** Not audited. Not legal advice: it screens the addresses the lists publish, nothing more.

Who may pay or be paid, for [quebracho-x402](https://crates.io/crates/quebracho-x402). A port of the
screening of the PHP library [quebracho/x402](https://github.com/quebracho-digital/x402).

The core asks **OFAC's list first, always**, then each list you add, in order: the first refusal wins.
A list that cannot answer **refuses** (fail closed), unless you build it to fail open, which is reported
as `Event::ScreeningSkipped` so the pass leaves a trace.

| Piece | Asks | Refuses with |
|---|---|---|
| `ofac::bundled()` (feature `ofac`, default) | OFAC's SDN list, shipped in the binary | `address_sanctioned` |
| `TokenBlacklist` | the token's own blacklist on chain: USDC `isBlacklisted`, USDT `isBlackListed` | `address_blacklisted` |
| `chainalysis::Oracle` | Chainalysis' on-chain sanctions oracle on Ethereum (free) | `address_sanctioned` |
| `chainalysis::Api` | Chainalysis' sanctions API (needs a key; a wrong key never fails open) | `address_sanctioned` |
| `Lists` | your allowlist (skips the denylist and the API, never OFAC), your denylist, then the API | `address_denied` |
| `AddressList` (core) | any plain-text list: one address per line, `#` comments | the reason you give |
| `sync` | downloads OFAC's SDN.CSV or a published list; keeps your copy unless the new one is good and not older | |

```rust
use quebracho_x402::ports::AddressListener;
use quebracho_x402_screening::{chainalysis, ofac, Lists, TokenBlacklist};

let ofac = ofac::bundled();                                   // or the younger of it and your synced copy
let frozen = TokenBlacklist::new(&https);                     // USDC/USDT freeze, by eth_call
let mine = Lists::new(&allow_txt, &deny_txt)
    .api(chainalysis::Api::new(&https, &key).unwrap());
let listeners: [&dyn AddressListener; 2] = [&frozen, &mine];
// Seller { ofac: &ofac, listeners: &listeners, .. }
```

Everything goes through the core's ports (`Https`, `Events`): `no_std` + `alloc`. The `std` feature adds
writing synced lists to files and `Lists::from_files`.

Differences from PHP: lists are asked in line, before the claim (PHP defers slow ones until just before
settling: same verdict, latency paid up front); no cache of API answers; `# updated:` dates are read in ISO
8601 only.
