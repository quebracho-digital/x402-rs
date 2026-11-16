# quebracho-x402-ofac

The digital-currency addresses of the U.S. Treasury's OFAC SDN list, shipped with
[quebracho-x402](https://crates.io/crates/quebracho-x402) so address screening works offline from the
first request. `no_std`.

```rust
let ofac = quebracho_x402_ofac::bundled();          // the shipped list
// Your device syncs its own copy; the younger of the two wins, so a stale copy never rolls it back.
let ofac = ofac.younger(quebracho_x402::screening::Ofac::from_snapshot(&own_snapshot_json));
assert_eq!(ofac.reason("0x0330070fd38ec3bb94f58fa55d40368271e9e54a"), Some("address_sanctioned"));
```

**Keeping the list fresh is your job**: OFAC updates it several times a week. This copy is refreshed
with each release of the PHP library [quebracho/x402](https://github.com/quebracho-digital/x402).
It screens the addresses OFAC publishes, nothing more. Not legal advice.

The list is a public U.S. government work. MIT for the code.
