# Next steps

## 1. Run the demo (Linux, no QNX)

```bash
cargo run -p quebracho-x402-gateway --bin demo
cargo run -p quebracho-x402-gateway --bin demo -- --safety
```

The first prints the 402, the paid charge, the meter, the stop at the block and the replay. The second
prints the same valid payment refused by OFAC, by the stop switch and by the rate limit; the charger
never starts. Both are offline: the payment is the PHP conformance vector, the facilitator, ledger and
charger are mocks.

## 2. QNX M0

See `spike/qnx-m0/COMMANDS.md`. It starts with the `find` commands for the QNX SDP. If none of them
finds `qnxsdp-env.sh`, send the output and do not install anything yet: the license is the blocker.

## 3. Commit

The changes are staged. The commit is blocked by the missing SSH signing key
`~/.ssh/id_ed25519.pub`. After restoring it:

```bash
git commit -m "feat(gateway): sanitize inputs, add the offline demo and the replay outcome"
```

Do not change `gpg.format` or `user.signingkey`; committing without a key is your call.

## 4. Video

`~/Proyects/Quebracho/VIDEO_SCRIPT.md` is restored next to `CONTEXT.md`. The demo scene now matches the
terminal demo: the charger is simulated, the payment is the PHP vector, and the QNX claim is
conditional on `qnx-m0` passing. The safety scene uses `--safety`.

## 5. Next implementation

The next code step is the seller HTTP(S) transport and the mock facilitator over HTTP, then the OCPP
1.6J adapter. The gateway already hides the charger behind `ChargePoint`; the demo calls it directly.
