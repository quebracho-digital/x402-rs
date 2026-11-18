# M0 results

Fill one row per run. This is the evidence that the project compiles and runs on QNX 8.0.

| Date | Host | rustc | Target | std build | link | run | tcp | files | core | OFAC | ws | tls | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-18 | sandbox Linux | 1.94.0 stable | x86_64-pc-nto-qnx800 | not run (no qcc, rust-src blocked) | | | | | | | | | target names confirmed; `target_os = nto` |
| | Mint + SDP 8.0 | | x86_64-pc-nto-qnx800 | | | | | | | | | | |
| | Mint + SDP 8.0 | | aarch64-unknown-nto-qnx800 | | | | | | | | | | |
| | QEMU / Pi 5 | | | | | | | | | | | | |

Use `PASS`, `FAIL` or `skip`, and paste the failing line in `notes`.
