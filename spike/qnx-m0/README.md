# M0: QNX 8.0 viability probe

This is not product code. It answers one question before the demo work continues:

> Does the minimum the seller and the gateway need build and run on QNX 8.0?

M0 was planned for 2026-11-09..15 and is the critical path. A `no_std` hello-world is not enough:
the seller server, the OCPP WebSocket and the TLS client need **`std`**, threads, sockets and the
filesystem.

## What it checks

| Check | Why |
|---|---|
| `std` builds for the target | Tier 3 targets have no prebuilt std; `-Z build-std` compiles it from `rust-src` |
| link with `qcc` | QNX needs its linker and the SDP libraries |
| clock | `validBefore` and TLS certificate validity need a real time |
| thread spawn/join | the blocking server is thread per connection |
| TCP loopback bind/connect/read/write | HTTP and OCPP are sockets |
| file create, `fsync`, rename, read | the `FileLedger` depends on it |
| keccak + ecrecover | the `no_std` core runs on the target |
| bundled OFAC list | the `include_str!` data and the screening path work |
| `tungstenite` constructs a WebSocket | the OCPP wire adapter has a pure-Rust candidate |
| TLS client (`--tls`) | `rustls` + `rustls-rustcrypto` handshake and Mozilla roots |

The probe does not touch the seller, the gateway or a facilitator. It is deliberately small.

## Target names: use the ones in your rustc

The planning notes said `x86_64-pc-qnx` and `aarch64-unknown-qnx`. In the Rust toolchain used here,
the QNX 8.0 targets are:

```
x86_64-pc-nto-qnx800
aarch64-unknown-nto-qnx800
```

and `rustc --print cfg` reports `target_os="nto"`, `target_env="nto80"`, `target_family="unix"`.
That also means the `getrandom` backend for `target_os = "nto"` may exist; verify it, do not assume.
If your SDP or rustc uses another spelling, run `rustc +nightly --print target-list | grep qnx` and
use that.

## Prerequisites

1. **QNX SDP 8.0** installed, with a valid license.
2. **Source the environment** so `qcc` is on `PATH` and `QNX_TARGET`/`QNX_HOST` are set:

   ```bash
   source ~/qnx800/qnxsdp-env.sh
   which qcc
   echo "$QNX_TARGET"
   ```

3. **Rust nightly + rust-src**:

   ```bash
   rustup toolchain install nightly
   rustup component add rust-src --toolchain nightly
   ```

   Tier 3 targets need nightly and `-Z build-std`. Pin the nightly in the CI or in a
   `rust-toolchain.toml` once one is known to work with the SDP.

4. **QEMU or a target**: the QNX Everywhere QEMU image is the fastest path. A Raspberry Pi 5 is the
   real-device path.

## Build

```bash
cd spike/qnx-m0
./check.sh                                  # x86_64-pc-nto-qnx800
./check.sh aarch64-unknown-nto-qnx800       # the Pi path
```

The script runs:

```bash
cargo +nightly build -Z build-std=std,panic_abort \
  --target x86_64-pc-nto-qnx800
```

If the link fails, the usual cause is that `qcc` is not the linker Rust expected, or the SDP
environment is not sourced. Check:

```bash
echo "$QNX_TARGET"
qcc -V
```

The Rust target spec normally calls `qcc` itself. If you need to point Cargo at it explicitly:

```bash
export CARGO_TARGET_X86_64_PC_NTO_QNX800_LINKER=qcc
```

## Run

Copy `target/<target>/debug/qnx-m0` into the QNX image or the target, then:

```bash
./qnx-m0
./qnx-m0 --tls
```

Expected:

```
qnx-m0: os=nto arch=x86_64
PASS clock: ...
PASS thread: spawn/join
PASS tcp-loopback: 127.0.0.1
PASS files: fsync + rename
PASS core-ecrecover: keccak + ecrecover
PASS screening-ofac: bundled SDN
PASS websocket-crate: tungstenite
PASS tls-client: rustls + rustls-rustcrypto
qnx-m0: all checks passed
```

`os=nto` is expected: Rust reports `target_os = "nto"` for QNX.

## Go / no-go

| Result | Decision |
|---|---|
| std builds, links, runs, TCP and files pass | Continue with the seller server and the OCPP gateway on QNX |
| std builds and runs, TLS fails | Try `ring` or the SDP OpenSSL; if neither works, keep TLS on a Linux sidecar and document the deviation. The demo is weaker, not dead |
| std does not build or run | Stop. Use the reduced plan: `no_std` core + resource manager on QNX, server and gateway on Linux. Decide with Leo the same day |

Do not spend December on a target that does not build. M0 is cheap; the rest is not.

## Results

Fill `RESULTS.md` with the output of each target. That file is the evidence for the README and the
video: "it compiles and runs on QNX 8.0".

## Known risks

- **`getrandom`**: the plan said the crate only knows `target_os = "nto"`, and the QNX 8.0 target is
  `nto`. That may be fine. Verify with `cargo tree -e normal | grep getrandom` and a runtime call.
  The core does not use it; a dependency might.
- **`rustls-rustcrypto`** is a pre-release. It works on Linux in the qnx crate tests. On QNX, test
  the handshake, not just the compile.
- **`tungstenite` 0.30** uses pure Rust. The probe uses it without its TLS features, because TLS is
  provided by the qnx crate's `rustls`; do not pull a second TLS stack into the OCPP adapter.
- **QEMU networking** may be absent by default. The TCP loopback check does not need it; `--tls`
  does. A failure of `--tls` in QEMU is not a failure of QNX until the network is configured.
