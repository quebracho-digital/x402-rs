# M0 on your Mint: exact commands

> QNX is not installed yet? The QEMU/QSTI runbook is in `../../QNX-QEMU.md`. This file assumes the SDP
> is installed and `qcc` is on `PATH`.

The probe is built. This is the runbook to build and run it on the QNX host. Work from the repository
root: `/home/leo/Proyects/Quebracho/x402-rs`.

If a command prints `FAIL`, stop and send me the whole output. The probe is a go/no-go gate, not a
product.

## 0. Find the QNX SDP

The SDP is a directory with `qnxsdp-env.sh` and `qcc`. It is not the Rust target and it is not inside
the repository. Run these; the first one that prints a path is your SDP.

```bash
ls -d ~/qnx* /opt/qnx* /usr/local/qnx* 2>/dev/null
```

```bash
find ~ -maxdepth 4 -name qnxsdp-env.sh 2>/dev/null
```

```bash
find /opt /usr/local -maxdepth 4 -name qnxsdp-env.sh 2>/dev/null
```

```bash
which qcc
echo "$QNX_TARGET"
echo "$QNX_HOST"
```

If none of them finds `qnxsdp-env.sh`, the SDP is not installed on this machine. That is the blocker,
not the Rust code. In that case send me the output and do not install anything yet: we decide between
installing the SDP (the QNX license is the gate) and using the hackathon's QNX image.

## 1. Source the SDP

Replace `/opt/qnx800` with the directory that contains `qnxsdp-env.sh`. The usual paths are
`~/qnx800` and `/opt/qnx800`.

```bash
source /opt/qnx800/qnxsdp-env.sh
```

Check it:

```bash
which qcc
qcc -V
echo "$QNX_TARGET"
echo "$QNX_HOST"
```

`qcc -V` must print the QNX 8.0 compiler. `QNX_TARGET` and `QNX_HOST` must not be empty.

## 2. Rust nightly and rust-src

The QNX 8.0 targets are Tier 3: there is no prebuilt `std`, so Cargo compiles `std` from `rust-src`.
This needs nightly.

```bash
rustup toolchain install nightly --profile minimal
```

```bash
rustup component add rust-src --toolchain nightly
```

Check the target name in *your* rustc:

```bash
rustc +nightly --print target-list | grep qnx
```

The expected lines are:

```text
aarch64-unknown-nto-qnx800
x86_64-pc-nto-qnx800
```

If your list has different spellings, use those in the next step.

## 3. Build and run the checks

From the repository root:

```bash
cd spike/qnx-m0
```

QEMU / x86_64:

```bash
./check.sh
```

Raspberry Pi 5 / aarch64:

```bash
./check.sh aarch64-unknown-nto-qnx800
```

`check.sh` verifies `qcc`, `QNX_TARGET`, `QNX_HOST` and `rust-src`, prints the target `cfg`, compiles
`std` with `-Z build-std=std,panic_abort`, and builds the probe.

If the link fails, try the explicit linker:

```bash
export CARGO_TARGET_X86_64_PC_NTO_QNX800_LINKER=qcc
```

Then run `./check.sh` again.

## 4. Run the probe on QNX

The binary is here:

```text
spike/qnx-m0/target/x86_64-pc-nto-qnx800/debug/qnx-m0
```

or:

```text
spike/qnx-m0/target/aarch64-unknown-nto-qnx800/debug/qnx-m0
```

Copy it into the QNX image or the target, then run:

```bash
./qnx-m0
```

```bash
./qnx-m0 --tls
```

The first line must say `os=nto`. Expected checks:

```text
PASS clock
PASS thread
PASS tcp-loopback
PASS files
PASS core-ecrecover
PASS screening-ofac
PASS websocket-crate
PASS tls-client
qnx-m0: all checks passed
```

The TLS check needs `https://example.com` and a sane clock. If the target has no network, skip
`--tls` and say so; it is not the critical check.

## 5. Record the result

Open `spike/qnx-m0/RESULTS.md` and paste the real output under the target you used. If a check fails,
leave the failure in the file; a clear failure is more useful than a clean story.

Then send me:

1. The output of step 0 (which SDP path was found).
2. The output of `./check.sh`.
3. The output of `./qnx-m0` (and `./qnx-m0 --tls` if you ran it).
4. The QNX version and the target (`x86_64` QEMU or `aarch64` Pi 5).

## Troubleshooting

- `qcc not found`: step 1 was not sourced in this shell, or the path is wrong.
- `QNX_TARGET is not set`: same; source `qnxsdp-env.sh` again.
- `target not in this rustc`: the target name differs; use the output of
  `rustc +nightly --print target-list | grep qnx`.
- `rust-src missing`: run step 2; the component is per toolchain.
- Linker errors: set the `CARGO_TARGET_..._LINKER=qcc` variable above and rebuild.
- `Permission denied` on `check.sh`: run `chmod +x check.sh` once.
- The binary runs on the host but not on QNX: check that you copied the binary for the same
  architecture as the target, not the host build in `target/debug/`.
