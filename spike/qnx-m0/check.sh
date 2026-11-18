#!/usr/bin/env bash
# M0 on the QNX host: check the toolchain, build std for the target, and build the probe.
#
# Usage:
#   ./check.sh                      # x86_64-pc-nto-qnx800
#   ./check.sh aarch64-unknown-nto-qnx800
#
# The QNX SDP must be installed and sourced: qcc on PATH, QNX_TARGET and QNX_HOST set.
set -euo pipefail

TARGET="${1:-x86_64-pc-nto-qnx800}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== host =="
uname -srm
echo "target: $TARGET"

command -v qcc >/dev/null || fail "qcc not found; source the QNX SDP environment (qnxsdp-env.sh)"
[[ -n "${QNX_TARGET:-}" ]] || fail "QNX_TARGET is not set"
[[ -n "${QNX_HOST:-}" ]] || fail "QNX_HOST is not set"
echo "qcc: $(command -v qcc)"
echo "QNX_TARGET: $QNX_TARGET"
echo "QNX_HOST: $QNX_HOST"

echo "== rust =="
rustc +nightly --version || fail "nightly toolchain not installed (rustup toolchain install nightly)"
rustc +nightly --print target-list | grep -qx "$TARGET" || fail "target $TARGET not in this rustc"
rustup component list --toolchain nightly --installed | grep -q rust-src \
  || fail "rust-src missing: rustup component add rust-src --toolchain nightly"

# target_os is "nto" and target_env is "nto80" for QNX 8.0. This matters for cfg and for getrandom.
rustc +nightly --print cfg --target "$TARGET" | grep -E 'target_(os|env|family)'

echo "== build std + probe =="
# Tier 3: no prebuilt std. build-std compiles core, alloc and std from rust-src.
cargo +nightly build \
  -Z build-std=std,panic_abort \
  --target "$TARGET" \
  --verbose

BIN="$HERE/target/$TARGET/debug/qnx-m0"
[[ -x "$BIN" ]] || fail "binary not produced at $BIN"
echo "built: $BIN"
file "$BIN" 2>/dev/null || true

cat <<EOF

Next: copy $BIN to the QNX image or target and run it there.

  ./qnx-m0            # std, threads, TCP, files, core, OFAC, WebSocket
  ./qnx-m0 --tls      # also a TLS handshake against https://example.com/

Record the output in RESULTS.md. If std or the link fails, stop and read README.md
before spending more time on the demo.
EOF
