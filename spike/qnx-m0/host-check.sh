#!/usr/bin/env bash
# Check whether this Linux host can install the QNX SDP 8.0 and the QSTI QEMU image.
#
# It never installs QNX. QNX is proprietary and comes from the QNX Software Center with a license;
# apt only has QEMU. This script can install QEMU (--install-qemu) and try to load KVM
# (--enable-kvm), then prints a gate verdict.
#
# Usage:
#   ./host-check.sh                         # read-only gate
#   ./host-check.sh --report                # show the biggest directories (read-only)
#   ./host-check.sh --install-qemu          # sudo apt install QEMU + bridge + libvirt
#   ./host-check.sh --enable-kvm            # sudo modprobe kvm_intel/kvm_amd
#   ./host-check.sh --install-dir /media/leo/ssd/qnx800
#   QNX_INSTALL_DIR=/media/leo/ssd/qnx800 ./host-check.sh
#
# Exit status: 0 when the gate passes, 1 when it stops.

set -euo pipefail

MIN_FREE_GB=80
INSTALL_DIR="${QNX_INSTALL_DIR:-$HOME/qnx800}"
INSTALL_QEMU=0
ENABLE_KVM=0
REPORT=0

QEMU_PACKAGES=(
  qemu-system-x86
  qemu-system-gui
  qemu-utils
  qemu-block-extra
  bridge-utils
  libvirt-daemon-system
  libvirt-clients
)

usage() {
  cat <<'EOF'
Check the QNX SDP 8.0 + QSTI QEMU host gate.

  --install-qemu       install QEMU and the bridge/libvirt packages with apt (needs sudo)
  --enable-kvm         try to load kvm_intel or kvm_amd and create /dev/kvm (needs sudo)
  --report             print the biggest directories and Docker/Podman usage (read-only)
  --install-dir PATH   check the filesystem where QNX will be installed
  --help, -h           this help

QNX itself is not installed by this script and is not in apt.
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --install-qemu)
        INSTALL_QEMU=1
        shift
        ;;
      --enable-kvm)
        ENABLE_KVM=1
        shift
        ;;
      --report)
        REPORT=1
        shift
        ;;
      --install-dir)
        if [ $# -lt 2 ]; then
          echo "--install-dir needs a path" >&2
          exit 2
        fi
        INSTALL_DIR="$2"
        shift 2
        ;;
      --install-dir=*)
        INSTALL_DIR="${1#*=}"
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

install_qemu() {
  echo "== Installing QEMU, not QNX =="
  echo "QNX SDP 8.0 is proprietary and comes from QSC with a license; apt has no QNX package."
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "FAIL: apt-get not found; this script is for Debian/Ubuntu/Mint." >&2
    exit 1
  fi
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${QEMU_PACKAGES[@]}"
  echo
  echo "QEMU installed. Check it with: qemu-system-x86_64 --version"
}

enable_kvm() {
  echo "== Trying to enable KVM =="
  if [ -e /dev/kvm ]; then
    echo "OK: /dev/kvm already exists."
    ls -l /dev/kvm
    if ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; then
      echo "KVM: /dev/kvm exists but is not accessible; add $USER to the kvm group:"
      echo "  sudo usermod -aG kvm $USER"
      echo "then log out and back in (or run the QEMU command with sudo, not recommended)."
    fi
    return 0
  fi

  local mod
  if grep -qE '^flags.*\bvmx\b' /proc/cpuinfo; then
    mod=kvm_intel
  elif grep -qE '^flags.*\bsvm\b' /proc/cpuinfo; then
    mod=kvm_amd
  else
    echo "FAIL: no vmx/svm in /proc/cpuinfo; enable virtualization in the BIOS." >&2
    return 1
  fi

  echo "CPU flag: $mod"
  echo "Running: sudo modprobe $mod"
  if ! sudo modprobe "$mod"; then
    echo "FAIL: modprobe $mod failed. Check BIOS virtualization and Secure Boot." >&2
    return 1
  fi
  if [ -e /dev/kvm ]; then
    echo "OK: /dev/kvm created."
    ls -l /dev/kvm
    return 0
  fi
  echo "FAIL: /dev/kvm is still missing. Check BIOS virtualization and Secure Boot." >&2
  return 1
}

report() {
  echo "== Read-only disk report (nothing is deleted) =="
  echo "Top-level usage in $HOME:"
  du -xhd1 "$HOME" 2>/dev/null | sort -rh | head -12 || true
  if command -v docker >/dev/null 2>&1; then
    echo
    echo "== Docker =="
    docker system df 2>/dev/null || true
  fi
  if command -v podman >/dev/null 2>&1; then
    echo
    echo "== Podman =="
    podman system df 2>/dev/null || true
  fi
  echo
  echo "Also check, and decide yourself before deleting anything:"
  echo "  sudo du -sh /var/lib/docker /var/lib/libvirt/images 2>/dev/null"
  echo "  sudo du -sh /var/cache/apt /var/log 2>/dev/null"
  echo "  du -sh ~/.cache ~/.cargo ~/.rustup ~/Downloads 2>/dev/null"
  echo "  find ~/Proyects -maxdepth 3 -type d -name target -prune -exec du -sh {} + 2>/dev/null"
}

gate() {
  echo "== QNX host gate =="
  echo "date: $(date -Is)"
  echo "host: $(uname -srm)"
  echo "install dir: $INSTALL_DIR"
  echo "cores: $(nproc)"

  local mem_gb
  mem_gb=$(free -g | awk 'NR==2 {print $2}')
  echo "RAM: ${mem_gb} GB"
  if [ "$mem_gb" -lt 8 ]; then
    echo "WARN: 8 GB is the minimum; 16 GB recommended."
  fi

  local virt
  virt=$(grep -m1 -oE 'vmx|svm' /proc/cpuinfo || true)
  echo "CPU virt: ${virt:-none}"

  if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
      echo "KVM: yes (/dev/kvm, accessible)"
    else
      echo "KVM: /dev/kvm exists but is not accessible; add $USER to the kvm group and log out/in."
    fi
  else
    echo "KVM: no (/dev/kvm missing); run --enable-kvm or enable BIOS virtualization."
  fi

  local probe="$INSTALL_DIR"
  while [ ! -d "$probe" ] && [ "$probe" != "/" ]; do
    probe="$(dirname "$probe")"
  done
  local avail_kb avail_gb
  avail_kb=$(df -Pk "$probe" | awk 'NR==2 {print $4}')
  avail_gb=$((avail_kb / 1024 / 1024))
  echo "disk: $probe, ${avail_gb} GB free"

  local fatal=0
  if [ "$avail_gb" -lt "$MIN_FREE_GB" ]; then
    echo "FAIL: need ${MIN_FREE_GB} GB free (100 GB safe); this filesystem has ${avail_gb} GB."
    fatal=1
  else
    echo "PASS: disk space."
  fi

  if command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "QEMU: $(qemu-system-x86_64 --version | head -1)"
  else
    echo "FAIL: qemu-system-x86_64 not installed; run --install-qemu."
    fatal=1
  fi
  if ! dpkg -s qemu-system-gui >/dev/null 2>&1; then
    echo "QEMU GUI: missing; run --install-qemu for the QSTI window."
  fi

  if [ -f "$INSTALL_DIR/qnxsdp-env.sh" ]; then
    echo "SDP: found at $INSTALL_DIR"
  else
    echo "SDP: not found at $INSTALL_DIR (install with QSC)."
  fi
  if [ -f "$INSTALL_DIR/images/qemu/unpack_qemu_image.sh" ]; then
    echo "QSTI: found at $INSTALL_DIR/images/qemu"
  else
    echo "QSTI: not found at $INSTALL_DIR/images/qemu (install with QSC)."
  fi

  echo
  if [ "$fatal" -eq 0 ]; then
    echo "GATE OK: install the SDP and QSTI with QSC, then run spike/qnx-m0/check.sh."
  else
    echo "GATE STOP: fix the FAIL lines above before installing QNX."
  fi
  return "$fatal"
}

main() {
  parse_args "$@"
  if [ "$INSTALL_QEMU" -eq 1 ]; then
    install_qemu
  fi
  if [ "$ENABLE_KVM" -eq 1 ]; then
    enable_kvm || true
  fi
  if [ "$REPORT" -eq 1 ]; then
    report
  fi
  gate
}

main "$@"
