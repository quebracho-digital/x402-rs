# QNX 8.0 on Linux Mint with QEMU

Short answer: **yes, QEMU can run QNX 8.0 on Mint.** But QEMU is only the target. You still need the
QNX Software Development Platform (SDP) 8.0, which contains the host toolchain and the Quick Start
Target Image (QSTI). The SDP install is about 43 GB; the QSTI image brings `~/qnx800` to about 79 GB.
If the notebook does not have that, do not start: use an external SSD or the fallback at the end.

## apt does not install QNX

`apt install qemu-system-x86` installs QEMU, not QNX. QNX SDP 8.0 is proprietary and comes from QSC
with a license. There is no apt package for QNX.

## Gate 0: measure first

Run these on the Mint notebook. They decide whether the install is worth starting.

The script `spike/qnx-m0/host-check.sh` runs the same gate and prints a verdict. Run it read-only:

```bash
./spike/qnx-m0/host-check.sh
```

```bash
df -h ~
free -h
nproc
ls -l /dev/kvm
egrep -c '(vmx|svm)' /proc/cpuinfo
qemu-system-x86_64 --version
```

- `df -h ~` must show **80 GB free** on the filesystem you will use for `~/qnx800`; 100 GB is safer.
- `/dev/kvm` must exist. If it does not, enable virtualization in the BIOS; without KVM QEMU is slow.
- 8 GB RAM or more. The QSTI defaults to 4 GB for the guest.
- QEMU 8.x from Mint is fine for the default 720p/no-Vulkan image. QEMU 10 is optional and not needed
  for the probe.

If the free space is short, stop here and read "If the disk is too small" at the end.
~/P/Q/x402-rs (main) ❯ df -h ~
                       free -h
                       nproc
                       ls -l /dev/kvm
                       egrep -c '(vmx|svm)' /proc/cpuinfo
                       qemu-system-x86_64 --version
Filesystem      Size  Used Avail Use% Mounted on
/dev/nvme0n1p5  459G  394G   42G  91% /
               total        used        free      shared  buff/cache   available
Mem:            38Gi        12Gi        11Gi       366Mi        14Gi        25Gi
Swap:           31Gi        10Gi        21Gi
16
gls: cannot access '/dev/kvm': No such file or directory
16
Command 'qemu-system-x86_64' not found, but can be installed with:
sudo apt install qemu-system-x86
fish: 
qemu-system-x86_64 --version
^~~~~~~~~~~~~~~~~^
~/P/Q/x402-rs (main) ❯ 


The script `spike/qnx-m0/host-check.sh` runs this gate. Your current output is 42 GB free on `/`, so the
SDP + QSTI do not fit on the internal disk. Do not install QNX there; use an external SSD or free space
first. `--report` shows the biggest directories; `--install-qemu` installs QEMU; `--enable-kvm` tries to
load KVM; `--install-dir /media/...` checks an external SSD.

## Minisforum is the better host

The minisforum output shows 677 GB free, 46 GB RAM, 24 cores, `/dev/kvm` and QEMU 8.2.2. Use the
minisforum for QNX; keep the Mint for the demo and the video. The Mint cannot hold the install; the
minisforum can.

The minisforum is headless:

- Run the QSC GUI from the Mint with `ssh -X minisforum` (or `ssh -Y`) and then `qsc`. The installer
  runs on the minisforum, but the window appears on the Mint.
- The QSTI QEMU window has no display on the minisforum. Install `xvfb` and run it under a virtual
  display: `sudo apt install xvfb xauth`, then
  `xvfb-run -a -s "-screen 0 1280x720x24" mkqnximage --run`.
  The terminal is the QNX serial console; `mkqnximage --getip` gives the IP; SSH to `qnxuser@<ip>`.
- The QEMU 8.2.2 on the minisforum is fine for the QSTI default 720p/no-Vulkan image.
- Clone the repo on the minisforum, run `./spike/qnx-m0/host-check.sh`; it should pass the disk, KVM and
  QEMU and say SDP/QSTI missing. If `/dev/kvm` is present but not accessible, add your user to `kvm`:
  `sudo usermod -aG kvm $USER`, then log out and in. Then install the SDP/QSTI, build `check.sh`, copy
  the probe and run it.

## What you need

1. A free myQNX account and the QNX Everywhere non-commercial SDP 8.0 license.
2. QNX Software Center (QSC) for Linux x86_64.
3. QNX SDP 8.0, installed with QSC.
4. The QSTI package `com.qnx.qnx800.quickstart.qemu`, installed with QSC.
5. QEMU and a network bridge on the QNX host (the minisforum, or the Mint with an external SSD).

The QNX Everywhere license is for non-commercial use. Read the terms; a hackathon project with no
revenue is normally non-commercial, but that is your call. If the hackathon gives you a license, use
that one.

## 1. License

Create the account and accept the license:

```text
https://www.qnx.com/getqnx
```

Deploy the license to the machine. QSC will use it.

## 2. Install QSC

Download the QNX Software Center for Linux (x86_64) from:

```text
https://www.qnx.com/download/
```

Install it and sign in with the myQNX account. Mint 22 is Ubuntu 24.04 based; QSC is the supported
installer. If it refuses Mint, send me the exact error before trying workarounds.

## 3. Install the SDP 8.0

In QSC, install **QNX Software Development Platform 8.0**. The default path `~/qnx800` is fine. The
download is large; the install is about 43 GB. Do not interrupt it.

## 4. Install the QEMU target image

In QSC, find and install:

```text
com.qnx.qnx800.quickstart.qemu
```

It contains the Quick Start Target Image for QEMU. The files land under `~/qnx800/images/qemu` (the
exact path is shown in QSC).

## 5. Install QEMU on Mint

Mint 22 is Ubuntu 24.04 based. The QSTI docs list these packages for Ubuntu 24.04:

```bash
sudo apt update
sudo apt install qemu-system qemu-utils qemu-user qemu-user-binfmt qemu-block-extra \
  libvirt-daemon-system libvirt-clients libguestfs-tools bridge-utils
```

The script's `--install-qemu` installs the QEMU packages needed for the QSTI; it skips the optional
foreign-arch and guestfs tools. Use the list above if you want the full set.

If `qemu-system` is not available, install `qemu-system-x86` instead. The bridge packages are for the
QSTI network; install them even if you are not sure yet.

## 6. Unpack the QSTI image

```bash
cd ~/qnx800/images/qemu
./unpack_qemu_image.sh
```

If the script is not executable:

```bash
chmod +x unpack_qemu_image.sh
./unpack_qemu_image.sh
```

When it finishes, a `qemu` folder appears under `~/qnx800/images/qemu`. It is large.

## 7. Run QNX in QEMU

```bash
source ~/qnx800/qnxsdp-env.sh
cd ~/qnx800/images/qemu/qemu
mkqnximage --run
```

The QEMU window opens, and the terminal that launched it becomes the QNX serial console. The welcome
screen is the QNX Developer Desktop. The defaults are 8 CPUs, 4 GB RAM, 720p and no Vulkan; that is
fine for the probe.

Get the IP from a second terminal in the same `qemu` folder:

```bash
mkqnximage --getip
```

Or run `ifconfig` in the QNX serial console.

Exit QEMU with `Ctrl + A`, then `x`, or `mkqnximage --stop` from the `qemu` folder.

## 8. SSH into QNX

The QSTI user is `qnxuser`; `root` is available for escalation. If SSH asks for a password and you do
not know it, set one in the QNX console:

```bash
passwd
```

Then from Mint:

```bash
ssh qnxuser@<ip>
```

If SSH is not running, start it from a root shell in the QNX console:

```bash
su
sshd
```

If the host cannot reach the VM IP, send me the output of `mkqnximage --getip` and `ifconfig` from the
guest. Do not guess a host-forward port.

## 9. Build the probe on Mint

The probe is cross-compiled on Mint; it is not built inside QNX.

```bash
cd ~/Proyects/Quebracho/x402-rs
source ~/qnx800/qnxsdp-env.sh
cd spike/qnx-m0
./check.sh
```

`check.sh` verifies `qcc`, `QNX_TARGET`, `QNX_HOST`, the target and `rust-src`, then builds `std` with
`-Z build-std=std,panic_abort`. The first build takes a while. The binary is:

```text
spike/qnx-m0/target/x86_64-pc-nto-qnx800/debug/qnx-m0
```

If the link fails, try:

```bash
export CARGO_TARGET_X86_64_PC_NTO_QNX800_LINKER=qcc
```

and run `./check.sh` again.

## 10. Copy the probe to QNX and run it

From the repository root on Mint:

```bash
scp spike/qnx-m0/target/x86_64-pc-nto-qnx800/debug/qnx-m0 qnxuser@<ip>:/tmp/qnx-m0
ssh qnxuser@<ip> 'chmod +x /tmp/qnx-m0 && /tmp/qnx-m0'
```

The first line must be:

```text
qnx-m0: os=nto
```

The important PASS lines are `clock`, `thread`, `tcp-loopback`, `files`, `core-ecrecover`,
`screening-ofac` and `websocket-crate`. The TLS check is optional:

```bash
ssh qnxuser@<ip> '/tmp/qnx-m0 --tls'
```

`--tls` needs working DNS, outbound network and a correct QNX clock. If it fails, skip it for M0 and
say so; the other checks are the gate.

## 11. Record the result

Copy the real output into `spike/qnx-m0/RESULTS.md`: QNX version, target, QEMU version, and the
`PASS`/`FAIL` lines. A clear failure is better evidence than a clean story. Send me the output.

## If the disk is too small

```bash
./spike/qnx-m0/host-check.sh --report
```

It lists the biggest directories, Docker/Podman usage and the Rust `target` directories; it deletes
nothing. Decide yourself what to move or remove.

- **External SSD:** install `~/qnx800` on a USB 3 SSD. QSC can install to that path; the QEMU image
  lives there too. The QSTI current directory must be on the same external disk. USB 3 is enough for
  the probe.
- **Raspberry Pi 4 QSTI:** if you have a Pi 4, the public QSTI image is a smaller target and closer to
  the real device. You still need the SDP on Mint to build the probe, but not the 36 GB QEMU image.
  The Pi 5 is a different image/BSP; do not assume the Pi 4 image boots on a Pi 5.
- **Fallback for the video:** do not install QNX if it does not fit. Record the Linux demo (it works),
  show the QNX target and the `qnx-m0` source, and say "the QNX build is next". The video script
  already has that conditional. Do not say "runs on QNX" without the `PASS` lines.

## What not to do

- Do not look for a QNX Docker image. There is no official QNX SDP container; QSTI is the supported
  path.
- Do not build QEMU 10 from source before the probe runs. The Mint QEMU 8 with no Vulkan is enough.
- Do not install the SDP inside the QEMU guest. The host Mint builds the probe; the guest only runs it.
- Do not claim QNX support in the video until `qnx-m0` prints `os=nto` and the PASS lines.
