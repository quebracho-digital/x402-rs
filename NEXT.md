# Next steps

## 1. Run the demo (Linux, no QNX)

```bash
cargo run -p quebracho-x402-gateway --bin demo
cargo run -p quebracho-x402-gateway --bin demo -- --safety
```

~/P/Q/x402-rs (main) ❯ cargo run -p quebracho-x402-gateway --bin demo

    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running `target/debug/demo`
x402 EV charging gateway: offline demo
  vector: "paid: delivered once, the retry is replayed"
  clock: 1800000000, connector 1, block 1 kWh

1. A driver asks for 1 kWh without a payment
  402: HTTP 402
    PAYMENT-REQUIRED: 588 bytes (base64)
    body: {"accepts":[{"amount":"10000","asset":"0x036CbD53842c5426634e7929541eC2318f3dCF7e","extra":{"name":"USDC","paymentFlow":"delivery","version":"2"},"maxTimeoutSeconds":60,"network":"eip155:84532","payTo":"0x000000000000000000000000000000000000dEaD","scheme":"exact"}],"error":"PAYMENT-SIGNATURE header is required","resource":{"description":"EV charging","mimeType":"application/json","url":"https://device.test/charging/1"},"x402Version":2}
  the buyer gets the offer in PAYMENT-REQUIRED

2. The driver sends the signed payment
  200: HTTP 200
    PAYMENT-RESPONSE: {"extensions":{"mock":true},"network":"eip155:84532","payer":"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23","success":true,"transaction":""}
    body: {"amount":"10000","connector":1,"limitWh":1000,"session":1,"transaction":1}
  session 1: 1000 Wh, amount 10000, transaction 1
  charger: Charging

3. The meter runs
  after 400 Wh: meter 400 Wh, 7000 W, at 0
  should stop: false
  after 1000 Wh: meter 1000 Wh, 7000 W, at 0
  should stop: true

4. The gateway stops at the block
  delivered: 1000 Wh
  session: Closed
  charger: Preparing

5. The same payment is retried
  200 (replayed): HTTP 200
    PAYMENT-RESPONSE: {"extensions":{"mock":true},"network":"eip155:84532","payer":"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23","success":true,"transaction":""}
    body: {"amount":"10000","connector":1,"limitWh":1000,"session":1,"transaction":1}
  no second charge; the meter still reads 1000 Wh

Done. The seller verified the payment and the facilitator settled it; the seller never held a key.

~/P/Q/x402-rs (main) ❯ 
                       cargo run -p quebracho-x402-gateway --bin demo -- --safety
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/demo --safety`
x402 gateway: safety cases
  the payment is valid; only the policy changes

1. OFAC: the payer is on the list
  OFAC: HTTP 402
    PAYMENT-REQUIRED: 564 bytes (base64)
    body: {"accepts":[{"amount":"10000","asset":"0x036CbD53842c5426634e7929541eC2318f3dCF7e","extra":{"name":"USDC","paymentFlow":"delivery","version":"2"},"maxTimeoutSeconds":60,"network":"eip155:84532","payTo":"0x000000000000000000000000000000000000dEaD","scheme":"exact"}],"error":"address_sanctioned","resource":{"description":"EV charging","mimeType":"application/json","url":"https://device.test/charging/1"},"x402Version":2}
  charger: Preparing (no start)

2. Emergency stop: the stop switch is engaged
  stop: HTTP 503
    body: {"error":"payments_paused"}
  charger: Preparing (no start)

3. Rate limit: the payer has no tokens
  rate limit: HTTP 429
    body: {"error":"rate_limited"}
  charger: Preparing (no start)

No charge started in any safety case.



The first prints the 402, the paid charge, the meter, the stop at the block and the replay. The second
prints the same valid payment refused by OFAC, by the stop switch and by the rate limit; the charger
never starts. Both are offline: the payment is the PHP conformance vector, the facilitator, ledger and
charger are mocks.

## 2. QNX M0: use the minisforum

The Mint has no QNX and cannot hold the install. The minisforum output has 677 GB free, 46 GB RAM,
24 cores, `/dev/kvm` and QEMU 8.2.2; use the minisforum for QNX and the Mint for the demo and the
video. The full install is about 80 GB; the minisforum has room.

Run Gate 0 on the minisforum. The script is the shorter path:

```bash
./spike/qnx-m0/host-check.sh
```

It prints a verdict. `--report` shows the biggest directories, `--install-qemu` installs QEMU,
`--enable-kvm` tries to load KVM, and `--install-dir /media/...` checks an external SSD.

Or run the commands by hand:

```bash
df -h ~
free -h
ls -l /dev/kvm
egrep -c '(vmx|svm)' /proc/cpuinfo
qemu-system-x86_64 --version
```

Your Minisforum output: 677 GB free, QEMU 8.2.2. The Mint output is 42 GB free; the gate stops there.
The minisforum is headless: the QSC GUI via `ssh -X`, the QSTI QEMU via `xvfb-run`, the probe via SSH.
`QNX-QEMU.md` has the details.

If the minisforum is not available, use the Mint with an external SSD or a Pi 4. `spike/qnx-m0/COMMANDS.md`
has the SDP build commands once the SDP is installed.

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
