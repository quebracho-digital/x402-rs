# Threat model

One page. Rule: every defence answers a threat in this table and has a test; anything else stays out,
so the code stays maintainable. **Status** says what exists today and what is still to build.

## Assets

| # | Asset | Harm if lost |
|---|---|---|
| A1 | The buyer's private key (`signerd`) | Someone spends the buyer's funds |
| A2 | The buyer's funds (USDC) | Direct loss |
| A3 | The seller's service (energy from a charger, a sensor reading) | Delivered without being paid |
| A4 | The integrity of the payment ledger and of charging sessions | Double delivery, lost payments |
| A5 | Compliance (OFAC and other lists) | Doing business with sanctioned addresses |
| A6 | The device's availability | No sales, a charger out of service |
| A7 | Drivers' and hosts' personal data | Privacy (GDPR in the EU) |

## Attackers

- **R**: the remote network (internet, a neighbour's Wi-Fi), with no access to the device.
- **C**: a compromised or buggy charger or app on the device.
- **P**: the other side of the payment (a cheating buyer against a seller, or the reverse).
- **L**: local access to the device, physical or as a user.

Out of scope: an attacker with root on the device, hardware side channels, legal coercion.

## Threats and defences

| # | Threat (attacker → asset) | Defence | Status |
|---|---|---|---|
| T1 | Replaying a payment to get two deliveries (P → A3/A4) | One signature, one delivery: an atomic claim on (network, payer, nonce) before the handler runs | **Done**: `seller`, `FileLedger`; race and replay tests |
| T2 | The process dies between charging and delivering (A3/A4) | State written before the effect (`settling`, `handling`); replay from the ledger; reconciler | **Done** for the seller; reconciler pending |
| T3 | A compromised app asks for signatures to any payee (C → A1/A2) | Policies inside `signerd`: allowed payees, known tokens and EIP-712 domains, amount caps, budget | Pending (`signerd`) |
| T4 | Another app steals the key (C/L → A1) | The key lives only in `signerd`: separate process, minimal QNX abilities, file mode 0600 | Pending (`signerd`) |
| T5 | A fake EIP-712 domain: signing for a token that is not USDC (R/P → A2) | Closed list of tokens and domains verified on chain | Pending (buyer) |
| T6 | A wrong clock: an expired or endless `validBefore` (R/L → A2/A4) | No trusted time, no payment admitted or signed (fail closed) | **Done**: `Clock::reliable`, `SystemClock` |
| T7 | Sanctioned or frozen addresses (P → A5) | OFAC's SDN list on by default, more lists, USDC freeze by RPC; a list that cannot answer refuses | **Done**: OFAC shipped, token blacklists (USDC/USDT freeze), Chainalysis oracle and API, own lists, list syncs (`quebracho-x402-screening`) |
| T8 | Reading or changing payment or charger traffic (R → A2/A3) | TLS on every connection; without TLS it does not run | **Done** for outgoing calls (`HttpsClient`); seller and OCPP servers pending |
| T9 | A fake charger connects to the gateway (R → A3/A7) | One identity per charger; `payTo` fixed by the gateway | Pending (gateway) |
| T10 | The charger lies about its meter (C → A2/A3) | v1: readings shown as declared, energy blocks capped. Production: signed meter readings | Pending (gateway) |
| T11 | A driver empties the wallet after charging starts (P → A3) | Settle when the start is confirmed, small blocks, stop if the settle fails | Pending (gateway) |
| T12 | Malformed or huge input (R → A6) | Strict parsing, size limits, one failing request does not take the rest down | **Done** for payments and HTTPS answers; servers pending |
| T13 | A process crashes or hangs (A6) | QNX High Availability Manager restarts it; recovery from the ledger | Pending (QNX) |
| T14 | An in-memory ledger lost on reboot (A4) | Accepted in the Lite profile: work is lost, not money (the spent nonce makes a second settle fail) | By design |
| T15 | Personal data leaks (R → A7) | Keep the minimum; never a signature or a body in logs or open entries | **Done** for the ledger's open entries |

## Left out on purpose

Entropy mixing, boot quarantine, in-flight signature limits: more checks than value. A per-charger
client-certificate PKI: costs more than it gives in v1. Defending against root: out of scope. Refunds
and disputes: x402 `exact` has none; exposure is bounded by small energy blocks.
