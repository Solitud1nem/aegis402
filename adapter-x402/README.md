# @aegis402/adapter-x402

A **thin** TypeScript wrapper that inserts the [Aegis402](../README.md) guard into an
x402 payment flow — right before the `PaymentPayload` is signed. Its only job is one
HTTP call to the core (`POST /guard/inspect`); the payment is signed/settled **only**
on `ALLOW` (or an explicitly approved `REVIEW`).

The adapter holds no keys and does no signing. Your `signAndSettle` callback is the real
x402 step, and it simply never runs when the guard returns `BLOCK`.

## Usage

```ts
import { createAegisGuard } from "@aegis402/adapter-x402";

const guard = createAegisGuard({ endpoint: "http://127.0.0.1:8402" });

await guard.guard(
  {
    user_request: "Pay 5 USDC to 0xVendor… for the invoice.",
    untrusted_context: [webPageText, emailBody], // whatever the agent read
    payment_intent: { recipient, amount, asset: "USDC", network: "base-sepolia" },
    mandate: { limit: 50_000_000, allowlist: ["0xVendor…"], networks: ["base-sepolia"] },
  },
  // `verified` is the exact payment the guard inspected (frozen). Build the
  // PaymentPayload from THIS — never an independently-constructed payment — so what
  // is signed is provably what was vetted. Runs only on ALLOW.
  (verified) => x402Client.signAndSettle(toPaymentPayload(verified)),
);
```

> **Why the argument matters.** The guard validates a payment *description*. That
> guarantee only holds if the description and the execution cannot diverge. Binding
> `signAndSettle` to the `verified` payment closes the gap where a compromised agent
> inspects a benign payment and signs a different (attacker) one.

On `BLOCK` (or un-approved `REVIEW`) it throws `PaymentBlockedError` carrying the
verdict. The guard is **fail-closed**: if the core is unreachable it returns a
synthetic `BLOCK` rather than letting the payment through.

## Demo

```bash
# 1. start the core (from the repo root)
aegis402 serve

# 2. run the guarded agent (from this directory)
pnpm install
pnpm demo:attack   # poisoned context → BLOCK, payment never signed
pnpm demo:benign   # clean payment    → ALLOW, payment signed
```
