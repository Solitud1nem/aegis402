# ADR 0002 — Mandate-scoped spend key (remove agent-controlled `subject`)

- **Status:** Accepted (2026-06-08)
- **Supersedes:** the initial L5 scoping via `Intent.subject`
- **Context tags:** security, trust-boundary, P0

## Context

The first L5 cut keyed velocity/budget accounting on `Intent.subject` — a free string
the agent supplied in the payload. But `subject` sits **outside the trust boundary**
(threat-model §2 trusts only `user_request` and `mandate`). A compromised or injected
agent could reset its spend history to zero on every payment by varying `subject`,
nullifying the entire L5 defense against a malicious agent — exactly the adversary
Aegis402 targets.

## Decision

Derive the ledger scope **only from the trusted mandate**:

- `Mandate.spend_key()` returns `mandate.id` when set, else a sha256 over the mandate's
  trust-relevant content (allowlist, limit, total_budget, expiry).
- `resolve_spend_key(mandate, default_key)` returns that key, or a fixed server-wide key
  (`velocity_default_key`) when there is no mandate.
- `Intent.subject` is **removed**; both the guard (record) and L5 (read) use
  `resolve_spend_key`.

The key is now unforgeable from untrusted context: no field the agent controls feeds it.

## Consequences

- L5 holds against an adversary who controls the payload — the core threat model.
- **Residual:** without a mandate, all spend shares one server-wide key per asset; L5
  still caps total throughput but cannot isolate one agent from another (threat-model
  §5). Issuing per-agent mandates removes this.
- Content-hash scoping means changing a mandate's content (e.g. raising the budget)
  yields a new scope — correct (a different mandate is a different budget envelope), but
  integrators must understand budgets are per-mandate-identity, not per-address.

## Alternatives considered

- **Sign `subject`** — would work but adds a key-management burden the guard explicitly
  avoids (it holds no keys); the mandate is already the trusted artifact.
- **Key on recipient address** — wrong granularity: one mandate legitimately pays many
  payees, and budgets are per-mandate, not per-payee.
