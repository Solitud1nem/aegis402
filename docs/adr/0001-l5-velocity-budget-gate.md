# ADR 0001 — L5 velocity / budget gate (stateful spend limits)

- **Status:** Accepted (2026-06-08)
- **Context tags:** defense-in-depth, stateful, AP2

## Context

L1–L4 are stateless: each inspects a single payment in isolation. That misses
**aggregate-over-time** abuse — "death by a thousand cuts" (many individually
within-limit payments summing past intent) and exceeding a cumulative mandate budget.
Competitors (Clampd hourly caps, Fireblocks spend governance) enforce such limits;
without them Aegis402 has a blind spot a poisoned agent can walk through one small
payment at a time.

## Decision

Add **L5**, a stateful detector backed by a `SpendLedger` (SQLite, shared DB with the
evidence log). The guard appends an entry for every **ALLOW**; L5 enforces two opt-in
limits per `(scope, asset)`:

- **Velocity** — trailing-window spend (`velocity_window_seconds`) must stay under
  `velocity_cap` (config-driven).
- **Total budget** — cumulative spend under `mandate.total_budget` (AP2-style).

Both are **prospective** (include the current payment); the current payment is written
only after it is ALLOWed. L5 is **opt-in**: with no cap and no budget it reports
`applicable=False` and is excluded from the aggregate (see ADR on the engine change),
so the default path is unchanged.

## Consequences

- Catches thousand-cuts / budget-bypass; reaches parity with Clampd/Fireblocks on rate
  control while staying offline and self-hosted.
- Introduces **state**, hence new failure modes documented in threat-model §5:
  - *Approved ≠ settled (ghost spend):* the ledger records allowances, not settlements;
    mitigated by a `mark_settled`/`void` reconciliation seam (ADR-adjacent, #2).
  - *TOCTOU:* check (in L5) and write (in the guard) are not atomic; acceptable for the
    single-tenant demo, needs serialization in production (#3).
- The ledger grows unbounded and is scanned per check (O(n)); fine at demo scale.

## Alternatives considered

- **In-memory counters** — simpler but lost on restart and untestable across processes.
- **Fold velocity into L3** — rejected: L3 is stateless/language-agnostic by contract;
  mixing state in muddies that and the engine weighting.
