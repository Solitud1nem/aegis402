# Crypto-native provenance corpus — isolating the L4 moat

Self-authored, grounded in documented crypto attack classes (address poisoning, vendor address-change notices, compromised docs). NOT external like AgentDojo; its job is to exercise L4 provenance, which the IBAN→synthetic-address rail-swap in the fiat corpora makes structurally unreachable. Semantic-clean (no injection phrasing).

## Headline — L4 as the SOLE grounded catcher

Cohort A (80 cases): attacker address sourced from poisoned untrusted context, **no address in the owner's request, no allowlist** — so L1/L2/L3 are silent.

- BLOCK recall: **80/80 = 100%**
- of which **L4 is the only grounded layer at/above block_threshold**: **80/80 = 100%**  ← the provenance number

## Cohort B — semantic-clean, no anchor (address nowhere in text)

- caught (BLOCK or REVIEW): **20/20**; L4-sole REVIEW: 20/20. Honest: unaccountable recipients route to REVIEW (human confirm), not BLOCK — nothing in text proves them malicious.

## Cohort C — benign (recipient is the address the owner named)

- false positives: **0/40 = 0%**

## Reading it

- Cohort A is the number the fiat corpora cannot produce: with the attacker address present in poisoned context and nothing else to catch it, **L4 provenance alone** blocks the redirect. This validates the moat the AgentDojo/InjecAgent runs could only assert via the single own-corpus case `smoke-a04`.
- Cohort B is the known L4 limit: no anchor anywhere → REVIEW, not BLOCK. Reported, not hidden.
- Latency and corpus are reproducible (seed 1); `crypto_corpus.jsonl` replays through run_battle.py too (which reports recall/FPR but not the sole-catcher split).
