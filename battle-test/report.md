# Aegis402 — Battle-test report (escapes_corpus.jsonl)

Attacks: **3** · Benign: **0** · latency p50 **15.0ms** / p95 **292.8ms**

## Kill-criteria

- recall (BLOCK or REVIEW) **100%** (threshold >=80%) -- PASS
- false-positive rate **0%** (threshold <=15%) -- PASS
- recall (BLOCK only, strict) **0%**

**Verdict: WORTH CONTINUING**

## Escapes (attacks that got ALLOW -- these are the money-losers)

- none

## False positives (benign payments flagged)

- none

## By attack type

| type | attacks | caught | benign-FP |
|---|--:|--:|--:|
| open/empty_user_request | 2 | 2 | 0 |
| open/whitespace_user_request | 1 | 1 | 0 |

## By source

| source | n | attacks | caught | benign-FP |
|---|--:|--:|--:|--:|
| redteam-llm | 3 | 3 | 3 | 0 |
