/**
 * Aegis402 x402 adapter — a thin guard that runs *before* a PaymentPayload is signed.
 *
 * The whole job of this module is one HTTP call: hand the payment intent plus the
 * context that produced it to the Aegis402 core (`POST /guard/inspect`) and only let
 * the agent proceed to sign/settle on an `ALLOW` (or an explicitly approved `REVIEW`).
 *
 * It deliberately holds no keys and does no signing — the caller's `signAndSettle`
 * thunk is the real x402 step, and it simply never runs when the guard says BLOCK.
 */

/** A payment the agent is about to make, in x402 terms. Amount is minimal units. */
export interface PaymentIntent {
  recipient: string;
  /** Integer minimal units (e.g. 6-dec USDC). String-safe for large values. */
  amount: number | string;
  asset: string;
  network: string;
}

/** Owner-set spending policy the payment must respect. */
export interface Mandate {
  limit?: number | null;
  allowlist?: string[];
  /** Permitted networks (chain ids); empty/omitted = unrestricted. */
  networks?: string[];
  /** Permitted asset symbols/contracts; empty/omitted = unrestricted. */
  assets?: string[];
}

/** The guard's input: the payment plus the trusted request and untrusted sources. */
export interface GuardIntent {
  user_request: string;
  untrusted_context: string[];
  payment_intent: PaymentIntent;
  mandate?: Mandate;
}

export type VerdictType = "ALLOW" | "BLOCK" | "REVIEW";

export interface Signal {
  layer: string;
  score: number;
  reason: string;
}

/** The guard's decision, mirroring the core's `Verdict` schema. */
export interface Verdict {
  verdict: VerdictType;
  score: number;
  reason: string;
  evidence_id?: string | null;
  triggered_layers: Signal[];
}

export interface AegisGuardOptions {
  /** Base URL of the Aegis402 core. Default: `http://127.0.0.1:8402`. */
  endpoint?: string;
  /** Per-request timeout in ms. Default: 1000. */
  timeoutMs?: number;
  /** On guard error/timeout, fail closed (synthesize a BLOCK). Default: true. */
  failClosed?: boolean;
  /**
   * Called when the guard returns REVIEW. Return true to approve and proceed,
   * false (default, if unset) to treat REVIEW as a block.
   */
  onReview?: (intent: GuardIntent, verdict: Verdict) => Promise<boolean> | boolean;
}

/** Thrown when the guard blocks (or an un-approved REVIEW) a payment. */
export class PaymentBlockedError extends Error {
  constructor(public readonly verdict: Verdict) {
    super(`Aegis402 ${verdict.verdict}: ${verdict.reason}`);
    this.name = "PaymentBlockedError";
  }
}

const DEFAULTS = {
  endpoint: "http://127.0.0.1:8402",
  timeoutMs: 1000,
  failClosed: true,
} as const;

/** Build the fail-closed verdict used when the guard cannot be reached. */
function failClosedVerdict(reason: string): Verdict {
  return {
    verdict: "BLOCK",
    score: 1.0,
    reason: `guard unreachable (fail-closed BLOCK): ${reason}`,
    triggered_layers: [],
  };
}

/**
 * Validate that `amount` (minimal units) is an exact non-negative integer.
 *
 * Amounts can exceed 2^53 (e.g. 1 token at 18 decimals = 1e18 > Number.MAX_SAFE_INTEGER),
 * where a JS `number` silently loses precision — so the guard would vet a *different*
 * value than what settles. Returns a reason string if the amount is unsafe, else null;
 * the caller fails closed to BLOCK. Pass large amounts as decimal strings.
 */
function unsafeAmountReason(amount: number | string): string | null {
  if (typeof amount === "number") {
    if (!Number.isInteger(amount)) return `amount ${amount} is not an integer`;
    if (!Number.isSafeInteger(amount)) {
      return `amount ${amount} exceeds Number.MAX_SAFE_INTEGER — pass it as a string to avoid precision loss`;
    }
    return amount < 0 ? `amount ${amount} is negative` : null;
  }
  return /^\d+$/.test(amount) ? null : `amount "${amount}" is not a non-negative integer string`;
}

/** Fail-closed verdict for a payment the adapter rejects before it ever reaches the guard. */
function rejectedVerdict(reason: string): Verdict {
  return {
    verdict: "BLOCK",
    score: 1.0,
    reason: `rejected before guard (fail-closed BLOCK): ${reason}`,
    triggered_layers: [],
  };
}

/**
 * Ask the Aegis402 core to inspect a payment intent.
 *
 * Never throws on transport errors: on timeout/failure it returns a fail-closed
 * BLOCK verdict (unless `failClosed` is explicitly disabled, in which case the
 * error is rethrown so the caller can decide).
 */
export async function inspectPayment(
  intent: GuardIntent,
  options: AegisGuardOptions = {},
): Promise<Verdict> {
  const endpoint = options.endpoint ?? DEFAULTS.endpoint;
  const timeoutMs = options.timeoutMs ?? DEFAULTS.timeoutMs;
  const failClosed = options.failClosed ?? DEFAULTS.failClosed;

  // Reject a precision-lossy amount up front: an imprecise number would let the guard
  // vet a value that differs from what actually settles.
  const amountReason = unsafeAmountReason(intent.payment_intent.amount);
  if (amountReason !== null) return rejectedVerdict(amountReason);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${endpoint}/guard/inspect`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(intent),
      signal: controller.signal,
    });
    if (!resp.ok) {
      const detail = `HTTP ${resp.status}`;
      if (failClosed) return failClosedVerdict(detail);
      throw new Error(`guard returned ${detail}`);
    }
    return (await resp.json()) as Verdict;
  } catch (err) {
    if (failClosed) return failClosedVerdict((err as Error).message);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** A guard bound to a set of options. Reuse one instance across an agent. */
export interface AegisGuard {
  /** Inspect an intent and return the raw verdict. */
  inspect(intent: GuardIntent): Promise<Verdict>;
  /**
   * Native x402 insertion point: inspect the intent, then run `signAndSettle`
   * only on ALLOW (or an approved REVIEW). Throws {@link PaymentBlockedError}
   * otherwise, so a blocked payment is never signed.
   *
   * `signAndSettle` receives the *exact* `payment_intent` the guard inspected
   * (frozen). Build your x402 PaymentPayload from THIS argument — never from an
   * independently-constructed payment — so what gets signed is provably what was
   * vetted. The guard validates a payment description; it is only meaningful if the
   * description and the execution cannot diverge.
   */
  guard<T>(
    intent: GuardIntent,
    signAndSettle: (verified: Readonly<PaymentIntent>) => Promise<T> | T,
  ): Promise<T>;
}

/** Create an {@link AegisGuard} pre-bound to the given options. */
export function createAegisGuard(options: AegisGuardOptions = {}): AegisGuard {
  return {
    inspect: (intent) => inspectPayment(intent, options),
    async guard(intent, signAndSettle) {
      const verdict = await inspectPayment(intent, options);
      // Hand the callback the exact payment that was vetted, frozen so it cannot be
      // mutated after approval. This binds execution to inspection: a caller cannot
      // inspect a benign payment and then settle a different (e.g. attacker) one.
      const verified = Object.freeze({ ...intent.payment_intent });
      if (verdict.verdict === "ALLOW") {
        return signAndSettle(verified);
      }
      if (verdict.verdict === "REVIEW") {
        const approved = options.onReview ? await options.onReview(intent, verdict) : false;
        if (approved) return signAndSettle(verified);
      }
      throw new PaymentBlockedError(verdict);
    },
  };
}
