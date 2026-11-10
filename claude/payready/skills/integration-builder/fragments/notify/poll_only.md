# Poll only

There is no callback. The provider never posts anything, never redirects with a token: the only
way to learn whether a payment settled is to ask, repeatedly, over the authenticated API. The
mistake that ends in a chargeback is the timeout branch — polling for a while, giving up, and
writing `failed`. **A payment you could not read is `unknown`, not failed.** An unknown payment
may still settle hours later: call it failed and you either hand the buyer free goods (you
shipped nothing, they were charged) or double-charge them when they retry a payment that had
already gone through. `unknown` is a real, terminal-until-proven state, and the thing that
resolves it is the settlement report, not a clock.

**Providers in this family:** none in the catalog yet — it ships ahead of the Wave 2 LATAM
acquirers, Niubiz first (`regions.json` puts it in Phase 2 for Peru). Selection is
`notification_model == "poll_only"` in the provider's own entry, never this list.

**Catalog fields this fragment reads:** `notification_model`, `webhook.refetch_endpoint`,
`checkout_spec.auth`, `checkout_spec.create_endpoint`, `env_vars.secret`,
`settlement.payout_delay_days`, `api_versioning.header`, `api_versioning.current`.

## The contract

1. Emit **no webhook route**. The `notification_handler` slot is skipped entirely — a route file
   for a provider that never calls it is dead code that reads as working coverage.
2. On authorisation, write the row as `pending` and enqueue poll attempt 1. The queue, not the
   request, owns the payment from here.
3. Each attempt reads status from `webhook.refetch_endpoint` with the API credential
   (`env_vars.secret`) and maps it through an explicit `STATUS_MAP`.
4. A terminal status stops the loop: `succeeded`, `failed`, `canceled`, `refunded`, `disputed`.
   Anything unmapped is **not** terminal — it reschedules.
5. A non-terminal status reschedules with exponential backoff plus jitter, capped (2 s → 5 min).
   Fixed-interval polling gets you rate-limited, then blocked, at exactly the moment volume
   makes it matter.
6. A transport error (timeout, 5xx, DNS) is **not** an answer. Reschedule; never map it to a
   status. "The status call failed" and "the payment failed" are different sentences.
7. Past the poll deadline, resolve to `unknown`, stop polling, and alert a human. Never `failed`.
   The catalog has no poll-deadline field: derive it from the provider's authorisation hold and
   record the value in `PAGOKIT_INTEGRATION.md` so the next reader knows where it came from.
8. Reconcile against the provider's settlement report once `settlement.payout_delay_days` has
   passed. Presence in the report resolves `unknown → succeeded`; **absence** resolves
   `unknown → failed`. That is the only evidence that closes an unknown — and it is evidence only
   for a payment old enough to have settled. A row younger than the payout delay is absent because
   it has not settled yet; skip it, or you have rebuilt the timeout bug inside the reconciler.
9. Reconcile in both directions. A settlement line with no local row is money you took and never
   recorded — an order nobody shipped.
10. The poll worker is idempotent and re-entrant: cron overlaps, and the same attempt will run
    twice. Terminal rows return immediately.

## Node / TypeScript

```ts
// jobs/poll-<provider>.ts
import { db } from '@/lib/db';
import { enqueuePoll, enqueueFulfilment, alertOps } from '@/lib/queue';
import { requireEnv } from '@/lib/env';          // Rule 1: throws when the credential is missing

const TERMINAL = new Set(['succeeded', 'failed', 'canceled', 'refunded', 'disputed']);
const STATUS_MAP: Record<string, string> = { '<from provider status values>': 'succeeded' };
// No catalog field holds this. Derive it from the provider's authorisation hold and record the
// number and its source in PAGOKIT_INTEGRATION.md; 24 h is only a starting default.
const DEADLINE_MS = 24 * 60 * 60 * 1000;

export async function pollOnce({ payment_id, attempt }: { payment_id: string; attempt: number }) {
  const payment = await db.pagokitPayment.findUnique({ where: { id: payment_id } });
  if (!payment || TERMINAL.has(payment.status) || payment.status === 'unknown') return;  // re-entrant

  if (Date.now() - payment.created_at.getTime() > DEADLINE_MS) return resolveUnknown(payment);

  let remote: any;
  try {
    remote = await fetchStatus(payment.provider_payment_id);
  } catch (err: any) {
    // A timeout or a 5xx is not "not found". Reschedule; only the deadline ends this loop.
    console.error('[<provider>.poll] status call failed', {
      id: payment.id, attempt, error_code: err?.code ?? 'unknown',    // Rule 6: metadata only
    });
    return enqueuePoll({ payment_id, attempt: attempt + 1, delay_ms: backoffMs(attempt + 1) });
  }

  const next = STATUS_MAP[String(remote.status)] ?? 'pending';
  if (!TERMINAL.has(next)) {
    return enqueuePoll({ payment_id, attempt: attempt + 1, delay_ms: backoffMs(attempt + 1) });
  }

  await db.pagokitPayment.update({ where: { id: payment.id }, data: { status: next } });
  // Rule 6: id, type, created. Never the status response — it carries the payer record.
  console.log('[<provider>.poll]', { id: payment.id, type: next, created: remote.created_at });
  if (next === 'succeeded') await enqueueFulfilment({ payment_id: payment.id });   // out of band
}

async function resolveUnknown(payment: { id: string }) {
  // UNKNOWN, never FAILED. An unknown payment may still settle; `failed` here either ships free
  // goods or double-charges the buyer on their retry. Only the settlement report closes this.
  await db.pagokitPayment.update({ where: { id: payment.id }, data: { status: 'unknown' } });
  await alertOps({ kind: 'payment_unknown', payment_id: payment.id });
}

async function fetchStatus(reference: string) {
  const url = '<from webhook.refetch_endpoint>'.replace('{id}', encodeURIComponent(reference));
  const res = await fetch(url, {
    headers: {
      // <from checkout_spec.auth> — the API credential from env_vars.secret (Rule 1).
      Authorization: `Bearer ${requireEnv('<from env_vars.secret>')}`,
      '<from api_versioning.header>': '<from api_versioning.current>',
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`status_failed_${res.status}`);
  return res.json();
}

// Half the window is fixed so a retry never fires instantly, half is random so a thousand
// pending payments do not hit the status API in lockstep after a provider outage.
export function backoffMs(attempt: number, base = 2_000, cap = 300_000): number {
  const window = Math.min(cap, base * 2 ** Math.max(0, attempt - 1));
  return Math.round(window / 2 + Math.random() * (window / 2));
}
```

### Reconciliation — the settlement report is the money truth

```ts
// jobs/reconcile-<provider>.ts — daily, after settlement.payout_delay_days.
// The status API answers about an attempt. The report answers about funds that moved.
import { db } from '@/lib/db';
import { enqueueFulfilment, alertOps } from '@/lib/queue';

const PAYOUT_DELAY_DAYS = 7;   // <from settlement.payout_delay_days>, the slow end of the range

export async function reconcileSettlement(
  rows: Array<{ reference: string; settled_at: string; batch_id: string }>,
  now = new Date(),
) {
  const byRef = new Map(rows.map((r) => [String(r.reference), r]));

  const open = await db.pagokitPayment.findMany({
    where: { provider: '<catalog id>', status: { in: ['unknown', 'pending'] } },
    take: 1000,
  });

  for (const p of open) {
    const row = byRef.get(p.provider_payment_id);
    if (row) {
      await db.pagokitPayment.update({
        where: { id: p.id },
        data: { status: 'succeeded', metadata: { ...(p.metadata as object), settlement_batch: row.batch_id } },
      });
      await enqueueFulfilment({ payment_id: p.id });
      continue;
    }
    // Absence is evidence only once the payout window has closed. A payment authorised this
    // morning is missing from today's batch because it has not settled yet — failing it here is
    // the timeout mistake wearing a reconciler's hat.
    if (now.getTime() - p.created_at.getTime() < PAYOUT_DELAY_DAYS * 86_400_000) continue;
    // Absent from a batch that should have carried it: no money moved. This — not a clock — is
    // the only route from `unknown` to `failed`.
    await db.pagokitPayment.update({ where: { id: p.id }, data: { status: 'failed' } });
  }

  // The other direction: money in the report with no local row is an order nobody shipped.
  const known = new Set(open.map((p) => p.provider_payment_id));
  for (const ref of byRef.keys()) {
    if (known.has(ref)) continue;
    const local = await db.pagokitPayment.findFirst({
      where: { provider: '<catalog id>', provider_payment_id: ref },
    });
    if (!local) await alertOps({ kind: 'unmatched_settlement', reference: ref });
  }
}
```

### The cron trigger

```ts
// app/api/cron/poll-<provider>/route.ts
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { db } from '@/lib/db';
import { enqueuePoll } from '@/lib/queue';
import { backoffMs } from '@/jobs/poll-<provider>';

export const runtime = 'nodejs';                          // Rule 5-adjacent: node crypto, never Edge

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 });       // Rule 10 applies to every public route
  }
  // Rule 1 + Rule 3: the trigger is public. An unset secret refuses the trigger; it never opens it.
  const configured = process.env.CRON_SECRET;
  if (!configured) {
    console.error('[<provider>.cron] CRON_SECRET is not set — refusing the trigger');
    return new NextResponse(null, { status: 500 });
  }
  const presented = (request.headers.get('authorization') ?? '').replace(/^Bearer /, '');
  if (!secretMatches(presented, configured)) {
    return new NextResponse(null, { status: 401 });       // 401 here: the caller is yours, not
  }                                                       // the provider's — nothing leaks either way
  await sweepPending();
  return NextResponse.json({ ok: true });
}

// Re-arm anything the queue dropped (a worker crash, a redeploy mid-flight). Cheap and idempotent:
// pollOnce() no-ops on terminal and unknown rows, so an overlapping sweep costs one indexed read.
async function sweepPending() {
  const stale = await db.pagokitPayment.findMany({
    where: { provider: '<catalog id>', status: 'pending' }, take: 500,
  });
  for (const p of stale) await enqueuePoll({ payment_id: p.id, attempt: 1, delay_ms: backoffMs(1) });
}

// Both sides hashed to a fixed 32 bytes: timingSafeEqual throws on a length mismatch, and a bare
// length comparison leaks how long CRON_SECRET is before a single byte is compared.
function secretMatches(presented: string, configured: string): boolean {
  if (!configured) return false;
  const a = crypto.createHash('sha256').update(presented, 'utf8').digest();
  const b = crypto.createHash('sha256').update(configured, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}
```

## Python

```python
# app/jobs/poll_<provider>.py
import logging, secrets
from datetime import datetime, timezone

log = logging.getLogger("<provider>.poll")
TERMINAL = {"succeeded", "failed", "canceled", "refunded", "disputed"}
STATUS_MAP = {"<from provider status values>": "succeeded"}
DEADLINE_S = 24 * 60 * 60          # from the provider's authorisation hold; record it in
                                   # PAGOKIT_INTEGRATION.md, this default is only a starting point

def backoff_ms(attempt: int, base: int = 2_000, cap: int = 300_000) -> int:
    window = min(cap, base * 2 ** max(0, attempt - 1))
    return window // 2 + secrets.randbelow(window // 2 + 1)

def poll_once(payment_id: str, attempt: int, db) -> None:
    payment = db.get(PagokitPayment, payment_id)
    if payment is None or payment.status in TERMINAL or payment.status == "unknown":
        return                                                    # re-entrant: cron runs overlap
    age = (datetime.now(timezone.utc) - payment.created_at).total_seconds()
    if age > DEADLINE_S:
        # UNKNOWN, never FAILED — only the settlement report closes this.
        payment.status = "unknown"; db.commit()
        alert_ops("payment_unknown", payment.id)
        return
    try:
        remote = fetch_status(payment.provider_payment_id)        # env_vars.secret, 10s timeout
    except StatusUnavailable as err:
        log.error("status call failed", extra={"id": payment.id, "attempt": attempt,
                                               "error_code": getattr(err, "code", "unknown")})  # Rule 6
        return enqueue_poll(payment.id, attempt + 1, backoff_ms(attempt + 1))

    nxt = STATUS_MAP.get(str(remote["status"]), "pending")
    if nxt not in TERMINAL:
        return enqueue_poll(payment.id, attempt + 1, backoff_ms(attempt + 1))
    payment.status = nxt
    db.commit()
    log.info("poll", extra={"id": payment.id, "type": nxt, "created": remote["created_at"]})
    if nxt == "succeeded":
        enqueue_fulfilment(payment.id)                            # slow work out of band
```

The FastAPI cron trigger mirrors the Node one: `await request.body()` (Rule 5), the 256 KB cap
(Rule 10), a `500` when `CRON_SECRET` is unset, and
`hmac.compare_digest(sha256(presented).digest(), sha256(configured).digest())` for the compare.

## Anti-patterns

- ❌ `status = 'failed'` when polling times out. This is the whole reason the fragment exists: an unknown payment may still settle, and failing it either ships free goods or double-charges the buyer on their retry.
- ❌ Polling on a fixed 1-second interval, or in a `while (true)` inside a request handler. You get rate-limited, then blocked, and the request times out holding a connection.
- ❌ Polling with no deadline. The queue fills with rows that will never resolve, and the real incidents drown in them.
- ❌ Generating `app/api/webhook/<provider>/route.ts` for a `poll_only` provider — a handler nothing ever calls, which reads as coverage in every audit.
- ❌ Treating an HTTP timeout or a 5xx from the status call as "not found". That is the same double-charge by a different route.
- ❌ Reconciling against the status API instead of the settlement report. The API describes an attempt; only the report describes money that moved.
- ❌ Failing every open row missing from today's batch. A payment authorised an hour ago is missing because it has not settled yet — absence is only evidence past `settlement.payout_delay_days`.
- ❌ One-directional reconciliation. A settlement line with no local row is an order you were paid for and never shipped.
- ❌ `Math.random()` as the poll backoff *and* as an idempotency key (Rule 4). Jitter may be non-cryptographic; keys may not.

## Security rules cited

- Rule 1: the status call reads its credential from `env_vars.secret` via `process.env` / `os.environ`; nothing is inlined in the worker.
- Rule 3: there is no callback to authenticate, so the authenticated status call *is* the verification. The public cron trigger is gated by a constant-time compare (`timingSafeEqual` / `hmac.compare_digest`) over SHA-256 digests of both sides, and an unset `CRON_SECRET` refuses the trigger rather than opening it.
- Rule 4: the poll job is keyed on the payment id and is re-entrant; terminal and `unknown` rows return immediately, so an overlapping cron cannot double-fulfil.
- Rule 5: no signature exists here, so no raw body is load-bearing — the cron route still reads under the Node runtime and skips `request.json()` on an unauthenticated caller.
- Rule 6: `id`, `type`, `created` and an error code. The status response holds the payer record and never reaches a log line.
- Rule 9: replay is not applicable (nothing is delivered to you), but the same idempotency it buys is provided by the terminal-state guard: a repeated attempt is a no-op.
- Rule 10: the cron trigger caps at 256 KB and returns `413`, like every other public route in the integration.
