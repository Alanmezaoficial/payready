# Return-URL commit

The provider never calls your server. It hands control back through the buyer's browser to your
`return_url` with a transaction token, and the payment becomes real only when you **commit** it
with an explicit authenticated call. The mistake that costs money is reading the browser return
as the result: an uncommitted transaction **auto-reverses** at the provider's deadline, the hold
goes back to the cardholder, and nothing is logged anywhere — it looks exactly like a buyer who
changed their mind. Transbank (Webpay Plus) is the canonical case.

**Providers in this family:** none in the catalog yet — this fragment ships ahead of Wave 2,
where Transbank lands. `scripts/generate-doctor-table.js` already emits `[FAIL]` for a
`return_url_commit` provider with no commit call: the audit exists before the provider does.

**Catalog fields this fragment reads:** `notification_model`, `commit_required.endpoint`,
`commit_required.sdk_method`, `commit_required.deadline_seconds`, `commit_required.on_timeout`,
`checkout_spec.response_redirect_pointer`, `checkout_spec.auth`, `env_vars.secret`,
`api_versioning.header`.

## The contract

1. At create time persist the row as `awaiting_return` with the provider token as
   `provider_payment_id`, a nonce from `crypto.randomUUID()` (Rule 4) appended to `return_url`,
   and `commit_deadline_at = now + commit_required.deadline_seconds`.
2. Emit **no webhook route**. `notification_model != 'webhook'` means nothing ever posts to you.
3. Cap the return body at 256 KB from `content-length` before reading it (Rule 10) → `413`. The
   return is `application/x-www-form-urlencoded`, not JSON.
4. Read the raw body (Rule 5). No signature exists in this family, so the token is a *lookup key*,
   never evidence — the browser is an untrusted intermediary carrying it.
5. Resolve the token against your own row. No row → `400`, no detail: the endpoint is public and
   someone will probe it for live tokens.
6. Compare the nonce in constant time wherever the provider preserves your `return_url` query
   string — defence in depth against a token lifted from a history or a referer header.
7. Claim the commit with a **conditional UPDATE**, never read-then-write. The buyer double-clicks
   and the browser retries the POST; exactly one request may move `awaiting_return → committing`.
   A losing request is a duplicate: return the stored outcome, commit nothing.
8. Commit through `commit_required.sdk_method`. The official SDKs expose commit as one
   fetch-and-acknowledge call that already knows the endpoint, the auth header and the API version.
9. The commit response is the only authoritative result. An unrecognised status resolves to
   `unknown` and goes to the reconciler — never `succeeded`, never `failed`.
10. Persist, then `303` to the result page. Receipts and fulfilment are enqueued, never awaited:
    the buyer is watching a spinner and the commit window is minutes wide.
11. Reconcile orphans. A buyer who closes the tab never returns, so the row sits `awaiting_return`
    forever unless a job commits it inside the window or records the reversal after it. The job
    takes the *same* conditional UPDATE before it commits anything: it is a second writer on rows
    a live browser return may be holding, and read-then-write there is the double commit again.

## Node / TypeScript

```ts
// lib/payments/<provider>/statuses.ts — one definition, imported by the route AND the reconciler.
// Provider data, not folklore: anything outside this set is `unknown`, fail closed to a human. A
// second copy in the job file drifts, and the drift ships goods for a status nobody authorised.
export const AUTHORIZED = new Set<string>(['<from provider commit response: authorised status values>']);
```

```ts
// app/api/payments/commit/route.ts   (Next.js App Router)
import { NextResponse } from 'next/server';
import { timingSafeEqual } from 'node:crypto';
import { db } from '@/lib/db';
import { gateway } from '@/lib/payments/<provider>';   // SDK client, API version pinned
import { enqueueFulfilment } from '@/lib/queue';
import { AUTHORIZED } from '@/lib/payments/<provider>/statuses';

export const runtime = 'nodejs';                       // Rule 5: raw body + node crypto, never Edge

const RESULT_PAGE = '/checkout/result';

export async function POST(request: Request) {
  // Rule 10: cap before reading a byte
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 });
  }

  const raw = await request.text();                    // Rule 5: exact bytes, form-encoded
  const form = new URLSearchParams(raw);
  const token = form.get('<from checkout_spec.response_redirect_pointer: token field>');
  const nonce = new URL(request.url).searchParams.get('nonce') ?? form.get('nonce') ?? '';

  // Buyer aborted at the provider: it returns with no token. Nothing ever authorised.
  if (!token) return NextResponse.redirect(new URL(`${RESULT_PAGE}?state=canceled`, request.url), 303);

  const payment = await db.pagokitPayment.findFirst({
    where: { provider: '<catalog id>', provider_payment_id: token },
  });
  if (!payment) return new NextResponse(null, { status: 400 });   // no detail: public endpoint
  const expectedNonce = (payment.metadata as any)?.return_nonce as string | undefined;
  if (expectedNonce && !safeEqual(nonce, expectedNonce)) return new NextResponse(null, { status: 400 });

  // Rule 4: idempotent commit. The conditional UPDATE is the lock — the double-click and the
  // browser's POST retry both arrive here, and only one of them may reach gateway.commit().
  const claimed = await db.pagokitPayment.updateMany({
    where: { id: payment.id, status: 'awaiting_return' },
    data: { status: 'committing' },
  });
  if (claimed.count === 0) {
    const current = await db.pagokitPayment.findUnique({ where: { id: payment.id } });
    return NextResponse.redirect(
      new URL(`${RESULT_PAGE}?state=${current?.status ?? 'pending'}`, request.url), 303);
  }

  let result: any;
  try {
    result = await gateway.commit(token);              // <from commit_required.sdk_method>
  } catch (err: any) {
    // "Token already used" is not a failure — an earlier attempt committed. Ask the provider
    // what happened and adopt its answer. Never assume either outcome from an exception.
    result = await gateway.status(token).catch(() => null);
    if (!result) {
      await db.pagokitPayment.update({ where: { id: payment.id }, data: { status: 'unknown' } });
      console.error('[<provider>.commit] deferred to reconciler', {
        id: payment.id, error_code: err?.code ?? 'unknown',      // Rule 6: metadata only
      });
      return NextResponse.redirect(new URL(`${RESULT_PAGE}?state=pending`, request.url), 303);
    }
  }

  const outcome = AUTHORIZED.has(String(result.status)) ? 'succeeded' : 'unknown';
  await db.pagokitPayment.update({
    where: { id: payment.id },
    data: { status: outcome, metadata: { ...(payment.metadata as object), committed_at: new Date().toISOString() } },
  });
  // Rule 6: id, type, created. The commit response carries card brand and last4 (Rule 12).
  console.log('[<provider>.commit]', { id: payment.id, type: 'commit', created: Math.floor(Date.now() / 1000), outcome });

  if (outcome === 'succeeded') await enqueueFulfilment({ payment_id: payment.id });  // fast ack
  return NextResponse.redirect(new URL(`${RESULT_PAGE}?state=${outcome}`, request.url), 303);
}

// timingSafeEqual throws on a length mismatch, so length is compared first.
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8'), bb = Buffer.from(b, 'utf8');
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
```

### The reconciler — the buyer who closed the tab

```ts
// jobs/reconcile-commits.ts — every 5 minutes. Without this, an abandoned tab is lost money.
import { db } from '@/lib/db';
import { gateway } from '@/lib/payments/<provider>';
import { enqueueFulfilment } from '@/lib/queue';
import { AUTHORIZED } from '@/lib/payments/<provider>/statuses';  // the same set the route imports

const DEADLINE_MS = 600 * 1000;      // <from commit_required.deadline_seconds>
const ON_TIMEOUT = 'auto_reverse';   // <from commit_required.on_timeout>
const GRACE_MS = 60 * 1000;          // the browser return owns the first minute; do not race it

export async function reconcileOrphanedCommits(now = new Date()) {
  const orphans = await db.pagokitPayment.findMany({
    where: {
      provider: '<catalog id>',
      status: { in: ['awaiting_return', 'committing', 'unknown'] },
      created_at: { lt: new Date(now.getTime() - GRACE_MS) },
    },
    take: 200,
  });
  for (const p of orphans) {
    try {
      // Read-only first: the provider knows whether the buyer authorised, even though you never
      // saw them. `status` is safe to call on a row somebody else is committing right now.
      const remote = await gateway.status(p.provider_payment_id).catch(() => null);
      if (remote && AUTHORIZED.has(String(remote.status))) { await settle(p, remote); continue; }

      if (now.getTime() - p.created_at.getTime() >= DEADLINE_MS) {
        if (ON_TIMEOUT === 'auto_reverse') {
          // Past the deadline the provider has already reversed it. Record it, release the stock.
          await db.pagokitPayment.updateMany({
            where: { id: p.id, status: { in: ['awaiting_return', 'committing'] } },
            data: { status: 'reversed' },
          });
        }
        continue;
      }
      // Only a row still in `awaiting_return` may be committed, and only by whoever wins the same
      // conditional UPDATE the route uses. A `committing` row already has an owner.
      const claimed = await db.pagokitPayment.updateMany({
        where: { id: p.id, status: 'awaiting_return' }, data: { status: 'committing' },
      });
      if (claimed.count === 0) continue;                                // the buyer got there first
      await settle(p, await gateway.commit(p.provider_payment_id));     // recovery, not a retry
    } catch (err: any) {
      console.error('[<provider>.reconcile]', { id: p.id, error_code: err?.code ?? 'unknown' });
    }
  }
}

async function settle(p: { id: string }, remote: any) {
  const outcome = AUTHORIZED.has(String(remote?.status)) ? 'succeeded' : 'unknown';
  await db.pagokitPayment.update({ where: { id: p.id }, data: { status: outcome } });
  console.log('[<provider>.reconcile]', { id: p.id, type: 'settle', created: Math.floor(Date.now() / 1000), outcome });
  if (outcome === 'succeeded') await enqueueFulfilment({ payment_id: p.id });
}
```

### Express

The return is form-encoded, so the raw parser names *that* content type, registered before any
body parser:

```ts
app.post('/api/payments/commit',
  express.raw({ type: 'application/x-www-form-urlencoded', limit: '256kb' }),  // Rule 5 + Rule 10
  handleCommit);
app.use(express.urlencoded({ extended: false }));   // ← AFTER the commit route
```

## Python

```python
# app/routes/commit.py   (FastAPI)
import hmac, time, logging
from urllib.parse import parse_qs
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import RedirectResponse

router, log = APIRouter(), logging.getLogger("<provider>.commit")
AUTHORIZED = {"<from provider commit response: authorised status values>"}

@router.post("/api/payments/commit")
async def commit(request: Request, db=Depends(get_db)):
    if int(request.headers.get("content-length", 0)) > 256 * 1024:
        return Response(status_code=413)                            # Rule 10
    raw = await request.body()                                      # Rule 5: never .json()
    form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
    token = form.get("<from checkout_spec.response_redirect_pointer: token field>")
    if not token:                                                   # buyer aborted at the provider
        return RedirectResponse("/checkout/result?state=canceled", status_code=303)
    payment = db.query(PagokitPayment).filter_by(
        provider="<catalog id>", provider_payment_id=token).first()
    if payment is None:
        return Response(status_code=400)                            # no detail leaked
    expected = (payment.metadata_ or {}).get("return_nonce")
    if expected and not hmac.compare_digest(request.query_params.get("nonce", ""), expected):
        return Response(status_code=400)                            # constant time

    # Rule 4: one UPDATE ... WHERE status='awaiting_return' wins; the retry loses and is a no-op.
    claimed = db.query(PagokitPayment).filter(
        PagokitPayment.id == payment.id, PagokitPayment.status == "awaiting_return",
    ).update({"status": "committing"}, synchronize_session=False)
    db.commit()
    if claimed == 0:
        db.refresh(payment)
        return RedirectResponse(f"/checkout/result?state={payment.status}", status_code=303)
    try:
        result = gateway.commit(token)                              # <from commit_required.sdk_method>
    except GatewayError as err:
        try:
            result = gateway.status(token)                          # already committed? adopt it
        except GatewayError:
            result = None                                           # never assume either outcome
        if result is None:
            payment.status = "unknown"; db.commit()
            log.error("deferred to reconciler",                     # Rule 6: metadata only
                      extra={"id": payment.id, "error_code": getattr(err, "code", "unknown")})
            return RedirectResponse("/checkout/result?state=pending", status_code=303)
    payment.status = "succeeded" if str(result.status) in AUTHORIZED else "unknown"
    db.commit()
    log.info("commit", extra={"id": payment.id, "type": "commit", "created": int(time.time())})
    if payment.status == "succeeded":
        enqueue_fulfilment(payment.id)                              # fast ack, slow work out of band
    return RedirectResponse(f"/checkout/result?state={payment.status}", status_code=303)
```

## Anti-patterns

- ❌ Marking the order paid when the browser hits `return_url` — the commit has not happened, and at the deadline the money silently goes back.
- ❌ Skipping the commit because "the buyer saw a success screen at the provider". That screen is the authorisation, not the capture.
- ❌ Read-then-write idempotency (`if (row.status === 'awaiting_return') commit()`) — the double-click passes the check twice and commits twice.
- ❌ Mapping an unrecognised commit status to `failed` — that refunds money you actually collected, or ships free goods on the retry.
- ❌ Hand-rolling the commit HTTP call when `commit_required.sdk_method` exists, or awaiting the receipt email inside the handler — the SDK acknowledges in one call, and the commit window is minutes wide with the buyer holding the connection open.
- ❌ Generating `app/api/webhook/<provider>/route.ts` for this provider — a file the provider will never call, which `/pagokit:doctor` then reports as an unexercised handler.
- ❌ A reconciler that calls `commit()` on whatever it finds. It is a second writer racing the buyer's own return — it claims the row with the same conditional UPDATE, or it commits the token twice.
- ❌ No reconciler. Every buyer who closes the tab becomes an unpaid order plus a reversed hold nobody ever sees.

## Security rules cited

- Rule 3: no signature exists in this family — the token is a lookup key. The authoritative fact comes from the commit response over the authenticated API, not from the browser.
- Rule 4: the return nonce and the checkout idempotency key both come from `crypto.randomUUID()`; the conditional UPDATE makes the commit itself idempotent.
- Rule 5: `await request.text()` / `await request.body()` under the Node runtime; Express registers `express.raw` for the form content type before `express.urlencoded()`.
- Rule 6: logs carry `id`, `type`, `created` and an error code — never the commit response.
- Rule 9: a replayed return commits nothing; the conditional UPDATE returns the stored outcome. There is no signed timestamp here, so this state guard *is* the replay defence.
- Rule 10: 256 KB cap read from `content-length` before the body; `413` otherwise.
- Rule 12: the commit response's card fields feed the receipt only; brand and last4 are the most that is ever persisted.
