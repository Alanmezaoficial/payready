# Ping, then poll

The provider posts you a nudge, not an event: a bare token or reference id with no useful
payload, which you exchange for the real transaction over an authenticated call. The one thing
developers get wrong is treating the ping like a webhook — reading `status` or `amount` out of
the posted body and writing them to the database. **The ping names a record; it does not
describe one.** Everything in it except the reference is attacker-controlled, and on most
providers in this family there is no signature at all, so anyone who learns the URL can post
`{"token":"abc","status":"PAID"}` all day.

**Providers in this family:** none in the catalog yet — it ships ahead of the Wave 2 LATAM
providers whose callback is a bare nudge (EBANX and Flow are the roadmap's candidates, PayPhone
follows in Phase 3). Selection is `notification_model == "ping_then_poll"` in the provider's own
entry, never this list: no provider belongs here until that value ships with `confidence: "high"`.

**Catalog fields this fragment reads:** `notification_model`, `webhook.payload_authoritative`,
`webhook.refetch_endpoint`, `webhook.event_id_pointer`, `webhook.verification_family`,
`webhook.signature_header`, `webhook.ack_body_literal`, `webhook.ack_deadline_seconds`,
`webhook.expected_filenames`, `env_vars.webhook_secret`, `env_vars.secret`, `checkout_spec.auth`.

## The contract

1. Cap the body at 256 KB from `content-length` before reading it (Rule 10) → `413`.
2. Read the raw body (Rule 5). The ping is usually `application/x-www-form-urlencoded`, so a
   reflexive `request.json()` returns `400` on every *genuine* delivery.
3. If `verification_family == 'shared_secret_header'`, compare that header to
   `env_vars.webhook_secret` in constant time over fixed-length digests (Rule 3). It accepts and
   rejects exactly what `verifyEvent()` in `scripts/lib/webhook-sign.js` does, so a `/pagokit:test`
   pass means the handler and the signer agree; hashing first only removes the length leak. An
   unset env var **fails closed with a 500** — it never degrades into "everything matches". The
   header authenticates the *caller*, not the contents. For `none_refetch` / `none` there is
   nothing to compare, and `scripts/sign-event.js` correctly reports `[SKIP]`.
4. Extract **only** the reference at `webhook.event_id_pointer`. Discard the rest of the body.
5. Look it up in your own tables. Unknown reference → log and ack `200`. A `404` tells a prober
   which references exist and makes the provider retry an id you will never recognise.
6. Re-fetch the transaction from `webhook.refetch_endpoint` with the API credential
   (`env_vars.secret`), **not** the callback secret. This response is the only authoritative
   state — `payload_authoritative` is `false` for this whole family.
7. Dedup (Rule 9). There is no event id and no signed timestamp, so the unit of deduplication is
   the *state transition*: key `webhook_events_processed` on `<provider>:<reference>:<status>`.
   Duplicate → `200`, no work. The key and the state change go in **one transaction** — a dedup row
   written on its own turns the next redelivery into a duplicate of work that never happened.
8. Apply the transition only if it advances. A late ping that re-reports `pending` after you
   recorded `succeeded` must not walk the payment backwards.
9. Still pending? Enqueue a delayed re-poll with exponential backoff and jitter, then ack
   immediately. Never sleep inside the handler: past `webhook.ack_deadline_seconds` the provider
   retries, and you get N concurrent handlers all sleeping on the same reference.
10. Ack with `webhook.ack_body_literal` verbatim when the catalog names one. `200` for unhandled
    statuses, with a logged TODO — a `4xx` gets the endpoint disabled.

## Node / TypeScript

```ts
// app/api/webhook/<provider>/route.ts   (Next.js App Router)
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { db } from '@/lib/db';
import { enqueuePoll, enqueueFulfilment } from '@/lib/queue';
import { requireEnv } from '@/lib/env';          // Rule 1: throws when the credential is missing

export const runtime = 'nodejs';                 // Rule 5: raw body + node crypto, never Edge
const ACK_BODY = '';                             // <from webhook.ack_body_literal>, '' when none
const SECRET_ENV = 'PROVIDER_WEBHOOK_SECRET';    // <from env_vars.webhook_secret>, '' for none_refetch
const STATUS_MAP: Record<string, string> = { '<from provider status values>': 'succeeded' };
// Monotonic ladder: a transition applies only if it climbs. Both terminal outcomes sit on the
// same rung, so succeeded→failed is refused — and so is failed→succeeded.
const RANK: Record<string, number> = {
  pending: 0, unknown: 1, authorized: 2, succeeded: 3, failed: 3, canceled: 3, refunded: 4, disputed: 5,
};

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 });            // Rule 10
  }
  const ping = parsePing(await request.text());                // Rule 5: exact bytes
  if (!ping) return new NextResponse(null, { status: 400 });

  // Rule 3: the only authentication a ping carries. An unset env var must never degrade into
  // "everything matches" — which is what `if (secret) { check }` does the day someone typos it.
  if (SECRET_ENV) {
    const configured = process.env[SECRET_ENV];
    if (!configured) {
      console.error(`[<provider>.ping] ${SECRET_ENV} is not set — refusing all callbacks`);
      return new NextResponse(null, { status: 500 });                             // fail closed
    }
    const got = request.headers.get('<from webhook.signature_header>');
    if (!sharedSecretMatches(got, configured)) return new NextResponse(null, { status: 400 });
  }
  const reference = String(ping['<from webhook.event_id_pointer>'] ?? '');
  if (!reference) return new NextResponse(null, { status: 400 });
  const payment = await db.pagokitPayment.findFirst({
    where: { provider: '<catalog id>', provider_payment_id: reference },
  });
  if (!payment) {
    console.log('[<provider>.ping] unknown reference', { id: reference });   // Rule 6
    return ack();                                              // 200, never 404
  }
  // The authoritative read. Everything in `ping` other than `reference` was discarded above.
  let remote: any;
  try {
    remote = await refetch(reference);
  } catch (err: any) {
    // Do NOT guess a status. 500 makes the provider redeliver; the dedup key makes that safe.
    console.error('[<provider>.ping] refetch failed', { id: reference, error_code: err?.code ?? 'unknown' });
    return new NextResponse(null, { status: 500 });
  }
  const next = STATUS_MAP[String(remote.status)] ?? 'unknown';

  // Rule 9: no event id, no signed timestamp — dedup on the transition itself. The dedup row and
  // the state change commit together or not at all: a failure between them burns the key, and the
  // redelivery that would have fixed it is then read as a duplicate and dropped.
  let applied = false;
  try {
    applied = await db.$transaction(async (tx: any) => {
      await tx.pagokitWebhookEventProcessed.create({
        data: {
          event_id: `<catalog id>:${reference}:${next}`, provider: '<catalog id>', event_type: next,
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });
      // Only if it climbs: a late ping re-reporting `pending` must not undo a recorded `succeeded`.
      if ((RANK[next] ?? -1) <= (RANK[payment.status] ?? -1)) return false;
      await tx.pagokitPayment.update({ where: { id: payment.id }, data: { status: next } });
      return true;
    });
  } catch (err: any) {
    if (err?.code === 'P2002') return ack();                   // duplicate transition → 200
    // Any other database failure is NOT a duplicate: nothing committed, so 500 and redeliver.
    console.error('[<provider>.ping] transaction failed', { id: reference, error_code: err?.code ?? 'unknown' });
    return new NextResponse(null, { status: 500 });
  }
  // Rule 6: reference, resolved type, provider timestamp. Never `remote`, never `ping`.
  console.log('[<provider>.ping]', { id: reference, type: next, created: remote.created_at });
  if (applied && next === 'succeeded') await enqueueFulfilment({ payment_id: payment.id });  // fast ack

  if (next === 'pending') {
    const attempt = Number((payment.metadata as any)?.poll_attempt ?? 0) + 1;
    await enqueuePoll({ payment_id: payment.id, attempt, delay_ms: backoffMs(attempt) });
  } else if (next === 'unknown') {
    console.log('[<provider>.ping] TODO map provider status', { id: reference });   // 200, not 4xx
  }

  return ack();
}

function ack() {
  // Some providers require an exact ack body. A JSON envelope where the provider expects a bare
  // token counts as a failed delivery, and it retries until it disables the endpoint.
  return ACK_BODY ? new NextResponse(ACK_BODY, { status: 200 }) : NextResponse.json({ received: true });
}

function parsePing(raw: string): Record<string, string> | null {
  try {
    return raw.trimStart().startsWith('{') ? JSON.parse(raw) : Object.fromEntries(new URLSearchParams(raw));
  } catch { return null; }
}

async function refetch(reference: string) {
  const url = '<from webhook.refetch_endpoint>'.replace('{id}', encodeURIComponent(reference));
  const res = await fetch(url, {
    headers: {
      // <from checkout_spec.auth> — the API credential. The callback secret does not open this.
      Authorization: `Bearer ${requireEnv('<from env_vars.secret>')}`,
      '<from api_versioning.header>': '<from api_versioning.current>',
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`refetch_failed_${res.status}`);
  return res.json();
}

// Backoff with jitter: half the window is fixed so a retry never fires instantly, half is random
// so N pings for N payments do not stampede the status API in lockstep.
export function backoffMs(attempt: number, base = 2_000, cap = 300_000): number {
  const window = Math.min(cap, base * 2 ** Math.max(0, attempt - 1));
  return Math.round(window / 2 + Math.random() * (window / 2));
}

// Both sides hashed to a fixed 32 bytes first: timingSafeEqual throws on a length mismatch, and a
// bare length comparison would leak how long the secret is before comparing a single byte.
function sharedSecretMatches(presented: string | null, configured: string): boolean {
  if (typeof presented !== 'string' || configured.length === 0) return false;
  const a = crypto.createHash('sha256').update(presented, 'utf8').digest();
  const b = crypto.createHash('sha256').update(configured, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}
```

### Express

```ts
app.post('/api/webhook/<provider>',
  express.raw({ type: '*/*', limit: '256kb' }),     // Rule 5 + Rule 10 — the ping may be form-encoded
  handlePing);
app.use(express.json());                            // ← AFTER the webhook route
```

## Python

```python
# app/routes/webhook_<provider>.py   (FastAPI)
import hashlib, hmac, os, json, logging, secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs
from fastapi import APIRouter, Request, Response, Depends
from sqlalchemy.exc import IntegrityError

router, log = APIRouter(), logging.getLogger("<provider>.ping")
ACK_BODY = ""                            # <from webhook.ack_body_literal>, "" when none
SECRET_ENV = "PROVIDER_WEBHOOK_SECRET"   # <from env_vars.webhook_secret>, "" for none_refetch
STATUS_MAP = {"<from provider status values>": "succeeded"}
RANK = {"pending": 0, "unknown": 1, "authorized": 2, "succeeded": 3,
        "failed": 3, "canceled": 3, "refunded": 4, "disputed": 5}

def ack() -> Response:
    # An exact ack body where the catalog names one: a JSON envelope reads as a failed delivery.
    return Response(content=ACK_BODY, status_code=200) if ACK_BODY else Response(status_code=200)

def shared_secret_matches(presented: str | None, configured: str) -> bool:
    if not isinstance(presented, str) or not configured:
        return False                                                  # fixed-length, leaks nothing
    return hmac.compare_digest(hashlib.sha256(presented.encode()).digest(),
                               hashlib.sha256(configured.encode()).digest())

def backoff_ms(attempt: int, base: int = 2_000, cap: int = 300_000) -> int:
    window = min(cap, base * 2 ** max(0, attempt - 1))
    return window // 2 + secrets.randbelow(window // 2 + 1)

@router.post("/api/webhook/<provider>")
async def ping(request: Request, db=Depends(get_db)):
    if int(request.headers.get("content-length", 0)) > 256 * 1024:
        return Response(status_code=413)                                  # Rule 10
    text = (await request.body()).decode("utf-8", "replace")              # Rule 5: never .json()
    try:
        body = json.loads(text) if text.lstrip().startswith("{") else \
               {k: v[0] for k, v in parse_qs(text).items()}
    except ValueError:
        return Response(status_code=400)

    if SECRET_ENV:                                                        # Rule 3, constant time
        configured = os.getenv(SECRET_ENV, "")
        if not configured:
            log.error("%s is not set — refusing all callbacks", SECRET_ENV)
            return Response(status_code=500)                               # fail closed, never open
        if not shared_secret_matches(
                request.headers.get("<from webhook.signature_header>"), configured):
            return Response(status_code=400)

    reference = str(body.get("<from webhook.event_id_pointer>", ""))
    if not reference:
        return Response(status_code=400)
    payment = db.query(PagokitPayment).filter_by(
        provider="<catalog id>", provider_payment_id=reference).first()
    if payment is None:
        log.info("unknown reference", extra={"id": reference})
        return ack()                                                      # 200, never 404

    remote = refetch(reference)          # authoritative; raises → 500 and the provider redelivers
    nxt = STATUS_MAP.get(str(remote["status"]), "unknown")
    applied = RANK.get(nxt, -1) > RANK.get(payment.status, -1)            # only if it climbs
    try:                    # Rule 9: the dedup row and the state change commit together or neither
        db.add(PagokitWebhookEventProcessed(
            event_id=f"<catalog id>:{reference}:{nxt}", provider="<catalog id>",
            event_type=nxt, expires_at=datetime.now(timezone.utc) + timedelta(days=7)))
        if applied:
            payment.status = nxt
        db.commit()
    except IntegrityError:
        db.rollback()
        return ack()                                                      # duplicate → 200

    log.info("ping", extra={"id": reference, "type": nxt, "created": remote["created_at"]})  # Rule 6
    if applied and nxt == "succeeded":
        enqueue_fulfilment(payment.id)                                    # fast ack
    if nxt == "pending":
        attempt = int((payment.metadata_ or {}).get("poll_attempt", 0)) + 1
        enqueue_poll(payment.id, attempt, delay_ms=backoff_ms(attempt))
    return ack()
```

## Anti-patterns

- ❌ Reading `status`, `amount` or `email` from the ping body. It is unsigned, unauthenticated data that happens to arrive over HTTPS.
- ❌ Returning `404` for an unknown reference — it confirms which references exist, and the provider retries it forever.
- ❌ `await new Promise(r => setTimeout(r, 5000))` inside the handler to "wait for pending". The ack deadline (`webhook.ack_deadline_seconds`) expires, the provider redelivers, and now several handlers sleep on the same reference.
- ❌ Deduplicating by hashing the ping body. The second ping is legitimately byte-identical and carries a *new* state — hash-dedup silently drops the transition to `succeeded`.
- ❌ Sending the callback secret (`env_vars.webhook_secret`) as the re-fetch credential. Two different secrets; the re-fetch 401s and the payment stays pending forever.
- ❌ `JSON.parse(raw)` on a form-encoded ping — `400` on every genuine delivery while forged JSON sails through.
- ❌ `if (secret) { check }`. On the day the env var is missing or misspelled the check disappears and the endpoint is open to anyone. A configured-secret family fails closed with a 500.
- ❌ Writing the dedup row in its own transaction, ahead of the state change — or catching every error around it as "duplicate → 200". Both burn the key on work that never happened: the redelivery is then read as a duplicate and the payment is stranded at `pending` with nothing left to move it.
- ❌ Treating the shared-secret header as proof of the payload. It authenticates the caller; the body is still a rumour.
- ❌ Applying the re-fetched status unconditionally, so a late `pending` overwrites a recorded `succeeded`.

## Security rules cited

- Rule 3: the shared-secret header is compared with `timingSafeEqual` / `hmac.compare_digest` over SHA-256 digests of both sides, accepting and rejecting exactly what `verifyEvent()` in `scripts/lib/webhook-sign.js` accepts and rejects — so a `/pagokit:test` pass means the handler and the signer agree. A missing secret refuses every callback. Where the family carries no secret at all, the authoritative check is the authenticated re-fetch.
- Rule 5: `await request.text()` / `await request.body()` under the Node runtime; Express registers `express.raw({ type: '*/*' })` before `express.json()` because the ping is often form-encoded.
- Rule 6: `id`, resolved `type` and the provider's `created` only — never the ping, never the re-fetched transaction.
- Rule 9: no event id and no signed timestamp, so replay protection is the transition-keyed `webhook_events_processed` row plus the monotonic rank check.
- Rule 10: 256 KB cap read from `content-length` before the body; `413` otherwise.
- Rule 11: the re-fetched transaction carries the full payer record; only the fields the flow needs are persisted.
