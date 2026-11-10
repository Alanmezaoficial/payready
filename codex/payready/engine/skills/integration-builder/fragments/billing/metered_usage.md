# Metered usage

Billing for what the customer actually consumed — tokens, requests, minutes, gigabytes — which is what AI applications need and what a plan-and-price subscription cannot express. **This is a layer over a PSP, not a replacement for one.** Metering decides the number on the invoice; a provider from `subscription_card.md` still has to collect it, with a stored credential, an MIT and a dunning loop underneath. A metering system with no PSP under it produces beautiful invoices nobody pays.

The thing developers get wrong is treating a usage event like a log line. A duplicated log line is noise; a duplicated usage event is **a double charge on a real invoice**, and a dropped one is revenue you will never find again because nothing downstream knows it existed. So idempotency lives on the *event*, minted by the emitter as a deterministic id, not on the HTTP request. Retries, at-least-once queues and a client that fires twice on a slow network are all normal, and all of them must land on the same row.

**Providers in this family:** none yet — no entry in the catalog carries a `metered` block, so every field named below reads as `undefined` today. The nearest thing is Lago, catalogued at `advise` with `role: "billing_layer"`: exactly the shape this fragment describes, a metering and invoicing layer that sits over a PSP rather than replacing one. When its `metered` block lands, expect `metered.requires_psp: true`. Until then the aggregation below runs in the merchant's own database and hands a total to the subscription flow.

**Catalog fields this fragment reads:** `metered.event_ingestion`, `metered.meters`, `metered.credit_balances`, `metered.requires_psp`, `supports.subscriptions`, `currencies[].exponent`, `webhook.signature_header`, `webhook.secret_env`, `webhook.event_id_pointer`.

## The contract

1. **The emitter mints the id.** `sha256(subject | meter | occurred_at | source_ref)`. Deterministic on purpose: two retries of the same call must collide. This is not the Rule 4 case — the cryptographic UUID belongs on the *invoice charge* you send the PSP; a usage event id must be reproducible, so it is a content hash.
2. **Ingest defensively.** Cap the body (Rule 10) and cap the batch. Verify the caller's HMAC in constant time. Insert with a unique index on `event_id` and treat the conflict as success.
3. **Bill by `occurred_at`, not arrival.** An event that happened at 23:59 on the last of the month belongs to that month even if it lands the next morning.
4. **Freeze, then adjust.** After a lateness grace the period closes. Anything arriving later posts to the next period, tagged with the period it adjusts. Reopening a closed period after you invoiced it is how the metered total and the invoiced total stop agreeing forever.
5. **Roll up by recomputation.** A rollup is `SUM` over deduplicated source events, never `balance = balance + n`. Recomputing must be safe to do twice.
6. **Credits are a ledger.** Append-only entries; the balance is their sum. Spend expiring-soonest first, then oldest. A mutable `credits_remaining` column drifts the first time two workers debit concurrently.
7. **Overage invoices.** What credits could not cover becomes an invoice line, converted to minor units with the currency's exponent, charged through the PSP.
8. **Reconcile every period.** Metered total versus invoiced total, per subject. Any drift is a bug in the pipeline, and the only way you find it is by checking.

## Schema this implies

```prisma
model PagokitUsageEvent {
  event_id    String   @id                  // sha256 content hash — the dedup key
  subject_id  String                        // customer / workspace / api key
  meter       String                        // "tokens_in" | "requests" | "gb_egress"
  units       Int                           // integer units; never a float you will sum a million times
  occurred_at DateTime                      // decides the period
  received_at DateTime @default(now())      // decides whether it was late
  period_id   String?                       // resolved at ingest
  adjusts     String?                       // set when it arrived after its own period froze
  source_ref  String?                       // request id — the join back to your logs
  @@index([subject_id, meter, occurred_at])
  @@index([period_id, subject_id, meter])
  @@map("pagokit_usage_events")
}
model PagokitCreditGrant {
  id         String    @id @default(cuid())
  subject_id String
  units      Int                            // prepaid pack size
  remaining  Int
  expires_at DateTime?                      // null = never expires
  granted_at DateTime  @default(now())
  @@index([subject_id, expires_at])
  @@map("pagokit_credit_grants")
}
model PagokitCreditLedger {                  // append-only. The balance is SUM(units), never a column.
  id         String   @id @default(cuid())
  subject_id String
  grant_id   String?
  units      Int                            // + on grant, − on debit
  reason     String
  created_at DateTime @default(now())
  @@index([subject_id, created_at])
  @@map("pagokit_credit_ledger")
}
```

## Node / TypeScript

```ts
// lib/usage/event-id.ts
import { createHash } from 'node:crypto';
/** Deterministic by design: the same call retried must produce the same id and collide on insert. */
export const usageEventId = (e: { subject_id: string; meter: string; occurred_at: string; source_ref: string }) =>
  createHash('sha256').update([e.subject_id, e.meter, e.occurred_at, e.source_ref].join('|')).digest('hex');
```

```ts
// app/api/usage/route.ts — the ingestion endpoint. The caller is the merchant's own service,
// so this is their HMAC, not the PSP's, and it is this fragment's job to verify it.
import { NextResponse } from 'next/server';
import { createHmac } from 'node:crypto';
import { MAX_BODY_BYTES, safeEqual } from '@/lib/payments/webhook-crypto'; // fragments/webhook/_preamble.md
import { usageEventId } from '@/lib/usage/event-id';
import { openPeriods, resolvePeriod } from '@/lib/usage/periods';
import { db } from '@/lib/db';

export const runtime = 'nodejs';                 // Rule 5: Edge has no node:crypto
const MAX_BATCH = 1000;

// Fail at boot, not per request: `createHmac('sha256', undefined)` throws inside the handler,
// which is a 500 on every ingest — indistinguishable, from the caller's side, from your database
// being down, and it retries into both.
const INGEST_SECRET = process.env.USAGE_INGEST_SECRET;
if (!INGEST_SECRET) throw new Error('USAGE_INGEST_SECRET is not set');

function verifyIngest(rawBody: string, presented: string | null, secret: string): boolean {
  if (!presented) return false;
  const expected = createHmac('sha256', secret).update(rawBody, 'utf8').digest('hex');
  // Rule 3: safeEqual compares length first — timingSafeEqual THROWS on a length mismatch.
  return safeEqual(expected, presented);
}

/** Units are money. A float or a negative number here is a wrong invoice, not a bad log line. */
function validEvent(e: any): boolean {
  return typeof e?.subject_id === 'string' && e.subject_id !== ''
      && typeof e.meter === 'string' && e.meter !== ''
      && Number.isSafeInteger(e.units) && e.units >= 0
      && !Number.isNaN(Date.parse(e.occurred_at));
}

export async function POST(request: Request) {
  // Rule 10: 256 KB, decided before a byte is read. Usage ingestion is the highest-volume
  // unauthenticated-until-verified surface in the whole integration.
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 });
  }
  const rawBody = await request.text();          // Rule 5: exact bytes — never request.json() first
  // Rule 10 again, and this one is the real cap: `content-length` is absent under
  // `Transfer-Encoding: chunked` and is the caller's number anyway. The header check is a filter.
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) return new NextResponse(null, { status: 413 });

  if (!verifyIngest(rawBody, request.headers.get('x-usage-signature'), INGEST_SECRET)) {
    return new NextResponse(null, { status: 400 });   // Rule 3: bare 400, no reason leaked
  }

  let events: any[];
  try {
    ({ events } = JSON.parse(rawBody));          // parse only after the MAC (Rule 3)
    if (!Array.isArray(events)) throw new Error('events');
  } catch {
    return new NextResponse(null, { status: 400 });
  }
  if (events.length > MAX_BATCH) return new NextResponse(null, { status: 413 });
  if (events.some((e) => !validEvent(e))) return new NextResponse(null, { status: 400 });

  const periods = await openPeriods();
  let accepted = 0, duplicates = 0;
  for (const e of events) {
    const event_id = e.event_id ?? usageEventId(e);
    const { period_id, adjusts } = resolvePeriod(e.occurred_at, new Date(), periods);
    try {
      await db.pagokitUsageEvent.create({
        data: { event_id, subject_id: e.subject_id, meter: e.meter, units: e.units,
                occurred_at: new Date(e.occurred_at), period_id, adjusts, source_ref: e.source_ref },
      });
      accepted++;
    } catch (err: any) {
      // ONLY a unique violation is a duplicate. A bare `catch {}` here counts a dead database as
      // "already recorded", answers 200, and the client never retries — usage silently deleted,
      // which is the one failure metering cannot recover from. Everything else must 500.
      // Bailing mid-batch is safe: the client retries the whole batch and every row already
      // written collides on `event_id`. That is what an event-level id buys you.
      if (err?.code !== 'P2002') {
        console.error('[usage.ingest] write failed', { batch: events.length, error_code: err?.code ?? 'unknown' });
        return new NextResponse(null, { status: 500 });
      }
      duplicates++;                              // unique violation on event_id: already counted
    }
  }
  // Rule 6: ids and counts. A usage payload for an AI product contains the prompt.
  console.log('[usage.ingest]', { accepted, duplicates, batch: events.length });
  return NextResponse.json({ accepted, duplicates });   // 200 even when everything was a duplicate
}
```

```ts
// lib/usage/periods.ts
import { db } from '@/lib/db';

/** The candidate periods, loaded once per batch — not once per event. */
export const openPeriods = (): Promise<Period[]> =>
  db.pagokitUsagePeriod.findMany({ where: { closed_at: null }, orderBy: { start: 'asc' } });

/** Late-but-before-freeze still counts in its own period. After the freeze it becomes an adjustment. */
export function resolvePeriod(occurredAt: string, arrivedAt: Date, periods: Period[]) {
  const t = new Date(occurredAt).getTime();
  const p = periods.find((q) => t >= +new Date(q.start) && t < +new Date(q.end));
  if (!p) return { period_id: null, adjusts: null };            // outside every open period: quarantine
  if (p.frozen_at && arrivedAt > new Date(p.frozen_at)) {
    const next = periods.find((q) => +new Date(q.start) === +new Date(p.end));
    return { period_id: next?.id ?? null, adjusts: p.id };      // posts forward, remembers where from
  }
  return { period_id: p.id, adjusts: null };
}
```

```ts
// lib/usage/credits.ts — allocation, and why the ledger is append-only.
export function allocateCredits(grants: Grant[], units: number, now = new Date()) {
  const usable = grants
    .filter((g) => g.remaining > 0 && (!g.expires_at || new Date(g.expires_at) > now))
    .sort((a, b) => (+new Date(a.expires_at ?? 8.64e15) - +new Date(b.expires_at ?? 8.64e15))
                 || (+new Date(a.granted_at) - +new Date(b.granted_at)));  // expiring first, then oldest
  const entries: { grant_id: string; units: number }[] = [];
  let left = units;
  for (const g of usable) {
    if (left <= 0) break;
    const take = Math.min(g.remaining, left);
    entries.push({ grant_id: g.id, units: -take });
    left -= take;
  }
  return { entries, overage: left };            // overage is what the PSP has to charge for
}

/** Balance is derived. Two workers debiting a `remaining` column concurrently lose an entry. */
export const balanceOf = (ledger: { units: number }[]) => ledger.reduce((s, e) => s + e.units, 0);
```

## Python

```python
# jobs/usage_rollup.py — aggregation and the reconciliation nobody writes until the first dispute.
async def rollup(period_id: str, subject_id: str, meter: str) -> int:
    """Recompute from source. Never `total += n` — a redelivered batch would inflate the invoice."""
    rows = await fetch_events(period_id=period_id, subject_id=subject_id, meter=meter)
    deduped = {r.event_id: r for r in rows}          # belt and braces over the unique index
    total = sum(r.units for r in deduped.values())
    await upsert_rollup(period_id, subject_id, meter, units=total)  # idempotent: same input, same row
    return total

async def close_period(period, grace_hours: int = 6) -> None:
    """Freeze, allocate credits, invoice the overage through the PSP, then reconcile."""
    if now() < period.end + timedelta(hours=grace_hours):
        return                                        # let the stragglers land before freezing
    await freeze(period.id)
    for subject in await subjects_with_usage(period.id):
        units = sum([await rollup(period.id, subject.id, m) for m in METERS])
        entries, overage = allocate_credits(await grants_for(subject.id), units)
        await append_ledger(subject.id, entries, reason=f"usage:{period.id}")   # append-only
        if overage:
            amount_minor = to_minor_units(price_for(overage), subject.currency)  # currencies[].exponent
            # Rule 4: the PSP call gets a cryptographic UUID — unlike the usage event id, it must be unique.
            await psp.charge_invoice(subject, amount_minor, idempotency_key=str(uuid.uuid4()))
    await reconcile(period.id)

async def reconcile(period_id: str) -> None:
    """Metered vs invoiced, per subject. Drift is always a pipeline bug; silence is not agreement."""
    for subject_id, metered, invoiced in await metered_vs_invoiced(period_id):
        if metered != invoiced:
            # Rule 6: ids and totals only — the events behind them carry customer content.
            log.error("usage_reconciliation_drift", extra={"period_id": period_id,
                      "subject_id": subject_id, "metered": metered, "invoiced": invoiced})
            await enqueue("billing.reconciliation_alert", period_id=period_id, subject_id=subject_id)
```

**Express (Rule 5):** the ingestion route needs `express.raw({ type: 'application/json', limit: '256kb' })` registered **before** `app.use(express.json())`, exactly like a webhook — the HMAC covers the bytes the client sent, and a re-serialised body will not match. FastAPI uses `await request.body()`.

## Anti-patterns

- ❌ Idempotency on the HTTP request instead of the event. The client retries the batch with a new request id and every event inside it counts twice.
- ❌ A random UUID as the usage event id. It defeats the whole mechanism: the retry gets a new id and a second charge.
- ❌ Assigning the period by arrival time. Every month-end boundary event lands in the wrong invoice.
- ❌ Reopening a frozen period after invoicing it. The metered total and the invoiced total never agree again, and you cannot tell which one is right.
- ❌ `credits_remaining -= n` as an UPDATE. Two concurrent debits lose one. Append to the ledger and derive.
- ❌ Spending non-expiring credits before expiring ones — the customer's expiring pack silently evaporates and support gets the ticket.
- ❌ Floats for units. A million float additions do not sum to what the customer counted. Reject them at ingest — a signed request is an authentic caller, not a correct one, and a negative `units` is a discount the customer wrote themselves.
- ❌ `catch { duplicates++ }` around the insert. A dead database then reads as "already recorded", the endpoint answers 200, and the client never retries. Only a unique violation is a duplicate; everything else is a 500.
- ❌ Capping on `content-length` alone. It is absent on chunked bodies and supplied by the caller — check the real byte length after reading, exactly as the webhook preamble does.
- ❌ Logging the usage payload. For an AI product that payload is the prompt (Rule 6).
- ❌ No reconciliation step. The gap between metered and invoiced only ever gets discovered by a customer.
- ❌ Building metering and calling it billing. Without the PSP layer there is no stored credential, no dunning and no way to collect.

## Security rules cited

- **Rule 3:** the ingestion endpoint verifies the caller's HMAC before parsing, reusing `safeEqual` / `safe_equal` from `_preamble.md` — length first, then `timingSafeEqual` / `hmac.compare_digest`. Failure is a bare 400.
- **Rule 4:** `crypto.randomUUID()` / `uuid.uuid4()` on the PSP invoice charge. The usage event id is deliberately *not* a UUID — it is a content hash, because it must collide on retry.
- **Rule 5:** `await request.text()` under `runtime = 'nodejs'`; `express.raw(...)` before `express.json()`; `await request.body()` on FastAPI. The ingest HMAC covers the received bytes.
- **Rule 6:** ingestion logs counts, reconciliation logs totals and ids. Neither logs an event body.
- **Rule 9:** the unique index on `event_id` is the replay defence — this endpoint has no signed timestamp, so dedup is the whole of it, exactly as for a `timestamp_source: none` webhook scheme.
- **Rule 10:** 256 KB enforced twice — on `content-length` before reading, on `Buffer.byteLength` after — plus a 1000-event batch cap, because a body under the cap can still hold a batch that blocks the event loop.
- **Rule 11:** a usage event carries a subject id and a meter. It is not the place for the customer's email, and never for the content being metered.
