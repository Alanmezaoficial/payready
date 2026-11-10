# One-time payment

A single charge for a single order. The thing developers get wrong is treating "the checkout was created" as "the money arrived": the create call returns a redirect URL, not a payment. On card that gap is two seconds and the bug hides; on a cash voucher or a virtual account it is three days, and an order with no timeout branch sits in `pending` forever — stock reserved, never invoiced, never cleaned up. **An order that cannot expire is a bug**, and the catalog says exactly when it expires.

**Providers in this family:** every entry with `supports.one_time: true`, which is all 42 in the catalog. The four at `integration_level: build`, the ones this fragment actually generates for, are Stripe, Mercado Pago, Wompi and Lemon Squeezy. The async rails are the provider's `methods[]` whose `methods.json` entry carries `async_pending: true` — Stripe: `oxxo`, `boleto`; Mercado Pago: `oxxo`, `boleto`, `efecty`, `pago_facil`, `rapipago`, `servipag`, `pagoefectivo`, `pse`, `spei`; Wompi: `efecty`, `baloto`, `su_red`, `pse`, `bancolombia_button`, `bancolombia_transfer`. Derive that list from `methods[]`, **not** from `supports.cash_voucher`: that key is optional (Wompi omits it entirely), it names only vouchers, and a generator keyed on it emits a synchronous checkout for a provider whose PSE transfers and three-day vouchers both need the timeout branch. Lemon Squeezy is card, wallet and BNPL with nothing marked `async_pending`, so its orders are synchronous and the expiry branch compiles out.

**Catalog fields this fragment reads:** `checkout_spec.amount_unit`, `checkout_spec.idempotency.{supported,in,name}`, `checkout_spec.response_redirect_pointer`, `webhook.payload_authoritative`, `webhook.refetch_endpoint`, `webhook.event_id_pointer`, `webhook.event_type_pointer`, `webhook.signature_header`, `webhook.secret_env`, `webhook.ack_deadline_seconds`, `methods[].expiry_seconds`, `methods[].async_pending`, `methods[].pending_status_lies`, `methods[].reversibility`, `currencies[].exponent`.

## The contract

1. Look the price up server-side. The client sends a product id and a quantity, never an amount — and validate the quantity as a positive integer before it multiplies anything. `quantity: -1` turns a server-side price into a client-controlled *negative* amount, which is the client-amount bug wearing a different hat.
2. Convert with the currency's ISO exponent, in integer arithmetic. Store minor units internally; convert only at the provider boundary, and only if `checkout_spec.amount_unit` is `major`.
3. Mint `crypto.randomUUID()` and **persist the order before calling the provider**, in `pending`. A crash between call and response is only recoverable if the key is already on disk.
4. Compute `expires_at`. A method with `expiry_seconds` uses that number. A method with `async_pending: true` and **no** published `expiry_seconds` — `pse`, `spei`, the Bancolombia rails — still gets a deadline, from a house default: the sweeper re-fetches before it writes anything, so a conservative timeout costs nothing and `null` costs you the row forever. Only a rail that is neither gets `null`.
5. Call the provider with that key. On a transport error **leave the order `pending`** — the charge may exist. Writing `failed` here is how you get a double charge on the retry.
6. Store the provider's id, return the redirect from `checkout_spec.response_redirect_pointer`.
7. On the callback the preamble caps, captures raw bytes, verifies, dedups and acks. This fragment supplies one thing: the order transition, inside that same transaction.
8. When `webhook.payload_authoritative` is `false`, re-fetch from `webhook.refetch_endpoint` before believing any amount or status.
9. Sweep expired orders on a schedule, re-fetching each one before writing `expired`.

State machine — `pending → paid | expired | failed`. `paid` is terminal. `expired → paid` is **legal** and you must handle it: the buyer paid at the counter forty seconds before the sweeper ran.

## Node / TypeScript

```ts
// lib/payments/order-state.ts
export type OrderStatus = 'pending' | 'paid' | 'expired' | 'failed';
const ALLOWED: Record<OrderStatus, OrderStatus[]> = {
  pending: ['paid', 'expired', 'failed'],
  expired: ['paid'],            // voucher paid at the counter before the sweeper ran
  failed:  ['paid', 'expired'], // a retry on the same reference succeeded
  paid:    [],                  // terminal: money in
};
/** The WHERE guard for a compare-and-swap. A late `expired` can never clobber `paid`. */
export const predecessorsOf = (to: OrderStatus): OrderStatus[] =>
  (Object.keys(ALLOWED) as OrderStatus[]).filter((from) => ALLOWED[from].includes(to));
export const canTransition = (from: OrderStatus, to: OrderStatus): boolean =>
  from === to ? false : ALLOWED[from].includes(to); // same-state redelivery is a no-op, not an error
```

```ts
// app/api/checkout/route.ts
import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { db } from '@/lib/db';
// Amount scaling belongs to fragments/money/minor_units.md — it refuses unknown currencies and
// over-precise amounts instead of guessing exponent 2. Never re-derive it here.
import { toMinorUnits, fromMinorUnits, amountForProvider } from '@/lib/payments/money';
import { createProviderCheckout } from '@/lib/payments/<provider>';

export const runtime = 'nodejs';

const AMOUNT_UNIT = 'minor';                      // <from checkout_spec.amount_unit>
const MAX_QUANTITY = 100;                         // <whatever the product line actually allows>
const EXPIRY_SECONDS: Record<string, number> = {  // <from methods[<id>].expiry_seconds>
  oxxo: 259200, boleto: 259200, efecty: 259200, virtual_account_id: 86400, blik: 120,
  card: 0,                                        // synchronous: nothing to expire
};
// <from methods[<id>].async_pending> minus the ids above: async rails the catalog publishes no
// expiry for. They still need a deadline — see contract step 4.
const ASYNC_NO_PUBLISHED_EXPIRY = new Set(['pse', 'spei', 'bancolombia_button', 'bancolombia_transfer']);
const HOUSE_EXPIRY_SECONDS = 86400;

export async function POST(request: Request) {
  // Every line below this throws on hostile input: a malformed body, a fractional quantity, a
  // currency `money.ts` will not price. Unhandled, each is a 500 the client retries — and one of
  // them throws *after* the order row exists, leaving a row nobody will ever collect against.
  // Refuse first, write second.
  let productId: string, method: string, quantity: number;
  try {
    const body = await request.json();
    productId = String(body.productId ?? '');
    method = String(body.method ?? '');
    quantity = body.quantity ?? 1;
    // The amount is server-side, but the multiplier is not: a negative or fractional quantity
    // hands the client control of the amount after all.
    if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > MAX_QUANTITY) throw new Error('quantity');
    if (!productId) throw new Error('productId');
  } catch {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  const product = await db.product.findUnique({ where: { id: productId } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  let totalMinor: bigint, totalMajor: string;
  try {
    totalMinor = toMinorUnits(product.price_major, product.currency) * BigInt(quantity);
    totalMajor = fromMinorUnits(totalMinor, product.currency);      // exact decimal string
  } catch (err: any) {
    // MoneyError: an unpriceable currency or a catalog row with more precision than its exponent
    // allows. That is your data, not the caller's — fail loudly and charge nobody.
    console.error('[checkout] unpriceable product', { product_id: product.id, currency: product.currency });
    return NextResponse.json({ error: 'unpriceable' }, { status: 500 });
  }

  const idempotencyKey = randomUUID();            // Rule 4: cryptographic UUID, never Date.now()
  const ttl = EXPIRY_SECONDS[method] ?? (ASYNC_NO_PUBLISHED_EXPIRY.has(method) ? HOUSE_EXPIRY_SECONDS : 0);
  const expiresAt = ttl > 0 ? new Date(Date.now() + ttl * 1000) : null;

  // Rule 4: the key is on disk BEFORE the provider call, so a crashed call is replayable.
  const order = await db.pagokitPayment.create({
    data: {
      provider: '<catalog id>',
      provider_payment_id: `pending:${idempotencyKey}`,  // rewritten once the provider answers
      amount: Number(totalMinor), currency: product.currency, status: 'pending',
      expires_at: expiresAt,                             // lifted column — you cannot index inside Json
      metadata: { product_id: product.id, method, idempotency_key: idempotencyKey },
    },
  });

  let created;
  try {
    created = await createProviderCheckout({
      idempotencyKey,                                    // <from checkout_spec.idempotency.name / .in>
      amount: amountForProvider(totalMajor, product.currency, AMOUNT_UNIT), // integer or decimal string
      currency: product.currency, method, expiresAt, reference: order.id,
    });
  } catch (err: any) {
    // Leave it `pending`: a timeout does not mean the charge does not exist. The reconciler replays
    // the SAME key and learns the truth. Writing `failed` here is how the retry double-charges.
    console.error('[checkout] provider call failed', { order_id: order.id, code: err.code ?? 'unknown' });
    return NextResponse.json({ error: 'checkout_unavailable' }, { status: 502 });
  }

  await db.pagokitPayment.update({ where: { id: order.id }, data: { provider_payment_id: created.id } });
  return NextResponse.json({ url: created.redirect_url, expires_at: expiresAt });
}
```

```ts
// app/api/webhook/<provider>/route.ts — the order branch. The handler shell (413 cap, raw-body
// capture, verifySignature, event-id dedup, metadata-only log, ack) is fragments/webhook/_preamble.md;
// re-fetch on an unauthoritative payload is fragments/notify/ping_then_poll.md. This is what the
// billing slot contributes: turning a verified event into an order transition, and nothing else.
import { predecessorsOf, type OrderStatus } from '@/lib/payments/order-state';
import { refetchPayment } from '@/lib/payments/<provider>';
import { enqueue } from '@/lib/jobs';
import { db } from '@/lib/db';

const PAYLOAD_AUTHORITATIVE = true;               // <from webhook.payload_authoritative>
const PENDING_STATUS_LIES   = false;              // <from methods[<id>].pending_status_lies>

export async function onOrderEvent(event: any, tx: typeof db) {
  // Rule 3 corollary: an unauthoritative payload is a rumour. Ask the provider before moving money.
  const truth = PAYLOAD_AUTHORITATIVE ? event.data.object : await refetchPayment(event.data.object.id);

  // A `pending_status_lies` rail reports an authorised-shaped status while the voucher is UNPAID.
  const isPaid = truth.status === 'approved' && !(PENDING_STATUS_LIES && truth.paid_at == null);
  const next: OrderStatus | null = isPaid ? 'paid' : truth.status === 'rejected' ? 'failed' : null;
  if (!next) {
    console.log('[<provider>.webhook] TODO unhandled status', { id: event.id, type: event.type }); // Rule 6
    return;                                        // preamble acks 200 — a 4xx disables the endpoint
  }

  // Compare-and-swap inside the preamble's transaction, so the dedup row and the state change
  // commit together. The WHERE guard is the transition table: a late `expired` cannot clobber `paid`.
  const { count } = await tx.pagokitPayment.updateMany({
    where: { provider_payment_id: truth.id, status: { in: predecessorsOf(next) } },
    data: { status: next, paid_at: next === 'paid' ? new Date() : null },
  });
  // Fast ack (webhook.ack_deadline_seconds is 20s on Stripe): fulfilment and receipts are jobs.
  // The job needs YOUR order id. `truth.id` is the PROVIDER's payment id — enqueue that and the
  // worker looks up an id that does not exist in `pagokit_payments.id`, finds nothing, ships
  // nothing, and logs nothing worth reading. Every other call site here uses the local id.
  if (count === 1 && next === 'paid') {
    const order = await tx.pagokitPayment.findFirst({
      where: { provider_payment_id: truth.id }, select: { id: true },
    });
    if (order) await enqueue('order.fulfil', { order_id: order.id });
  }
}
```

```ts
// jobs/expire-orders.ts — every minute. Without this, async orders never leave `pending`.
import { predecessorsOf } from '@/lib/payments/order-state';
import { refetchPayment } from '@/lib/payments/<provider>';
import { enqueue } from '@/lib/jobs';
import { db } from '@/lib/db';

export async function expireStaleOrders() {
  const due = await db.pagokitPayment.findMany({
    where: { status: 'pending', expires_at: { lt: new Date() } }, take: 500,
  });
  for (const order of due) {
    const truth = await refetchPayment(order.provider_payment_id); // never expire on the clock alone
    const next = truth.status === 'approved' ? 'paid' : 'expired';
    const { count } = await db.pagokitPayment.updateMany({
      where: { id: order.id, status: { in: predecessorsOf(next) } }, data: { status: next },
    });
    // The sweeper is the second place an order can become `paid` — the counter payment that
    // beat the webhook. Marking it paid and not fulfilling is worse than leaving it pending:
    // the money is yours, the dashboard is green, and nothing ships.
    if (count === 1 && next === 'paid') await enqueue('order.fulfil', { order_id: order.id });
  }
}
```

## Python

```python
# jobs/orders.py — the expiry sweep, the piece a card-only integration never needs.
ORDER_TRANSITIONS = {"pending": {"paid", "expired", "failed"},
                     "expired": {"paid"}, "failed": {"paid", "expired"}, "paid": set()}
PREDECESSORS = {to: [f for f, tos in ORDER_TRANSITIONS.items() if to in tos]
                for to in ("paid", "expired", "failed")}

async def apply_transition(order_id: str, nxt: str) -> bool:
    """UPDATE … WHERE status IN (predecessors). The guard IS the state machine."""
    return await db.execute_update(
        "UPDATE pagokit_payments SET status = :s WHERE id = :id AND status = ANY(:from)",
        s=nxt, id=order_id, **{"from": PREDECESSORS[nxt]}) == 1

async def expire_stale_orders(now) -> None:
    """Without this, every voucher order lives in `pending` forever."""
    for order in await db.fetch_pending_past_expiry(now, limit=500):
        truth = await refetch(order.provider_payment_id)   # never expire on the clock alone
        nxt = "paid" if truth["status"] == "approved" else "expired"
        if await apply_transition(order.id, nxt) and nxt == "paid":
            await enqueue("order.fulfil", order_id=order.id)
```

**Raw body (Rule 5):** the handler shell in `fragments/webhook/_preamble.md` reads `await request.text()` on Next.js App Router under `export const runtime = 'nodejs'`, and `await request.body()` on FastAPI. On Express, register `express.raw({ type: 'application/json', limit: '256kb' })` on the webhook route **before** `app.use(express.json())` and hash `req.body` as the Buffer it then is. Registering the JSON parser first breaks verification permanently and silently.

## Anti-patterns

- ❌ Taking `amount` from the request body — the buyer edits it and pays one cent for the annual plan.
- ❌ `Math.round(amount * 100)` for every currency — 100× overcharge on CLP/JPY, 10× under on KWD/BHD, and on providers that hash the amount at its ISO exponent the signature breaks too, so the developer debugs crypto instead of arithmetic.
- ❌ Trusting `quantity` from the request body. `-1` makes the amount negative, `1.5` makes `BigInt()` throw a 500 the client retries, and both start from a price you correctly looked up server-side.
- ❌ No `expires_at` on a voucher order — stock stays reserved forever and reconciliation never balances. Same outcome for an `async_pending` rail with no published `expiry_seconds` if you let the lookup fall through to `null`.
- ❌ Enqueueing fulfilment with the provider's payment id under an `order_id` key. The worker finds no such order and returns quietly; the money arrived and nothing shipped.
- ❌ Marking the order `failed` when the provider call times out — the charge may exist, and the retry double-charges.
- ❌ Treating `expired` as terminal — a rail with `expiry_seconds` will hand you a genuine `paid` afterwards.
- ❌ Fulfilling on an authorised-shaped status for a `pending_status_lies: true` rail — that ships free goods.
- ❌ Returning 4xx for an event type you do not handle — the provider disables the endpoint. 200 plus a logged TODO.
- ❌ Offering a refund endpoint on a rail whose `reversibility` is `irreversible_no_refund` (PSE, Pix, SPEI, Bre-B) — "refund the charge" is not an operation there. Emit the payout-based alternative.

## Security rules cited

- **Rule 3:** `onOrderEvent` runs only on a verified event — `_preamble.md`'s `safeEqual` compares length first, then `timingSafeEqual` / `hmac.compare_digest`, and an invalid signature is a bare 400 with no reason.
- **Rule 4:** `crypto.randomUUID()` on the idempotency line, persisted before the provider call so the retry deduplicates instead of double-charging.
- **Rule 5:** `await request.text()` under `runtime = 'nodejs'`; `await request.body()` on FastAPI; `express.raw(...)` registered before `express.json()`.
- **Rule 6:** the handler logs `id`, `type`, `created`. Voucher payloads carry the buyer's name and address.
- **Rule 9:** timestamp window where the scheme signs a timestamp; event-id dedup with a 7-day TTL always. For `timestamp_source: none` schemes (Lemon Squeezy) the dedup is the only replay defence, so it is not optional.
- **Rule 10:** 256 KB decided from `content-length` before reading, and `limit: '256kb'` on the Express parser.
- **Rule 12:** the order row holds the provider's payment id and nothing from the card.
