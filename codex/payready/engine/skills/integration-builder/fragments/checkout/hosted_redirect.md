# Hosted redirect checkout

The server creates a session, the provider answers with a URL, the browser leaves your site to pay and comes back to a return URL you chose. Lowest-risk pattern there is — no card field renders on your origin, so the merchant stays at PCI SAQ A. And it is wrong in the same place in almost every implementation: **the return URL is treated as proof of payment.** It is not. The buyer controls their browser — they can type `/checkout/return?status=approved` by hand, or close the tab after a successful charge and never hit it at all. The return URL picks which page to render. The webhook, or a re-fetch you initiated, decides whether the order is paid.

**Providers in this family:** `stripe`, `mercadopago` (`checkout_spec.pattern: "hosted_redirect"`). They agree on almost nothing else — Stripe takes minor units and an SDK-level `idempotencyKey`, Mercado Pago takes major units and an `X-Idempotency-Key` header — which is the whole reason this fragment reads those values instead of spelling them out.

**Catalog fields this fragment reads:** `checkout_spec.create_endpoint`, `checkout_spec.auth.{in,name,scheme}`, `checkout_spec.amount_unit`, `checkout_spec.idempotency.{supported,in,name}`, `checkout_spec.response_redirect_pointer`, `credentials[].env_var`, `provider.currencies`, `currencies.json → currencies[].exponent`, `pci.scope`.

## The contract

1. Cap the body at 256 KB before reading it (Rule 10).
2. Accept **identifiers only** — item id, quantity, coupon code. A body carrying `amount`, `price` or `currency` is rejected 400; do not "validate" it, refuse it (Rule 25; validator `ERR_CLIENT_AMOUNT`). A body that is not JSON, or not an object, is also a 400 — an unhandled parse rejection is a 500 that tells the caller your framework's stack trace.
3. Look price and currency up server-side, compute the total there, and reject a currency absent from `provider.currencies`.
4. Convert once, at the ISO 4217 exponent from `currencies.json`, then shape per `checkout_spec.amount_unit` (`minor` → integer, `major` → decimal string). Never a reflexive `× 100` (Rule 13, `ERR_MINOR_UNITS`).
5. Write the local order row `status = "pending"` with an unguessable reference **before** calling the provider. That reference is the only thread from the provider's world back to yours.
6. Get-or-create the idempotency key for `(scope, reference)` and persist it, so a retry of the same attempt reuses it instead of opening a second session (Rule 4). Omit it when `checkout_spec.idempotency.supported` is false.
7. POST `checkout_spec.create_endpoint` with the catalog's auth. Metadata carries the reference — never the buyer's email, name or address (Rule 11).
8. Read the URL at `checkout_spec.response_redirect_pointer` and hand it to the browser.
9. On return: verify the MAC over the reference in constant time (Rule 19), then read authoritative state — your row, which only the webhook writes. Never read `?status=`.
10. Return the page and enqueue the fulfilment (Rule 18).

## Node / TypeScript

Amount conversion is not re-implemented here. `fragments/money/minor_units.md` emits
`lib/payments/money.ts` from `currencies.json`, and this fragment calls it:

- `toMinorUnits(amount: string, currency): bigint` — exact integer scaling at the currency's ISO exponent.
- `fromMinorUnits(minor, currency): string` — back to a decimal string for display or a `major` provider.
- `amountForProvider(amount: string, currency, unit): number | string` — `unit` is `<from checkout_spec.amount_unit>`.


```ts
// app/api/checkout/route.ts
import { NextResponse } from 'next/server';
import { randomUUID, createHmac } from 'node:crypto';
import { db } from '@/lib/db';
import { toMinorUnits, amountForProvider } from '@/lib/payments/money';

const AMOUNT_UNIT = 'minor' as const; // <from checkout_spec.amount_unit>

export const runtime = 'nodejs';
const CLIENT_PRICE_FIELDS = ['amount', 'price', 'unit_price', 'total', 'currency'];

// Rule 1: an unset — or empty — return secret makes every return token forgeable. Fail at
// module load, where it is loud, instead of minting worthless MACs in production.
const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET;
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function POST(request: Request) {
  // Rule 10: cap before reading — the same ceiling the webhook route uses
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 });
  }
  // A malformed body is a 400. Letting request.json() reject un-caught is a 500 with a stack trace.
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400 });
  }

  // Rule 25: the client names what it wants, never what it costs (ERR_CLIENT_AMOUNT)
  if (CLIENT_PRICE_FIELDS.some((f) => f in body)) {
    return NextResponse.json({ error: 'amount_is_server_side' }, { status: 400 });
  }

  const quantity = Math.min(Math.max(Number(body.quantity ?? 1) | 0, 1), 99);
  const product = await db.product.findUnique({ where: { id: String(body.productId) } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  // Rule 13: price is a decimal string in the DB; the total is exact integer arithmetic
  const totalMinor = toMinorUnits(product.price, product.currency) * BigInt(quantity);
  const reference = `ord_${randomUUID()}`;
  await db.order.create({
    data: { reference, productId: product.id, quantity, currency: product.currency,
            amountMinor: totalMinor, status: 'pending' },
  });

  // Rule 4: one key per logical attempt, persisted, so a retry reuses it instead of double-charging
  const seen = await db.idempotencyKey.findUnique({
    where: { scope_ref: { scope: 'checkout.create', ref: reference } },
  });
  const idempotencyKey = seen?.key ?? randomUUID();
  if (!seen) {
    await db.idempotencyKey.create({ data: { scope: 'checkout.create', ref: reference, key: idempotencyKey } });
  }

  const secret = process.env.PROVIDER_SECRET_KEY; // <from credentials[id=secret].env_var>
  if (!secret) throw new Error('PROVIDER_SECRET_KEY is not set. See .env.example.'); // Rule 1

  const res = await fetch('<from checkout_spec.create_endpoint>', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${secret}`,     // <from checkout_spec.auth.{name,scheme}>
      'X-Idempotency-Key': idempotencyKey,   // <from checkout_spec.idempotency.name>; drop this
    },                                       // line when `in` is "sdk_option" and pass it to the SDK
    body: JSON.stringify({
      items: [{ id: product.id, title: product.name, quantity,
                unit_price: amountForProvider(product.price, product.currency, AMOUNT_UNIT),
                currency_id: product.currency }],
      // success and cancel both come back through one signed handler; the outcome is a hint
      back_urls: { success: returnUrl(reference, 'success'), failure: returnUrl(reference, 'cancel') },
      notification_url: `${process.env.PUBLIC_URL}/api/webhook/<provider>`,
      external_reference: reference, // Rule 11: the reference, never the buyer
    }),
  });

  if (!res.ok) {
    // Rule 6: status and reference only — the provider body drags PII into your logs
    console.error('[checkout] create failed', { status: res.status, reference });
    return NextResponse.json({ error: 'checkout_failed' }, { status: 502 });
  }
  const session = await res.json();
  return NextResponse.json({ url: session.init_point }); // <from checkout_spec.response_redirect_pointer>
}

/** The return URL is public and editable, so the reference travels with a MAC over it. */
function returnUrl(reference: string, outcome: string): string {
  const mac = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  return `${process.env.PUBLIC_URL}/checkout/return?ref=${reference}&t=${mac}&o=${outcome}`;
}
```

```ts
// app/checkout/return/route.ts — where the buyer's browser lands
import { NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';

export const runtime = 'nodejs';
const page = (p: string) => NextResponse.redirect(`${process.env.PUBLIC_URL}${p}`, 303);

const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET; // Rule 1: same guard as the create route
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function GET(request: Request) {
  const q = new URL(request.url).searchParams;
  const reference = q.get('ref') ?? '';
  const expected = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(q.get('t') ?? '', 'utf8');
  // Rule 19: length first — timingSafeEqual throws on a length mismatch — then constant-time
  if (a.length !== b.length || !timingSafeEqual(a, b)) return page('/checkout/failed');

  const order = await db.order.findUnique({ where: { reference } });
  if (!order) return page('/checkout/failed');

  // `?o=` picks the page. It is NOT the payment state: only the webhook writes order.status.
  if (order.status === 'paid') {
    await enqueue('order.fulfilled', { orderId: order.id }); // Rule 18: never email inline
    return page('/checkout/success');
  }
  // Pending is normal — vouchers settle in hours and the webhook can land after the redirect.
  // Show "we're confirming", never "payment failed".
  return page('/checkout/pending');
}
```

Express: same body, different plumbing. `express.json({ limit: '256kb' })` is right here (Rule 10) — a checkout request carries no signature. Only the webhook route needs `express.raw({ type: 'application/json' })` registered **before** `express.json()` (Rule 5).

## Python

```python
# routers/checkout.py  (FastAPI)
import hmac, hashlib, os, uuid
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
import httpx

from lib.payments.money import to_minor_units, amount_for_provider  # from currencies.json
from lib.db import db
from lib.queue import enqueue

router = APIRouter()
AMOUNT_UNIT = "minor"  # <from checkout_spec.amount_unit>
CLIENT_PRICE_FIELDS = {"amount", "price", "unit_price", "total", "currency"}

# Rule 1: absent raises KeyError at import; empty would silently make every token forgeable.
RETURN_SECRET = os.environ["CHECKOUT_RETURN_SECRET"].encode()
if not RETURN_SECRET:
    raise RuntimeError("CHECKOUT_RETURN_SECRET is empty. See .env.example.")


@router.post("/api/checkout")
async def create_checkout(request: Request):
    if int(request.headers.get("content-length", 0)) > 256 * 1024:  # Rule 10
        raise HTTPException(status_code=413)
    try:
        body = await request.json()
    except ValueError:  # a malformed body is a 400, not a 500
        raise HTTPException(status_code=400, detail="invalid_json")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid_json")
    if CLIENT_PRICE_FIELDS & set(body):  # Rule 25: ERR_CLIENT_AMOUNT
        raise HTTPException(status_code=400, detail="amount_is_server_side")

    quantity = max(1, min(int(body.get("quantity", 1)), 99))
    # .get(), not [] — a missing key must be a 404, not a KeyError the framework renders as 500
    product = await db.product.find_unique(where={"id": body.get("productId")})
    if product is None:
        raise HTTPException(status_code=404, detail="product_not_found")

    total_minor = to_minor_units(product.price, product.currency) * quantity  # Rule 13: exact
    reference = f"ord_{uuid.uuid4()}"
    await db.order.create(data={"reference": reference, "productId": product.id,
                                "quantity": quantity, "currency": product.currency,
                                "amountMinor": total_minor, "status": "pending"})

    # Rule 4: persisted against (scope, reference) so a retried attempt reuses the key
    seen = await db.idempotencykey.find_unique(
        where={"scope_ref": {"scope": "checkout.create", "ref": reference}})
    idempotency_key = seen.key if seen else str(uuid.uuid4())
    if seen is None:
        await db.idempotencykey.create(
            data={"scope": "checkout.create", "ref": reference, "key": idempotency_key})

    async with httpx.AsyncClient(timeout=15) as client:
        res = await client.post("<from checkout_spec.create_endpoint>", headers={
            # Rule 1, <from credentials[id=secret].env_var> and checkout_spec.auth.{name,scheme}
            "Authorization": f"Bearer {os.environ['PROVIDER_SECRET_KEY']}",
            "X-Idempotency-Key": idempotency_key,  # <from checkout_spec.idempotency.name>
        }, json={
            "items": [{"id": product.id, "title": product.name, "quantity": quantity,
                       "unit_price": amount_for_provider(product.price, product.currency, AMOUNT_UNIT),
                       "currency_id": product.currency}],
            "back_urls": {"success": _return_url(reference, "success"),
                          "failure": _return_url(reference, "cancel")},
            "notification_url": f"{os.environ['PUBLIC_URL']}/api/webhook/<provider>",
            "external_reference": reference,  # Rule 11
        })
    if res.status_code >= 400:
        print("[checkout] create failed", {"status": res.status_code, "reference": reference})  # Rule 6
        raise HTTPException(status_code=502, detail="checkout_failed")
    return {"url": res.json()["init_point"]}  # <from checkout_spec.response_redirect_pointer>


def _return_url(reference: str, outcome: str) -> str:
    mac = hmac.new(RETURN_SECRET, reference.encode(), hashlib.sha256).hexdigest()
    return f"{os.environ['PUBLIC_URL']}/checkout/return?ref={reference}&t={mac}&o={outcome}"


@router.get("/checkout/return")
async def checkout_return(ref: str = "", t: str = ""):
    expected = hmac.new(RETURN_SECRET, ref.encode(), hashlib.sha256).hexdigest()
    # Rule 19: compare BYTES. compare_digest raises TypeError on a non-ASCII str, so `?t=café`
    # would be a 500 instead of a rejection — a crash oracle on the verification path.
    if not hmac.compare_digest(expected.encode(), t.encode()):
        return RedirectResponse(f"{os.environ['PUBLIC_URL']}/checkout/failed", status_code=303)
    order = await db.order.find_unique(where={"reference": ref})
    if order is None or order.status != "paid":
        return RedirectResponse(f"{os.environ['PUBLIC_URL']}/checkout/pending", status_code=303)
    await enqueue("order.fulfilled", {"order_id": order.id})  # Rule 18: out of band
    return RedirectResponse(f"{os.environ['PUBLIC_URL']}/checkout/success", status_code=303)
```

## Anti-patterns

- ❌ Granting access from the return URL — `?status=approved`, or a `session_id` that merely exists. All buyer-controlled. Grant on the webhook, or on a re-fetch you initiated.
- ❌ Reading the amount from the request body, even "just for display". Once it is in the payload, someone eventually passes it through (`ERR_CLIENT_AMOUNT`).
- ❌ `Math.round(price * 100)` — right for USD, 100× wrong for CLP and JPY, 10× wrong for KWD, and quietly wrong for `0.1 + 0.2` in all of them.
- ❌ A fresh `randomUUID()` on every retry of the same attempt. That is not idempotency, that is a second charge with extra steps.
- ❌ Buyer email or address in provider metadata "for support" — metadata is echoed into webhooks, dashboards and logs (Rule 11).
- ❌ Rendering "Payment failed" while the order is `pending`. Vouchers and transfers settle hours later; the buyer sees a lie and pays twice.
- ❌ Creating the provider session before the local order row: if the redirect succeeds and your write fails, the money exists and the order does not.

## Security rules cited

- Rule 1: the key is read from `process.env.<from credentials[].env_var>` behind a runtime guard, never inlined.
- Rule 3: the return handler grants nothing itself — it reads the row that the signature-verified webhook wrote. The redirect is never treated as authenticated input.
- Rule 4: `crypto.randomUUID()` / `uuid.uuid4()`, persisted per `(scope, reference)` so retries reuse the key.
- Rule 6: failures log status and reference — not the provider body, not the buyer.
- Rule 10: 256 KB cap read from `content-length` before the body.
- Rule 11: only the order reference crosses into provider metadata.
- Rule 12: no card field renders on your origin — `pci.scope` stays `SAQ_A`.
- Rule 13: the total is converted once, at the currency's ISO exponent from `currencies.json` (`ERR_MINOR_UNITS`).
- Rule 19: the return token is compared with `timingSafeEqual` after a length check (Node) and over bytes with `compare_digest` (Python), so neither a timing oracle nor a non-ASCII token gets a different answer (`ERR_TIMING_UNSAFE`).
- Rule 25: an `amount`, `price` or `currency` in the request body is refused, never adopted (`ERR_CLIENT_AMOUNT`).
- Rule 18: the return handler enqueues fulfilment instead of doing it inline.
