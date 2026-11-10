# Widget tokenisation

The provider drops a widget onto your page, collects the card inside frames it owns, tokenises it against its own API, and hands your code a token or a transaction id. Your server sees a `tok_…`, never a card number. The mistake that ends this arrangement is always the same one, and it is always well-intentioned: **somebody builds a tokenisation endpoint on the merchant's own backend** — "so we control the UX", "so we can retry", "just to proxy the widget call". The moment a PAN arrives at your server, the merchant leaves PCI SAQ A (≈20 questions, self-assessed) and enters SAQ D (300+ controls, ASV scans, penetration testing, a QSA). That is a six-figure programme, retroactive to the first request. There is no small version of it.

**Providers in this family:** `wompi` (`checkout_spec.pattern: "widget_token"`, `checkout_spec.idempotency.supported: false`, `credentials[kind=signing_salt]: WOMPI_INTEGRITY_SECRET`, loader `checkout.wompi.co`).

**Catalog fields this fragment reads:** `checkout_spec.amount_unit`, `checkout_spec.idempotency.supported`, `credentials[kind=publishable_key].{env_var,scope}`, `credentials[kind=signing_salt].env_var`, `credentials[kind=api_key].scope`, `provider.currencies`, `webhook.payload_authoritative`, `webhook.refetch_endpoint`, `pci.{scope,pan_touches_server,loader_exempt_from_sri}`, `currencies.json → currencies[].exponent`.

## The contract

1. **Do not write a card endpoint.** No route on your origin accepts `card_number`, `cvv`, `exp_month` or anything shaped like a PAN. Guard the checkout routes so an "improvement" cannot add one quietly (Rule 12).
2. Look the price up server-side (a body carrying an amount is refused 400: Rule 25, `ERR_CLIENT_AMOUNT`) and convert at the currency's ISO exponent (Rule 13). The widget is handed an amount; whatever it is handed, it charges.
3. Mint an unguessable reference. With `checkout_spec.idempotency.supported: false` there is no idempotency header to send, so the reference plays that role — which means **you** have to enforce it: a `UNIQUE` constraint on `order.reference` and a duplicate treated as the same attempt. The catalog records that idempotency is unsupported, not that the provider deduplicates references, so a double-submit guard built on assumed provider behaviour is a double charge waiting for the day that behaviour changes (Rule 4).
4. Compute the widget's integrity signature **server-side**: `sha256(reference + amount_in_minor_units + currency + <signing_salt>)`, hex. Note the shape — the secret is part of the hashed input, so this is a plain digest, not an HMAC. It is the same branch `scripts/lib/webhook-sign.js` takes when `signed_payload_template` contains `{secret}`.
5. Persist the pending order row before handing anything to the browser. The widget can succeed and the callback can be lost; the row is what the webhook reconciles against.
6. The browser gets the **publishable** key (`credentials[kind=publishable_key].scope: "client"`) and never the private one.
7. The widget's callback is a UI event. With `webhook.payload_authoritative: false`, so is the webhook body — re-fetch `webhook.refetch_endpoint` before changing state, or wait for the handler that does.
8. If the widget returns a *card token* rather than a transaction, send it to the charge call server-side and store only the token plus `last4`, `brand`, `exp` for receipts. Never a PAN, never a CVV, in any column, log or cache (Rule 12).

## Node / TypeScript

```ts
// app/api/checkout/widget/route.ts — everything the widget needs, computed where it is safe
import { NextResponse } from 'next/server';
import { randomUUID, createHash, createHmac } from 'node:crypto';
import { db } from '@/lib/db';
import { toMinorUnits } from '@/lib/payments/money';

export const runtime = 'nodejs';

// Rule 1: an unset — or empty — return secret makes every return token forgeable. Fail at load.
const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET;
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

const CARD_FIELDS = /^(card_?number|pan|cvv|cvc|cvv2|security_?code|track[12]|exp_?month|exp_?year|expiry)$/i;
const PAN_SHAPE = /^[0-9](?:[ -]?[0-9]){12,18}$/; // 13–19 digits, spaces or dashes allowed

function luhn(digits: string): boolean {
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** Rule 12: a PAN must never reach this process. Refuse the request; do not log the body. */
function assertNoCardData(value: unknown, seen = new Set<unknown>()): void {
  if (value === null || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (CARD_FIELDS.test(k)) throw new Error(`field "${k}" looks like card data`);
    if (typeof v === 'string') {
      const t = v.trim();
      if (PAN_SHAPE.test(t) && luhn(t.replace(/[ -]/g, ''))) throw new Error('value looks like a PAN');
    }
    if (v && typeof v === 'object') assertNoCardData(v, seen);
  }
}

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 }); // Rule 10
  }
  // A malformed body is a 400; an un-caught request.json() rejection is a 500 with a stack trace
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400 });
  }

  try {
    assertNoCardData(body); // Rule 12: SAQ A survives only while this holds
  } catch {
    // Rule 6: the reason is not echoed and the body is never logged — it may hold a real PAN
    console.error('[widget] rejected a request carrying card-shaped data');
    return NextResponse.json({ error: 'card_data_not_accepted' }, { status: 400 });
  }
  // Rule 25: identifiers in, price never (ERR_CLIENT_AMOUNT)
  if (['amount', 'price', 'total', 'currency'].some((f) => f in body)) {
    return NextResponse.json({ error: 'amount_is_server_side' }, { status: 400 });
  }

  const product = await db.product.findUnique({ where: { id: String(body.productId) } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  // Rule 13: exact scaling at the currency's ISO exponent. money.ts refuses anything outside
  // the safe integer range, so Number() here is exact and the widget's numeric field is safe.
  const amountInMinor = Number(toMinorUnits(product.price, product.currency));
  // Rule 4: idempotency.supported is false — the reference is the key, and it must be unguessable
  const reference = `ord_${randomUUID()}`;

  const salt = process.env.PROVIDER_INTEGRITY_SECRET; // <from credentials[kind=signing_salt].env_var>
  if (!salt) throw new Error('PROVIDER_INTEGRITY_SECRET is not set. See .env.example.'); // Rule 1

  // Plain digest: the salt is inside the hashed input, not an HMAC key. Computing this in the
  // browser would ship the salt with it — and the salt is what stops the price being edited.
  const integrity = createHash('sha256')
    .update(`${reference}${amountInMinor}${product.currency}${salt}`, 'utf8')
    .digest('hex');

  await db.order.create({ data: { reference, productId: product.id,
    currency: product.currency, amountMinor: amountInMinor, status: 'pending' } });

  // The widget's redirectUrl is public and editable, so the reference travels with a MAC
  const t = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');

  return NextResponse.json({
    reference,
    amountInMinor,                                     // <from checkout_spec.amount_unit: "minor">
    currency: product.currency,
    integrity,
    publicKey: process.env.NEXT_PUBLIC_PROVIDER_PUBLIC_KEY, // credentials[kind=publishable_key], scope: "client"
    redirectUrl: `${process.env.PUBLIC_URL}/checkout/return?ref=${reference}&t=${t}`,
  });
}
```

```tsx
// components/WidgetCheckout.tsx
'use client';
import Script from 'next/script';
import { useRef } from 'react';

declare global {
  interface Window { WidgetCheckout?: new (o: Record<string, unknown>) => { open: (cb: (r: any) => void) => void } }
}

export function WidgetCheckout({ productId }: { productId: string }) {
  const ready = useRef(false);

  async function pay() {
    if (!ready.current || !window.WidgetCheckout) return;
    const res = await fetch('/api/checkout/widget', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ productId }), // Rule 13: identifiers only — and no card data, ever
    });
    const init = await res.json();
    const widget = new window.WidgetCheckout({
      currency: init.currency,
      amountInCents: init.amountInMinor,
      reference: init.reference,
      publicKey: init.publicKey,
      redirectUrl: init.redirectUrl,
      signature: { integrity: init.integrity }, // computed server-side, opaque here
    });
    widget.open((result) => {
      // webhook.payload_authoritative is false: this is a hint. Show "confirming", then let
      // the webhook (which re-fetches webhook.refetch_endpoint) flip the order.
      console.log('[widget] closed', { reference: init.reference, id: result?.transaction?.id });
      window.location.href = `/checkout/pending?ref=${init.reference}`;
    });
  }

  return (
    <>
      {/* Rule 15: no integrity attribute on this loader — it is versionless and rotates, and
          its host is listed in pci.loader_exempt_from_sri. Everything else here stays pinned
          and inventoried in payment-page-scripts.json. */}
      <Script src="https://checkout.wompi.co/widget.js" strategy="afterInteractive"
              onLoad={() => { ready.current = true; }} />
      <button onClick={pay}>Pagar</button>
    </>
  );
}
```

## Python

```python
# routers/widget.py  (FastAPI)
import hashlib, hmac, os, re, uuid
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from lib.payments.money import to_minor_units
from lib.db import db

router = APIRouter()

# Rule 1: absent raises KeyError at import; empty would make every return token forgeable.
RETURN_SECRET = os.environ["CHECKOUT_RETURN_SECRET"].encode()
if not RETURN_SECRET:
    raise RuntimeError("CHECKOUT_RETURN_SECRET is empty. See .env.example.")

CARD_FIELDS = re.compile(
    r"^(card_?number|pan|cvv|cvc|cvv2|security_?code|track[12]|exp_?month|exp_?year|expiry)$", re.I)
PAN_SHAPE = re.compile(r"^[0-9](?:[ -]?[0-9]){12,18}$")


def _luhn(digits: str) -> bool:
    total, dbl = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total, dbl = total + d, not dbl
    return total % 10 == 0


def assert_no_card_data(value) -> None:
    """Rule 12: a PAN must never reach this process."""
    if isinstance(value, dict):
        for k, v in value.items():
            if CARD_FIELDS.match(str(k)):
                raise ValueError("card data field")
            assert_no_card_data(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            assert_no_card_data(v)
    elif isinstance(value, str):
        t = value.strip()
        if PAN_SHAPE.match(t) and _luhn(t.replace(" ", "").replace("-", "")):
            raise ValueError("PAN-shaped value")


@router.post("/api/checkout/widget")
async def widget_init(request: Request):
    if int(request.headers.get("content-length", 0)) > 256 * 1024:  # Rule 10
        raise HTTPException(status_code=413)
    try:
        body = await request.json()
    except ValueError:  # a malformed body is a 400, not a 500
        raise HTTPException(status_code=400, detail="invalid_json")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="invalid_json")
    try:
        assert_no_card_data(body)  # Rule 12
    except ValueError:
        print("[widget] rejected a request carrying card-shaped data")  # Rule 6: never the body
        raise HTTPException(status_code=400, detail="card_data_not_accepted")
    if {"amount", "price", "total", "currency"} & set(body):  # Rule 25: ERR_CLIENT_AMOUNT
        raise HTTPException(status_code=400, detail="amount_is_server_side")

    # .get(), not [] — a missing key must be a 404, not a KeyError the framework renders as 500
    product = await db.product.find_unique(where={"id": body.get("productId")})
    if product is None:
        raise HTTPException(status_code=404, detail="product_not_found")

    amount_in_minor = to_minor_units(product.price, product.currency)  # Rule 13
    reference = f"ord_{uuid.uuid4()}"  # Rule 4: the key, since idempotency.supported is false
    salt = os.environ["PROVIDER_INTEGRITY_SECRET"]  # Rule 1, credentials[kind=signing_salt]

    # Plain digest — the salt is part of the hashed input, exactly as the reference signer does
    # when signed_payload_template contains {secret}.
    integrity = hashlib.sha256(
        f"{reference}{amount_in_minor}{product.currency}{salt}".encode()).hexdigest()

    await db.order.create(data={"reference": reference, "productId": product.id,
                                "currency": product.currency, "amountMinor": amount_in_minor,
                                "status": "pending"})
    # The redirect is public and editable, so the reference travels with a MAC
    t = hmac.new(RETURN_SECRET, reference.encode(), hashlib.sha256).hexdigest()
    return {"reference": reference, "amountInMinor": amount_in_minor,
            "currency": product.currency, "integrity": integrity,
            "publicKey": os.environ["PROVIDER_PUBLIC_KEY"],  # credentials[kind=publishable_key]
            "redirectUrl": f"{os.environ['PUBLIC_URL']}/checkout/return?ref={reference}&t={t}"}


@router.get("/checkout/return")
async def widget_return(ref: str = "", t: str = ""):
    expected = hmac.new(RETURN_SECRET, ref.encode(), hashlib.sha256).hexdigest()
    # Rule 19: compare BYTES — compare_digest raises TypeError on a non-ASCII str, turning
    # `?t=café` into a 500 instead of a redirect to the failure page.
    if not hmac.compare_digest(expected.encode(), t.encode()):
        return RedirectResponse(f"{os.environ['PUBLIC_URL']}/checkout/failed", status_code=303)
    order = await db.order.find_unique(where={"reference": ref})
    page = "success" if order and order.status == "paid" else "pending"
    return RedirectResponse(f"{os.environ['PUBLIC_URL']}/checkout/{page}", status_code=303)
```

```ts
// app/checkout/return/route.ts — where the widget sends the buyer back
import { NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { db } from '@/lib/db';

export const runtime = 'nodejs';

const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET; // Rule 1: same guard as the widget route
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function GET(request: Request) {
  const q = new URL(request.url).searchParams;
  const reference = q.get('ref') ?? '';
  const expected = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(q.get('t') ?? '', 'utf8');
  // Rule 19: length first — timingSafeEqual throws on a length mismatch — then constant-time
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return NextResponse.redirect(`${process.env.PUBLIC_URL}/checkout/failed`, 303);
  }
  // `?id=` and `?status=` also arrive here. They are buyer-editable strings, not evidence:
  // read the row the webhook writes after it re-fetches webhook.refetch_endpoint.
  const order = await db.order.findUnique({ where: { reference } });
  const done = order?.status === 'paid';
  return NextResponse.redirect(`${process.env.PUBLIC_URL}/checkout/${done ? 'success' : 'pending'}`, 303);
}
```

## Anti-patterns

- ❌ `POST /api/tokenize` on your own backend, taking `card_number` and `cvv` and forwarding them to the provider. SAQ A → SAQ D, from the first request, retroactively.
- ❌ Storing a PAN "encrypted, just for retries", or a CVV "until the charge settles". Storing a CVV after authorisation is prohibited outright — no encryption makes it allowed (Rule 12).
- ❌ Computing the integrity signature in the browser. The salt ships with it, and the salt is the only thing binding the amount to the reference.
- ❌ Letting the client send `amountInCents` to the widget. It charges what it is handed (`ERR_CLIENT_AMOUNT`).
- ❌ A sequential or reused `reference`. With `idempotency.supported: false` it is the idempotency key; guessable references let one buyer collide with another's checkout.
- ❌ Relying on the provider to reject a duplicate `reference`. The catalog says idempotency is unsupported; it does not promise reference uniqueness. Put the `UNIQUE` constraint in your own schema.
- ❌ Marking the order paid inside the widget callback. `webhook.payload_authoritative` is false even for the webhook — re-fetch, or wait for the handler that does.
- ❌ Shipping the private key (`prv_…`) to the browser because "the public key returned a 401". A 401 means the wrong key kind, not the wrong secrecy level.
- ❌ Putting an SRI hash on the widget loader. Versionless by design; the hash breaks the checkout on the provider's next deploy (Rule 15).

## Security rules cited

- Rule 1: the integrity salt and private key live in `process.env`, guarded at use; only the `scope: "client"` public key is serialised to the page.
- Rule 4: with `checkout_spec.idempotency.supported: false`, `crypto.randomUUID()` / `uuid.uuid4()` mints the reference that plays the idempotency role, persisted — under a `UNIQUE` constraint you own — before the widget opens.
- Rule 6: a rejected card-shaped request logs a fixed string — never the body, which may hold a live PAN.
- Rule 10: 256 KB cap before the body is read.
- Rule 12: no tokenisation endpoint exists, the request guard refuses PAN-shaped input, and only token plus `last4`/`brand`/`exp` is ever stored (`pci.pan_touches_server: false`, `pci.scope: SAQ_A`).
- Rule 13: amount from the database, converted at the ISO exponent, then signed into the integrity value so it cannot be edited in flight (`ERR_MINOR_UNITS`).
- Rule 19: the return token is compared with `timingSafeEqual` after a length check (Node) and over bytes with `compare_digest` (Python) (`ERR_TIMING_UNSAFE`).
- Rule 25: an `amount`, `price` or `currency` in the request body is refused, never converted (`ERR_CLIENT_AMOUNT`).
- Rule 15: the widget loader is exempt from SRI per `pci.loader_exempt_from_sri`; every other payment-page script is pinned and inventoried.
