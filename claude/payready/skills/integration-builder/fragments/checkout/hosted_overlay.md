# Hosted overlay checkout

The provider's checkout opens in an iframe over your page instead of navigating away. The buyer never leaves and the card fields live on the provider's origin, so the merchant's PCI exposure is whatever `pci.scope` says: `SAQ_A` for a plain PSP overlay, and `not_applicable` for the only provider in this family today — Lemon Squeezy is the merchant of record, so the sale is legally theirs and the questionnaire is not yours to fill in. Neither answer survives the moment you forget what the overlay actually is: **a cross-origin iframe whose "success" callback is a UI event, not an authenticated message.** Any script on the page can fire it, and the buyer's devtools can fire it too. Developers grant access on `Checkout.Success` because it arrives at exactly the right moment and looks like a result. It is a hint to change the screen, nothing more.

**Providers in this family:** `lemonsqueezy` (`checkout_spec.pattern: "hosted_overlay"`, loader `app.lemonsqueezy.com`, `checkout_spec.idempotency.supported: false`).

**Catalog fields this fragment reads:** `checkout_spec.create_endpoint`, `checkout_spec.auth.{name,scheme}`, `checkout_spec.amount_unit`, `checkout_spec.idempotency.supported`, `checkout_spec.response_redirect_pointer`, `credentials[].env_var`, `pci.requires_script_inventory`, `pci.loader_exempt_from_sri`, `currencies.json → currencies[].exponent`.

## The contract

1. Create the checkout server-side exactly as in `hosted_redirect.md` — identifiers in (a body carrying an amount is refused 400: Rule 25, `ERR_CLIENT_AMOUNT`), price looked up in your database, amount converted at the currency's ISO exponent (Rule 13). The overlay opens the same URL a redirect would.
2. When `checkout_spec.idempotency.supported` is false, the unguessable order reference **is** your dedup key: one pending row per attempt, and the webhook reconciles against it.
3. Load the provider's loader script with your framework's script tag. **Never put `integrity` on it** — it is versionless by design and its bundle rotates, so an SRI hash breaks live checkouts within days. That exemption is data: `pci.loader_exempt_from_sri` (Rule 15).
4. Every *other* script on the payment page is not exempt. Inventory them in `payment-page-scripts.json` with a reason and an integrity hash, and keep tag managers and session recorders off this page entirely — they are what drops a merchant out of SAQ A eligibility (Rule 15, `ERR_PCI_SCRIPT_INVENTORY`).
5. Register the event handler **before** opening the overlay, or you lose the first event.
6. On `Checkout.Success`: switch to a "confirming" state and poll your own server. Do not grant, do not fulfil, do not email.
7. If you listen to `postMessage` yourself, compare `event.origin` against an exact allowlisted origin. `startsWith`/`includes` matches `https://app.lemonsqueezy.com.evil.test`.
8. The status endpoint the client polls reads your own row — written only by the webhook — and authenticates the reference with a constant-time MAC (Rule 19). Bound the poll: an abandoned tab that never stops asking is a self-inflicted load test.

## Node / TypeScript

```ts
// app/api/checkout/route.ts — creating the overlay session
import { NextResponse } from 'next/server';
import { randomUUID, createHmac } from 'node:crypto';
import { db } from '@/lib/db';
import { toMinorUnits, amountForProvider } from '@/lib/payments/money'; // fragments/money/minor_units.md

const AMOUNT_UNIT = 'minor' as const; // <from checkout_spec.amount_unit>

export const runtime = 'nodejs';

// Rule 1: an unset — or empty — secret makes every poll token forgeable. Fail at module load.
const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET;
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) {
    return new NextResponse(null, { status: 413 }); // Rule 10
  }
  // A malformed body is a 400; an un-caught request.json() rejection is a 500 with a stack trace
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400 });
  }
  // Rule 25: an amount from the client is refused, not corrected (ERR_CLIENT_AMOUNT)
  if (['amount', 'price', 'total', 'currency'].some((f) => f in body)) {
    return NextResponse.json({ error: 'amount_is_server_side' }, { status: 400 });
  }

  const product = await db.product.findUnique({ where: { id: String(body.variantId) } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  const totalMinor = toMinorUnits(product.price, product.currency); // Rule 13
  const reference = `ord_${randomUUID()}`;
  // <from checkout_spec.idempotency.supported>: false — the reference is the dedup key (Rule 4)
  await db.order.create({ data: { reference, productId: product.id, currency: product.currency,
                                  amountMinor: totalMinor, status: 'pending' } });

  const secret = process.env.PROVIDER_API_KEY; // Rule 1, <from credentials[id=secret].env_var>
  if (!secret) throw new Error('PROVIDER_API_KEY is not set. See .env.example.');

  const res = await fetch('<from checkout_spec.create_endpoint>', {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${secret}` },
    body: JSON.stringify({
      data: { type: 'checkouts', attributes: {
        checkout_options: { embed: true },              // opens as an overlay, not a redirect
        custom_price: amountForProvider(product.price, product.currency, AMOUNT_UNIT),
        checkout_data: { custom: { reference } },       // Rule 11: reference only, no PII
      } },
    }),
  });
  if (!res.ok) {
    console.error('[checkout] create failed', { status: res.status, reference }); // Rule 6
    return NextResponse.json({ error: 'checkout_failed' }, { status: 502 });
  }
  const json = await res.json();
  const url = json.data.attributes.url; // <from checkout_spec.response_redirect_pointer>

  // The poll token: the client may ask about this reference and no other.
  const token = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  return NextResponse.json({ url, reference, token });
}
```

```ts
// app/api/checkout/status/route.ts — the only thing the overlay's callback is allowed to trigger
import { NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { db } from '@/lib/db';

export const runtime = 'nodejs';

const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET; // Rule 1: same guard as the create route
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function GET(request: Request) {
  const q = new URL(request.url).searchParams;
  const reference = q.get('ref') ?? '';
  const expected = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(q.get('t') ?? '', 'utf8');
  // Rule 19: length check first — timingSafeEqual throws on a mismatch — then constant-time
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return new NextResponse(null, { status: 400 }); // no detail leaked to the caller
  }
  const order = await db.order.findUnique({ where: { reference } });
  // Only the webhook writes `status`. This endpoint reports; it never promotes.
  return NextResponse.json({ status: order?.status ?? 'unknown' });
}
```

```tsx
// components/CheckoutOverlay.tsx
'use client';
import { useEffect, useRef, useState } from 'react';
import Script from 'next/script';

declare global {
  interface Window {
    LemonSqueezy?: { Setup: (o: { eventHandler: (e: { event: string }) => void }) => void;
                     Url: { Open: (url: string) => void } };
  }
}

export function CheckoutOverlay({ variantId }: { variantId: string }) {
  const [state, setState] = useState<'idle' | 'opening' | 'confirming' | 'paid'>('idle');
  const handle = useRef<{ reference: string; token: string } | null>(null);

  // Step 5: the handler is registered on load, before any overlay can open.
  function onLoaderReady() {
    window.LemonSqueezy?.Setup({
      eventHandler: (e) => {
        // Step 6: a UI event from an iframe. It moves the screen, it does not grant anything.
        if (e.event === 'Checkout.Success') setState('confirming');
      },
    });
  }

  useEffect(() => {
    if (state !== 'confirming' || !handle.current) return;
    const { reference, token } = handle.current;
    // Bounded: ~2 minutes. A voucher can settle hours later and the webhook still writes the
    // row — an unbounded interval just has every abandoned tab hammering your own API forever.
    let left = 60;
    const id = setInterval(async () => {
      if (left-- <= 0) { clearInterval(id); return; }
      const r = await fetch(`/api/checkout/status?ref=${reference}&t=${token}`);
      if (!r.ok) return; // 400 means the token is wrong; keep the screen honest, grant nothing
      if ((await r.json()).status === 'paid') { setState('paid'); clearInterval(id); }
    }, 2000);
    return () => clearInterval(id);
  }, [state]);

  async function open() {
    setState('opening');
    const res = await fetch('/api/checkout', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ variantId }), // Rule 25: identifiers only — no amount, ever
    });
    if (!res.ok) { setState('idle'); return; } // no session, no overlay
    const { url, reference, token } = await res.json();
    handle.current = { reference, token };
    window.LemonSqueezy?.Url.Open(url);
  }

  return (
    <>
      {/* Rule 15: NO integrity attribute here. The loader is versionless and rotates its
          bundle; an SRI hash on it breaks live checkouts. Host is listed in
          pci.loader_exempt_from_sri. Every other script on this page IS pinned. */}
      <Script src="https://app.lemonsqueezy.com/js/lemon.js" strategy="afterInteractive"
              onLoad={onLoaderReady} />
      <button onClick={open} disabled={state !== 'idle'}>
        {state === 'idle' ? 'Comprar' : state === 'paid' ? '¡Listo!' : 'Confirmando…'}
      </button>
    </>
  );
}
```

If you wire a raw listener instead of the provider's `Setup`, the origin check is not optional:

```ts
const ALLOWED_ORIGIN = 'https://app.lemonsqueezy.com'; // <from pci.loader_exempt_from_sri>
window.addEventListener('message', (e) => {
  if (e.origin !== ALLOWED_ORIGIN) return; // exact match; startsWith() matches evil lookalikes
});
```

## Python

```python
# routers/checkout.py  (FastAPI) — server half; the overlay itself is browser-side
import hmac, hashlib, os, uuid
from fastapi import APIRouter, HTTPException, Request, Response
import httpx

from lib.payments.money import to_minor_units, amount_for_provider
from lib.db import db

router = APIRouter()
AMOUNT_UNIT = "minor"  # <from checkout_spec.amount_unit>

# Rule 1: absent raises KeyError at import; empty would make every poll token forgeable.
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
    if {"amount", "price", "total", "currency"} & set(body):  # Rule 25: ERR_CLIENT_AMOUNT
        raise HTTPException(status_code=400, detail="amount_is_server_side")

    # .get(), not [] — a missing key must be a 404, not a KeyError the framework renders as 500
    product = await db.product.find_unique(where={"id": body.get("variantId")})
    if product is None:
        raise HTTPException(status_code=404, detail="product_not_found")

    total_minor = to_minor_units(product.price, product.currency)  # Rule 13
    reference = f"ord_{uuid.uuid4()}"  # Rule 4: the dedup key when idempotency.supported is false
    await db.order.create(data={"reference": reference, "productId": product.id,
                                "currency": product.currency, "amountMinor": total_minor,
                                "status": "pending"})

    async with httpx.AsyncClient(timeout=15) as client:
        res = await client.post(
            "<from checkout_spec.create_endpoint>",
            headers={"Authorization": f"Bearer {os.environ['PROVIDER_API_KEY']}"},  # Rule 1
            json={"data": {"type": "checkouts", "attributes": {
                "checkout_options": {"embed": True},
                "custom_price": amount_for_provider(product.price, product.currency, AMOUNT_UNIT),
                "checkout_data": {"custom": {"reference": reference}}}}})  # Rule 11
    if res.status_code >= 400:
        print("[checkout] create failed", {"status": res.status_code})  # Rule 6
        raise HTTPException(status_code=502, detail="checkout_failed")

    token = hmac.new(RETURN_SECRET, reference.encode(), hashlib.sha256).hexdigest()
    return {"url": res.json()["data"]["attributes"]["url"], "reference": reference, "token": token}


@router.get("/api/checkout/status")
async def checkout_status(ref: str = "", t: str = ""):
    expected = hmac.new(RETURN_SECRET, ref.encode(), hashlib.sha256).hexdigest()
    # Rule 19: compare BYTES — compare_digest raises TypeError on a non-ASCII str, which would
    # turn `?t=café` into a 500 instead of a rejection.
    if not hmac.compare_digest(expected.encode(), t.encode()):
        return Response(status_code=400)      # no detail leaked to the caller
    order = await db.order.find_unique(where={"reference": ref})
    return {"status": order.status if order else "unknown"}  # written only by the webhook
```

## Anti-patterns

- ❌ Granting access, sending the licence key, or firing the fulfilment job on `Checkout.Success`. It is a `postMessage` from an iframe; anything on the page can emit it.
- ❌ Adding `integrity="sha384-…"` to the provider's loader script. It is deliberately versionless, the bundle rotates, and the SRI check then blocks it — a checkout that worked in staging dies in production a week later (Rule 15).
- ❌ Concluding from that exemption that SRI is optional in general. Every non-exempt script on the payment page needs a pinned hash and an entry in `payment-page-scripts.json`.
- ❌ Google Tag Manager, Hotjar, Clarity or a session recorder on the page hosting the overlay. That is the fastest way out of SAQ A eligibility, and a recorder can capture what the buyer types beside the iframe.
- ❌ `if (e.origin.includes('lemonsqueezy.com'))` — matches `https://app.lemonsqueezy.com.evil.test`. Compare the full origin with `===`.
- ❌ Calling `Setup()` after `Url.Open()`. The success event fires into a handler that does not exist yet, and the buyer stares at a spinner.
- ❌ Passing `custom_price` from the browser. The overlay will happily charge whatever it is handed (`ERR_CLIENT_AMOUNT`).
- ❌ Polling `/api/checkout/status` on an unbounded `setInterval`. Every abandoned tab keeps asking until the browser closes; the webhook is what eventually writes the row, not the poll.

## Security rules cited

- Rule 1: the API key stays server-side behind `process.env.<from credentials[].env_var>`; the overlay needs no client key.
- Rule 3: nothing here grants anything — the status endpoint reports the row that the signature-verified webhook wrote.
- Rule 4: with `idempotency.supported: false`, the UUID reference is the dedup key and one row is created per attempt.
- Rule 6: create failures log status and reference only.
- Rule 10: 256 KB cap before the body is read.
- Rule 11: only the reference travels in `checkout_data.custom`.
- Rule 12: card fields render inside the provider's iframe; nothing on your origin can read them (`pci.scope` — `not_applicable` for `lemonsqueezy` as merchant of record, `SAQ_A` for a non-MoR overlay).
- Rule 13: price from the database, converted at the ISO exponent (`ERR_MINOR_UNITS`).
- Rule 19: the poll token is compared with `timingSafeEqual` after a length check (Node) and over bytes with `compare_digest` (Python), and the endpoint answers a bare 400 (`ERR_TIMING_UNSAFE`).
- Rule 25: an amount in the request body is refused, never corrected (`ERR_CLIENT_AMOUNT`).
- Rule 15: the loader is exempt from SRI per `pci.loader_exempt_from_sri`; everything else on the payment page is inventoried and pinned (`ERR_PCI_SCRIPT_INVENTORY`).
