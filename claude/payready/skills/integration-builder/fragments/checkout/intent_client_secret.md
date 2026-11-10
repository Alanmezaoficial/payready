# Intent + client secret

The server creates a payment intent for an amount it decided, and hands the browser one thing: a client secret. The provider's element mounts with that secret, collects the card on the provider's own frames, and confirms the payment directly against the provider. Your server never sees a PAN, so the merchant stays at PCI SAQ A. The thing developers get wrong is subtle, because it sounds like the same question twice: **"safe to expose" is not "safe to trust."** The client secret is genuinely safe to put in a page. The browser's report of what happened with it — `status === 'succeeded'` — is not safe to believe, because the same devtools that can read the secret can print that string.

**Providers in this family:** none in the catalog declares `checkout_spec.pattern: "intent_client_secret"` yet — this fragment ships ahead of Wave 1. It is reached today through `frontend_style: embedded`, by `stripe` (`frontend_options: [hosted, embedded, elements]`, `recommended_api_flow: "payment_intents"`) and `mercadopago` (`frontend_options: [hosted, embedded, bricks]`).

**Catalog fields this fragment reads:** `checkout_spec.amount_unit`, `checkout_spec.idempotency.{supported,in,name}`, `credentials[kind=api_key].{env_var,scope}`, `credentials[kind=publishable_key].{env_var,scope}`, `methods[]`, `supports.{cash_voucher,qr,installments}`, `method_coverage_regions`, `recurring.network_txn_id_required`, `pci.loader_exempt_from_sri`, `currencies.json → currencies[].exponent`.

## Why the client secret is safe and the API key is not

The client secret authorises exactly one thing: confirming — and reading — the single intent it was minted for, at the amount that intent already has. It cannot create a charge, cannot change the amount, cannot list customers, cannot refund, and dies with the intent. The API key (`credentials[kind=api_key].scope: "server"`) can do all of those against the whole account. That is the entire difference, and it is why `credentials[kind=publishable_key].scope` is `"client"` while the secret key never leaves the server.

It is still a bearer token for that one payment, so: never log it (Rule 6), never put it in a URL — query strings land in `Referer` headers, proxy logs and analytics — and hand it only to the session that created the intent.

## The contract

1. Cap the body at 256 KB (Rule 10) and accept identifiers only; a body with `amount` or `currency` — or one that is not a JSON object at all — is refused 400 (Rule 25, `ERR_CLIENT_AMOUNT`).
2. Price and currency come from your database; convert at the ISO exponent from `currencies.json` and shape per `checkout_spec.amount_unit` (Rule 13).
3. Create the intent with a persisted idempotency key (Rule 4), and store the local order row keyed by an unguessable reference before responding.
4. Return **only** `client_secret` plus the publishable key. Never the API key, never the raw provider response.
5. Enable payment methods declaratively (`automatic_payment_methods`) instead of hardcoding a list. The provider then offers the buyer's local rails — the ones in `supports.cash_voucher` and `supports.qr` for their country — and that same switch is what lets the issuer request 3DS/SCA when it wants it.
6. The element confirms with `redirect: 'if_required'`. A `requires_action` result is normal, not an error: the SDK runs the challenge and comes back.
7. Off-session (a stored card, a renewal) can also return `requires_action`, with nobody there to answer it. Mark the payment `needs_authentication` and bring the customer back; do not retry the charge in a loop.
8. The intent's amount is frozen at creation. If the cart changes, update or recreate the intent **server-side**. Never accept a new amount from the client.
9. Fulfil on the webhook. The browser's `succeeded` only decides which screen to render, and the status endpoint it polls authenticates the reference with a constant-time MAC (Rule 19).
10. Create the intent exactly **once** per checkout. A component that fetches during render mints a fresh intent on every re-render, and two intents are two authorisations on one card (Rule 4).

## Node / TypeScript

```ts
// app/api/checkout/intent/route.ts
import { NextResponse } from 'next/server';
import { randomUUID, createHmac } from 'node:crypto';
import { db } from '@/lib/db';
import { toMinorUnits, fromMinorUnits, amountForProvider } from '@/lib/payments/money';

const AMOUNT_UNIT = 'minor' as const; // <from checkout_spec.amount_unit>

export const runtime = 'nodejs';

// Rule 1: an unset — or empty — secret makes every status token forgeable. Fail at module load.
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
  // Rule 25: an amount from the client is refused, never adopted (ERR_CLIENT_AMOUNT)
  if (['amount', 'price', 'total', 'currency'].some((f) => f in body)) {
    return NextResponse.json({ error: 'amount_is_server_side' }, { status: 400 });
  }

  const quantity = Math.min(Math.max(Number(body.quantity ?? 1) | 0, 1), 99);
  const product = await db.product.findUnique({ where: { id: String(body.productId) } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  // Rule 13: exact integer arithmetic, then one decimal string for the provider boundary
  const totalMinor = toMinorUnits(product.price, product.currency) * BigInt(quantity);
  const total = fromMinorUnits(totalMinor, product.currency);
  const reference = `ord_${randomUUID()}`;
  await db.order.create({ data: { reference, productId: product.id, quantity,
    currency: product.currency, amountMinor: totalMinor, status: 'pending' } });

  // Rule 4: persisted per (scope, reference) so a retry reuses the key instead of creating
  // a second intent — two intents means two authorisations on the buyer's card.
  const seen = await db.idempotencyKey.findUnique({
    where: { scope_ref: { scope: 'intent.create', ref: reference } } });
  const idempotencyKey = seen?.key ?? randomUUID();
  if (!seen) await db.idempotencyKey.create({
    data: { scope: 'intent.create', ref: reference, key: idempotencyKey } });

  const secret = process.env.PROVIDER_SECRET_KEY; // Rule 1, <from credentials[kind=api_key].env_var>
  if (!secret) throw new Error('PROVIDER_SECRET_KEY is not set. See .env.example.');

  const res = await fetch('<from checkout_spec.create_endpoint>/payment_intents', {
    method: 'POST',
    headers: { Authorization: `Bearer ${secret}`, 'content-type': 'application/json',
               'Idempotency-Key': idempotencyKey }, // <from checkout_spec.idempotency.name>
    body: JSON.stringify({
      amount: amountForProvider(total, product.currency, AMOUNT_UNIT),
      currency: product.currency,
      // Step 5: the provider decides which of `methods[]` the buyer's region can actually
      // use — OXXO in MX, Pix in BR — and this is also the 3DS/SCA switch.
      automatic_payment_methods: { enabled: true },
      metadata: { reference }, // Rule 11: the reference, never the buyer
    }),
  });
  if (!res.ok) {
    console.error('[intent] create failed', { status: res.status, reference }); // Rule 6
    return NextResponse.json({ error: 'checkout_failed' }, { status: 502 });
  }
  const intent = await res.json();

  const token = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  // Rule 6: the client secret is returned, never logged, never placed in a URL.
  return NextResponse.json({
    clientSecret: intent.client_secret,
    publishableKey: process.env.NEXT_PUBLIC_PROVIDER_PUBLISHABLE_KEY, // scope: "client"
    reference, token,
  });
}
```

```ts
// app/api/checkout/status/route.ts — what the browser is allowed to ask after confirming
import { NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { db } from '@/lib/db';

export const runtime = 'nodejs';

const RETURN_SECRET = process.env.CHECKOUT_RETURN_SECRET; // Rule 1: same guard as the intent route
if (!RETURN_SECRET) throw new Error('CHECKOUT_RETURN_SECRET is not set. See .env.example.');

export async function GET(request: Request) {
  const q = new URL(request.url).searchParams;
  const reference = q.get('ref') ?? '';
  const expected = createHmac('sha256', RETURN_SECRET)
    .update(reference, 'utf8').digest('hex');
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(q.get('t') ?? '', 'utf8');
  // Rule 19: length first — timingSafeEqual throws on a mismatch — then constant-time
  if (a.length !== b.length || !timingSafeEqual(a, b)) return new NextResponse(null, { status: 400 });
  const order = await db.order.findUnique({ where: { reference } });
  return NextResponse.json({ status: order?.status ?? 'unknown' }); // webhook writes it, not this
}
```

```tsx
// components/PaymentForm.tsx
'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement, useStripe, useElements } from '@stripe/react-stripe-js';

function Inner({ reference, token }: { reference: string; token: string }) {
  const provider = useStripe();
  const elements = useElements();
  const [msg, setMsg] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!provider || !elements) return;
    const { error, paymentIntent } = await provider.confirmPayment({
      elements,
      confirmParams: { return_url: `${window.location.origin}/checkout/return?ref=${reference}` },
      redirect: 'if_required', // 3DS runs in a modal; a redirect happens only if the issuer insists
    });
    if (error) return setMsg(error.message ?? 'No pudimos procesar el pago.');
    if (paymentIntent?.status === 'requires_action') return setMsg('Autenticando con tu banco…');
    // NOT a grant: the row flips to paid only when the webhook says so.
    const r = await fetch(`/api/checkout/status?ref=${reference}&t=${token}`);
    setMsg((await r.json()).status === 'paid' ? '¡Listo!' : 'Confirmando tu pago…');
  }

  return (
    <form onSubmit={onSubmit}>
      <PaymentElement />
      <button type="submit" disabled={!provider}>Pagar</button>
      {msg && <p role="alert">{msg}</p>}
    </form>
  );
}

export function PaymentForm({ productId }: { productId: string }) {
  const [init, setInit] = useState<{ clientSecret: string; publishableKey: string;
                                     reference: string; token: string } | null>(null);
  const started = useRef(false);

  // Step 10 / Rule 4: exactly one intent per checkout. Fetching in the render body — the shape
  // this almost always starts as — re-fires on every re-render and on StrictMode's double
  // mount, and each call is another authorisation the buyer's issuer counts against them.
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    fetch('/api/checkout/intent', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ productId }) })  // Rule 25: identifiers only
      .then((r) => (r.ok ? r.json() : null))
      .then(setInit)
      .catch(() => setInit(null));
  }, [productId]);

  // loadStripe() must not run in the render path either: a new promise each render remounts
  // <Elements> and throws away the card fields the buyer is currently typing into.
  // Rule 15: that loader is versionless — it is fetched without SRI, and its host is listed in
  // pci.loader_exempt_from_sri. Every other script on this page stays pinned.
  const stripePromise = useMemo(
    () => (init ? loadStripe(init.publishableKey) : null), [init?.publishableKey]);

  if (!init || !stripePromise) return <p>Cargando…</p>;
  return (
    <Elements stripe={stripePromise} options={{ clientSecret: init.clientSecret }}>
      <Inner reference={init.reference} token={init.token} />
    </Elements>
  );
}
```

## Python

```python
# routers/intent.py  (FastAPI)
import hmac, hashlib, os, uuid
from fastapi import APIRouter, HTTPException, Request, Response
import httpx

from lib.payments.money import to_minor_units, from_minor_units, amount_for_provider
from lib.db import db

router = APIRouter()
AMOUNT_UNIT = "minor"  # <from checkout_spec.amount_unit>

# Rule 1: absent raises KeyError at import; empty would make every status token forgeable.
RETURN_SECRET = os.environ["CHECKOUT_RETURN_SECRET"].encode()
if not RETURN_SECRET:
    raise RuntimeError("CHECKOUT_RETURN_SECRET is empty. See .env.example.")


@router.post("/api/checkout/intent")
async def create_intent(request: Request):
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
    product = await db.product.find_unique(where={"id": body.get("productId")})
    if product is None:
        raise HTTPException(status_code=404, detail="product_not_found")

    quantity = max(1, min(int(body.get("quantity", 1)), 99))
    total_minor = to_minor_units(product.price, product.currency) * quantity  # Rule 13
    total = from_minor_units(total_minor, product.currency)
    reference = f"ord_{uuid.uuid4()}"
    await db.order.create(data={"reference": reference, "productId": product.id,
                                "quantity": quantity, "currency": product.currency,
                                "amountMinor": total_minor, "status": "pending"})

    seen = await db.idempotencykey.find_unique(
        where={"scope_ref": {"scope": "intent.create", "ref": reference}})
    idempotency_key = seen.key if seen else str(uuid.uuid4())  # Rule 4
    if seen is None:
        await db.idempotencykey.create(
            data={"scope": "intent.create", "ref": reference, "key": idempotency_key})

    async with httpx.AsyncClient(timeout=15) as client:
        res = await client.post(
            "<from checkout_spec.create_endpoint>/payment_intents",
            headers={"Authorization": f"Bearer {os.environ['PROVIDER_SECRET_KEY']}",  # Rule 1
                     "Idempotency-Key": idempotency_key},
            json={"amount": amount_for_provider(total, product.currency, AMOUNT_UNIT),
                  "currency": product.currency,
                  "automatic_payment_methods": {"enabled": True},  # local rails + 3DS/SCA
                  "metadata": {"reference": reference}})           # Rule 11
    if res.status_code >= 400:
        print("[intent] create failed", {"status": res.status_code, "reference": reference})  # Rule 6
        raise HTTPException(status_code=502, detail="checkout_failed")

    token = hmac.new(RETURN_SECRET, reference.encode(), hashlib.sha256).hexdigest()
    # Rule 6: client_secret goes to the browser, never to a log line or a query string
    return {"clientSecret": res.json()["client_secret"],
            "publishableKey": os.environ["PROVIDER_PUBLISHABLE_KEY"],  # scope: "client"
            "reference": reference, "token": token}


@router.get("/api/checkout/status")
async def status(ref: str = "", t: str = ""):
    expected = hmac.new(RETURN_SECRET, ref.encode(), hashlib.sha256).hexdigest()
    # Rule 19: compare BYTES — compare_digest raises TypeError on a non-ASCII str, turning
    # `?t=café` into a 500 instead of a rejection.
    if not hmac.compare_digest(expected.encode(), t.encode()):
        return Response(status_code=400)
    order = await db.order.find_unique(where={"reference": ref})
    return {"status": order.status if order else "unknown"}
```

Off-session charges (renewals, saved cards) live in `direct_charge.md`; when `recurring.network_txn_id_required` is true, persist the network transaction id from the first intent or the renewal is declined as an unrecognised merchant-initiated transaction (Rule 21, `ERR_MIT_NO_TLID`).

## Anti-patterns

- ❌ Sending the API key to the browser because "the client needs to talk to the provider". It does — with the client secret and the publishable key, which is what they are for.
- ❌ Fulfilling on `paymentIntent.status === 'succeeded'` in the browser. That is a string in the buyer's console; the webhook is the fact.
- ❌ Putting the client secret in the URL or a log line. Query strings leak through `Referer`, proxies and analytics (Rule 6).
- ❌ Hardcoding `payment_method_types: ['card']` "for now". The buyer in Mexico loses OXXO and the buyer in Brazil loses Pix — both listed in `supports.cash_voucher` / `supports.qr` — and you also opt out of the automatic 3DS path.
- ❌ Treating `requires_action` as a failure and retrying the charge. It is the issuer asking for SCA; retrying just burns another authorisation.
- ❌ Letting the client "update the total" before confirming. The intent's amount was fixed server-side at creation; change it server-side or create a new intent (`ERR_CLIENT_AMOUNT`).
- ❌ Reusing one intent across buyers or carts. A client secret is scoped to a single payment for a reason.
- ❌ Calling `/api/checkout/intent` from the render body, or `loadStripe()` inline in JSX. The first mints an intent per render; the second remounts `<Elements>` and discards the card fields mid-payment.

## Security rules cited

- Rule 1: the API key stays in `process.env.<from credentials[kind=api_key].env_var>`; only the `scope: "client"` key from `credentials[kind=publishable_key]` reaches the browser, and the status secret is guarded at module load.
- Rule 3: the status endpoint reports the row the signature-verified webhook wrote; it never promotes anything itself.
- Rule 4: `crypto.randomUUID()` / `uuid.uuid4()`, persisted, so a retry cannot open a second intent — and the component creates the intent once, in an effect, not per render.
- Rule 6: the client secret and the provider's error body never reach a log; failures log status and reference.
- Rule 10: 256 KB cap before the body is read.
- Rule 11: only the order reference goes into intent metadata.
- Rule 12: the PAN is entered inside the provider's frames and confirmed directly against the provider — it never touches your server (`pci.scope: SAQ_A`).
- Rule 13: the amount is converted once at the currency's ISO exponent and frozen at creation (`ERR_MINOR_UNITS`).
- Rule 19: the status token is compared with `timingSafeEqual` after a length check (Node) and over bytes with `compare_digest` (Python) (`ERR_TIMING_UNSAFE`).
- Rule 25: an amount in the request body is refused, never adopted (`ERR_CLIENT_AMOUNT`).
- Rule 15: the element loader is exempt from SRI per `pci.loader_exempt_from_sri`; other payment-page scripts are inventoried and pinned.
- Rule 21: off-session renewals persist the network transaction id when `recurring.network_txn_id_required` is true.
