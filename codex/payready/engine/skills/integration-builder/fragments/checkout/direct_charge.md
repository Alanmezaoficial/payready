# Direct charge (server-to-server)

**Read this before writing a line of it.** A direct charge is your server calling the provider's charge API itself, with no hosted page and no widget in between. If raw card data — PAN, CVV, expiry — passes through your process to get there, the merchant is no longer in PCI SAQ A (≈20 self-assessed questions). They are in **SAQ D**: 300+ controls, quarterly ASV scans, annual penetration testing, network segmentation, a QSA engagement. Six figures, retroactive to the first request, and it does not go away when you delete the endpoint. So this pattern is legitimate in exactly two shapes: **a non-card rail** (bank transfer, cash voucher, QR, mobile money, wallet redirect), where there is no card to protect, and **a stored token** the provider already vaulted, where the PAN stayed on their side. The mistake this fragment exists to prevent is the third shape — "we'll just accept the card ourselves and forward it" — which is not a smaller version of the same thing.

**Providers in this family:** no catalog entry declares `checkout_spec.pattern: "direct_charge"` yet — this fragment ships ahead of Wave 1. It is reached today through `required_methods`: non-card rails on `mercadopago` (`pix`, `boleto`, `oxxo`, `spei`, `pse`, `efecty`, `pagoefectivo`) and `stripe` (`oxxo`, `boleto`, `pix`, `sepa_debit`, `ach_debit`), and stored tokens on any entry with `supports.save_card: true` (`stripe`, `mercadopago`, `wompi`, `lemonsqueezy`).

**Catalog fields this fragment reads:** the provider's `methods[]` id list, and for each id `methods.json → methods[<id>].{category,reversibility,irreversible,async_pending,expiry_seconds,pending_status_lies}`, `supports.{save_card,tokenization_owner,cash_voucher,qr}`, `checkout_spec.{amount_unit,idempotency}`, `recurring.{rails,network_txn_id_required}`, `webhook.refetch_endpoint`, `pci.pan_touches_server`, `currencies.json → currencies[].exponent`.

## The contract

1. **No route on this server accepts card data.** Guard the charge endpoints so a later "improvement" cannot add one quietly, refuse with 400, and never log the rejected body — it may contain a live PAN (Rule 12, Rule 6).
2. If the requirement really is "collect the card ourselves", the answer is `widget_token.md` or `intent_client_secret.md`, not a smaller version of this. `pci.pan_touches_server: false` is a property of the design, not a promise in a README.
3. **Stored token:** never charge a token id that arrived in the request. Look the token up scoped to the authenticated customer — an unscoped `where: { id: tokenId }` lets one account charge another's card (Rule 12 keeps you out of PCI scope; this keeps you out of the news).
4. When the charge is off-session and `recurring.network_txn_id_required` is true, persist the network transaction id from the first authorisation; without it later merchant-initiated charges are declined as unrecognised (Rule 21, `ERR_MIT_NO_TLID`).
5. **Non-card rail:** the successful response is a voucher, a QR or a redirect — never a settled payment. If `methods[<id>].async_pending` is true, write `status: "pending"` and an `expires_at` computed from `expiry_seconds`, and let the webhook settle it.
6. `methods[<id>].pending_status_lies: true` means the rail reports an authorised-shaped status while the voucher is still unpaid. Fulfilling on that ships free goods.
7. Amount server-side — a body carrying one is refused 400 (Rule 25, `ERR_CLIENT_AMOUNT`) — converted at the currency's ISO exponent (Rule 13); idempotency key minted once and persisted, reused on retry (Rule 4).
8. Refunds follow `methods[<id>].reversibility`. On `irreversible_no_refund` (`pix`, `pse`, `spei`, `nequi`) there is no refund operation to call — a "refund" is an outbound payout, and `fragments/money/irreversible_refund.md` owns it. On `mandate_indemnity` (`sepa_debit`, `ach_debit`) a settled charge can still be clawed back weeks later.
9. Charge, persist, respond. The receipt email goes to a queue (Rule 18).

## Node / TypeScript

```ts
// lib/payments/no-card-data.ts — the wall this fragment is built around
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

/** Rule 12: throws if anything card-shaped reached this process. Callers must not log the body. */
export function assertNoCardData(value: unknown, seen = new Set<unknown>()): void {
  if (value === null || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (CARD_FIELDS.test(k)) throw new Error('card data field');
    if (typeof v === 'string') {
      const t = v.trim();
      if (PAN_SHAPE.test(t) && luhn(t.replace(/[ -]/g, ''))) throw new Error('PAN-shaped value');
    }
    if (v && typeof v === 'object') assertNoCardData(v, seen);
  }
}
```

```ts
// app/api/charge/route.ts — stored token, and non-card rails. No card ever enters here.
import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { db } from '@/lib/db';
import { getSession } from '@/lib/auth';
import { enqueue } from '@/lib/queue';
import { assertNoCardData } from '@/lib/payments/no-card-data';
import { toMinorUnits, fromMinorUnits, amountForProvider } from '@/lib/payments/money';

export const runtime = 'nodejs';

const AMOUNT_UNIT = 'minor' as const;   // <from checkout_spec.amount_unit>
const ASYNC_PENDING = true;             // <from methods[<id>].async_pending>
const EXPIRY_SECONDS = 259_200;         // <from methods[<id>].expiry_seconds> (OXXO: 3 days)
const PENDING_STATUS_LIES = false;      // <from methods[<id>].pending_status_lies>

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
    assertNoCardData(body); // Rule 12: the SAQ A boundary, enforced in code
  } catch {
    // Rule 6: fixed string only — the rejected body may hold a live card number
    console.error('[charge] rejected a request carrying card-shaped data');
    return NextResponse.json({ error: 'card_data_not_accepted' }, { status: 400 });
  }
  // Rule 25: the client picks a saved card and a product, never a price (ERR_CLIENT_AMOUNT)
  if (['amount', 'price', 'total', 'currency'].some((f) => f in body)) {
    return NextResponse.json({ error: 'amount_is_server_side' }, { status: 400 });
  }

  const session = await getSession(request);
  if (!session) return new NextResponse(null, { status: 401 });

  const product = await db.product.findUnique({ where: { id: String(body.productId) } });
  if (!product) return NextResponse.json({ error: 'product_not_found' }, { status: 404 });

  const totalMinor = toMinorUnits(product.price, product.currency); // Rule 13
  const total = fromMinorUnits(totalMinor, product.currency);
  const reference = `ord_${randomUUID()}`;

  // Rule 4: minted once, persisted, reused by any retry of this same attempt
  const seen = await db.idempotencyKey.findUnique({
    where: { scope_ref: { scope: 'charge.create', ref: reference } } });
  const idempotencyKey = seen?.key ?? randomUUID();
  if (!seen) await db.idempotencyKey.create({
    data: { scope: 'charge.create', ref: reference, key: idempotencyKey } });

  let payload: Record<string, unknown>;
  if (body.paymentMethodId) {
    // (a) STORED TOKEN — scoped to this customer. An unscoped lookup by id is an IDOR that
    // charges someone else's card. The PAN lives at the provider (supports.tokenization_owner);
    // we hold the token plus last4/brand/exp and nothing else.
    const method = await db.paymentMethod.findFirst({
      where: { id: String(body.paymentMethodId), customerId: session.customerId },
    });
    if (!method) return new NextResponse(null, { status: 404 });
    payload = { payment_method: method.providerToken, customer: session.providerCustomerId,
      off_session: true, confirm: true,
      // Rule 21: <from recurring.network_txn_id_required> — replay the first authorisation's
      // network transaction id or the issuer declines this as an unrecognised MIT
      network_transaction_id: method.networkTransactionId ?? undefined };
  } else {
    // (b) NON-CARD RAIL — nothing to protect, and nothing settles synchronously
    payload = { payment_method_id: String(body.method), // 'oxxo' | 'pix' | 'pse' | 'spei' …
                payer: { email: session.email } };      // Rule 11: the minimum the rail needs
  }

  const res = await fetch('<from checkout_spec.create_endpoint>', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.PROVIDER_SECRET_KEY!}`, // Rule 1
               'content-type': 'application/json',
               'X-Idempotency-Key': idempotencyKey },   // <from checkout_spec.idempotency.name>
    body: JSON.stringify({ ...payload, amount: amountForProvider(total, product.currency, AMOUNT_UNIT),
                           currency: product.currency, external_reference: reference }),
  });
  if (!res.ok) {
    console.error('[charge] failed', { status: res.status, reference }); // Rule 6
    // Leave the order absent rather than `failed`: the charge may exist. Reconcile from the webhook.
    return NextResponse.json({ error: 'charge_failed' }, { status: 502 });
  }
  const charge = await res.json();

  // A 200 here is "the provider accepted the instruction", not "the money arrived".
  const settled = !ASYNC_PENDING && !PENDING_STATUS_LIES && charge.status === 'approved';
  await db.order.create({ data: {
    reference, productId: product.id, currency: product.currency, amountMinor: totalMinor,
    providerPaymentId: String(charge.id), status: settled ? 'paid' : 'pending',
    // <from methods[<id>].expiry_seconds>: an async rail without a deadline never gets cleaned up
    expiresAt: ASYNC_PENDING ? new Date(Date.now() + EXPIRY_SECONDS * 1000) : null,
  } });

  if (settled) await enqueue('order.fulfilled', { reference }); // Rule 18: never inline
  return NextResponse.json({
    reference,
    status: settled ? 'paid' : 'pending',
    voucherUrl: charge.point_of_interaction?.transaction_data?.ticket_url ?? null,
    qr: charge.point_of_interaction?.transaction_data?.qr_code ?? null,
  });
}
```

The scheduled renewal path is the same charge with no browser attached, so the trigger itself has to be authenticated:

```ts
// app/api/internal/renewals/route.ts
import { NextResponse } from 'next/server';
import { timingSafeEqual } from 'node:crypto';

export const runtime = 'nodejs';

// Rule 1: fail at module load. A missing cron secret must not become an endpoint that
// compares against '' — and it must not become a route that throws on every call either.
const CRON_SECRET = process.env.RENEWAL_CRON_SECRET;
if (!CRON_SECRET) throw new Error('RENEWAL_CRON_SECRET is not set. See .env.example.');

export async function POST(request: Request) {
  const a = Buffer.from(CRON_SECRET, 'utf8');
  const b = Buffer.from((request.headers.get('authorization') ?? '').replace(/^Bearer /, ''), 'utf8');
  // Rule 19: length first — timingSafeEqual throws on a mismatch — then constant-time
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return new NextResponse(null, { status: 400 }); // no detail leaked to the caller
  }
  // …then the stored-token branch above, per due subscription, out of band.
  return NextResponse.json({ accepted: true });
}
```

## Python

```python
# routers/charge.py  (FastAPI)
import hmac, os, re, uuid
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request

from lib.auth import require_session          # raises 401; never a default of None
from lib.payments.money import to_minor_units, from_minor_units, amount_for_provider
from lib.db import db
from lib.queue import enqueue

router = APIRouter()
AMOUNT_UNIT = "minor"        # <from checkout_spec.amount_unit>
ASYNC_PENDING = True         # <from methods.json → methods[<id>].async_pending>
EXPIRY_SECONDS = 259_200     # <from methods.json → methods[<id>].expiry_seconds>
PENDING_STATUS_LIES = False  # <from methods.json → methods[<id>].pending_status_lies>

# Rule 1: absent raises KeyError at import, where it is loud.
CRON_SECRET = os.environ["RENEWAL_CRON_SECRET"].encode()

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
    """Rule 12: raises if anything card-shaped reached this process."""
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


@router.post("/api/charge")
async def charge(request: Request, session=Depends(require_session)):
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
        print("[charge] rejected a request carrying card-shaped data")  # Rule 6: never the body
        raise HTTPException(status_code=400, detail="card_data_not_accepted")
    if {"amount", "price", "total", "currency"} & set(body):  # Rule 25: ERR_CLIENT_AMOUNT
        raise HTTPException(status_code=400, detail="amount_is_server_side")

    # .get(), not [] — a missing key must be a 404, not a KeyError the framework renders as 500
    product = await db.product.find_unique(where={"id": body.get("productId")})
    if product is None:
        raise HTTPException(status_code=404, detail="product_not_found")

    total_minor = to_minor_units(product.price, product.currency)  # Rule 13
    total = from_minor_units(total_minor, product.currency)
    reference = f"ord_{uuid.uuid4()}"

    # Rule 4: minted once, persisted before the call, reused by any retry of this same attempt
    seen = await db.idempotencykey.find_unique(
        where={"scope_ref": {"scope": "charge.create", "ref": reference}})
    idempotency_key = seen.key if seen else str(uuid.uuid4())
    if seen is None:
        await db.idempotencykey.create(
            data={"scope": "charge.create", "ref": reference, "key": idempotency_key})

    if body.get("paymentMethodId"):
        # Stored token, scoped to the authenticated customer — never by id alone (IDOR)
        method = await db.paymentmethod.find_first(
            where={"id": body["paymentMethodId"], "customerId": session.customer_id})
        if method is None:
            raise HTTPException(status_code=404)
        payload = {"payment_method": method.provider_token, "off_session": True, "confirm": True,
                   "network_transaction_id": method.network_transaction_id}  # Rule 21
    else:
        payload = {"payment_method_id": body.get("method"),
                   "payer": {"email": session.email}}  # Rule 11

    payload |= {"amount": amount_for_provider(total, product.currency, AMOUNT_UNIT),
                "currency": product.currency, "external_reference": reference}

    async with httpx.AsyncClient(timeout=15) as client:
        res = await client.post(
            "<from checkout_spec.create_endpoint>",
            headers={"Authorization": f"Bearer {os.environ['PROVIDER_SECRET_KEY']}",  # Rule 1
                     "X-Idempotency-Key": idempotency_key},  # <from checkout_spec.idempotency.name>
            json=payload)
    if res.status_code >= 400:
        # Rule 6: status and reference only. Leave the order absent rather than `failed` —
        # the charge may exist, and the webhook is what reconciles it.
        print("[charge] failed", {"status": res.status_code, "reference": reference})
        raise HTTPException(status_code=502, detail="charge_failed")
    charge = res.json()

    # A 200 here is "the provider accepted the instruction", not "the money arrived".
    settled = (not ASYNC_PENDING and not PENDING_STATUS_LIES
               and charge.get("status") == "approved")
    await db.order.create(data={
        "reference": reference, "productId": product.id, "currency": product.currency,
        "amountMinor": total_minor, "providerPaymentId": str(charge["id"]),
        "status": "paid" if settled else "pending",
        # an async rail with no deadline leaves stock reserved on a voucher nobody will pay
        "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=EXPIRY_SECONDS)
                      if ASYNC_PENDING else None)})
    if settled:
        await enqueue("order.fulfilled", {"reference": reference})  # Rule 18: never inline
    return {"reference": reference, "status": "paid" if settled else "pending"}


@router.post("/api/internal/renewals")
async def renewals(authorization: str = Header(default="")):
    presented = authorization.removeprefix("Bearer ").encode()
    # Rule 19: compare BYTES — compare_digest raises TypeError on a non-ASCII str, so a header
    # with one high byte would be a 500 instead of a rejection.
    if not hmac.compare_digest(CRON_SECRET, presented):
        raise HTTPException(status_code=400)
    return {"accepted": True}
```

## Anti-patterns

- ❌ `POST /api/charge` taking `{ card_number, cvv, exp_month }` and forwarding it to the provider "because the SDK accepts it". SAQ A → SAQ D on the first request, retroactively, whether or not you store it.
- ❌ Storing a PAN "encrypted, for retries" or a CVV "until settlement". Storing a CVV after authorisation is prohibited outright; encryption does not make it allowed (Rule 12).
- ❌ Logging the request body of a rejected card-shaped request "to debug the client". That writes a live PAN into your log retention (Rule 6).
- ❌ `db.paymentMethod.findUnique({ where: { id: body.paymentMethodId } })`. Scope the lookup to the session's customer or you have built a way to charge other people's cards.
- ❌ Marking a voucher, transfer or Pix order `paid` on the 201. `async_pending: true` means the buyer has not paid yet; `pending_status_lies: true` means the status field will actively tell you otherwise.
- ❌ Creating an async order with no `expires_at`. Stock stays reserved on a voucher nobody will ever pay, and nothing sweeps it.
- ❌ Retrying a timed-out charge with a fresh idempotency key. The first one may have succeeded; the new key authorises a second charge.
- ❌ Emitting a refund endpoint for an `irreversible_no_refund` rail. There is no such API call — the refund is an outbound payout, and pretending otherwise ships a 404 to your support team.

## Security rules cited

- Rule 1: `PROVIDER_SECRET_KEY` and `RENEWAL_CRON_SECRET` come from the environment; nothing is inlined.
- Rule 3: nothing here promotes an order on its own word — an `async_pending` rail stays `pending` until the signature-verified webhook says otherwise.
- Rule 4: `crypto.randomUUID()` / `uuid.uuid4()`, persisted per `(scope, reference)` so a retry replays the same charge instead of creating a second one.
- Rule 6: rejected card-shaped requests and provider failures log a fixed string plus status and reference — never the body.
- Rule 10: 256 KB cap before the body is read.
- Rule 11: only the email the rail actually requires is sent; no demographic padding.
- Rule 12: this fragment's core. No endpoint accepts a PAN, the guard enforces it in code, stored cards are provider tokens plus `last4`/`brand`/`exp`, and `pci.pan_touches_server` stays false.
- Rule 13: amount from the database, converted at the currency's ISO exponent (`ERR_MINOR_UNITS`).
- Rule 19: the internal renewal trigger authenticates with a constant-time comparison — length-checked before `timingSafeEqual` in Node, over bytes with `compare_digest` in Python — and answers 400 with no detail (`ERR_TIMING_UNSAFE`).
- Rule 25: an `amount`, `price` or `currency` in the request body is refused (`ERR_CLIENT_AMOUNT`).
- Rule 18: fulfilment is enqueued after the row is written, never sent inline.
- Rule 21: the network transaction id is persisted and replayed on off-session charges when `recurring.network_txn_id_required` is true (`ERR_MIT_NO_TLID`).
