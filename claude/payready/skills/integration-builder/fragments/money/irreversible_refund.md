# Irreversible rails — when "refund the charge" is not an API operation

On Pix, SPEI, Bre-B, PayShap, UPI, RTP, FedNow and stablecoins the money moved from the payer's account to yours and the rail considers that final. There is no reversal primitive, no dispute window, no `POST /refunds`. A generated refund endpoint on these rails is **fiction**: it compiles, it looks like every other refund endpoint, and it 404s or silently no-ops the first time a customer asks for their money back. What you actually owe the customer is a **payout** — a fresh outbound transfer that happens to be for the same amount. Different endpoint, different credential scope, different fee, funds must already be in your balance, and — because you are now choosing an arbitrary destination — a real fraud surface: pay to the wrong account and you have laundered money for someone.

**Providers in this family:** every provider whose `methods[]` includes an `irreversible_no_refund` method — 31 of the catalog's 42. Among the four you can generate against today: `mercadopago` (pix, spei, pse) and `wompi` (pse, nequi, bancolombia_button, bancolombia_transfer). Their cash-voucher rails are *not* in this family: `efecty`, `baloto`, `su_red`, `boleto`, `oxxo` and `mercadopago_wallet` are `refund_only`, and a voucher that looks like "cash, therefore final" still has a refund endpoint. `stripe` mixes rails: card is `chargeback`, pix, bizum and usdc are `irreversible_no_refund`, sepa_debit and ach_debit are `mandate_indemnity`. **The branch is per payment, not per provider.**

The validator that enforces this is `hooks/checks/no-refund-on-irreversible.js` (Rule 17); it reads reversibility from the catalog, so a rail added to `methods.json` is covered without a code change.

**Catalog fields this fragment reads:** `methods[].reversibility` (`chargeback` | `refund_only` | `irreversible_no_refund` | `mandate_indemnity`), `methods[].reversal_window_days`, `methods[].category`, provider `supports.marketplace_payouts`, `settlement.holds_funds`, `checkout_spec.idempotency`.

## The contract

1. Branch on the **method that actually paid**, read from the payment row. Not the order, not the provider default — a customer who paid by Pix and a customer who paid by card need two different endpoints from the same button.
2. `chargeback` (16 of the catalog's 136 methods, incl. card, paypal, klarna, apple_pay) and `refund_only` (53, incl. boleto, oxxo, konbini, efecty, mercadopago_wallet) → the provider's real refund call, with an idempotency key and an authorisation check.
3. `irreversible_no_refund` (59 methods) → **payout**, not refund. Verify the destination belongs to the original payer before sending. If the provider entry declares no payout capability, generate **no endpoint at all** — emit a manual-process TODO in `PAGOKIT_INTEGRATION.md`. A fabricated payout call is worse than an honest gap.
4. `mandate_indemnity` (7: sepa_debit, ach_debit, bacs_debit, pix_automatico, upi_autopay, payto, pac_chile) → a real refund, plus the warning that the payer can *also* claw the original charge back independently within `reversal_window_days` (SEPA 56, ACH 60, Bacs 395; the catalog leaves it null for pix_automatico, upi_autopay, payto and pac_chile, which means unknown, not zero). Refunding inside that window risks paying twice.
5. Cap every refund at `captured_minor − sum(prior refunds)`, in minor units (`fragments/money/minor_units.md`). The payout path has no server-side cap — the provider will happily send more than you collected.
6. Write the attempt row **before** the outbound call, and key the idempotency value to the *attempt*, not to the request. One `randomUUID()` per HTTP call is not idempotency: the operator's second click is a brand-new key, and on the payout path a brand-new key is a second transfer. Get-or-create the row on `(payment_id, request_id)` and reuse its key on every retry.
7. Amounts on this path are already minor-unit integers. They leave through `minorForProvider`; `amountForProvider(String(minor), …)` re-scales them and pays out 100× (`fragments/money/minor_units.md`).
8. Payouts settle asynchronously. Do not mark the order refunded on the API's 200 — wait for the payout webhook, verify it, and update then.

## Binding the payout to the original payer

The fraud is simple: pay you 500 BRL from account A, ask for a refund to account B. The check is equally simple, and it has to happen at **capture** time, not refund time — capture the payer identifier the rail gives you (Pix key / CPF, SPEI CLABE, UPI VPA), store a peppered HMAC of it rather than the raw value (Rule 11: it is regulated PII), and compare digests when the refund is requested.

```ts
// lib/payments/payer-binding.ts
import { createHmac, timingSafeEqual } from 'node:crypto';

/** Same account, different formatting: "123.456.789-09" and " 12345678909 " must match. */
function normaliseKey(raw: string): string {
  return String(raw).trim().toLowerCase().replace(/[\s.\-()+]/g, '');
}

/** Rule 11: store the digest, never the CPF/CLABE/VPA. The pepper makes it un-enumerable. */
export function payerRefDigest(rawIdentifier: string): string {
  const pepper = process.env.REFUND_BINDING_PEPPER;          // Rule 1: env, never inline
  if (!pepper) throw new Error('REFUND_BINDING_PEPPER is not set. See .env.example.');
  return createHmac('sha256', pepper).update(normaliseKey(rawIdentifier), 'utf8').digest('hex');
}

export function sameParty(storedDigest: string | null, requestedDigest: string): boolean {
  const a = Buffer.from(String(storedDigest ?? ''), 'utf8');
  const b = Buffer.from(String(requestedDigest ?? ''), 'utf8');
  // Rule 19: length first — timingSafeEqual throws RangeError on a length mismatch.
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);                               // Rule 19: constant time
}
```

Verified by running it (`REFUND_BINDING_PEPPER=test_pepper`): the same CPF written `123.456.789-09` and ` 12345678909 ` produces one 64-char digest and `sameParty` returns `true`; a different CPF returns `false`; a null stored digest returns `false`; a truncated digest returns `false` **without throwing**, which is exactly what the length guard is for — `timingSafeEqual(Buffer.from('abc'), Buffer.from('ab'))` raises `RangeError: Input buffers must have the same byte length`.

## Node / TypeScript — the branching refund endpoint

```ts
// app/api/refund/route.ts
import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { db } from '@/lib/db';
import { auth } from '@/lib/auth';
import { toMinorUnits, minorForProvider } from '@/lib/payments/money';
import { payerRefDigest, sameParty } from '@/lib/payments/payer-binding';

export const runtime = 'nodejs';

// <from methods[].reversibility> — the full 136-method map is generated from methods.json;
// emit every method in the provider's methods[], not just the ones shown here. A method whose
// entry has no `reversibility` at all (today: cuotealo) lands in the refusal below, by design.
type Reversibility = 'chargeback' | 'refund_only' | 'irreversible_no_refund' | 'mandate_indemnity';
const REVERSIBILITY: Record<string, Reversibility> = {
  card: 'chargeback', paypal: 'chargeback', klarna: 'chargeback', apple_pay: 'chargeback',
  boleto: 'refund_only', oxxo: 'refund_only', mercadopago_wallet: 'refund_only',
  pix: 'irreversible_no_refund', spei: 'irreversible_no_refund', pse: 'irreversible_no_refund',
  nequi: 'irreversible_no_refund', upi: 'irreversible_no_refund', usdc: 'irreversible_no_refund',
  sepa_debit: 'mandate_indemnity', ach_debit: 'mandate_indemnity', bacs_debit: 'mandate_indemnity',
  pix_automatico: 'mandate_indemnity', upi_autopay: 'mandate_indemnity', payto: 'mandate_indemnity',
  pac_chile: 'mandate_indemnity',
};
// <from methods[].reversal_window_days>. The catalog leaves it null for several mandate rails,
// so read it as "unknown", never as zero — the warning below has to survive a missing number.
const REVERSAL_WINDOW_DAYS: Record<string, number | undefined> = {
  sepa_debit: 56, ach_debit: 60, bacs_debit: 395,
};

// Neither endpoint is a catalog field — the provider schema has no refund_spec or payout_spec.
// Take both from the provider's API reference (`docs_url` in its catalog entry). If the provider
// has no payout API, delete the payout branch and emit the manual-process note instead.
const REFUND_ENDPOINT = '<the refund endpoint from the provider API reference; {id} = provider payment id>';
const PAYOUT_ENDPOINT = '<the payout endpoint from the provider API reference>';

export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user?.canRefund) return new NextResponse(null, { status: 403 }); // refunds are staff-only

  // A malformed body is a 400. Left unhandled it is a rejected promise, a 500, and an operator
  // clicking "refund" again on a button that never worked.
  let input: any;
  try {
    input = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400 });
  }
  const { paymentId, requestId, amount, destination } = input ?? {};
  if (typeof paymentId !== 'string' || typeof requestId !== 'string' || !requestId) {
    return NextResponse.json({ error: 'payment_id_and_request_id_required' }, { status: 400 });
  }

  const payment = await db.pagokitPayment.findUnique({ where: { id: paymentId } });
  if (!payment) return NextResponse.json({ error: 'payment_not_found' }, { status: 404 });

  const reversibility = REVERSIBILITY[payment.method];
  if (!reversibility) {
    // Unknown or unclassified method: refuse. Guessing 'chargeback' generates a call the rail
    // does not have; guessing 'irreversible' opens a payout endpoint for a rail that refunds.
    return NextResponse.json({ error: 'unsupported_method' }, { status: 422 });
  }

  // Rule 13: integers in the currency's minor unit; never re-scale a float here. A bad amount is
  // a 422 — toMinorUnits throwing into the handler is a 500 that tells the operator nothing.
  const remaining = BigInt(payment.amount_minor) - BigInt(payment.refunded_minor ?? 0);
  let requested: bigint;
  try {
    requested = amount === undefined || amount === null
      ? remaining
      : toMinorUnits(String(amount), payment.currency);
  } catch {
    return NextResponse.json({ error: 'invalid_amount' }, { status: 422 });
  }
  if (requested <= 0n || requested > remaining) {
    return NextResponse.json({ error: 'amount_exceeds_captured' }, { status: 422 });
  }

  // Rule 4: ONE key per refund attempt, reused by every retry of that attempt. A fresh
  // randomUUID() per request is not idempotency — on the payout path it is a second transfer
  // with a key the provider has never seen. `requestId` is minted by the staff UI, per click.
  const scope = `refund:${payment.id}:${requestId}`;
  const attempt = await db.pagokitRefundAttempt.upsert({
    where: { scope },
    create: {
      scope, idempotency_key: randomUUID(), payment_id: payment.id,
      amount_minor: requested.toString(), state: 'pending',
    },
    update: {},                        // the retry reuses the row, and therefore the key
  });
  if (attempt.amount_minor !== requested.toString()) {
    return NextResponse.json({ error: 'request_id_reused_with_different_amount' }, { status: 409 });
  }
  if (attempt.state === 'sent') {      // already done: replay the answer, do not send money twice
    return NextResponse.json({
      status: attempt.mechanism === 'payout' ? 'refund_pending' : 'refund_sent',
      mechanism: attempt.mechanism, provider_ref: attempt.provider_ref,
    });
  }
  const idempotencyKey = attempt.idempotency_key;
  // <from checkout_spec.idempotency.name>; drop the header when idempotency.supported is false.
  const IDEMPOTENCY_HEADER = 'X-Idempotency-Key';

  if (reversibility === 'irreversible_no_refund') {
    // ---- PAYOUT PATH -------------------------------------------------------
    // There is no refund on this rail. This is a new outbound transfer, and it needs a destination.
    if (!destination?.key || typeof destination.key !== 'string') {
      return NextResponse.json({ error: 'destination_required' }, { status: 422 });
    }

    // The fraud check: the destination must be the account that paid.
    if (!sameParty(payment.payer_ref_digest, payerRefDigest(destination.key))) {
      console.warn('[refund] destination does not match payer', { payment_id: payment.id }); // Rule 6: ids only
      return NextResponse.json({ error: 'destination_mismatch_manual_review' }, { status: 422 });
    }

    let payout: any;
    try {
      const res = await fetch(PAYOUT_ENDPOINT, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.PROVIDER_PAYOUT_KEY!}`,  // Rule 1: distinct, payout-scoped credential
          [IDEMPOTENCY_HEADER]: idempotencyKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          // Rule 13: `requested` is ALREADY minor units. Passing it through amountForProvider
          // would scale it a second time — a 100x payout on a two-decimal currency.
          amount: minorForProvider(requested, payment.currency, '<from checkout_spec.amount_unit>'),
          currency: payment.currency,
          destination_key: destination.key,
          reference: `refund:${payment.id}`,
        }),
      });
      if (!res.ok) throw new Error(`payout_http_${res.status}`);
      payout = await res.json();
    } catch {
      // The row stays, so the same requestId retries onto the same idempotency key.
      await db.pagokitRefundAttempt.update({ where: { scope }, data: { state: 'failed' } });
      return NextResponse.json({ error: 'payout_failed' }, { status: 502 }); // no provider detail leaked
    }
    await db.pagokitRefundAttempt.update({
      where: { scope }, data: { state: 'sent', mechanism: 'payout', provider_ref: payout.id },
    });
    // A payout settles asynchronously. The order stays 'refund_pending' until the payout webhook lands.
    return NextResponse.json({ status: 'refund_pending', payout_id: payout.id, mechanism: 'payout' });
  }

  // ---- REFUND PATH (chargeback | refund_only | mandate_indemnity) ----------
  let refund: any;
  try {
    const res = await fetch(REFUND_ENDPOINT.replace('{id}', encodeURIComponent(payment.provider_payment_id)), {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.PROVIDER_SECRET_KEY!}`,
        [IDEMPOTENCY_HEADER]: idempotencyKey,
        'Content-Type': 'application/json',
      },
      // Rule 13: already minor units — minorForProvider, not amountForProvider.
      body: JSON.stringify({ amount: minorForProvider(requested, payment.currency, '<from checkout_spec.amount_unit>') }),
    });
    if (!res.ok) throw new Error(`refund_http_${res.status}`);
    refund = await res.json();
  } catch {
    await db.pagokitRefundAttempt.update({ where: { scope }, data: { state: 'failed' } });
    return NextResponse.json({ error: 'refund_failed' }, { status: 502 });
  }
  await db.pagokitRefundAttempt.update({
    where: { scope }, data: { state: 'sent', mechanism: 'refund', provider_ref: refund.id },
  });

  const windowDays = REVERSAL_WINDOW_DAYS[payment.method];
  return NextResponse.json({
    status: 'refund_sent', refund_id: refund.id, mechanism: 'refund',
    // The payer can ALSO claim the original charge back through their own bank inside this window.
    warning: reversibility !== 'mandate_indemnity' ? undefined
      : windowDays
        ? `payer may independently reverse the original debit for ${windowDays} days — refunding now risks a double outflow`
        : 'payer may independently reverse the original debit — confirm the scheme window before refunding',
  });
}
```

## Python — FastAPI

```python
# routers/refund.py
import hashlib, hmac, os, re, uuid
from fastapi import APIRouter, Depends, HTTPException
from lib.payments.money import to_minor_units, minor_for_provider

router = APIRouter()

REVERSIBILITY = {  # <from methods[].reversibility>
    "card": "chargeback", "boleto": "refund_only", "oxxo": "refund_only",
    "pix": "irreversible_no_refund", "spei": "irreversible_no_refund", "upi": "irreversible_no_refund",
    "sepa_debit": "mandate_indemnity", "ach_debit": "mandate_indemnity", "bacs_debit": "mandate_indemnity",
}
REVERSAL_WINDOW_DAYS = {"sepa_debit": 56, "ach_debit": 60, "bacs_debit": 395}  # null in the catalog = unknown

_STRIP_RE = re.compile(r"[\s.\-()+]")  # same character class as the TS normaliseKey, so the
                                       # two languages produce the SAME digest for one identifier

def _normalise(raw: str) -> str:
    return _STRIP_RE.sub("", str(raw).strip().lower())

def payer_ref_digest(raw_identifier: str) -> str:
    pepper = os.environ["REFUND_BINDING_PEPPER"]      # Rule 1: env, never inline
    return hmac.new(pepper.encode(), _normalise(raw_identifier).encode(), hashlib.sha256).hexdigest()

def same_party(stored: str | None, requested: str) -> bool:
    if not stored or len(stored) != len(requested):   # length first, then constant time
        return False
    return hmac.compare_digest(stored, requested)     # Rule 19

@router.post("/api/refund")
async def refund(body: dict, user=Depends(staff_only)):          # refunds are staff-only
    payment_id, request_id = body.get("payment_id"), body.get("request_id")
    if not isinstance(payment_id, str) or not isinstance(request_id, str) or not request_id:
        raise HTTPException(400, "payment_id_and_request_id_required")   # not a 500 on KeyError
    payment = await db.get_payment(payment_id)
    if payment is None:
        raise HTTPException(404, "payment_not_found")
    reversibility = REVERSIBILITY.get(payment.method)
    if reversibility is None:
        raise HTTPException(422, "unsupported_method")            # refuse rather than guess the rail

    remaining = payment.amount_minor - payment.refunded_minor
    try:
        requested = remaining if body.get("amount") is None else to_minor_units(str(body["amount"]), payment.currency)
    except ValueError:                                            # MoneyError -> 422, never a 500
        raise HTTPException(422, "invalid_amount")
    if requested <= 0 or requested > remaining:                                # Rule 13
        raise HTTPException(422, "amount_exceeds_captured")

    # Rule 4: one key per ATTEMPT. get_or_create on (payment_id, request_id) so the operator's
    # second click reuses the key instead of originating a second payout.
    attempt = await db.get_or_create_refund_attempt(payment.id, request_id, requested, key=str(uuid.uuid4()))
    if attempt.amount_minor != requested:
        raise HTTPException(409, "request_id_reused_with_different_amount")
    if attempt.state == "sent":
        return {"status": "refund_pending" if attempt.mechanism == "payout" else "refund_sent",
                "mechanism": attempt.mechanism, "provider_ref": attempt.provider_ref}
    # `requested` is ALREADY minor units: minor_for_provider, never amount_for_provider.
    amount = minor_for_provider(requested, payment.currency, "<from checkout_spec.amount_unit>")

    if reversibility == "irreversible_no_refund":
        dest = (body.get("destination") or {}).get("key")
        if not isinstance(dest, str) or not dest:
            raise HTTPException(422, "destination_required")
        if not same_party(payment.payer_ref_digest, payer_ref_digest(dest)):
            log.warning("refund destination mismatch", extra={"payment_id": payment.id})  # Rule 6
            raise HTTPException(422, "destination_mismatch_manual_review")
        payout = await provider.create_payout(amount=amount, currency=payment.currency,
                                              destination_key=dest, idempotency_key=attempt.key)
        await db.mark_refund_attempt(attempt, state="sent", mechanism="payout", provider_ref=payout["id"])
        return {"status": "refund_pending", "payout_id": payout["id"], "mechanism": "payout"}

    obj = await provider.create_refund(payment.provider_payment_id, amount, idempotency_key=attempt.key)
    await db.mark_refund_attempt(attempt, state="sent", mechanism="refund", provider_ref=obj["id"])
    days = REVERSAL_WINDOW_DAYS.get(payment.method)
    warning = None
    if reversibility == "mandate_indemnity":
        warning = (f"payer may independently reverse the original debit for {days} days"
                   if days else "payer may independently reverse the original debit — confirm the scheme window")
    return {"status": "refund_sent", "refund_id": obj["id"], "mechanism": "refund", "warning": warning}
```

## Anti-patterns

- ❌ Generating `POST /api/refund` that calls the provider's refund endpoint for a Pix or SPEI payment. The rail has no such operation; the endpoint fails in production, on a customer who is already unhappy.
- ❌ Accepting a payout destination from the refund request without binding it to the payer. That is an open money-transmission endpoint behind your admin login.
- ❌ Storing the raw CPF / CLABE / VPA to compare later. Store the peppered digest (Rule 11) — you only ever need equality.
- ❌ `storedDigest === requestedDigest` with `==`/`===`. Rule 19: use `timingSafeEqual` / `hmac.compare_digest`, after a length check, because `timingSafeEqual` throws `RangeError` on mismatched lengths.
- ❌ A fresh `randomUUID()` on every call to the refund route. The idempotency key must belong to the attempt, not to the HTTP request — otherwise the operator's impatient second click is a second payout with a key the provider has never seen.
- ❌ Passing a minor-unit integer back through `amountForProvider` / `amount_for_provider`. `String(50000n)` is indistinguishable from a major-unit price, so it is scaled twice and you refund 100× — the one bug in this repo that moves money in the wrong direction at scale.
- ❌ Letting a malformed body or an unparseable amount reach the provider call. Those are a 400 and a 422; unhandled they are a 500, which tells the operator nothing and invites the retry that the paragraph above turns into a second payout.
- ❌ Marking the order refunded on the payout API's 200. A payout can fail hours later; the money is only gone when the payout webhook says so.
- ❌ Treating `mandate_indemnity` as settled money. SEPA is reversible for 56 days and ACH for 60 — refunding on day 3 can mean paying twice.
- ❌ Calling Pix's MED a refund API. It is a Bacen dispute process the payer initiates through their own bank; it is not something your backend calls.
- ❌ Letting the refund exceed what you captured because "the provider will validate it". On the payout path there is nothing to validate against — the provider does not know what the payment was.

## Security rules cited

- **Rule 17** (no refund on an irreversible rail): this fragment *is* the rule. `hooks/checks/no-refund-on-irreversible.js` denies a refund call in a file that also names an `irreversible_no_refund` method, reading reversibility from `methods.json` rather than from a list in the validator — and it deliberately never flags `payouts.create` / `transfers.create`, because the payout is the fix.
- **Rule 4** (idempotency): `crypto.randomUUID()` / `uuid.uuid4()` minted **once per attempt**, persisted before the outbound call and reused by every retry of that attempt. A per-request key is not idempotency, and on the payout path a retried payout is money leaving twice, not a duplicate row.
- **Rule 19** (no plaintext secret compare): the payer-binding digests are compared with `timingSafeEqual` / `hmac.compare_digest`, length-checked first.
- **Rule 13** (minor units): amounts are integers in the currency's minor unit end to end; the cap arithmetic is exact.
- **Rule 11** (minimum PII): the payer's tax id / bank key is stored as a peppered HMAC, not in the clear, because equality is all the refund path needs.
- **Rule 1** (no hardcoded keys): the payout credential is a separate, payout-scoped env var — a leaked checkout key should not be able to move money out.
- **Rule 6** (log metadata only): mismatches log `payment_id` and nothing else. Never the destination key, never the payload.
- **Rule 3 / Rule 9 / Rule 18** apply to the payout confirmation webhook: verify its signature, dedup by event id, ack fast and finish the bookkeeping out of band.
