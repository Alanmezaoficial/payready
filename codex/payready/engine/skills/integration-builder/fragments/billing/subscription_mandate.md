# Subscription — bank mandate

Recurring billing where the customer authorises you to **pull** from their bank account instead of leaving a card on file. The rails are the `methods.json` entries in the `direct_debit` category whose `reversibility` is `mandate_indemnity`: SEPA Direct Debit, Bacs, ACH Debit, UPI AutoPay, Pix Automático, PAC and PayTo. The thing developers get wrong is reaching for the card state machine, because the words look the same and nothing underneath is. There is no authorisation step: a card charge tells you in two seconds whether the money is there, and a direct debit tells you **days later, by not failing**. So the states are not `pending → paid`; they are *submitted*, then *confirmed*, then — weeks later, sometimes — *clawed back*.

Three facts drive the whole design. A debit must be **pre-notified**: SEPA and UPI require the payer to be told the amount and the date in advance, and if the notice went out late you must move the debit, not send it anyway. The payer can **revoke the mandate at their own bank** and nobody tells you — you find out because a charge comes back with a code meaning "no valid mandate", and retrying it is worse than useless. And a **"successful" charge is not final**: `methods[].reversibility` is `mandate_indemnity`, with `reversal_window_days` of 56 for SEPA, 60 for ACH and **395 for Bacs**. If you ship an irreversible good on the confirmation, you have shipped it on a promise the payer can withdraw for over a year.

**Providers in this family:** Stripe is the only entry with `recurring.mandate_lifecycle: true` (`recurring.rails` includes `sepa_debit` and `ach_debit`), and the only one at `integration_level: build`. The other rails do have catalogued providers now — GoCardless (`sepa_debit`, `bacs_debit`, `ach_debit`), Razorpay (`upi_autopay`), Asaas (`pix_automatico`), Fintoc (`pac_chile`), Airwallex (`payto`), plus Adyen, Mollie and Hyperswitch on SEPA — but every one of them is `advise` with **no `recurring` block at all**. So `mandate_lifecycle`, `pre_debit_notice_hours` and `afa_threshold` read as `undefined` there, not as `false` or `0`, and this fragment is what they promote into once someone verifies the numbers. Note also `becs_debit`: it sits in the `direct_debit` category but its `reversibility` is `refund_only`, so it does not belong to this family.

**Catalog fields this fragment reads:** `recurring.rails`, `recurring.mandate_lifecycle`, `recurring.pre_debit_notice_hours`, `recurring.afa_threshold`, `recurring.consumer_revocable`, `methods[].reversibility`, `methods[].reversal_window_days`, `methods[].settlement_speed`, `methods[].async_pending`, `webhook.required_events_minimum`, `currencies[].exponent`.

## The contract

1. **Collect the mandate.** Capture the debtor's account details through the provider's element (Rule 12 applies to IBANs and account numbers exactly as it does to PANs) and record the mandate reference the provider returns.
2. **Wait for approval.** The mandate is `pending_approval` until the bank or the scheme confirms it. On UPI AutoPay and Pix Automático the payer approves in their own banking app, which may be hours later. Do not debit against an unapproved mandate.
3. **Pre-notify.** At least `recurring.pre_debit_notice_hours` before each debit date, send the amount and the date. Record `notice_sent_at` — it is your evidence in an indemnity dispute. The SEPA rulebook default is 14 calendar days unless the mandate agrees otherwise; UPI AutoPay is 24 hours. Read the number from the catalog, do not hardcode 14.
4. **Postpone rather than debit early.** If the notice went out late, the earliest legal debit date moves. Move the debit.
5. **Additional factor authentication.** Above `recurring.afa_threshold` the payer must authenticate the individual debit (UPI AutoPay). That debit is not fire-and-forget; it needs a customer touch and can time out.
6. **Submit.** The charge enters `submitted`, not `paid`. Grant nothing yet.
7. **Confirm.** Days later the rail confirms. Set `confirmed_at`, and compute `final_at = confirmed_at + reversal_window_days`. Entitlement can start at confirmation; irreversible fulfilment waits for `final_at`.
8. **Classify returns.** A return code is either "retry this" (insufficient funds) or "this mandate is over" (revoked, account closed, payer deceased, refund claimed). Terminal codes revoke the mandate. **Never** put a terminal code into a dunning loop.
9. **Handle the indemnity claim.** It arrives after `confirmed`, sometimes months after. Reverse the entitlement, record the debt, and do not re-debit the same mandate to recover it.

Two state machines, not one:

```
mandate: created → pending_approval → active → revoked | expired | failed
charge:  scheduled → notified → submitted → confirmed → returned | indemnity_claimed
                                              └─ not final until confirmed_at + reversal_window_days
```

## Schema this implies

```prisma
model PagokitMandate {
  id                  String    @id @default(cuid())
  provider_mandate_id String    @unique     // the scheme's mandate reference (UMR on SEPA)
  status              String                // created | pending_approval | active | revoked | expired | failed
  rail                String                // <from recurring.rails[]>: sepa_debit | bacs_debit | upi_autopay | …
  debtor_last4        String?               // display only — Rule 12: never the full IBAN or account number
  approved_at         DateTime?
  revoked_at          DateTime?
  revoked_reason      String?               // usually learned from a return code, not from the payer
  @@map("pagokit_mandates")
}
model PagokitMandateCharge {
  id             String    @id @default(cuid())
  mandate_id     String
  amount         Int                        // minor units, per currencies[].exponent
  status         String                     // scheduled | notified | submitted | confirmed | returned | indemnity_claimed
  scheduled_for  DateTime
  notice_sent_at DateTime?                  // evidence in a dispute; also gates the debit date
  submitted_at   DateTime?
  confirmed_at   DateTime?
  final_at       DateTime?                  // confirmed_at + reversal_window_days. NULL = still clawable
  return_code    String?
  @@index([status, scheduled_for])
  @@map("pagokit_mandate_charges")
}
```

## Node / TypeScript

```ts
// lib/payments/mandate-schedule.ts
const PRE_DEBIT_NOTICE_HOURS = 14 * 24;   // <from recurring.pre_debit_notice_hours> — SEPA default
// <from recurring.afa_threshold> — null on a rail with no additional-factor step. Typed nullable
// on purpose: `const x = 1500000` gives it the literal type, and the null branch below then reads
// as dead code to anyone editing it for a rail that has no threshold.
const AFA_THRESHOLD_MINOR: number | null = 1500000;
// <from methods[<rail>].reversal_window_days>. Missing means UNKNOWN, not zero — never treat a
// rail with no published window as final; hold it until you have confirmed the number.
export const REVERSAL_WINDOW_DAYS: Record<string, number | null> = {
  sepa_debit: 56, ach_debit: 60, bacs_debit: 395,
  upi_autopay: null, pix_automatico: null, pac_chile: null, payto: null,
};

export const earliestDebitDate = (noticeSentAt: Date, hours = PRE_DEBIT_NOTICE_HOURS): Date =>
  new Date(noticeSentAt.getTime() + hours * 3600_000);

/** Late notice moves the debit. It never shortens the notice period. */
export function debitDateOrPostpone(scheduledFor: Date, noticeSentAt: Date): Date {
  const earliest = earliestDebitDate(noticeSentAt);
  return earliest > scheduledFor ? earliest : scheduledFor;
}

/** Confirmed is not final. Gate irreversible fulfilment on this, never on confirmed_at. */
export function isFinal(confirmedAt: Date | null, rail: string, now = new Date()): boolean {
  const days = REVERSAL_WINDOW_DAYS[rail];
  if (!confirmedAt || days == null) return false;   // unknown window ⇒ never final
  return now >= new Date(confirmedAt.getTime() + days * 86400_000);
}

export const needsAfa = (amountMinor: number): boolean =>
  AFA_THRESHOLD_MINOR !== null && amountMinor > AFA_THRESHOLD_MINOR;
```

```ts
// lib/payments/mandate-returns.ts
// ISO 20022 R-transaction codes as the canonical example. Your PSP surfaces its own list under
// its own field name — map from templates/<provider>/errors.md; do not assume these strings.
const TERMINAL = new Set([
  'MD01', // no valid mandate — the payer cancelled it at their bank and told nobody
  'MD06', // refund requested by the payer (the 8-week no-questions claim)
  'MD07', // payer deceased
  'AC04', // account closed
  'AC06', // account blocked
  'SL01', // debtor-bank service: the payer set a block or a limit on you specifically
]);
const RETRYABLE = new Set(['AM04' /* insufficient funds */, 'MS03' /* reason not specified */]);

export async function onChargeReturned(charge: any, code: string) {
  await db.pagokitMandateCharge.update({
    where: { id: charge.id }, data: { status: 'returned', return_code: code },
  });
  if (TERMINAL.has(code)) {
    // consumer_revocable: true means this is the ONLY way you learn the mandate is gone.
    // Retrying it re-presents a debit the payer has refused — on SEPA that is an unauthorised debit.
    await db.pagokitMandate.update({
      where: { id: charge.mandate_id },
      data: { status: 'revoked', revoked_at: new Date(), revoked_reason: code },
    });
    return enqueue('billing.mandate_lost', { mandate_id: charge.mandate_id, code });
  }
  if (RETRYABLE.has(code)) return enqueue('billing.represent', { charge_id: charge.id });
  // Unknown code: stop and ask a human. Guessing "probably retryable" is how re-presentment fines start.
  return enqueue('billing.manual_review', { charge_id: charge.id, code });
}

/** Arrives weeks or months after `confirmed`. Reverse the entitlement, record the debt, do not re-debit. */
export async function onIndemnityClaim(charge: any) {
  await db.pagokitMandateCharge.update({ where: { id: charge.id }, data: { status: 'indemnity_claimed' } });
  await revokeEntitlement(charge.mandate_id);
  await db.pagokitDebt.create({ data: { mandate_id: charge.mandate_id, amount: charge.amount, source: 'indemnity' } });
}
```

```ts
// app/api/webhook/<provider>/route.ts — mandate branch. The handler shell (413 cap, raw-body capture
// under runtime='nodejs', verifySignature → bare 400, event-id dedup → 200 duplicate, metadata-only
// log, fast ack) is fragments/webhook/_preamble.md. This is what the billing slot contributes — and
// it is a FUNCTION called from the preamble's applyStateChange, not a loose block: top-level
// `await` and `return` pasted into a route file do not compile.
import { db } from '@/lib/db';
import { enqueue } from '@/lib/jobs';
import { REVERSAL_WINDOW_DAYS } from '@/lib/payments/mandate-schedule';
import { onChargeReturned, onIndemnityClaim } from '@/lib/payments/mandate-returns';

export async function onMandateEvent(event: any, eventId: string, eventType: string) {
  const obj = event.data.object;

  if (eventType === 'mandate.activated' || eventType === 'mandate.revoked') {
    const mandate = await findMandate(obj.id);                     // by provider_mandate_id
    if (!mandate) {
      console.log('[<provider>.webhook] unknown mandate', { id: eventId, type: eventType });
      return;                                                      // preamble still acks 200
    }
    if (eventType === 'mandate.activated') {
      await db.pagokitMandate.update({ where: { id: mandate.id },
        data: { status: 'active', approved_at: new Date() } });
    } else {
      await revokeMandate(mandate.id, 'payer_revoked');
    }
    return;
  }

  // Charge events. Resolve the charge AND its mandate up front — REVERSAL_WINDOW_DAYS is keyed by
  // rail, and the rail lives on the mandate, not on the event.
  const charge = await findMandateCharge(obj.id);
  if (!charge) {
    console.log('[<provider>.webhook] unknown charge', { id: eventId, type: eventType }); // 200, not 4xx
    return;
  }
  const mandate = await findMandateById(charge.mandate_id);

  switch (eventType) {                                  // <from webhook.required_events_minimum>
    case 'charge.confirmed': {
      const days = REVERSAL_WINDOW_DAYS[mandate.rail];
      const confirmedAt = new Date();
      await db.pagokitMandateCharge.update({ where: { id: charge.id },
        data: { status: 'confirmed', confirmed_at: confirmedAt,
                // NULL final_at means "window unknown, never final" — isFinal() reads it that way
                // and settle_finality() skips it. It does NOT mean "final now".
                final_at: days == null ? null : new Date(confirmedAt.getTime() + days * 86400_000) } });
      await enqueue('entitlement.grant', { mandate_id: mandate.id }); // access yes; shipping no
      break;
    }
    case 'charge.returned':  await onChargeReturned(charge, obj.return_code); break;
    case 'charge.indemnity': await onIndemnityClaim(charge); break;
    default:
      console.log('[<provider>.webhook] TODO unhandled', { id: eventId, type: eventType }); // 200, not 4xx
  }
}
```

## Python

```python
# jobs/mandate_billing.py — FastAPI/Celery side. The two sweeps this rail cannot live without.
async def notify_and_submit(now: datetime) -> None:
    """Pre-notification is a legal obligation on SEPA and UPI, not a courtesy email."""
    for charge in await charges_with_status("scheduled"):
        if charge.notice_sent_at is None:
            await enqueue("billing.pre_debit_notice", charge_id=charge.id,
                          amount=charge.amount, on=charge.scheduled_for)   # Rule 6: ids and amount, no payload
            await set_notice_sent(charge.id, now)
            continue
        debit_on = debit_date_or_postpone(charge.scheduled_for, charge.notice_sent_at)
        if debit_on > charge.scheduled_for:
            await reschedule(charge.id, debit_on)        # late notice ⇒ move the debit, never debit early
        elif now >= debit_on:
            if needs_afa(charge.amount):                 # <from recurring.afa_threshold>
                await request_additional_factor(charge)  # the payer must approve this one
            else:
                await submit(charge.id, idempotency_key=str(uuid.uuid4()))  # Rule 4
                await set_status(charge.id, "submitted") # NOT "paid" — nothing has settled yet

async def settle_finality(now: datetime) -> None:
    """The only place irreversible fulfilment is allowed to happen."""
    for charge in await charges_with_status("confirmed"):
        if charge.final_at is not None and now >= charge.final_at:
            await enqueue("fulfilment.irreversible", charge_id=charge.id)
```

## Anti-patterns

- ❌ Reusing the card state machine. `submitted` is not `paid`, and `confirmed` is not final.
- ❌ Granting irreversible fulfilment on confirmation — a Bacs payer has 395 days to take it back.
- ❌ Treating a missing `reversal_window_days` as zero. Missing means unknown; hold it.
- ❌ Debiting without a recorded `notice_sent_at`, or debiting early after a late notice. Both hand the payer an indemnity claim you cannot contest.
- ❌ Hardcoding 14 days. UPI AutoPay is 24 hours; read `recurring.pre_debit_notice_hours`.
- ❌ Putting a terminal return code into the dunning retry loop. `MD01` means the mandate is gone; re-presenting is an unauthorised debit, and it accrues a per-return fee every time.
- ❌ Re-debiting the same mandate to recover an indemnity claim. That is the transaction the payer just disputed.
- ❌ Ignoring the mandate's own state and debiting a `pending_approval` mandate on UPI or Pix Automático, where approval happens in the payer's app on their schedule.
- ❌ Storing the full IBAN or account number to "make support easier" — Rule 12 covers bank credentials, not only cards. Keep the token and the last four.
- ❌ Assuming a single cancellation path. The payer can revoke at their bank without ever visiting your product, so your UI state is not authoritative.

## Security rules cited

- **Rule 3:** every mandate and charge transition happens after `verifySignature` (fragments/webhook/<family>.md); an invalid signature is a bare 400 with no reason.
- **Rule 4:** `crypto.randomUUID()` / `uuid.uuid4()` on every submission — a re-presented debit that duplicates is a second withdrawal from a real bank account, not a reversible card charge.
- **Rule 5:** `await request.text()` under `runtime = 'nodejs'`; `await request.body()` on FastAPI; `express.raw(...)` registered before `express.json()`.
- **Rule 6:** notice and claim jobs carry the charge id, the amount and the date. The payload carries the debtor's name and account details.
- **Rule 9:** these rails deliver confirmations and returns days apart and retry on any 5xx, so the event-id dedup table with a TTL well past the settlement lag is the only thing stopping a redelivered `charge.returned` from revoking a mandate twice.
- **Rule 10:** 256 KB cap before reading; batch settlement notifications are the largest bodies on this rail.
- **Rule 11:** collect the mandate fields the scheme requires and nothing else.
- **Rule 12:** the debtor's account identifier is stored as the provider's token plus a display last4 — never the full IBAN, and never in a log line.
