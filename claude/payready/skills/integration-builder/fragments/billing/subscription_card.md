# Subscription — stored card

Recurring billing against a card kept on file. Almost every template stops at "create the subscription, grant access", which is the first five minutes of a relationship that lasts years. Everything that decides whether you keep the revenue happens later: the trial converting, the renewal that declines, the card that expires, the plan change nobody prorated, the cancel that should have been end-of-period. **Involuntary churn — cards that expired or declined — is usually larger than the churn people actually choose**, and it is the only kind you can engineer away.

The second thing developers get wrong is invisible until a renewal declines with a code they have never seen. The first charge is **customer-initiated** (CIT): the cardholder is present and can answer a 3DS challenge. Every renewal after it is **merchant-initiated** (MIT), and an MIT is only valid if it carries the **network transaction id returned by that original CIT**. Mastercard requires the stored Trace ID on economically-related MITs from **23 October 2026**; an unlinked MIT is a decline, not a warning. If your `subscriptions` table has no column for it, every renewal you have is on borrowed time.

**Providers in this family:** 28 catalog entries carry `supports.subscriptions: true`; the three at `integration_level: build` are Stripe (`recurring.rails: ["card","sepa_debit","ach_debit"]`, `network_txn_id_required: true` — the only entry where that flag is true), Mercado Pago (`rails: ["card"]`, `network_txn_id_required: false`) and Lemon Squeezy (`rails: ["card"]`, `mor.is_mor: true` — it owns the stored credential, so these columns are reconciliation data rather than something you send; Paddle and Polar are the catalog's other merchants of record and behave the same way). Wompi is **not** in this family: `supports.subscriptions: false` and `recurring.rails: []`, so recurring there means your own scheduler over saved cards — and then the CIT/MIT linkage below is yours to maintain, not the provider's. Every other subscription-capable entry is `advise` and carries no `recurring` block yet, so treat `network_txn_id_required` as unknown rather than false for those.

**Catalog fields this fragment reads:** `supports.subscriptions`, `supports.save_card`, `supports.tokenization_owner`, `recurring.rails`, `recurring.network_txn_id_required`, `recurring.mandate_lifecycle`, `mor.is_mor`, `webhook.required_events_minimum`, `methods[card].reversibility`, `currencies[].exponent`.

## The contract

1. **Trial.** Take the card up front with a zero-amount or account-verification CIT so 3DS happens while the customer is watching. Status `trialing`, `trial_ends_at` set. A trial without a stored credential is a signup, not a trial.
2. **Activation.** At `trial_ends_at`, run the first real charge. If it needs a challenge it is still a CIT; store what it returns.
3. **Store the credential.** From the CIT response persist the token, `network_transaction_id`, the scheme, and `cit_completed_at`. Never the PAN (Rule 12).
4. **Renew as an MIT.** Every subsequent charge carries the stored `network_transaction_id` and an explicit merchant-initiated flag.
5. **Upgrade** prorates immediately: charge the unused-to-new difference now. **Downgrade** schedules at period end and issues account credit — never a refund by default.
6. **Dunning.** On decline, classify: hard declines (stolen, lost, invalid account, revoked authorisation) stop instantly and mark the credential dead. Soft declines enter the retry schedule.
7. **Grace.** `past_due` keeps entitlements until `grace_until`. Access is a function of state and clock, never a boolean column someone forgot to flip.
8. **Involuntary churn.** Watch `card_exp_month/year`; warn at T-30 days and again at T-7. This is cheaper than every recovery email you will send afterwards.
9. **Cancel.** Immediate (`access_until = now`) or end-of-period (`cancel_at_period_end = true`, `access_until = current_period_end`). Default to end-of-period.
10. **Reactivate.** Before the period ends: clear the flag, no new CIT. After it ends: a new subscription and a **new CIT** — the old network transaction id belongs to a finished agreement and reusing it produces an unlinked MIT.

States — `incomplete → trialing → active → past_due → canceled`, plus `paused`. `cancel_at_period_end` is a flag on `active`, not a state; modelling it as one loses the fact that the customer is still entitled.

## Schema this implies

```prisma
model PagokitSubscription {                 // columns added on top of the base adapter
  trial_ends_at            DateTime?
  grace_until              DateTime?        // past_due keeps access until here
  access_until             DateTime?        // set on cancel; the entitlement clock
  cancel_at_period_end     Boolean  @default(false)
  dunning_attempts         Int      @default(0)
  first_failed_at          DateTime?
  credential_id            String?
}
model PagokitStoredCredential {
  id                       String   @id @default(cuid())
  provider_payment_method_id String @unique  // token only — Rule 12: no PAN, no CVV, ever
  card_brand               String?           // for the receipt and the expiry warning, nothing else
  card_last4               String?
  card_exp_month           Int?
  card_exp_year            Int?
  network_transaction_id   String?           // the CIT's trace id; every MIT must carry it
  network_scheme           String?           // "visa" | "mastercard" | "amex" — schemes name it differently
  cit_completed_at         DateTime?
  dead_at                  DateTime?         // hard decline: never retry this credential again
  @@index([card_exp_year, card_exp_month])   // drives the expiry-warning sweep
  @@map("pagokit_stored_credentials")
}
```

## Node / TypeScript

```ts
// lib/payments/stored-credential.ts
const NETWORK_TXN_ID_REQUIRED = true;  // <from recurring.network_txn_id_required>

/** Called with the CIT result — the ONLY moment the network transaction id exists. */
export async function recordStoredCredential(citResult: any, subscriptionId: string) {
  const cred = await db.pagokitStoredCredential.create({
    data: {
      provider_payment_method_id: citResult.payment_method,       // Rule 12: a token, never the PAN
      card_brand: citResult.card?.brand, card_last4: citResult.card?.last4,
      card_exp_month: citResult.card?.exp_month, card_exp_year: citResult.card?.exp_year,
      network_transaction_id: citResult.network_transaction_id,   // Visa: Transaction ID; MC: Trace ID
      network_scheme: citResult.card?.brand, cit_completed_at: new Date(),
    },
  });
  await db.pagokitSubscription.update({ where: { id: subscriptionId }, data: { credential_id: cred.id } });
  return cred;
}

/** Build the MIT. Refuses to send an unlinked one rather than eating the decline at renewal. */
export function mitPayload(cred: { provider_payment_method_id: string; network_transaction_id: string | null }) {
  if (NETWORK_TXN_ID_REQUIRED && !cred.network_transaction_id) {
    // Mastercard rejects economically-related MITs without the stored Trace ID from 2026-10-23.
    throw new Error('unlinked_mit: re-run a CIT before charging this credential again');
  }
  return {
    payment_method: cred.provider_payment_method_id,
    off_session: true, confirm: true,                 // no cardholder present
    initiator: 'merchant', mit_reason: 'recurring',
    network_transaction_id: cred.network_transaction_id,
  };
}
```

```ts
// lib/payments/dunning.ts
// Index 0 is the original renewal charge, at hour 0. The retries are indices 1-4: +24h, +72h,
// +120h, +168h. Five attempts across seven days, and then the schedule ENDS in a cancellation.
const DUNNING_SCHEDULE_HOURS = [0, 24, 72, 120, 168];
const GRACE_DAYS = 3;

/** null means the schedule is exhausted: cancel for non-payment, do not keep hammering the issuer. */
export function nextDunningAttempt(attemptCount: number, firstFailedAt: Date): Date | null {
  if (attemptCount >= DUNNING_SCHEDULE_HOURS.length) return null;
  return new Date(firstFailedAt.getTime() + DUNNING_SCHEDULE_HOURS[attemptCount] * 3600_000);
}

// Map from templates/<provider>/errors.md. A hard decline retried is a scheme-fee generator,
// and on several networks a fine once you cross the excessive-retry threshold.
const HARD_DECLINES = new Set(['stolen_card', 'lost_card', 'pickup_card', 'invalid_account',
                               'revoked_authorization', 'do_not_honor_permanent']);

export async function onRenewalDeclined(sub: any, code: string) {
  if (HARD_DECLINES.has(code)) {
    await db.pagokitStoredCredential.update({ where: { id: sub.credential_id }, data: { dead_at: new Date() } });
    return markCanceled(sub, 'hard_decline');            // ask for a new card; do not retry this one
  }
  const firstFailedAt = sub.first_failed_at ?? new Date();
  const attempts = sub.dunning_attempts + 1;
  const nextAt = nextDunningAttempt(attempts, firstFailedAt);
  await db.pagokitSubscription.update({
    where: { id: sub.id },
    data: { status: 'past_due', first_failed_at: firstFailedAt, dunning_attempts: attempts,
            grace_until: new Date(firstFailedAt.getTime() + GRACE_DAYS * 86400_000) },
  });
  return nextAt ? enqueue('subscription.retry', { id: sub.id }, { runAt: nextAt })
                : markCanceled(sub, 'dunning_exhausted');
}
```

```ts
// lib/entitlements.ts — the single source of truth. Never a granted:boolean column.
export function hasAccess(sub: any, now = new Date()): boolean {
  if (sub.status === 'trialing' || sub.status === 'active') return true;
  if (sub.status === 'past_due') return sub.grace_until != null && now <= new Date(sub.grace_until);
  if (sub.status === 'canceled') return sub.access_until != null && now <= new Date(sub.access_until);
  return false;                                  // incomplete: the CIT never finished. No access.
}
```

```ts
// app/api/billing/change-plan/route.ts
import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';
import { db } from '@/lib/db';
import { requireSession } from '@/lib/auth';

export const runtime = 'nodejs';
export async function POST(request: Request) {
  const session = await requireSession(request);
  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  let subscriptionId: string, newPlanId: string;
  try {
    const body = await request.json();
    subscriptionId = String(body.subscriptionId ?? '');
    newPlanId = String(body.newPlanId ?? '');
    if (!subscriptionId || !newPlanId) throw new Error('missing');
  } catch {
    return NextResponse.json({ error: 'invalid_request' }, { status: 400 });
  }

  // `subscriptionId` arrived in the request body. Scope the lookup to the caller's own customer
  // or this route downgrades other people's subscriptions for them — the id is a guessable
  // handle to somebody else's money, and `findUniqueOrThrow({ where: { id } })` will happily
  // return it. A 404 rather than a 403: do not confirm the id exists.
  const sub = await db.pagokitSubscription.findFirst({
    where: { id: subscriptionId, customer_id: session.customerId },
  });
  if (!sub) return NextResponse.json({ error: 'not_found' }, { status: 404 });

  const [current, next] = await Promise.all([getPlan(sub.plan_id!), getPlan(newPlanId)]);
  if (!current || !next) return NextResponse.json({ error: 'unknown_plan' }, { status: 400 });
  if (next.id === current.id) return NextResponse.json({ error: 'no_change' }, { status: 400 });
  const upgrade = next.amount_minor > current.amount_minor;

  const updated = await providerUpdateSubscription(sub.provider_subscription_id, {
    plan: newPlanId,
    // Upgrade bills the difference now; downgrade waits so nobody is refunded by surprise.
    proration_behavior: upgrade ? 'always_invoice' : 'none',
    effective_at: upgrade ? 'now' : 'period_end',
  }, { idempotencyKey: randomUUID() });          // Rule 4

  if (!upgrade) await creditAccount(sub.customer_id, unusedRemainder(sub, current, next)); // credit, not refund
  return NextResponse.json({ status: updated.status, effective_at: upgrade ? 'now' : sub.current_period_end });
}
```

```ts
// app/api/webhook/<provider>/route.ts — subscription branch. The handler shell (413 cap, raw-body
// capture under runtime='nodejs', verifySignature → bare 400, event-id dedup → 200 duplicate,
// metadata-only log, ack inside webhook.ack_deadline_seconds) is fragments/webhook/_preamble.md.
// This is the billing slot's contribution: what a verified subscription event does to state.
// It is a FUNCTION, called from the preamble's applyStateChange — a bare `switch` with top-level
// `await` and `return` pasted into a route file is not valid module code.
import { db } from '@/lib/db';
import { onRenewalDeclined } from '@/lib/payments/dunning';
import { enqueue } from '@/lib/jobs';

export async function onSubscriptionEvent(event: any, eventId: string, eventType: string) {
  const obj = event.data.object;
  // Resolve the local subscription ONCE, before the switch. Every branch needs it, and an event
  // for a subscription this database has never seen is a logged no-op, not a crash: the preamble
  // already acked ownership of the event, so throwing here loses it permanently.
  const sub = await findSub(obj);
  if (!sub) {
    console.log('[<provider>.webhook] no local subscription', { id: eventId, type: eventType });
    return;
  }

  switch (eventType) {                        // <from webhook.required_events_minimum>
    case 'customer.subscription.updated':     // authoritative state: proration, pause, cancel_at
      await syncSubscription(obj); break;
    case 'invoice.payment_failed':
      // The decline code is NOT on the invoice envelope — it is on the payment that failed
      // (`last_payment_error` / the charge outcome). Map the real path from
      // templates/<provider>/errors.md. Read the wrong field and you pass `undefined`:
      // `HARD_DECLINES.has(undefined)` is false, so every stolen card is classed a soft decline
      // and re-presented five times against an issuer that already said no.
      await onRenewalDeclined(sub, declineCodeOf(obj) ?? 'unknown_decline'); break;
    case 'invoice.paid':                      // recovery: clear dunning, restore access
      await db.pagokitSubscription.update({ where: { id: sub.id },
        data: { status: 'active', dunning_attempts: 0, first_failed_at: null, grace_until: null } }); break;
    case 'customer.subscription.deleted':
      await markCanceled(sub, 'provider'); break;
    default:
      console.log('[<provider>.webhook] TODO unhandled', { id: eventId, type: eventType }); // 200, not 4xx
  }
  // Fast ack: the preamble returns the 200. Emails and receipts are jobs, never inline here.
  await enqueue('billing.notify', { subscription_id: sub.id, event: eventType });
}
```

## Python

```python
# jobs/renewals.py — the worker that owns the MIT and the expiry warning.
async def charge_renewal(sub, cred) -> None:
    if NETWORK_TXN_ID_REQUIRED and not cred.network_transaction_id:
        # Backfill path: this credential predates the linkage columns. A 2026-10-23 MIT would decline.
        return await request_reauthentication(sub)           # send the customer through a fresh CIT
    key = str(uuid.uuid4())                                  # Rule 4: cryptographic UUID
    result = await provider.charge(
        payment_method=cred.provider_payment_method_id, amount=sub.amount_minor,
        currency=sub.currency, off_session=True, initiator="merchant", mit_reason="recurring",
        network_transaction_id=cred.network_transaction_id, idempotency_key=key)
    if result.status == "succeeded":
        return await mark_active(sub)
    await on_renewal_declined(sub, result.decline_code)

async def warn_expiring_cards(now: date) -> None:
    """Involuntary churn you can see coming 30 days out. Cheaper than any recovery email."""
    for cred in await credentials_expiring_between(now + timedelta(days=7), now + timedelta(days=30)):
        # Rule 6: the notification job gets ids and last4 for the copy, never the payload.
        await enqueue("billing.card_expiring", credential_id=cred.id, last4=cred.card_last4)
```

## Anti-patterns

- ❌ No `network_transaction_id` column — every renewal is an unlinked MIT and starts declining on 23 Oct 2026 with a code your error map has never seen.
- ❌ Reusing the old trace id after the customer replaces the card, or after a cancel-and-resubscribe. A new PAN or a new agreement means a new CIT and a new id.
- ❌ Granting access on `checkout.session.completed` alone. That event fires once; the subscription then lives in `customer.subscription.updated` forever.
- ❌ A `has_access` boolean column. It drifts within a week. Compute entitlement from state plus clock.
- ❌ Loading the subscription by the `subscriptionId` in the request body without scoping it to the caller. Plan changes, pauses and cancels are all one guessable id away from being done to somebody else's account.
- ❌ Reading `decline_code` off the invoice instead of the failed payment. `undefined` is not in `HARD_DECLINES`, so every hard decline silently becomes a soft one and gets re-presented on a schedule.
- ❌ Retrying a hard decline. It generates scheme fees, and past the excessive-retry threshold, fines.
- ❌ Retrying forever on soft declines. The schedule must terminate in a cancellation.
- ❌ Refunding on downgrade by default — issue account credit; refunds on a card invite a dispute you will lose.
- ❌ Cancelling immediately when the customer clicks cancel mid-period. They paid for the period; end-of-period is both fairer and the law in several markets.
- ❌ Modelling `cancel_at_period_end` as a state. The customer is still entitled and still countable as active.
- ❌ No customer portal. Cancellation must be self-service; in the EU and California, making it harder than signup is a regulatory problem, not a growth tactic.

## Security rules cited

- **Rule 3:** the subscription branch runs only after `verifySignature` (fragments/webhook/<family>.md); an invalid signature is a bare 400.
- **Rule 4:** `crypto.randomUUID()` / `uuid.uuid4()` on every subscription mutation and every renewal charge — a retried renewal must not become two charges.
- **Rule 5:** `await request.text()` under `runtime = 'nodejs'`; `express.raw(...)` before `express.json()`; `await request.body()` on FastAPI.
- **Rule 6:** dunning and expiry jobs carry ids, `last4` and brand — never the invoice payload, which holds the billing address.
- **Rule 9:** renewals are retried by the provider on any 5xx, so the event-id dedup table is what stops a retried `invoice.payment_failed` from advancing the dunning counter twice.
- **Rule 10:** 256 KB cap on the webhook route; subscription payloads with long line-item lists are the biggest bodies you will receive.
- **Rule 12:** `PagokitStoredCredential` holds a provider token, brand, last4 and expiry. No PAN, no CVV — storing either puts the merchant in PCI Level 1 scope.
