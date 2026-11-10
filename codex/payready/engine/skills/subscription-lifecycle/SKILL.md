---
name: subscription-lifecycle
description: Covers everything after the subscription is created — trials, proration on upgrade and downgrade, dunning and retry schedules, grace periods, involuntary churn from expired cards, cancellation timing, and the bank-mandate lifecycle for SEPA, Bacs, PAD, UPI AutoPay and Pix Automatico. Also covers the stored-credential framework and the network transaction id that recurring charges must carry. This is the part every payment tutorial stops short of, and where production subscriptions actually break.
when_to_use: |
  - Generating or reviewing subscription billing
  - The user asks about trials, proration, dunning, failed payments, cancellation or churn
  - A recurring integration uses a bank mandate rather than a card
allowed-tools: Read, Glob
---
<!-- Copyright (c) 2026 Enrique Rocha (@soyenriquerocha) · tododeia.com · id er-fee52fa9 -->

# subscription-lifecycle

Creating a subscription is one API call. Everything that follows is where the money is lost.

## The state machine nobody draws

```
trialing ──► active ──► past_due ──► canceled
    │           │  ▲         │
    │           │  └─────────┘  (retry succeeded)
    │           ▼
    │       paused / grace
    └──► canceled (trial abandoned)
```

`past_due` is the state that matters. A subscription there is still delivering value and no
longer being paid for. How long you tolerate that, and what the customer sees while it lasts,
is a product decision the code has to encode explicitly — the default of "keep serving forever
because nobody wrote the branch" is the expensive one.

## Involuntary churn is the biggest line item

Most subscription cancellations are not decisions. They are expired cards, changed cards, and
issuer declines on a merchant-initiated transaction. Concretely:

- **Retry on a schedule, not immediately.** Same-day retries mostly fail again. Spread them
  over days, and stop before the issuer starts treating you as abusive.
- **Ask before it breaks.** A card expiring next month is knowable this month.
- **Use account updater** where the provider offers it — the issuer tells them the new number.
- **Distinguish soft from hard declines.** "Insufficient funds" is worth retrying on payday.
  "Stolen card" is not worth retrying at all, and retrying it looks like testing stolen cards.

## The stored-credential framework

The first charge is customer-initiated (CIT), with the customer present. Every later charge is
merchant-initiated (MIT), and the networks require it to reference the original.

**Persist the network transaction id from the first charge and send it on every subsequent
one.** Mastercard requires the stored Trace ID on economically-related MITs from 23 October
2026, and Visa's Original Transaction ID already drives approval rates today. An unlinked MIT
is not a warning — it is a decline.

That means a column: `network_transaction_id` on the stored payment method or the subscription.
Read `recurring.network_txn_id_required` from the provider entry.

## Proration

When a plan changes mid-cycle, someone is owed money. The three defensible answers:

- **Prorate immediately** — credit the unused portion, charge the new plan pro rata, invoice
  the difference now. Correct, and the most confusing to read on a statement.
- **Prorate at next renewal** — apply the credit to the next invoice. Gentler, and delays revenue.
- **No proration** — the change takes effect at renewal. Simplest, and only acceptable when the
  price difference is small.

Pick one, write it down, and make the checkout say what will be charged **before** the click.
The support burden of an unexplained mid-cycle charge exceeds its revenue.

## Cancellation

Cancel-at-period-end is almost always right: the customer keeps what they paid for, and you
keep the revenue you already earned. Immediate cancellation with a refund is a separate,
deliberate choice.

Two things that are not optional: cancellation must be possible **without contacting support**
(a legal requirement in several markets, not a UX preference), and the customer must be told
exactly when access ends.

## Bank mandates are a different animal

For SEPA, Bacs, PAD, UPI AutoPay, Pix Automático and PAC, read
`fragments/billing/subscription_mandate.md`. The differences that break card-shaped code:

- A mandate has its own lifecycle: created → pending → active, and can take days to activate.
- Advance notice before each debit is legally required — amount and date, days ahead.
- "Successful" is not final. SEPA allows an unauthorised claim for 13 months; Bacs has the
  Direct Debit Guarantee. Money can leave weeks after you counted it.
- The payer can revoke the mandate **at their bank**, without telling you. You discover it on
  the next failed debit.

Never model these as a card on file. `supports.subscriptions: true` does not mean the rails
behave alike.

## What a generated subscription integration must include

1. The full state machine, with `past_due` handled explicitly.
2. A dunning schedule with soft/hard decline branching.
3. `network_transaction_id` persisted and sent.
4. A customer portal, or an in-app equivalent, that can cancel without support.
5. Webhook handlers for payment failure, subscription updated and subscription deleted — a
   subscription cancelled in the provider dashboard must revoke access in your app.
6. For mandates: the pre-notification job and a reversal handler.

## Anti-patterns

- Do not create a subscription and consider the feature done.
- Do not retry a failed charge immediately, repeatedly, or forever.
- Do not grant access on a checkout redirect. Grant it on the webhook or a re-fetch.
- Do not treat a mandate rail as a card.
- Do not let a subscription cancelled provider-side keep working in the app.
