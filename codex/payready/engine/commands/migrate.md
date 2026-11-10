---
description: Migrate from one payment provider to another, keeping the old one running until the new one is proven.
argument-hint: "<from-provider> <to-provider>"
---

# /pagokit:migrate

The common reasons are real ones: taxes became a burden and a merchant of record solves it; a
local provider now covers the market better than the cross-border one; the current provider
does not support a rail that customers keep asking for; or the provider is being wound down.

A migration is not a rewrite. It is a period where **both run at once**.

## 1. Establish what is actually in use

Read `PAGOKIT_INTEGRATION.md`, then verify against the code — it can be stale. Inventory:

- Which events are routed, and what each one does.
- Which customers have a stored payment method. **These usually cannot move.** Card tokens
  belong to the provider that vaulted them; some providers support a network token migration
  on request, most do not. Establish this before promising anything.
- Active subscriptions and their next billing dates.
- Anything referencing a provider id in the database.

## 2. State the constraints plainly, before planning

Read both providers' catalog entries and name the differences that will bite:

- **Stored cards.** If they cannot migrate, existing subscribers must re-enter a card. That is
  a churn event, not a technical detail, and the user needs to decide how to handle it.
- **Event vocabulary.** The two providers do not use the same event names. Map them
  explicitly, `required_events_minimum` to `required_events_minimum`, and flag anything with
  no equivalent.
- **Notification model.** Moving to a `return_url_commit` or `ping_then_poll` provider is a
  different architecture, not a swapped SDK.
- **Merchant of record.** Moving to one means it becomes the seller of record. Invoices,
  tax handling and the name on the customer's statement all change.
- **Refund semantics.** If the new provider's rails include irreversible ones, the refund path
  changes shape.

## 3. Plan the coexistence

1. Add the new provider alongside the old one (`/pagokit:add` does this).
2. Route **new** payments to the new provider; leave existing subscriptions on the old one.
3. Run both webhook handlers. Keep the old one alive for as long as the provider can still
   send disputes and refunds — that is months, not days.
4. Migrate subscriptions at their natural renewal, not in a batch.
5. Keep a `provider` column on every payment row, forever. Historical reconciliation needs it
   long after the old provider is gone.

## 4. Write the plan down

`PAGOKIT_MIGRATION.md`: what moves when, what cannot move, what the customer sees, and the
rollback. A migration without a written rollback is a bet.

## Anti-patterns

- Do not switch atomically. There is no moment where flipping every payment at once is safe.
- Do not delete the old webhook handler when the last payment is created. Disputes arrive
  weeks later.
- Do not promise that stored cards will migrate until you have confirmed it with both
  providers in writing.
- Do not migrate and refactor in the same change. When something breaks you will not know
  which one did it.
