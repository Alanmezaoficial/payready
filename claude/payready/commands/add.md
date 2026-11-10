---
description: Add a second payment provider alongside an existing integration, without touching the one already running.
argument-hint: "[<provider-id>]"
---

# /payready:add

Real projects end up with more than one provider: a local one for domestic buyers and a
cross-border one for everyone else, or a card processor plus a wallet. PayReady has assumed
this since v0.1 — every webhook route is namespaced `/api/webhook/<provider>` precisely so a
second one can land without a collision.

1. Read `PAGOKIT_INTEGRATION.md` to learn what already exists: provider, routes, tables, env
   vars. If it is missing, detect the existing integration by globbing for webhook routes and
   payment SDK imports, and say you are working from inference.
2. If no provider was named, run `payment-advisor` for the **new** requirement — not the one
   already solved. Ask what the existing provider does not cover: a country, a rail, a
   billing mode.
3. Plan the addition, and be explicit about what is shared and what is not:

| Shared | Duplicated per provider |
|---|---|
| `payments`, `customers`, `webhook_events_processed` tables (add a `provider` column if absent) | The webhook route, namespaced |
| `lib/payments/errors.ts` — extend the taxonomy | The SDK client and its env vars |
| The checkout entry point, which now routes by provider | The provider-specific checkout call |

4. Delegate to `integration-specialist` with an explicit instruction: **do not modify the
   existing provider's files.** Additive changes only.

## Before you write anything

- Confirm the `provider` column exists on the shared tables. Without it, a webhook from the
  new provider can update a payment created by the old one.
- Confirm the new webhook route does not collide. The `existing-webhook-check` validator will
  block it if it does, but catching it here is cheaper than a blocked write.
- Decide how the checkout picks a provider — buyer country, currency, or an explicit choice —
  and write it down in `PAGOKIT_INTEGRATION.md`. This is the part that gets forgotten and
  becomes unexplainable six months later.

## Anti-patterns

- Do not refactor the existing integration "while you are in there". Adding a provider must
  not risk the one currently taking money.
- Do not share an idempotency key namespace across providers.
- Do not merge the two webhook handlers into one route with a switch. Separate routes are
  what let you disable one provider without touching the other.
