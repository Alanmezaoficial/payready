---
description: Show what you can actually use in a given country — providers, local rails, currency exponent, e-invoicing obligation, and whether a local acquirer is required.
argument-hint: "<country-code | country name>"
---

# /payready:coverage

Answers "what are my options in X?" with data rather than a general impression.

1. Resolve the argument to an ISO-3166 alpha-2 code. Accept a country name in English or
   Spanish. If the code is not in `regions.json`, say so plainly — an absent country means
   PayReady has no verified answer there, which is different from there being no answer.
2. Read `skills/payment-advisor/data/regions.json` for that code and
   `providers.index.json` for the providers it names.
3. If `unsupported` is set, report the reason and stop. Do not suggest a workaround for a
   sanctioned market.

## Output

```
<Country> (<code>) — <currency>, <exponent> decimal places

Local providers:      <name> [<level>] · <name> [<level>]
Cross-border MoR:     <name> [<level>]
Dominant instant rail: <rail label>
Local rails available: <methods from the catalog for this region>

What you must know:
• <requires_local_acquirer, with the reason, if set>
• <e-invoicing mandate, if set — and that a merchant of record removes the obligation>
• <installments_expected, if set>
• <currency exponent, when it is not 2 — the amount must be sent at that exponent>

PayReady can build: <the providers at build level>
PayReady can only advise on: <the ones at advise level>
```

If `primary_providers` is empty, say exactly that: there is no local provider in the catalog
yet, the fallback is a cross-border merchant of record, and it costs more than a local option
would. Do not dress that up.

## Anti-patterns

- Do not list a provider without its integration level.
- Do not omit the e-invoicing obligation. A working payment is not a compliant sale.
- Do not treat an empty `primary_providers` as "use the fallback and move on" — the user
  should know they are paying a cross-border premium.
