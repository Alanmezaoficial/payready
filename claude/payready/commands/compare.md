---
description: Compare two or more payment providers head to head for a concrete situation — real fees on a real amount, coverage, onboarding time, and what PayReady can actually build for each.
argument-hint: "<provider-a> <provider-b> [--country MX] [--amount 500] [--currency MXN]"
---

# /payready:compare

Comparisons in blog posts are generic. This one is for **their** situation, with arithmetic.

1. Read the arguments. If country, amount or currency are missing, either infer them from
   `project-analyzer` or ask once — a comparison without a concrete amount is just a feature
   table.
2. Run the engine for the situation:

```bash
node scripts/advise.js --country <ISO2> --amount <n> --currency <CUR> [--billing ...] [--methods ...]
```

3. Pull the named providers out of `candidates` **and** `rejected`. A provider that was ruled
   out is often the most useful row in the table — say which filter removed it.
4. Read `skills/payment-advisor/data/providers/<id>.json` for each one, for the detail the
   index does not carry.

## Output

```
<A> vs <B> — selling from <country>, charging <amount> <currency>

                        <A>                     <B>
Cost per charge         <fee.explanation>       <fee.explanation>
You receive             <net>                   <net>
Buyer coverage          ...                     ...
Subscriptions           ...                     ...
Merchant of record      ...                     ...
Onboarding              <model>, ~<days> days   ...
PayReady can             <integration_level>     <integration_level>
Notification model      <webhook | ...>         ...
Settlement              <payout_delay_days>     ...

Where they actually differ:
• <the one or two things that would change the decision>

Ruled out for your situation:
• <name> — <filter>: <reason>
```

Lead with cost, because that is what they came for — but do not stop there. The decision is
usually made by something the fee table does not show: an onboarding gate, a missing local
rail, a merchant-of-record trade-off, or the fact that one of them will not send you a webhook
at all.

## Anti-patterns

- Do not compare providers on a generic 2.9% + 30¢ when the catalog has real figures for the
  actual amount and currency.
- Do not present a provider as available if the engine rejected it on merchant domicile or
  onboarding. Show it in the ruled-out list with the reason.
- Do not hide the `integration_level` difference. "PayReady builds A completely and only advises
  on B" is frequently the deciding factor.
- Do not invent a fee. If the catalog has no figure, say so and link the pricing page.
