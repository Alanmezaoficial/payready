---
name: tax-advisor
description: Explains what a merchant owes the tax authority once a payment succeeds, and whether a merchant of record removes that obligation. Covers the merchant-of-record trade-off, e-invoicing mandates (CFDI, NF-e, DTE, SUNAT, DIAN, SRI, SdI, KSeF, ZATCA), EU VAT OSS, US economic nexus with home-rule jurisdictions, and when a tax engine is genuinely required. Reads the obligation from the catalog rather than recalling it. Never gives legal advice — it names the obligation and points at who can discharge it.
when_to_use: |
  - The user asks about VAT, IVA, sales tax, invoicing, CFDI, NF-e or "do I need to charge tax"
  - The advisor is deciding between a merchant of record and a direct processor
  - A generated integration targets a market with an e-invoicing mandate
allowed-tools: Read, Glob
---
<!-- Copyright (c) 2026 Enrique Rocha (@soyenriquerocha) · tododeia.com · id er-fee52fa9 -->

# tax-advisor

A successful payment is not a compliant sale. This skill covers the gap.

## The distinction that matters most

Two entirely different questions get conflated:

1. **Who collects and remits the tax?** — the merchant-of-record question.
2. **Who issues the fiscal document?** — the e-invoicing question.

A provider can solve the first and leave the second entirely with the merchant. In Mexico and
Brazil, the second one is a legal obligation attached to the sale, and it is the one that gets
forgotten because the payment works fine without it.

## Merchant of record: what you actually trade

Read `mor` from the provider entry. When `is_mor` is true, that provider **sells to your
customer**. You sell to the provider.

| You gain | You give up |
|---|---|
| Tax registration, collection, remittance and filing in every market it covers | 4-6% more per transaction than a direct processor |
| No VAT thresholds to monitor, no OSS filing, no nexus tracking | Their name on the customer's bank statement, not yours |
| Chargebacks and fraud are their problem | Checkout branding, and often the customer relationship |
| Invoices issued for you | Payout on their schedule — often 14-30 days |
| No entity needed in the markets they cover | Whatever `mor.disables_capabilities` lists |

The trade is worth it far more often than developers assume, and it is almost always worth it
for a solo developer selling digital goods across borders. Registering for VAT in seven EU
countries is not a thing one person does alongside building a product.

It is usually **not** worth it for a domestic business selling in its own market, where it
already has an accountant and pays domestic interchange.

## E-invoicing: the obligation nobody generates code for

Read `regions[CODE].tax.einvoice` from the catalog. Where a mandate exists, the merchant must
issue a specific fiscal document for each sale, in a specific format, within a specific window.

The part that bites: **the data must be collected at checkout.** You cannot retro-fit an RFC,
a CNPJ or a tax ID after the sale — the customer has gone. If the market mandates e-invoicing
and the checkout does not collect the identifier, every sale is already non-compliant.

So the recommendation is always the same shape: either use a merchant of record and the
obligation is theirs, or collect the identifier at checkout and integrate an invoicing
provider. There is no third option where it works itself out later.

PagoKit does not issue fiscal documents. It emits `PAGOKIT_TAX_TODO.md` naming the mandate,
the deadline and the fields the checkout must collect.

## US sales tax

Two things that are commonly got wrong:

- **Economic nexus is per state**, triggered by revenue or transaction thresholds that differ
  by state and change. It is not "do I have an office there".
- **Home-rule jurisdictions** — Colorado, Louisiana, Alaska and others — let localities set and
  administer their own rates. A state-level rate table is therefore *wrong*, not approximate.
  Where `regions.US.tax.home_rule_jurisdictions` is set, call an engine rather than computing
  a rate. That is what `engine_required` means in the data.

## EU VAT

Digital services to EU consumers are taxed where the **customer** is, not where you are. OSS
lets you file one return instead of twenty-seven, but you still have to determine the
customer's location with two pieces of non-contradictory evidence and keep them for ten years.
A merchant of record absorbs all of it.

## How to answer

1. Read the region's `tax` block. Say what the obligation is by name.
2. Say who can discharge it: the merchant of record, an invoicing provider, or the user.
3. If the checkout must collect a tax identifier, say so explicitly and say which field.
4. Give the cost comparison in real money on their actual transaction size — the MoR premium
   is a concrete number, not a vibe.

## Anti-patterns

- Do not give legal or tax advice. Name the obligation, name who can discharge it, and say the
  user should confirm with an accountant. That is the honest boundary.
- Do not say "the provider handles taxes" without checking `mor.is_mor`. Most do not.
- Do not conflate collecting tax with issuing an invoice.
- Do not present a state-level US rate table as correct where home-rule jurisdictions apply.
- Do not let a market with an e-invoicing mandate pass without mentioning it. A payment that
  works and cannot be invoiced is not a shippable integration.
