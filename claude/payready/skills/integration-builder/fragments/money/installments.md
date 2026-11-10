# Installments — parcelamento, cuotas, meses sin intereses

A checkout without installments converts materially worse in Brazil, Argentina and Mexico, and in Mexico **MSI** (*meses sin intereses*) is close to table stakes for anything above roughly a week's wages. The thing developers get wrong is treating the instalment count as a display option: they render "12x $83.33" from their own division, pass `installments: 12` to the provider, and never notice that the issuer bills a different split, that the merchant is now funding the interest, or that the money arrives over twelve months rather than on Friday. The instalment count changes **who pays interest**, **what the merchant nets**, and **when it settles** — three facts that live outside your database.

**Providers in this family:** `mercadopago` (`supports.installments` → BR, MX, AR) and `stripe` (BR, MX). The other 40 providers in the catalog declare no `supports.installments` key, so for those the instalment UI must not be generated at all.

**Catalog fields this fragment reads:** `supports.installments.<COUNTRY>`, `checkout_spec.amount_unit`, `checkout_spec.create_endpoint`, `currencies[]`, `methods[]` (`card`, `pix_parcelado`), `settlement.payout_delay_days`, `fees.*`.

## The contract

1. Gate on the catalog: emit the instalment selector only if `supports.installments[country] === true`. Absent means the provider will reject the field at payment time — after the customer has already committed.
2. Gate on the method too. Instalments ride the **card** rail. A boleto, an OXXO voucher or a plain Pix cannot be split. `pix_parcelado` exists in `methods.json` — a bank lending over Pix, not a Pix feature — but no provider in the current catalog lists it in `methods[]`, so do not emit that branch unless the provider entry you are generating for actually declares it. Its `reversibility` is `irreversible_no_refund`: an instalment plan with no refund endpoint (`fragments/money/irreversible_refund.md`).
3. **Ask the provider for the plans; do not compute them.** The available counts, the per-instalment amount and the total-with-interest are the *issuer's* numbers, published through the provider's instalment endpoint. Yours are an estimate at best.
4. Establish who funds the interest for each plan:
   - **Issuer-funded** (*con interés*, *com juros*, most AR cuotas): the payer's bank lends. The payer pays more than the sticker price; the merchant receives the sticker price minus the ordinary MDR.
   - **Merchant-funded** (MSI, *sem juros*, *cuotas sin interés*): the payer pays exactly the sticker price split *n* ways; the merchant absorbs the funding cost as an increased discount rate that grows with *n*. Three MSI and twelve MSI are different prices to you.
   - Bank/state promotional programmes (Ahora 12 in AR is the canonical one) are enrolled per merchant and settle on their own schedule.
5. Pass the chosen count to the provider at payment-creation time, with the amount converted through `fragments/money/minor_units.md` — the amount you send is always the **full** price, never the per-instalment slice. The issuer does the splitting.
6. Persist `installments`, `installment_funding` (`issuer` | `merchant`), the total the payer was quoted, and the plan id the provider returned. Reconciliation and any later refund need all four.
7. Settlement is not the payout you are used to. Read `settlement.payout_delay_days` and then read your acquirer contract: in Brazil the acquirer's default for parcelado is to release **one instalment per month** unless the merchant has contracted *antecipação* (which buys the receivable forward at a discount). In Mexico MSI is more commonly settled up front net of the MSI commission. Neither is safe to assume in code — surface it as a warning in `PAGOKIT_INTEGRATION.md`.
8. Display the provider's numbers verbatim: per-instalment amount, count, total payable, and whether interest applies. Brazil's *Código de Defesa do Consumidor* art. 52 requires the cash price, the interest amount, the number of instalments and the total payable to be disclosed before purchase (Rule 11).

## Node / TypeScript

```ts
// lib/payments/installments.ts
import { toMinorUnits, fromMinorUnits } from './money';

// <from supports.installments> — the catalog's country map, not a guess.
const INSTALLMENTS_BY_COUNTRY: Record<string, boolean> = { BR: true, MX: true, AR: true };

export type Funding = 'issuer' | 'merchant';
export interface Plan {
  installments: number;
  perInstallmentMinor: bigint;   // what the issuer will actually bill each month
  totalMinor: bigint;            // >= price when funding === 'issuer'
  funding: Funding;
  planId?: string;               // opaque id to echo back on payment creation
}

// The splittable rails this provider declares, <from methods[]>. `card` is the universal one;
// add `pix_parcelado` only if the provider entry actually lists it — no catalog provider does today.
const INSTALLMENT_METHODS = new Set<string>(['card']);

export function installmentsAvailable(country: string, method: string): boolean {
  // Rule 11: an instalment offer outside the catalog's country map is an offer you cannot honour.
  return INSTALLMENTS_BY_COUNTRY[country.toUpperCase()] === true && INSTALLMENT_METHODS.has(method);
}

/**
 * Ask the provider which plans this card BIN and amount qualify for.
 *
 * The plans endpoint is NOT a catalog field — `checkout_spec` has no key for it. Take the URL
 * from the provider's own API reference (`docs_url` in its catalog entry) and paste it here. If
 * you cannot cite the endpoint, do not write this function: the plans then come back on the
 * payment-creation response instead, so render the selector AFTER creation. Never invent counts.
 */
const PLANS_ENDPOINT = '<the instalment-plans endpoint from the provider API reference — not a catalog field>';

export async function fetchPlans(
  amount: string, currency: string, country: string, bin: string
): Promise<Plan[]> {
  const sticker = toMinorUnits(amount, currency);   // Rule 13: the sticker price, once
  let body: any;
  try {
    const res = await fetch(
      `${PLANS_ENDPOINT}?amount=${encodeURIComponent(amount)}&currency=${encodeURIComponent(currency)}&bin=${encodeURIComponent(bin)}`,
      { headers: { Authorization: `Bearer ${process.env.PROVIDER_SECRET_KEY!}` } } // Rule 1: env, never inline
    );
    if (!res.ok) return [];      // no plans is a valid answer — fall back to a single payment
    body = await res.json();
  } catch {
    return [];                   // the plans call is advisory: it must never take the checkout down
  }

  return (body?.plans ?? []).map((p: any): Plan => {
    const totalMinor = toMinorUnits(String(p.total_amount), currency);          // Rule 13
    return {
      installments: Number(p.installments),
      perInstallmentMinor: toMinorUnits(String(p.installment_amount), currency), // Rule 13
      totalMinor,
      // Merchant-funded exactly when the payer's total equals the sticker price.
      funding: totalMinor === sticker ? 'merchant' : 'issuer',
      planId: p.id,
    };
  });
}

/**
 * Local split — ONLY for a provisional "≈" label before the BIN is known.
 * Integer arithmetic, remainder on the first instalment, so the parts always sum to the total.
 */
export function provisionalSplit(totalMinor: bigint, n: number): bigint[] {
  if (!Number.isInteger(n) || n < 1) throw new Error(`instalment count ${n} is not a positive integer`);
  const count = BigInt(n);
  const base = totalMinor / count;                 // BigInt division truncates
  const parts = new Array<bigint>(n).fill(base);
  parts[0] = base + (totalMinor - base * count);   // Rule 13: the cents must not evaporate
  return parts;
}

export function label(plan: Plan, currency: string): string {
  const each = fromMinorUnits(plan.perInstallmentMinor, currency);
  const total = fromMinorUnits(plan.totalMinor, currency);
  // Rule 11: never show only "12x" — the total and the interest status are disclosure obligations.
  return plan.funding === 'merchant'
    ? `${plan.installments}x ${each} ${currency} — sin intereses (total ${total})`
    : `${plan.installments}x ${each} ${currency} — con intereses (total ${total})`;
}
```

Verified by running it: `provisionalSplit(10000n, 3)` returns `[3334n, 3333n, 3333n]` (sums to 10000), `provisionalSplit(10000n, 12)` returns `[837n, 833n × 11]` (sums to 10000), and `provisionalSplit(25000n, 6)` — a JPY-shaped zero-decimal total — returns `[4170n, 4166n × 5]`. A float split would render `12 × 83.33 = 999.96` and lose four cents on every order.

```ts
// app/api/checkout/route.ts (excerpt) — the instalment count on the payment call
import { randomUUID } from 'node:crypto';
import { amountForProvider } from '@/lib/payments/money';
import { installmentsAvailable, fetchPlans } from '@/lib/payments/installments';

const installments = Number(input.installments ?? 1);
if (installments > 1 && !installmentsAvailable(country, method)) {
  return NextResponse.json({ error: 'installments_unavailable' }, { status: 400 });
}

const idempotencyKey = randomUUID(); // Rule 4: canonical UUID, generated after the amount is final

await fetch('<from checkout_spec.create_endpoint>', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${process.env.PROVIDER_SECRET_KEY!}`,
    'X-Idempotency-Key': idempotencyKey,  // <from checkout_spec.idempotency.name>; omit the
                                          // header entirely when idempotency.supported is false
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    // Rule 13: the FULL price in the provider's unit — never the per-instalment slice.
    amount: amountForProvider(order.price, order.currency, '<from checkout_spec.amount_unit>'),
    currency: order.currency,
    installments,                       // <from the provider's instalment field name>
    installment_plan_id: plan?.planId,  // echo the plan the payer actually saw
  }),
});
```

## Python

```python
# lib/payments/installments.py
from lib.payments.money import to_minor_units, from_minor_units

INSTALLMENTS_BY_COUNTRY = {"BR": True, "MX": True, "AR": True}  # <from supports.installments>

INSTALLMENT_METHODS = frozenset({"card"})  # <from methods[]>; pix_parcelado only if declared

def installments_available(country: str, method: str) -> bool:
    return INSTALLMENTS_BY_COUNTRY.get(country.upper(), False) and method in INSTALLMENT_METHODS

def provisional_split(total_minor: int, n: int) -> list[int]:
    """Integer split; remainder on the first instalment so the parts sum exactly."""
    if not isinstance(n, int) or n < 1:
        raise ValueError(f"instalment count {n} is not a positive integer")
    base, remainder = divmod(total_minor, n)   # Rule 13: never float division
    parts = [base] * n
    parts[0] = base + remainder
    return parts

def classify_funding(plan_total: str, sticker: str, currency: str) -> str:
    """Merchant-funded exactly when the payer pays the sticker price."""
    return "merchant" if to_minor_units(plan_total, currency) == to_minor_units(sticker, currency) else "issuer"
```

Verified by running it: `provisional_split(10000, 3) == [3334, 3333, 3333]` and `provisional_split(10000, 12)` sums to `10000`.

## Anti-patterns

- ❌ Rendering `12x` from your own `total / 12` and calling it the price. The issuer's split will differ by cents, the payer's statement will not match the checkout, and in a *com juros* plan it will not match by a lot.
- ❌ Sending the per-instalment amount as the charge amount. You have just charged 1/12 of the order and shipped all of it.
- ❌ Offering MSI without pricing the funding cost. Twelve MSI can cost several points of extra discount rate; a merchant-funded plan on a thin-margin SKU sells at a loss.
- ❌ Assuming the money lands on the normal payout schedule. In Brazil, parcelado default is one instalment released per month; a merchant who budgeted for T+1 has a cash-flow surprise, not a bug report.
- ❌ Letting the plans call fail the checkout. It is advisory — a timeout or a 500 from the plans endpoint means "offer one payment", not "no checkout".
- ❌ Hardcoding `[3, 6, 9, 12]` because that is what the demo showed. Eligibility depends on the issuer, the BIN, the amount and the current promotion — ask, do not assume.
- ❌ Enabling the selector wherever the currency is BRL/MXN/ARS. The gate is `supports.installments[country]`, and a provider that does not declare it will reject the field at payment time.
- ❌ Floats anywhere in the split. `Math.round(total / n * 100)` reintroduces exactly the bug `fragments/money/minor_units.md` exists to prevent.
- ❌ Refunding a merchant-funded plan and expecting the funding cost back. The instalment commission is generally not returned with the principal — record `installment_funding` at charge time so the finance team can see it.

## Security rules cited

- **Rule 13** (minor units): every instalment amount is an integer in the currency's minor unit; the split is `divmod`, never float division. The provisional split is a display label, and it is marked as one.
- **Rule 4** (idempotency): `crypto.randomUUID()` on the payment call, generated after the instalment count is fixed. A retry that re-reads the selector could otherwise create a second payment on a different plan.
- **Rule 11** (minimum PII, regional regulation): the instalment disclosure — count, per-instalment amount, total, interest status — is a consumer-protection obligation in BR (CDC art. 52) and is surfaced in the report's regional section, not buried in the UI.
- **Rule 1** (no hardcoded keys): the plans endpoint is authenticated from `process.env`, like every other provider call.
- **Rule 6** (log metadata only): log the plan id and instalment count; never the BIN, and never the payload the plan arrived in.
