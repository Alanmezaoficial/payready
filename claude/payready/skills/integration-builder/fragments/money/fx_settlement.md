# FX and settlement — presentment currency is not settlement currency

Three currencies exist in every cross-border payment and developers store one. The **presentment currency** is what the payer saw and agreed to. The **settlement currency** is what the provider deposits in your bank. The **accounting currency** is what your P&L is denominated in. When they differ, somebody converts, and whoever converts takes a spread — usually the provider, typically 1–2% on top of the interbank rate, and it is *not* itemised on the charge object. The mistake that costs a quarter of finance's time is storing only the presented amount: from `amount = 100.00, currency = USD` you cannot tell later whether the 512.30 BRL that landed was an FX move, a fee change, or a partial refund. All three look identical — "we got less than we expected".

**Providers in this family:** every provider that settles in a currency it does not always present in. In the current catalog only `wompi` declares the fields explicitly (`settlement_currencies: ["COP"]`, `presentment_currencies: ["COP"]` — no FX at all, which is itself worth recording). The other 41 providers omit them, and **an omitted field is not a promise that presentment equals settlement** — it means nobody has verified it, so the integration must record both sides and let the first real payout prove it.

**Catalog fields this fragment reads:** `settlement.presentment_currencies`, `settlement.settlement_currencies`, `settlement.fx_markup_pct`, `settlement.payout_delay_days`, `settlement.holds_funds`, `currencies[]`, `fees.*`, and the exponent of each currency from `currencies.json`.

## The contract

1. Decide the presentment currency per market **before** checkout, and never convert a displayed price at request time. A price that moves with the spot rate is a price the customer will screenshot.
2. Persist the presented side at authorisation: `presented_amount_minor`, `presented_currency`. That is the number the customer agreed to and the number a dispute is judged on.
3. Persist the settled side when the **settlement report or payout** arrives — not when the charge succeeds. At charge time the settled amount does not exist yet; the provider has not converted anything.
4. Store the rate as a **decimal string** with its source and quote time (`fx_rate`, `fx_rate_source`, `fx_quoted_at`). A rate is evidence, not an input: never multiply money by a rate you looked up afterwards to "fill in" a missing amount.
5. Store the two deductions separately: `fx_fee_minor` (the conversion spread) and `provider_fee_minor` (the MDR). Netting them into one number destroys the only signal that tells you the provider changed your pricing.
6. Every fee and converted amount is an integer in the **settlement** currency's minor unit; the presented amount is an integer in the **presentment** currency's minor unit. Two currencies, two exponents (`fragments/money/minor_units.md`).
7. Reconcile against the identity `converted − fx_fee − provider_fee = settled`, in integers. Non-zero drift is an alert, not a rounding excuse.
8. Reconcile at the **payout batch**, not the charge. One payout nets many charges, refunds and chargebacks; a per-charge reconciliation will never balance.

## The seven columns

```sql
-- Migration: settlement facts. Each column answers a question the others cannot.
ALTER TABLE pagokit_payments
  ADD COLUMN presented_amount_minor  BIGINT      NOT NULL,  -- what the payer agreed to
  ADD COLUMN presented_currency      CHAR(3)     NOT NULL,
  ADD COLUMN settled_currency        CHAR(3),               -- NULL until the payout lands
  ADD COLUMN converted_amount_minor  BIGINT,                -- gross, in settled_currency, at fx_rate
  ADD COLUMN fx_rate                 NUMERIC(20,10),        -- evidence; never an input to an amount
  ADD COLUMN fx_rate_source          TEXT,                  -- 'provider_balance_txn' | 'ecb' | ...
  ADD COLUMN fx_quoted_at            TIMESTAMPTZ,
  ADD COLUMN fx_fee_minor            BIGINT,                -- the conversion spread, itemised
  ADD COLUMN provider_fee_minor      BIGINT,                -- the MDR, itemised separately
  ADD COLUMN settled_amount_minor    BIGINT,                -- net that actually hit the bank
  ADD COLUMN payout_id               TEXT;                  -- which batch it landed in
```

## Node / TypeScript

```ts
// lib/payments/fx.ts
import { exponentFor } from './money';

/**
 * Convert presented minor units to settled minor units at a decimal rate, in integers.
 * Both exponents come from currencies.json — a USD→JPY conversion crosses exponent 2 to 0.
 * The settlement currency has to be in the money module's vouched set even when the provider
 * will not let you *present* a price in it (`fragments/money/minor_units.md`).
 */
export function convertAtRate(
  presentedMinor: bigint, presentedCurrency: string, rate: string, settledCurrency: string
): bigint {
  const expIn = exponentFor(presentedCurrency);    // Rule 13
  const expOut = exponentFor(settledCurrency);     // Rule 13: the target exponent is a different number
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(rate).trim());
  if (!m) throw new Error(`"${rate}" is not a positive decimal rate`);
  const rateScale = (m[2] ?? '').length;
  const rateInt = BigInt(m[1] + (m[2] ?? ''));

  // BigInt division truncates toward zero, so a signed amount would round the wrong way on a
  // tie. Round the magnitude, then reapply the sign — a refund row must mirror its charge.
  const neg = presentedMinor < 0n;
  const num = (neg ? -presentedMinor : presentedMinor) * rateInt * 10n ** BigInt(expOut);
  const den = 10n ** BigInt(rateScale + expIn);
  const q = num / den, r = num % den;
  const rounded = r * 2n >= den ? q + 1n : q;      // half-up, computed on integers only
  return neg ? -rounded : rounded;
}

/** The identity that must hold on every settled row. Drift is an alert, not a rounding excuse. */
export function reconcile(row: {
  converted_amount_minor: string; fx_fee_minor: string;
  provider_fee_minor: string; settled_amount_minor: string;
}): { balanced: boolean; driftMinor: bigint } {
  const drift = BigInt(row.converted_amount_minor)
    - BigInt(row.fx_fee_minor) - BigInt(row.provider_fee_minor) - BigInt(row.settled_amount_minor);
  return { balanced: drift === 0n, driftMinor: drift };
}

/** Reporting only. Derived from stored amounts — never used to reconstruct one. */
export function effectiveSpreadPct(row: {
  converted_amount_minor: string; fx_fee_minor: string;
}): number {
  const gross = Number(row.converted_amount_minor);
  return gross === 0 ? 0 : (Number(row.fx_fee_minor) / gross) * 100;
}
```

Verified by running it: `convertAtRate(10000n,'USD','5.4321','BRL') === 54321n` (100.00 USD → 543.21 BRL); `convertAtRate(10000n,'USD','155.25','JPY') === 15525n` — 15,525 yen, not 155.25, because the target exponent is 0; `convertAtRate(25000n,'CLP','0.00105','USD') === 2625n` (25,000 CLP → $26.25, crossing exponent 0 → 2); `convertAtRate(100000n,'KWD','3.26','USD') === 32600n` (100.000 KWD → $326.00, crossing 3 → 2); and `convertAtRate(1n,'USD','5.4321','BRL') === 5n` (one cent → 0.054321 BRL, half-up to 0.05). `reconcile` returns `driftMinor: 878n` on a row where the fees do not explain the shortfall. A rate of `-5`, `1e3` or `5.` is refused in both languages rather than silently converted.

## Python

```python
# lib/payments/fx.py
import re
from decimal import Decimal, ROUND_HALF_UP
from lib.payments.money import from_minor_units, exponent_for

RATE_RE = re.compile(r"\d+(?:\.\d+)?\Z")  # same grammar as the TS regex: no sign, no 1e-3, no nan

def convert_at_rate(presented_minor: int, presented_currency: str, rate: str, settled_currency: str) -> int:
    text = str(rate).strip()
    if not RATE_RE.match(text):
        # Without this, Decimal("-5") converts happily and a negative rate turns a settlement
        # into money owed; Decimal("abc") escapes as decimal.InvalidOperation instead.
        raise ValueError(f'"{rate}" is not a positive decimal rate')
    major = from_minor_units(presented_minor, presented_currency)         # Decimal, exact
    scaled = (major * Decimal(text)).scaleb(exponent_for(settled_currency))  # Rule 13: target exponent
    return int(scaled.quantize(Decimal(1), rounding=ROUND_HALF_UP))

def reconcile(row: dict) -> tuple[bool, int]:
    drift = (int(row["converted_amount_minor"]) - int(row["fx_fee_minor"])
             - int(row["provider_fee_minor"]) - int(row["settled_amount_minor"]))
    return drift == 0, drift
```

Verified by running it: identical results to the Node version on all five conversion vectors and both reconcile cases. That agreement is the point — a settlement figure computed by the worker and by the report must not differ by a cent.

## Dynamic currency conversion — why to turn it off

DCC is the checkout offering to bill a foreign cardholder in *their* home currency: "pay 92.40 EUR instead of 100.00 USD". The rate is set by the DCC provider, the markup is typically 3–7%, and a share of it is rebated to the merchant — which is precisely why it gets enabled. It is a bad trade. The payer sees a worse rate than their own bank would have given, card scheme rules require an explicit informed opt-in with the markup disclosed and the original amount shown, and a DCC transaction the payer did not understand they accepted is a well-worn chargeback narrative. It also poisons your data: the presented amount is now in a currency you never priced in, so `presented_currency` no longer means "the currency of your price list". If DCC is enabled, record `dcc_applied`, the original currency and the original amount alongside the seven columns, or the reconciliation above cannot balance.

## Multi-currency vs single-currency pricing

**Single-currency** — one presentment currency for everyone. The payer's issuer converts and may add a foreign-transaction fee, so the customer sees an unfamiliar number on their statement. Simplest to reconcile (`presented_currency` is constant), and it measurably depresses conversion outside your home market.

**Multi-currency** — a price list per market. Conversion improves, and you take FX risk on the *pricing*, not on the settlement: your BRL price is fixed while the rate moves, so your USD-equivalent margin drifts until you reprice. Price in **round local numbers** (`R$ 49,90`, not `R$ 187,43`), review on a schedule, and never generate the local price by multiplying the USD price by today's rate at render time — that is how a customer gets two different prices on two page loads.

Either way: `presentment_currencies` and `settlement_currencies` must both be recorded per payment. Reconciliation is not a question of which strategy you picked, it is a question of whether you kept both numbers.

## Anti-patterns

- ❌ Storing only `amount` + `currency`. Six months later, nobody can separate an FX move from a fee change from a partial refund.
- ❌ Filling `settled_amount_minor` at charge time by multiplying by a rate you fetched yourself. The provider had not converted anything yet; you have invented a number that will disagree with the bank.
- ❌ Netting the FX spread into the processing fee. That one column collapse hides a provider repricing your account.
- ❌ Converting with floats. `presented * rate` on doubles drifts by cents per transaction and by real money per month.
- ❌ Reusing the checkout's "does the provider accept this currency" gate to look up the settlement exponent. The currency you are paid in is often one you may not price in, and the reconciliation job throws on the first payout.
- ❌ Applying the presentment currency's exponent to the settled amount. USD → JPY crosses exponent 2 → 0; the wrong exponent is a 100× reporting error.
- ❌ Reconciling per charge instead of per payout batch. A payout nets refunds and chargebacks; per-charge reconciliation never balances and everyone stops looking at the alert.
- ❌ Enabling DCC because of the rebate. You are selling your customers a 3–7% markup and buying chargeback exposure with the proceeds.
- ❌ Assuming settlement equals presentment because the provider entry has no `settlement_currencies`. Absent is unverified, not confirmed.

## Security rules cited

- **Rule 13** (minor units): every amount is an integer in *its own* currency's minor unit, and the conversion reads both exponents from `currencies.json` rather than assuming they match.
- **Rule 6** (log metadata only): settlement logs carry `payout_id`, `payment_id` and the drift — never the payout payload, which itemises customers.
- **Rule 18** (fast ack): the payout/settlement webhook verifies, records `payout_id`, returns 200, and does the batch reconciliation out of band. Reconciling several thousand charges inline blows the provider's ack deadline and earns a retry storm.
- **Rule 3 / Rule 9** (signature, replay): the settlement webhook is authenticated and deduped like any other — a forged payout event would let an attacker rewrite your books.
- **Rule 28** (currency the provider does not support): the presentment currency is checked against `currencies[]` before it is ever displayed as a price — a market you cannot settle is a market you must not price in.
- **Rule 11** (regional regulation): CFDI 4.0 (MX) and NF-e (BR) invoicing require the transaction currency and, on a foreign-currency sale, the rate applied — which is `fx_rate` plus `fx_quoted_at`, and is unreconstructable if you did not store them.
