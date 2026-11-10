# Minor units — converting a price into what the provider actually charges

Every provider takes an amount in a fixed unit, and the unit is a property of the **currency**, not of the provider. The one thing developers get wrong is `Math.round(amount * 100)`. It is correct for 81 of the 106 currencies in the catalog and catastrophically wrong for the other 25: in a zero-decimal currency the amount is already final, so `× 100` charges the customer **100× too much**; in a three-decimal currency the smallest unit is 1/1000, so `× 100` is off by **10×** — and because several providers hash the amount at its ISO exponent when they build the callback signature, the developer spends the afternoon debugging HMAC instead of the exponent.

**Providers in this family:** all 42. The split is `checkout_spec.amount_unit`: `minor` (stripe, wompi, lemonsqueezy — send the integer) vs `major` (mercadopago — send the decimal). Only those four `integration_level: build` entries declare a `checkout_spec` at all; for the 38 advise-level providers the unit comes from the provider's own reference, and reading it there does not make the exponent question go away.

**Catalog fields this fragment reads:** `checkout_spec.amount_unit`, `currencies[]` (the provider's accepted list), and from `currencies.json`: `exponent`, `zero_decimal`, `three_decimal`.

## The contract

1. Store the price as an **exact decimal in major units** plus its ISO 4217 code. A float column (`REAL`, `DOUBLE`, JS `number`) is already a bug — `DECIMAL(19,4)` / `NUMERIC` / a string.
2. Look up the exponent for that code in `currencies.json`. **Never default to 2 for a code you have not looked up.** An unknown code is a refusal, not a guess.
3. Reject the currency outright if it is not in the provider's `currencies[]` (`assertPresentable`). The provider was going to reject it anyway, after the customer committed. Keep that gate separate from the exponent lookup: a settlement currency you cannot *charge* in still needs its exponent read.
4. Scale to minor units with **integer arithmetic on the decimal string**, never `amount * 10 ** exponent` on a float.
5. Reject an amount carrying more precision than the exponent allows (`1500.50` in JPY, `19.999` in USD). Silently truncating loses money; silently rounding creates a charge nobody authorised.
6. Send it in the unit the provider wants: `amount_unit: "minor"` → the integer; `amount_unit: "major"` → the fixed-point decimal with exactly `exponent` places.
7. Persist `amount_minor` (integer), `currency`, and the `exponent` you used. Reconciliation later compares integers; it cannot compare "about 19.99".
8. Divide by `10 ** exponent` **for display only**. Never round-trip through a float on the way back into a charge, a refund or an instalment split.
9. An amount that is already a minor-unit integer leaves through `minorForProvider`, never through `toMinorUnits`. `String(10000n)` looks exactly like a major-unit price string, so the second scaling is silent and the refund is 100x.

## Node / TypeScript

```ts
// lib/payments/money.ts — the only place in the codebase allowed to scale an amount.

// Rule 13: exponents generated from skills/payment-advisor/data/currencies.json.
// Only non-2 exponents are listed; anything else the catalog vouches for is 2 (ISO 4217 default).
const EXPONENT: Record<string, number> = {
  BIF: 0, CLP: 0, DJF: 0, GNF: 0, ISK: 0, JPY: 0, KMF: 0, KRW: 0,
  PYG: 0, RWF: 0, UGX: 0, VND: 0, VUV: 0, XAF: 0, XOF: 0, XPF: 0,
  MGA: 1, MRU: 1, // ariary/ouguiya subdivide by 5, not 10; the catalog says 1 and providers
                  // disagree — read the provider's own docs before charging one.
  BHD: 3, IQD: 3, JOD: 3, KWD: 3, LYD: 3, OMR: 3, TND: 3,
};

// Rule 28: the codes this integration may PRESENT a price in, <from currencies[]>.
const PRESENTMENT_CURRENCIES = new Set<string>(['USD', 'EUR', 'GBP', 'MXN', 'BRL', 'JPY', 'CLP', 'KWD']);
// Every code it may ever scale: presentment plus <from settlement.settlement_currencies>. The
// settlement currency needs an exponent too, and it is not always one you are allowed to charge in.
const VOUCHED_CURRENCIES = new Set<string>([...PRESENTMENT_CURRENCIES, 'COP']);

const MAX_SAFE_MINOR = 9007199254740991n;

export class MoneyError extends Error {}

export function exponentFor(currency: string): number {
  const code = String(currency).toUpperCase();
  // Rule 13: refuse rather than assume 2 — an unknown exponent is an unpriced charge.
  if (!VOUCHED_CURRENCIES.has(code)) {
    throw new MoneyError(`no verified exponent for ${code} — refusing to guess it`);
  }
  return EXPONENT[code] ?? 2;
}

/** Rule 28: the checkout gate, separate from the exponent lookup. */
export function assertPresentable(currency: string): string {
  const code = String(currency).toUpperCase();
  if (!PRESENTMENT_CURRENCIES.has(code)) {
    throw new MoneyError(`currency ${code} is not accepted by this provider`);
  }
  return code;
}

/** "19.99" + USD -> 1999n. Integer arithmetic on the digits; the float never appears. */
export function toMinorUnits(amount: string, currency: string): bigint {
  const exp = exponentFor(currency);
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(String(amount).trim());
  if (!m) throw new MoneyError(`"${amount}" is not a decimal amount`);
  const [, sign, whole] = m;
  let frac = m[3] ?? '';
  if (frac.length > exp) {
    // Trailing zeros are harmless ("1500.00" in JPY); real digits are not.
    if (/[^0]/.test(frac.slice(exp))) {
      throw new MoneyError(`${amount} has more precision than ${currency} allows (exponent ${exp})`);
    }
    frac = frac.slice(0, exp);
  }
  const minor = BigInt(sign + whole + frac.padEnd(exp, '0'));
  if (minor > MAX_SAFE_MINOR || minor < -MAX_SAFE_MINOR) {
    throw new MoneyError('amount exceeds the safe integer range — send it as a string');
  }
  return minor;
}

/** 1999n + USD -> "19.99". Display and provider-major serialisation only. */
export function fromMinorUnits(minor: bigint | number, currency: string): string {
  const exp = exponentFor(currency);
  const n = BigInt(minor);
  const neg = n < 0n;
  const digits = (neg ? -n : n).toString().padStart(exp + 1, '0');
  const cut = digits.length - exp;
  return (neg ? '-' : '') + (exp === 0 ? digits : `${digits.slice(0, cut)}.${digits.slice(cut)}`);
}

/**
 * An amount that is ALREADY an integer in minor units -> the wire value. Refunds, payouts and
 * instalments all hold minor-unit integers; sending one back through `toMinorUnits` reads it as
 * a major-unit price and scales it a second time — a 100x refund that no test with a whole-unit
 * amount will catch. This is the only correct exit for a minor-unit integer.
 */
export function minorForProvider(minor: bigint, currency: string, unit: 'minor' | 'major'): number | string {
  if (unit === 'minor') {
    if (minor > MAX_SAFE_MINOR || minor < -MAX_SAFE_MINOR) {
      throw new MoneyError('amount exceeds the safe integer range — send it as a string');
    }
    return Number(minor);                              // e.g. Stripe: 1999
  }
  return fromMinorUnits(minor, currency);              // e.g. Mercado Pago: "19.99"
}

/** The single call the checkout route makes, from a major-unit price string.
 *  `unit` is <from checkout_spec.amount_unit>. */
export function amountForProvider(amount: string, currency: string, unit: 'minor' | 'major'): number | string {
  assertPresentable(currency);                         // Rule 28: refuse before the customer commits
  return minorForProvider(toMinorUnits(amount, currency), currency, unit);
}
```

Verified by running it: `toMinorUnits('19.99','USD') === 1999n`, `('1500','JPY') === 1500n`, `('1500.00','JPY') === 1500n`, `('1500.50','JPY')` throws, `('8.115','KWD') === 8115n`, `('8.11','KWD') === 8110n`, `('1.005','USD')` throws (where `Math.round(1.005*100)` silently returns **100**, undercharging by a cent), and `fromMinorUnits(8115n,'KWD') === '8.115'`. `minorForProvider(10000n,'BRL','minor') === 10000` where `amountForProvider(String(10000n),'BRL','minor')` returns **1000000** — the same 100x, arriving through the refund path instead of the checkout one. `exponentFor('COP')` returns 2 so the settlement path can scale it, while `assertPresentable('COP')` still refuses it at checkout.

### When the provider wants a JSON number, not a string

Mercado Pago's `transaction_amount` is a JSON *number* in major units. A quoted string is rejected, so the string has to become a double at the last moment:

```ts
const major = amountForProvider(price, currency, 'major') as string; // "19.99"
const body = { transaction_amount: Number(major), currency_id: currency };
// Safe only because JSON.stringify emits the shortest round-tripping repr:
// JSON.stringify({a: Number("19.99")}) === '{"a":19.99}'  (verified)
// This holds up to 15 significant digits. Past that, keep the string and use a provider field that accepts one.
```

## Python

```python
# lib/payments/money.py
import re
from decimal import Decimal, InvalidOperation

# Rule 13: generated from skills/payment-advisor/data/currencies.json (non-2 exponents only).
EXPONENT = {
    "BIF": 0, "CLP": 0, "DJF": 0, "GNF": 0, "ISK": 0, "JPY": 0, "KMF": 0, "KRW": 0,
    "PYG": 0, "RWF": 0, "UGX": 0, "VND": 0, "VUV": 0, "XAF": 0, "XOF": 0, "XPF": 0,
    "MGA": 1, "MRU": 1,   # subunit of 5 — read the provider's docs, not this table
    "BHD": 3, "IQD": 3, "JOD": 3, "KWD": 3, "LYD": 3, "OMR": 3, "TND": 3,
}
PRESENTMENT_CURRENCIES = frozenset({"USD", "EUR", "GBP", "MXN", "BRL", "JPY", "CLP", "KWD"})  # <from currencies[]>
VOUCHED_CURRENCIES = PRESENTMENT_CURRENCIES | {"COP"}  # + <from settlement.settlement_currencies>
DECIMAL_RE = re.compile(r"-?\d+(?:\.\d+)?\Z")  # no 1e3, no nan, no Infinity — same grammar as the TS regex

class MoneyError(ValueError):
    pass

def exponent_for(currency: str) -> int:
    code = str(currency).upper()
    if code not in VOUCHED_CURRENCIES:  # Rule 13: refuse, do not default to 2
        raise MoneyError(f"no verified exponent for {code}")
    return EXPONENT.get(code, 2)

def assert_presentable(currency: str) -> str:
    code = str(currency).upper()
    if code not in PRESENTMENT_CURRENCIES:  # Rule 28: the checkout gate
        raise MoneyError(f"currency {code} is not accepted by this provider")
    return code

def to_minor_units(amount, currency: str) -> int:
    exp = exponent_for(currency)
    text = str(amount).strip()  # str() first: Decimal(19.99) would import the float's error
    if not DECIMAL_RE.match(text):
        # Without this, Decimal accepts "1e3", "nan" and "Infinity"; "Infinity" then leaves
        # to_minor_units as an OverflowError the caller is not catching.
        raise MoneyError(f"{amount!r} is not a decimal amount")
    try:
        d = Decimal(text)
    except InvalidOperation as exc:
        raise MoneyError(f"{amount!r} is not a decimal amount") from exc
    scaled = d.scaleb(exp)
    if scaled != scaled.to_integral_value():
        raise MoneyError(f"{amount} has more precision than {currency} allows (exponent {exp})")
    return int(scaled)

def from_minor_units(minor: int, currency: str) -> Decimal:
    return Decimal(int(minor)).scaleb(-exponent_for(currency))

def minor_for_provider(minor: int, currency: str, unit: str):
    """An amount ALREADY in minor units -> the wire value. Never re-enter to_minor_units with it."""
    return int(minor) if unit == "minor" else format(from_minor_units(minor, currency), "f")

def amount_for_provider(amount, currency: str, unit: str):
    assert_presentable(currency)  # Rule 28
    return minor_for_provider(to_minor_units(amount, currency), currency, unit)
```

Verified by running it: the same vectors pass, and the `Decimal(str(x))` guard turns float contamination into a loud failure — `to_minor_units(0.1 + 0.2, "USD")` raises, because `str(0.1+0.2)` is `'0.30000000000000004'`. That is the desired outcome: a float that has already drifted must never become a charge.

## Anti-patterns

- ❌ `Math.round(amount * 100)` — 100× overcharge in the 16 zero-decimal currencies (JPY, KRW, VND, CLP, PYG, ISK, XAF, XOF…), 10× in the 7 three-decimal ones (KWD, BHD, OMR, JOD, TND, IQD, LYD).
- ❌ `amount / 100` on the way out for a zero-decimal currency — a ¥25,000 order renders as ¥250 in the receipt and the customer emails support, not you.
- ❌ Assuming IDR is zero-decimal because rupiah prices are large. ISO 4217 and `currencies.json` both say **exponent 2**. Assuming either way without reading the catalog is the actual bug; the direction of the assumption is luck.
- ❌ Defaulting an unrecognised code to 2. That is the `× 100` bug with extra steps.
- ❌ `parseFloat(price)` anywhere between the database and the provider. `19.99 * 100` is `1998.9999999999998`; `4.475 * 100` is `447.49999999999994`, which rounds **down** to 447.
- ❌ `toFixed(2)` as the money formatter — `(1.005).toFixed(2)` is `"1.00"`, and it hardcodes 2 decimals for every currency.
- ❌ Storing only the major-unit decimal and re-deriving `amount_minor` per call. Two call sites, two roundings, one reconciliation mismatch.
- ❌ Scaling the amount again inside the refund or instalment path — `amountForProvider(String(minorAmount), …)`. The argument is a major-unit price string; a minor-unit integer stringified is indistinguishable from one, and it is scaled twice. Use `minorForProvider`.
- ❌ Reusing the "is this currency accepted" gate as the exponent lookup. The FX and settlement paths need the exponent of a currency the provider may never let you present in, and a shared gate makes reconciliation throw.

## Security rules cited

- **Rule 13** (minor units): the exponent comes from `currencies.json`, never from a literal 100. `hooks/checks/minor-units.js` denies an amount-shaped `× 100` in a payments file that also names a zero- or three-decimal currency; this helper is what makes the check pass honestly rather than via `// pagokit-ignore`.
- **Rule 4** (idempotency): the idempotency key is generated *after* the amount is final, so a retry replays the same integer. Re-scaling inside a retry is how one order becomes two different charges.
- **Rule 3 / Rule 9** (signature, replay): providers that include the amount in the signed payload hash it at its ISO exponent. A wrong exponent presents as a signature mismatch on the callback, which sends the developer to the HMAC code rather than to this file.
- **Rule 25** (never trust a client-supplied amount): `toMinorUnits` takes the price the server looked up from the cart or catalog row. Converting an amount that arrived in the request body just converts the attacker's number correctly.
- **Rule 28** (currency the provider does not support): `PRESENTMENT_CURRENCIES` is generated from the provider's `currencies[]`, so an unsupported code fails in your code with a clear message instead of at the provider's API on the first live checkout. `VOUCHED_CURRENCIES` adds `settlement.settlement_currencies` — codes you must be able to scale but must not price in.
- **Rule 6** (log metadata only): log `amount_minor` and `currency` if you must; never the payload the amount arrived in.
