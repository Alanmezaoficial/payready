# E-invoicing: the fiscal document the sale still owes

A successful payment is not a compliant sale. In the markets this fragment covers, issuing the fiscal document is a legal obligation attached to the transaction — not a receipt you send if you feel like it — and the tax authority, not your customer, is the counterparty. The thing that bites is not the issuance API. It is that **the fiscal document needs identity data you can only collect at checkout, and you cannot retro-fit it.** An RFC, a CNPJ, a RUT, an SdI destination code: once the buyer has paid and closed the tab, they are gone, and a stamped document is now impossible for a sale that already legally required one. So the decision this fragment forces is a *checkout form* decision, made before the first payment, not an accounting decision made at month end.

**Providers in this family:** selection is by **region**, not provider. The only provider field that matters is `mor.is_mor`, and three of the catalog's 42 providers set it true: Lemon Squeezy, Paddle and Polar. Only Lemon Squeezy also declares `mor.handles` including `"invoicing"`, which is the field that actually says the obligation moved. Paddle and Polar carry no `handles` array at all — the catalog asserts they are the seller of record but says nothing about what they issue. Three more declare `mor.is_mor: false` outright (Stripe, Mercado Pago, Wompi) and the remaining **36 carry no `mor` block at all**. Absent is not `false` here any more than it is in PCI's exemption list — but the effect is the same and it is the safe one: `mor?.is_mor` is falsy either way, so the obligation stays yours, which is where it belongs until a provider claims otherwise in writing.

> **Composer note.** The `tax_todo` slot in `recipes/default.json` skips on `provider.mor.is_mor == true` alone, and that expression has two problems. For Paddle and Polar it skips the TODO on a claim the catalog never makes — neither declares `handles`. And for the 36 providers with no `mor` block at all it dereferences `null`, so the guard must be `provider.mor?.is_mor == true AND "invoicing" in provider.mor.handles`. Until those entries declare `handles`, treat a missing `handles` as unknown and emit the TODO — and fix it in the catalog entry, not here.

**Catalog fields this fragment reads:** `regions[CODE].tax.einvoice.mandate`, `regions[CODE].tax.einvoice.applies_to`, `regions[CODE].tax.einvoice.note`, `regions[CODE].default_currency`, `regions[CODE].languages`, `mor.is_mor`, `mor.handles`, `mor.mode`.

## The contract

1. Resolve the merchant's region and read `regions[CODE].tax.einvoice`. **No `einvoice` key means no mandate in the catalog** — emit nothing rather than inventing an obligation.
2. Read `mor.is_mor` on the chosen provider. If true and `mor.handles` includes `"invoicing"`, the obligation belongs to the MoR. Say so once, emit no TODO, and stop.
3. Otherwise, determine the fiscal-identity fields that market's document requires, and add them to the checkout form **before** the payment call. This is the only step with a deadline that has already passed once the customer leaves.
4. Validate the identifier client-side and server-side with its real check-digit algorithm. A structurally invalid RFC or CNPJ is rejected by the authority *after* the sale, which is the worst possible time to learn about it.
5. Persist the fiscal identity alongside the payment, keyed by the payment id, so the issuing step can run out of band.
6. Never issue inside the payment handler. Verify, persist, return 200, enqueue `tax.issue_document`. Stamping is a synchronous call to a third party with its own outages; a webhook that waits on it will time out and be retried, and you will stamp twice.
7. Emit `PAGOKIT_TAX_TODO.md` naming the document, the deadline, the data collected, and the issuing route chosen. **PagoKit does not issue fiscal documents** — it makes issuing them possible.

## Mandates in the catalog

Read from `regions[CODE].tax.einvoice`; deadlines confirmed against the authority before go-live, because they move.

| Region | `mandate` | `applies_to` | Document | Issued when |
|---|---|---|---|---|
| MX | `cfdi` | B2B and B2C sales | CFDI 4.0, stamped by an authorised PAC | At the transaction; stamped within 72 h of `fecha de emisión` |
| BR | `nfe` | goods and services | NF-e (goods) / NFS-e (services, municipal) | Authorised by SEFAZ **before** the goods ship |
| CL | `dte` | all sales | DTE — factura or boleta electrónica | At the sale; boletas reported to SII in near-real time |
| PE | `sunat` | all sales | CPE — factura or boleta, via an OSE/SEE | Sent to SUNAT within the current `plazo de envío` (1 calendar day) |
| CO | `dian` | all sales | Factura electrónica de venta | **Pre-validated by DIAN** before delivery to the buyer |
| EC | `sri` | all sales | Comprobante electrónico | Online authorisation; the offline scheme allows 24 h to transmit |
| IT | `sdi` | domestic B2B and B2C | Fattura elettronica via SdI | Transmitted to SdI within 12 days of the operation |

**Known mandates the catalog does not encode:** Poland (KSeF) and Saudi Arabia (ZATCA Phase 2 — invoice clearance plus a cryptographic stamp) are real obligations, and both regions now exist in `regions.json` with providers attached — but neither entry carries a `tax.einvoice` key, so the recipe's `skip_if: "region has no tax.einvoice.mandate"` fires and no TODO is emitted. That is the catalog's answer, not the law's. Argentina and Uruguay are in the same position. Adding `tax.einvoice` to those region entries — not editing this fragment — is what turns them on, which is the point: 80 regions and one fragment.

## The data you must collect at checkout

This is the retro-fit trap, market by market. Everything here is a *form field*, not a database migration.

| Region | Identifier | The rest of it |
|---|---|---|
| MX | RFC — 12 chars (moral) or 13 (física) | `razón social` **exactly as SAT holds it** (CFDI 4.0 validates the name against the RFC and rejects a mismatch), `régimen fiscal` (`c_RegimenFiscal`), `código postal` of the fiscal address, `uso del CFDI` (`c_UsoCFDI`). Público en general: RFC `XAXX010101000`, régimen `616`, uso `S01`. Foreign buyers: `XEXX010101000`. |
| BR | CPF (11) or CNPJ (14) | Full address with município + UF; for goods, NCM per line item and a CFOP. |
| CL | RUT with check digit | `giro`, address and `comuna` for a factura; boleta needs far less — decide which you issue *before* building the form. |
| PE | RUC (11) for a factura, DNI (8) for a boleta | Buyer identification is mandatory on boletas above the SUNAT threshold, so you cannot always skip it. |
| CO | NIT or cédula | `tipo de documento` and the buyer's `responsabilidades tributarias` from their RUT. |
| EC | RUC / cédula / pasaporte | `tipo de identificación` — the document code changes with it. |
| IT | Partita IVA (B2B) or Codice Fiscale (B2C) | `Codice Destinatario` (7 chars) or a PEC address for B2B; B2C uses `0000000`. |

Rule 11 still applies: collect these fields **only** when `regions[CODE].tax.einvoice` exists and the provider is not the MoR. A tax ID is regulated personal data under LFPDPPP, LGPD and the GDPR — collecting one "just in case" is a liability, not preparation.

## Node / TypeScript

```ts
// lib/tax/fiscal-identity.ts — check digits, so a bad id is caught at checkout, not by the authority
import { createHmac, timingSafeEqual } from 'node:crypto';

const RFC_RE = /^([A-ZÑ&]{3,4})(\d{2})(\d{2})(\d{2})([A-Z\d]{2})([A\d])$/;
const RFC_GENERIC = new Set(['XAXX010101000', 'XEXX010101000']); // público en general / foreign buyer

export function validRfc(v: string): boolean {
  const s = v.toUpperCase().replace(/[\s-]/g, '');
  if (RFC_GENERIC.has(s)) return true;
  const m = RFC_RE.exec(s);
  if (!m) return false;
  const month = Number(m[3]), day = Number(m[4]), yr = 2000 + Number(m[2]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const d = new Date(Date.UTC(yr > new Date().getUTCFullYear() ? yr - 100 : yr, month - 1, day));
  return d.getUTCMonth() === month - 1 && d.getUTCDate() === day; // rejects 31 February
}

export function validCpf(v: string): boolean {
  const s = v.replace(/\D/g, '');
  if (s.length !== 11 || /^(\d)\1{10}$/.test(s)) return false;
  for (const n of [9, 10]) {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += Number(s[i]) * (n + 1 - i);
    if (((sum * 10) % 11) % 10 !== Number(s[n])) return false;
  }
  return true;
}

const CNPJ_W = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
export function validCnpj(v: string): boolean {
  // charCode-48 is the official alphanumeric-CNPJ rule, and it is arithmetically identical to
  // the old digit rule for numeric ids — so this stays correct across Brazil's 2026 transition.
  const s = v.toUpperCase().replace(/[^0-9A-Z]/g, '');
  if (s.length !== 14 || /^(.)\1{13}$/.test(s) || !/^[0-9A-Z]{12}\d{2}$/.test(s)) return false;
  for (const n of [12, 13]) {
    const w = CNPJ_W.slice(CNPJ_W.length - n);
    let sum = 0;
    for (let i = 0; i < n; i++) sum += (s.charCodeAt(i) - 48) * w[i];
    const r = sum % 11;
    if ((r < 2 ? 0 : 11 - r) !== Number(s[n])) return false;
  }
  return true;
}

/** RUT (CL), RUC (PE) and NIT (CO) are one algorithm with three parameterisations. Keeping
 *  them as data rather than three near-identical functions is how new markets cost one row. */
const MOD11 = {
  CL: { field: 'rut', label: 'RUT', strip: /[^0-9K]/g, weights: [2, 3, 4, 5, 6, 7], fromRight: true,
        dv: (r: number) => (r === 0 ? '0' : r === 1 ? 'K' : String(11 - r)) },
  PE: { field: 'ruc', label: 'RUC', strip: /\D/g, weights: [5, 4, 3, 2, 7, 6, 5, 4, 3, 2], fromRight: false,
        len: 11, prefixes: ['10', '15', '17', '20'], dv: (r: number) => String((11 - r) % 10) },
  CO: { field: 'nit', label: 'NIT', strip: /\D/g, fromRight: true,
        weights: [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71],
        dv: (r: number) => String(r < 2 ? r : 11 - r) },
} as const;

export function mod11Valid(raw: string, spec: (typeof MOD11)[keyof typeof MOD11]): boolean {
  const s = raw.toUpperCase().replace(spec.strip, '');
  if (s.length < 2 || ('len' in spec && s.length !== spec.len)) return false;
  if ('prefixes' in spec && !spec.prefixes.includes(s.slice(0, 2) as never)) return false;
  const body = s.slice(0, -1);
  if (!/^\d+$/.test(body)) return false;
  let sum = 0;
  for (let i = 0; i < body.length; i++) {
    const digit = Number(spec.fromRight ? body[body.length - 1 - i] : body[i]);
    sum += digit * spec.weights[i % spec.weights.length];
  }
  return s.slice(-1) === spec.dv(sum % 11);
}

// EC and IT are mandated in the catalog but have no check-digit rule here yet. They still get
// a row, with a presence-only check: "no validator" must mean "the accredited issuer validates
// it", never "the form does not ask". Leaving them out of this table is the retro-fit trap
// firing inside the fragment meant to prevent it — the checkout would collect nothing while
// `REQUIRED_FIELD` in the issuing worker below still demands the field, so every EC and IT sale
// pays successfully and is unissuable. A missing row here is silence, and silence is the bug.
const FISCAL_ID: Record<string, { field: string; label: string; validate: (v: string) => boolean }> = {
  MX: { field: 'rfc',      label: 'RFC',      validate: validRfc },
  BR: { field: 'cpf_cnpj', label: 'CPF/CNPJ', validate: (v) => validCpf(v) || validCnpj(v) },
  CL: { ...MOD11.CL, validate: (v) => mod11Valid(v, MOD11.CL) },
  PE: { ...MOD11.PE, validate: (v) => mod11Valid(v, MOD11.PE) },
  CO: { ...MOD11.CO, validate: (v) => mod11Valid(v, MOD11.CO) },
  EC: { field: 'identificacion',      label: 'RUC / cédula / pasaporte', validate: (v) => v.length >= 5 },
  // IT accepts either form the table names: a 7-char destination code (B2C is `0000000`) or a PEC address.
  IT: { field: 'codice_destinatario', label: 'Codice Destinatario',      validate: (v) => /^[A-Z0-9]{7}$/.test(v.toUpperCase()) || /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(v) },
};

/** Throw before the payment call, never after. The caller here is the customer, so — unlike
 *  a webhook 400, which leaks nothing — this 400 names the offending field. */
export function assertFiscalIdentity(regionCode: string, input: Record<string, string>, catalog: any) {
  const einvoice = catalog.regions?.[regionCode]?.tax?.einvoice; // <from regions[CODE].tax.einvoice>
  const spec = FISCAL_ID[regionCode];
  if (!einvoice || !spec) return;                                // Rule 11: no mandate, collect nothing
  const raw = (input[spec.field] ?? '').trim();
  const fail = (msg: string) => { throw Object.assign(new Error(msg), { status: 400, field: spec.field }); };
  if (!raw) fail(`${spec.label} is required to issue the ${String(einvoice.mandate).toUpperCase()}`);
  // Not "check digit is invalid": only CPF/CNPJ/RUT/RUC/NIT carry one that is verified here.
  // An RFC is checked structurally, EC and IT for presence and shape. Naming a check digit that
  // was never computed sends the buyer hunting for a typo in a field that is merely the wrong shape.
  if (!spec.validate(raw)) fail(`${spec.label} is not valid — check the format`);
  // Rule 6: region, mandate and outcome only. Never the tax id — it is regulated PII.
  console.log('[tax.identity]', { region: regionCode, mandate: einvoice.mandate, valid: true });
}

/** Same-taxpayer dedup with no plaintext id on the comparison path. */
export function sameTaxpayer(a: string, b: string): boolean {
  const h = (v: string) => createHmac('sha256', process.env.TAX_ID_PEPPER!)
    .update(v.toUpperCase().replace(/\W/g, '')).digest();
  const [x, y] = [h(a), h(b)];
  if (x.length !== y.length) return false;  // timingSafeEqual throws on a length mismatch
  return timingSafeEqual(x, y);
}
```

## Python

```python
# workers/issue_fiscal_document.py — the out-of-band half of the contract (steps 5-6).
# Fed by enqueue("tax.issue_document", {"payment_id": ...}) from the payment handler AFTER it
# has returned 200. Never called inline: stamping is a third-party round trip, so a handler
# that waits on it times out, the provider retries the webhook, and you stamp the sale twice.
import os
from datetime import datetime, timezone
import httpx

from app.models import Payment          # whatever the project already uses; the row the sale wrote

MAX_ATTEMPTS = 5
REQUIRED_FIELD = {"MX": "rfc", "BR": "cpf_cnpj", "CL": "rut", "PE": "ruc", "CO": "nit",
                  "EC": "identificacion", "IT": "codice_destinatario"}

class Unissuable(Exception):
    """The sale is legally invoiceable but the data to invoice it was never collected."""

def issue_fiscal_document(session, catalog: dict, payment_id: str) -> str:
    payment = session.get(Payment, payment_id)

    # Rule 4: idempotent on payment_id. A queue retry must never produce a second document —
    # a duplicate CFDI or NF-e has to be cancelled with the authority, not deleted.
    if payment.fiscal_document_id:
        return payment.fiscal_document_id

    einvoice = catalog["regions"].get(payment.region_code, {}).get("tax", {}).get("einvoice")
    if not einvoice:
        return ""                       # no mandate in the catalog for this region: nothing owed

    field = REQUIRED_FIELD.get(payment.region_code)
    identity = payment.fiscal_identity or {}
    if field and not identity.get(field):
        # This is the retro-fit trap firing. It is an ops alert, not a retry: no amount of
        # requeueing will conjure an RFC the checkout form never asked for.
        raise Unissuable(f'{einvoice["mandate"]} requires {field}, absent on payment {payment_id}')

    # The accredited issuer's request shape is theirs, not PagoKit's — take the field names
    # from your PAC / OSE / NF-e gateway's docs. Only the control flow around it is generic.
    resp = httpx.post(
        os.environ["FISCAL_ISSUER_URL"],
        headers={"Authorization": f'Bearer {os.environ["FISCAL_ISSUER_TOKEN"]}'},  # Rule 1: env, never inline
        json={
            "document_type": einvoice["mandate"],
            "currency": catalog["regions"][payment.region_code]["default_currency"],
            "language": catalog["regions"][payment.region_code]["languages"][0],
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "external_id": payment_id,      # the issuer's own idempotency key
            "buyer": identity,
            "lines": [{"description": li.description, "quantity": li.quantity,
                       "unit_amount_minor": li.unit_amount_minor} for li in payment.line_items],
        },
        timeout=30,
    )
    if resp.status_code >= 500 and payment.tax_attempts < MAX_ATTEMPTS:
        payment.tax_attempts += 1
        session.commit()
        raise RuntimeError("issuer unavailable")   # let the queue back off and retry
    if resp.status_code >= 400:
        raise Unissuable(f"issuer rejected {einvoice['mandate']}: {resp.status_code}")

    # The stamp is the audit trail: UUID for a CFDI, chave de acesso for an NF-e, track id
    # for DIAN. Store it on the payment row before anything else can fail.
    payment.fiscal_document_id = resp.json()["document_id"]
    session.commit()
    # Rule 6: ids and outcome only. Never the buyer block, never the issuer's response body.
    print("[tax.issued]", {"payment_id": payment_id, "mandate": einvoice["mandate"],
                           "document_id": payment.fiscal_document_id})
    return payment.fiscal_document_id
```

The equivalent Python for the checkout-side validators is a direct transliteration of the TypeScript above — `hmac.compare_digest(x, y)` replaces `timingSafeEqual`, guarded by the same explicit length check, since `compare_digest` is only constant-time on equal-length inputs.

## `PAGOKIT_TAX_TODO.md`

Emitted only when `regions[CODE].tax.einvoice` exists **and** `mor.is_mor` is false.

```markdown
# Tax TODO — {region_name} ({REGION_CODE})

PagoKit wired up the payment. It did **not** issue any fiscal document, and it cannot:
issuing one requires a taxpayer certificate and an accredited channel that belong to you.

## The obligation
- **Document:** {einvoice.mandate | uppercase} — {document_name}
- **Applies to:** {einvoice.applies_to}
- **Deadline:** {issued_when}. Confirm against the authority before go-live; these move.
- **Currency / language:** {regions[CODE].default_currency} / {regions[CODE].languages[0]}
- Source: `regions.json → {REGION_CODE}.tax.einvoice`{einvoice.note ? " — " + einvoice.note : ""}

## Data now collected at checkout (do not remove these fields)
{per-region rows from "The data you must collect at checkout"}

Removing a field here does not simplify the form. It makes the document unissuable for every
sale after the deploy, and those sales cannot be fixed retroactively.

## Choose an issuing route
- [ ] **A merchant of record** — the MoR becomes the seller and the obligation is theirs. The
      only change that deletes this file. Costs you `mor.disables_capabilities`.
- [ ] **An accredited issuer** — a PAC (MX), an OSE/SEE (PE), an NF-e/NFS-e gateway (BR), an
      SdI intermediary (IT). You send the sale, they stamp and transmit.
- [ ] **Your ERP already issues** — push the sale into it from `tax.issue_document`. Usually
      right, and usually remembered only at the first audit.
- [ ] **Manual issuance in the authority's portal** — low volume only, and it still needs
      every checkout field above.

Wiring: `tax.issue_document` is enqueued after the handler returns 200, is idempotent on
`payment_id`, stores the stamp (CFDI UUID, NF-e chave de acesso, DIAN track id) on the
payment row, and alerts a human on failure — the sale happened either way.
```

## Anti-patterns

- ❌ Adding the tax-id field "later, in the account settings page". The obligation attaches to the sale, and by then the sale is done. This is the whole fragment in one line.
- ❌ Stamping inside the webhook handler. The PAC/OSE call is a third-party round trip; the handler times out, the provider retries, and you stamp the same sale twice.
- ❌ Validating an RFC or CNPJ with a length check alone. A structurally valid, check-digit-invalid id passes your form and is rejected by the authority after the money moved.
- ❌ Storing the buyer's name however they typed it. CFDI 4.0 matches `razón social` against the RFC at the SAT and rejects the stamp on a mismatch — the field needs its own explanation in the form.
- ❌ Assuming an MoR covers everything. `mor.handles` is an explicit list; if `"invoicing"` is not in it, the obligation is still yours.
- ❌ Logging the tax id (Rule 6). It is regulated personal data under LFPDPPP, LGPD and the GDPR, and it lands in Datadog forever.
- ❌ Emitting this TODO for a region with no `tax.einvoice` key, on the assumption that "everywhere in LATAM has e-invoicing". Argentina and Uruguay have real regimes that this catalog does not yet encode — invent nothing; add the region entry.

## Security rules cited

- **Rule 6** — the fiscal-identity path logs region, mandate and outcome. Never the identifier, never the buyer's name.
- **Rule 11** — fields are collected only where `regions[CODE].tax.einvoice` exists and the provider is not the MoR; a tax id is minimum-necessary PII, and the report's "Legal obligations in your detected region" section is generated from the same catalog key.
- **Rule 4** — the `tax.issue_document` job is idempotent on `payment_id`, so a queue retry cannot stamp twice.
- **Rule 12** — a fiscal identity is regulated PII but it is *not* card data. Nothing here weakens the PAN wall; the document carries last4 at most.
- Constant-time comparison (`timingSafeEqual` / `hmac.compare_digest`) guards `sameTaxpayer`, so taxpayer-matching cannot be probed byte by byte.
