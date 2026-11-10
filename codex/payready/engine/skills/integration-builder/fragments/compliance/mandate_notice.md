# Direct-debit mandate pre-notification

On a direct-debit rail the payer is not present at the moment of the debit — you are reaching into their account on the strength of a mandate they signed once. Every scheme compensates for that by requiring **advance notice before each collection**, and it is a condition of the debit rather than a courtesy: miss it and the payer's indemnity claim succeeds automatically, which on Bacs means up to 395 days later, and on SEPA means 8 weeks no-questions-asked. The thing developers get wrong is the direction of the dependency. They pick a collection date, create the charge, and send "your payment is being processed" — at which point the notice window has already closed and the debit is unlawful the moment it settles. **The notice does not follow the collection date; the collection date follows the notice.** Every scheduling function below is written that way: you ask for the earliest date you may legally collect, and the answer is a function of today plus the rail's lead time.

**Providers in this family:** of the catalog's 42 providers, exactly one qualifies today — Stripe, with `recurring.mandate_lifecycle: true` and `recurring.rails: ["card", "sepa_debit", "ach_debit"]`. Every other provider either sets `mandate_lifecycle: false` or carries no `recurring` block at all, so the recipe skips this fragment for them. That gate is narrower than method coverage, deliberately: `methods.json` carries eight rails at `category: "direct_debit"` — `ach_debit`, `bacs_debit`, `becs_debit`, `pac_chile`, `payto`, `pix_automatico`, `sepa_debit`, `upi_autopay` — and each of the eight is offered by at least one provider (GoCardless three of them, Airwallex `becs_debit` and `payto`, Razorpay `upi_autopay`, Fintoc `pac_chile`, Asaas `pix_automatico`). All of those entries are `integration_level: advise`, and none declares a mandate lifecycle. **Listing a direct-debit rail is not the same as having the mandate lifecycle to schedule notices on it**, and the gate is the second one. This fragment ships ahead of those waves, which is why the rail table below is keyed by rail and not by provider.

> **Composer note.** Nothing selects this fragment yet. `recipes/default.json` references `compliance/pci_script_inventory.md` and `compliance/einvoice.md`, but no slot lists `compliance/mandate_notice.md`, so the composer will never emit it and the gate in step 1 below is currently unreachable. It belongs on the `billing/subscription_mandate` slot, or on a new slot with `skip_if: "provider.recurring?.mandate_lifecycle != true OR no rail in provider.recurring.rails has methods[rail].category == 'direct_debit'"`. Fix that in the recipe, not here.

**Catalog fields this fragment reads:** `recurring.mandate_lifecycle`, `recurring.rails`, `recurring.network_txn_id_required`, `methods[rail].category`, `methods[rail].reversibility`, `methods[rail].reversal_window_days`, `methods[rail].notes`, `regions[CODE].languages`.

## The contract

1. Gate on the catalog: emit nothing unless `recurring.mandate_lifecycle` is true and some rail in `recurring.rails` has `methods[rail].category == "direct_debit"`. A card-on-file subscription has no pre-notification duty; conflating the two produces notices nobody needs and trains users to ignore them.
2. Derive the collection date **from** the notice deadline, never the reverse. `earliestCollectionDate(rail, now)` is the only legal starting point for a first debit.
3. Count in the rail's own unit. SEPA and PAD count calendar days; Bacs counts **working** days, so weekends and bank holidays push the date out. Counting Bacs in calendar days is silently four days late in a normal month.
4. Put every field the scheme mandates in the notice — amount, collection date, mandate reference, creditor/service-user identity — in the payer's language (`regions[CODE].languages[0]`). A notice that omits the amount is not a notice.
5. Re-arm on change. A different amount or a different date is a **new** notice with a fresh full lead time, on SEPA, Bacs and PAD alike. The dedup key must therefore include the amount, or a price rise ships silently.
6. Emit exactly once per (mandate, collection date, amount). Insert the row, then enqueue; never send the email inside the scheduling transaction (Rule 4's idempotency argument, applied to outbound mail).
7. Persist what you sent. When the indemnity claim arrives — 56 days on SEPA, 395 on Bacs — the notice record is the only evidence you have.
8. Record the reversal exposure. `methods[rail].reversibility` is `mandate_indemnity` on every rail in the table below that the catalog carries — `sepa_debit`, `bacs_debit`, `ach_debit`, and also `pac_chile`, `payto`, `pix_automatico`, `upi_autopay`. The one exception is `becs_debit`, which is `refund_only`; read the field rather than assuming, because the remedy differs. Either way a "successful" charge is not final, and downstream code must not treat settlement as revenue.

## The rails

| Rail | Notice lead | Unit | The notice must state | `reversal_window_days` |
|---|---|---|---|---|
| `sepa_debit` | 14 (default; the mandate may agree otherwise) | calendar | Amount, due date, Unique Mandate Reference, Creditor Identifier | 56 — plus 13 months if unauthorised |
| `bacs_debit` | 10 (a shorter period only if agreed with your sponsoring bank/PSP) | **working** | Amount, collection date, Service User name, the Direct Debit Guarantee | 395 |
| `pad_ca` (Canada, Rule H1) | 10 for a variable amount, unless waived in the PAD agreement | calendar | Amount, due date, recourse rights, how to cancel | not in the catalog |
| `upi_autopay` | 24 **hours** | hours | Amount, debit date, UMN; AFA required above the per-transaction limit | not stated |
| `ach_debit` (Nacha) | 10 on an amount change, 7 on a date change | calendar | New amount or new effective date | 60 |

`upi_autopay`'s AFA threshold has moved more than once and differs by mandate category — read it from configuration and never hardcode it. `pad_ca` is not in `methods.json`; when it is added, this table row is what its entry should encode.

`becs_debit` (AU) **is** in the catalog as a direct-debit rail but has no row in `NOTICE`, so `leadFor` throws `no pre-notification rule for rail "becs_debit" — do not debit`. That is the correct failure, not a gap to paper over: BECS carries its own advance-notice duty under the payer's Direct Debit Request Service Agreement, and inventing a lead time produces a notice that is confidently wrong. Add the row from the scheme rules, or use PayTo — which `methods.json` already recommends for new AU integrations.

## Node / TypeScript

```ts
// lib/mandates/notice-schedule.ts
import { createHmac, timingSafeEqual } from 'node:crypto';
import { enqueue } from '@/lib/queue';

type Unit = 'calendar' | 'business' | 'hours';
type Rail = { lead: number; unit: Unit; mandateMayShorten?: boolean; onChangeOnly?: boolean };

// Lead times are scheme rules, not catalog data — methods.json carries the reversal window,
// not the notice window. Keep them here, one row per rail, and cite the scheme in review.
const NOTICE: Record<string, Rail> = {
  sepa_debit:  { lead: 14, unit: 'calendar', mandateMayShorten: true },  // "unless the mandate agrees otherwise"
  bacs_debit:  { lead: 10, unit: 'business' },                           // shortening needs your sponsoring bank
  pad_ca:      { lead: 10, unit: 'calendar', mandateMayShorten: true },  // the payor may waive, in the agreement
  upi_autopay: { lead: 24, unit: 'hours' },                              // scheme-fixed
  ach_debit:   { lead: 10, unit: 'calendar', onChangeOnly: true },       // Nacha: 10 on amount, 7 on date
};

const iso = (d: Date) => d.toISOString().slice(0, 10);
const isWeekend = (d: Date) => d.getUTCDay() === 0 || d.getUTCDay() === 6;

/** Business days skip weekends AND the scheme calendar. Bacs does not settle on a bank holiday,
 *  so a holiday set that is empty or stale makes every notice in that month late. */
function shiftDays(from: Date, n: number, unit: Unit, holidays: Set<string>): Date {
  const d = new Date(from.getTime());
  if (unit === 'calendar') { d.setUTCDate(d.getUTCDate() + n); return d; }
  const step = n < 0 ? -1 : 1;
  for (let left = Math.abs(n); left > 0; ) {
    d.setUTCDate(d.getUTCDate() + step);
    if (!isWeekend(d) && !holidays.has(iso(d))) left--;
  }
  return d;
}

/** A longer lead is always allowed. A SHORTER one only where the scheme lets the mandate
 *  agree it — and only from a value recorded on the mandate. A checkbox in your UI is not a
 *  mandate, and an undocumented shortcut is an unlawful debit, so the scheme floor wins. */
function leadFor(rail: string, mandate: { notice_lead_days?: number | null }): Rail {
  const spec = NOTICE[rail];
  if (!spec) throw new Error(`no pre-notification rule for rail "${rail}" — do not debit`);
  const override = mandate.notice_lead_days;
  if (override == null) return spec;
  if (override > spec.lead) return { ...spec, lead: override };
  if (spec.mandateMayShorten) return { ...spec, lead: Math.max(0, override) };
  return spec;
}

export function noticeDueAt(rail: string, collectionDate: string, mandate = {}, holidays = new Set<string>()): Date {
  const spec = leadFor(rail, mandate);
  const at = new Date(`${collectionDate}T00:00:00.000Z`);
  if (spec.unit === 'hours') return new Date(at.getTime() - spec.lead * 3_600_000);
  return shiftDays(at, -spec.lead, spec.unit, holidays);
}

/** The only legal starting point for a first debit. Ask this BEFORE showing the customer a date. */
export function earliestCollectionDate(rail: string, now: Date, mandate = {}, holidays = new Set<string>()): string {
  const spec = leadFor(rail, mandate);
  const from = new Date(`${iso(now)}T00:00:00.000Z`);
  if (spec.unit === 'hours') return iso(new Date(from.getTime() + Math.ceil(spec.lead / 24) * 86_400_000));
  return iso(shiftDays(from, spec.lead, spec.unit, holidays));
}

/** Moves the date rather than notifying late. A late notice is worse than a moved collection
 *  date: the debit still settles, and the indemnity claim against it cannot be defended.
 *
 *  `sendNow` matters. Counting working days backwards from the floor is not the exact inverse
 *  of counting forwards when today is a weekend or a bank holiday, so `due` can land on or
 *  before today. That is not "already late": the floor was computed forwards from today, so
 *  dispatching immediately still gives the payer the full lead. Treat sendNow as "send in
 *  this run", not as an error. */
export function scheduleCollection(rail: string, wanted: string, now: Date, mandate = {}, holidays = new Set<string>()) {
  const earliest = earliestCollectionDate(rail, now, mandate, holidays);
  const collectionDate = wanted < earliest ? earliest : wanted;
  const due = noticeDueAt(rail, collectionDate, mandate, holidays);
  return { collectionDate, noticeDueAt: due, sendNow: due <= now, pushed: collectionDate !== wanted };
}

/** Rule 4 applied to outbound mail: the key includes the amount, so a price change re-arms
 *  the notice (required on SEPA, Bacs and PAD) while a re-run of the scheduler does not resend. */
export async function emitNoticeOnce(db: any, n: {
  mandate_id: string; rail: string; collection_date: string; amount_minor: number; currency: string;
}) {
  try {
    await db.mandateNotice.create({ data: { ...n, notice_key: `${n.mandate_id}:${n.collection_date}:${n.amount_minor}` } });
  } catch (err: any) {
    // ONLY a unique violation means "already notified". A bare `catch {}` here reports a dead
    // database as an idempotent no-op: the scheduler looks healthy, no notice is ever sent, and
    // every debit that follows is indemnity-claimable — 56 days on SEPA, 395 on Bacs. Anything
    // that is not the constraint firing must reach the queue's retry and the on-call.
    const unique = err?.code === 'P2002'                 // Prisma
      || err?.code === '23505'                           // Postgres / node-postgres
      || err?.code === 'ER_DUP_ENTRY'                    // MySQL
      || err?.name === 'SequelizeUniqueConstraintError';
    if (!unique) throw err;
    return { sent: false, duplicate: true };
  }
  // Enqueue, never send here. Rendering and delivery are slow and fail independently of the
  // scheduling transaction; an SMTP timeout must not roll back the notice record.
  await enqueue('mandate.send_notice', { mandate_id: n.mandate_id, collection_date: n.collection_date });
  // Rule 6: mandate id, rail and date. Never the IBAN, the account number or the payer's name.
  console.log('[mandate.notice]', { mandate_id: n.mandate_id, rail: n.rail, collection_date: n.collection_date });
  return { sent: true, duplicate: false };
}

/** Every notice carries a manage/cancel link. Compare its token in constant time. */
export function verifyNoticeToken(mandateId: string, token: string): boolean {
  const want = createHmac('sha256', process.env.MANDATE_NOTICE_SECRET!).update(mandateId).digest('hex');
  const [a, b] = [Buffer.from(want, 'utf8'), Buffer.from(token, 'utf8')];
  if (a.length !== b.length) return false;        // timingSafeEqual throws on a length mismatch
  return timingSafeEqual(a, b);
}
```

Verified against the UK 2026 bank-holiday set. A collection on `2026-09-30` puts the Bacs notice deadline at `2026-09-16`; counting those same 10 days on the calendar gives `2026-09-20` — four days late, every time, silently. SEPA's 14 calendar days happen to land on `2026-09-16` too in that month, which is a coincidence and not a reason to share the code path. Asked on Monday 31 August 2026 (a UK bank holiday) for the earliest Bacs collection, `scheduleCollection` returns `2026-09-14` with `sendNow: true`; a mandate that records a 5-day SEPA lead moves the SEPA floor to `2026-09-05`, while a mandate claiming a 2-day Bacs lead is ignored and the floor stays at `2026-09-14`.

## Python

```python
# lib/mandates/notice_render.py — contract step 4, enforced: a notice missing a field the
# scheme mandates is not a notice, and must never leave the queue. Consumes the schedule
# produced by notice-schedule.ts (or its transliteration) and is called by the send worker.
import hmac, os
from hashlib import sha256

# Every field here is required BY THE SCHEME, not by the template. Adding a field is a
# product decision; removing one is a compliance incident.
MANDATORY = {
    "sepa_debit":  ("amount", "currency", "collection_date", "umr", "creditor_id", "creditor_name"),
    "bacs_debit":  ("amount", "currency", "collection_date", "service_user_name", "sun", "ddg_text"),
    # Rule H1 makes the category and the frequency part of the notice, not decoration: a
    # "variable" PAD and a "sporadic" one carry different recourse windows.
    "pad_ca":      ("amount", "currency", "collection_date", "payee_name", "payee_contact",
                    "pad_agreement_id", "pad_category", "pad_frequency", "recourse_window",
                    "recourse_text", "manage_url"),
    "upi_autopay": ("amount", "currency", "collection_date", "umn", "merchant_name", "manage_url"),
    "ach_debit":   ("amount", "currency", "collection_date", "company_name"),
}

class IncompleteNotice(Exception):
    """Refuse to send. A partial notice does not start the lead time — it wastes it."""

def render_notice(rail: str, ctx: dict, template: str, afa_threshold_minor: int | None = None) -> str:
    required = MANDATORY.get(rail)
    if not required:
        raise IncompleteNotice(f'no notice template for rail "{rail}" — do not debit')
    missing = [f for f in required if not ctx.get(f)]
    if missing:
        raise IncompleteNotice(f"{rail} notice missing {', '.join(missing)}")

    body = template
    # UPI AutoPay only: the additional-factor-authentication line appears above the scheme's
    # per-transaction limit. Read the threshold from config — it has moved more than once and
    # differs by mandate category, so a hardcoded number silently stops being true.
    # ctx.get, not ctx[...]: a KeyError here is an uncaught crash in the send worker, which
    # looks like an outage rather than a refusal. Every failure in this function must be an
    # IncompleteNotice, so the caller can tell "cannot send" from "did not send".
    if rail == "upi_autopay":
        if afa_threshold_minor is not None and ctx.get("amount_minor") is None:
            raise IncompleteNotice("upi_autopay notice needs amount_minor to apply the AFA threshold")
        over = afa_threshold_minor is not None and ctx["amount_minor"] > afa_threshold_minor
        if over and not ctx.get("afa_line"):
            raise IncompleteNotice("upi_autopay debit is above the AFA threshold but afa_line is missing")
        body = body.replace("{afa_line}", ctx["afa_line"] if over else "")

    for key, value in ctx.items():
        body = body.replace("{" + key + "}", str(value))
    if "{" in body.replace("{}", ""):             # an unsubstituted placeholder ships as literal text
        raise IncompleteNotice(f"{rail} notice has unfilled placeholders")

    # Rule 6: mandate id, rail and date. Never the rendered body — it carries the payer's
    # name, the account tail and the amount.
    print("[mandate.notice.rendered]", {"mandate_id": ctx["mandate_id"], "rail": rail,
                                        "collection_date": ctx["collection_date"]})
    return body

def verify_notice_token(mandate_id: str, token: str) -> bool:
    want = hmac.new(os.environ["MANDATE_NOTICE_SECRET"].encode(), mandate_id.encode(), sha256).hexdigest()
    return len(want) == len(token) and hmac.compare_digest(want, token)  # equal lengths, constant time
```

The scheduling functions above transliterate directly: `timedelta` for `shiftDays`, `date` comparison for `wanted < earliest`, and `hmac.compare_digest` — guarded by the same explicit length check — in place of `timingSafeEqual`.

## The notices

Render in `regions[CODE].languages[0]`. Placeholders in `{}` are required fields, not decoration — a notice missing one is not a notice.

```text
SEPA Direct Debit — pre-notification              (send by noticeDueAt, ≥14 calendar days ahead)
Subject: We will collect {amount} {currency} on {collection_date}

We will debit {amount} {currency} from the account ending {last4} on or shortly after
{collection_date}, under the mandate you signed on {mandate_signed_at}.

Mandate reference (UMR): {umr}
Creditor Identifier (CID): {creditor_id}
Creditor: {creditor_name}

If the amount or the date changes we will tell you again, with the same notice period. You
can dispute a collected direct debit with your bank for 8 weeks without giving a reason.
```

```text
Bacs Direct Debit — advance notice           (send by noticeDueAt, ≥10 WORKING days ahead)
Subject: {service_user_name} will collect {amount} on {collection_date}

Amount: {amount}   Collection date: {collection_date}
Service User Number: {sun}   Reference: {dd_reference}

The Direct Debit Guarantee
- This Guarantee is offered by all banks and building societies that accept instructions to
  pay Direct Debits.
- If there are any changes to the amount, date or frequency of your Direct Debit
  {service_user_name} will notify you {lead} working days in advance of your account being
  debited, or as otherwise agreed. If you request {service_user_name} to collect a payment,
  confirmation of the amount and date will be given to you at the time of the request.
- If an error is made in the payment of your Direct Debit by {service_user_name} or your bank
  or building society, you are entitled to a full and immediate refund of the amount paid
  from your bank or building society.
- If you receive a refund you are not entitled to, you must pay it back when
  {service_user_name} asks you to.
- You can cancel a Direct Debit at any time by simply contacting your bank or building
  society. Written confirmation may be required. Please also notify us.
```

The Guarantee is published scheme wording. Reproduce it, do not paraphrase it, and confirm the current text and your agreed notice period with your sponsoring bank or PSP before go-live. Everything from *The Direct Debit Guarantee* heading down **is** the value of `ddg_text` — it is inlined here so you can read it, and it is a `MANDATORY["bacs_debit"]` field so that an edit to the template body cannot quietly drop it. If you shorten the template to `{ddg_text}`, the required field is what fills it back in; if you keep it inline, pass the same block as `ddg_text` so the check still bites.

```text
UPI AutoPay — pre-debit notification                    (send by noticeDueAt, ≥24 hours ahead)
Subject: {amount} will be debited on {collection_date}

Mandate (UMN): {umn}   Merchant: {merchant_name}
{afa_line}
Pause or cancel this mandate in your UPI app, or here: {manage_url}
```

`{afa_line}` is emitted by `render_notice` only when `amount_minor > afa_threshold_minor`, and reads: *"You will be asked to authenticate this debit, because it is above the per-transaction e-mandate limit."* Below the threshold the debit runs unattended and the line would be a lie.

```text
Pre-Authorized Debit (Canada) — notice                  (send by noticeDueAt, ≥10 days ahead)
Subject: PAD of {amount} on {collection_date}

Payee: {payee_name}, {payee_contact}
Amount: {amount}   Due date: {collection_date}   Agreement: {pad_agreement_id}
This is a {pad_category} PAD under a {pad_frequency} agreement.

You have certain recourse rights if a debit does not comply with this agreement — for
example, the right to a reimbursement of any debit not authorised or not consistent with
the PAD agreement. Recourse must be claimed within {recourse_window}.
You may cancel this agreement at any time with 30 days' written notice: {manage_url}
```

`pad_category` is `personal` or `business`; `pad_frequency` is `fixed`, `variable` or
`sporadic`; `recourse_window` is `90 calendar days` for a personal PAD and `10 business days`
for a business one. They are real fields on `MANDATORY["pad_ca"]`, not choose-one prose: a
pipe left in the template is an unsubstituted placeholder, and `render_notice` refuses to send
it rather than mailing the payer a literal `{personal|business}`.

The PAD agreement itself — payor name, account, amount and frequency, recourse statement, cancellation terms, payee contact — is a separate document collected before the first debit; the notice above does not replace it. Confirm both against Payments Canada Rule H1.

## Anti-patterns

- ❌ Sending the notice when the charge is created. The window is measured backwards from the collection date, so by then it is already gone. Derive the date from `earliestCollectionDate`.
- ❌ Counting Bacs lead time in calendar days. Ten calendar days is roughly six working days: every notice ships late, and the Direct Debit Guarantee makes each of those debits refundable on request.
- ❌ An empty or stale bank-holiday set. `shiftDays` is only as correct as `holidays`; a missing August bank holiday moves the deadline by one day and nobody notices until an indemnity claim.
- ❌ Raising the price and reusing the existing notice. A changed amount re-arms the full lead time on SEPA, Bacs and PAD — which is why `notice_key` includes `amount_minor`.
- ❌ Sending the email inside the scheduling transaction. An SMTP timeout rolls back the notice record, the next run re-sends, and the payer gets duplicates for a debit that never moved.
- ❌ Treating a settled direct debit as final revenue. Every rail in the table that the catalog carries is `reversibility: "mandate_indemnity"` — 56 days on SEPA, **395** on Bacs, 60 on ACH. (`becs_debit` is `refund_only`; a different remedy, not a shorter one.)
- ❌ Logging the IBAN, sort code or account number with the notice (Rule 6). Log `mandate_id`, rail and collection date; the payer's bank details belong in the mandate record, not in your log pipeline.
- ❌ Shortening a lead because "the customer agreed in the UI". A checkbox is not a mandate: `leadFor` accepts a shorter period only on the rails whose scheme lets the mandate agree one (SEPA, PAD), and only from a value recorded on the mandate itself. It never shortens Bacs, UPI AutoPay or ACH.

## Security rules cited

- **Rule 4** — `notice_key` = `mandate_id:collection_date:amount_minor` is the idempotency key for outbound notices: a scheduler re-run is a no-op, a price change is a new notice. Same argument as the `idempotency_keys` table, applied to mail.
- **Rule 6** — the notice path logs `mandate_id`, rail and collection date only. Never the IBAN, sort code, account number or payer name.
- **Rule 9** — the unique constraint on `notice_key` is the same dedup pattern as `webhook_events_processed`: exactly-once behaviour from a database constraint rather than from application memory.
- **Rule 11** — the notice carries only what its scheme mandates. `last4` is enough to identify the account for the payer; the full IBAN in an email is a data breach waiting for a forwarded message.
- **Rule 12** — a mandate reference (UMR, UMN, SUN, PAD agreement id) is not card data and is safe to store and display. The PAN wall is untouched by anything here.
- Constant-time comparison guards `verifyNoticeToken` / `verify_notice_token`, so the manage-mandate link in a notice cannot be brute-forced byte by byte.
