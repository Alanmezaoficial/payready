# `sdk_verifier` — the provider's SDK owns verification

The provider documents a webhook signature but not a recipe you can implement: the canonical
string, the encoding or the key derivation only exists inside its official SDK. **Braintree is the
canonical case** — its notifications arrive as form fields rather than a JSON body, and the SDK's
`parse` call is the whole documented verification path. The mistake is treating that as a
challenge. Someone captures a sandbox event, reverse-engineers the digest, and ships a hand-rolled
verifier that works — until the provider changes the scheme, which it may do without a changelog,
because the SDK is the published interface and the wire format is an implementation detail. Then
the verifier either rejects every genuine event, or keeps accepting after the signature's meaning
has shifted. Call the SDK. Pin it. Tag it.

**Providers in this family:** none assigned yet, and the bar is deliberately high. **Paddle**
(wave 1) ships a `verify` helper in its SDK yet does *not* belong here: the catalog's research note
records the scheme completely — `Paddle-Signature: ts=<unix>;h1=<hex>`, HMAC-SHA256 over
`<ts>:<raw_body>`, timestamp signed, multiple `h1` values during rotation — so once those fields
are transcribed it composes as `hmac_timestamp_body`, which `scripts/lib/webhook-sign.js` can then
round-trip in CI. (It sits at `unverified` until someone types them in, like the other 30.)
**The test is the documentation, not the existence of an SDK helper.** A
provider lands here only when the docs describe no reproducible recipe; 31 catalog entries sit at
`verification_family: "unverified"` today, and this family is not a parking spot for them.

That distinction has a cost worth naming. A family PagoKit cannot sign locally is a family
`/pagokit:test` cannot prove: `webhook-sign.js` raises `UnsignableError` for `sdk_verifier`, so the
forged-event and replayed-event checks never run, and your only verification evidence is a real
event captured from the provider's sandbox. Say so in `PAGOKIT_INTEGRATION.md`. Ships ahead of
Braintree.

**Catalog fields this fragment reads:** `webhook.signature_location` (`"form_field"` for
Braintree-shaped delivery, `"header"` otherwise), `webhook.signature_header` (the header **or form
field** carrying the signature), `webhook.secret_env`, `webhook.event_id_pointer`,
`webhook.event_type_pointer`, `webhook.replay_mitigation_strategy`, `webhook.payload_authoritative`,
`webhook.refetch_endpoint`, `webhook.evidence.confidence`, `sdks.node.pkg`, `sdks.python.pkg`,
`api_version`.

## The contract

The preamble owns everything but step 4. This fragment's step 4 is a delegation, plus three
obligations that have nothing to do with cryptography.

1. If `webhook.signature_location == "form_field"`, parse the form yourself from the raw bytes
   (`new URLSearchParams` / `parse_qs`) and hand the SDK the two field values. Keep a JSON body
   parser away from it — `express.raw({ type: 'application/json' })` does not match
   `application/x-www-form-urlencoded`, so `req.body` arrives empty and the SDK is handed `""`.
2. **Call the SDK's verify/parse method** with the signature and payload exactly as received: no
   trimming, no re-encoding, no case normalisation.
3. A thrown or rejected verification is a **400** with an empty body. Never catch it and continue —
   that one `try { } catch { }` is the entire vulnerability.
4. **Pin the SDK to an exact version** (`"braintree": "3.31.0"`, not `^3.31.0`), commit the
   lockfile, install with `npm ci` or a hashed `requirements.txt`. The SDK *is* your signature
   verifier; a floating range means your security control updates itself without review.
5. Add `// @pagokit:signature-verified` above the handler. `hooks/checks/webhook-has-signature.js`
   matches a fixed list of verifier shapes plus catalog-declared names, and an SDK method it has
   never seen is invisible to it. A Rule 3 failure here usually gets "fixed" by bolting on a decoy
   `createHmac` that verifies nothing but satisfies the validator.
6. In a multi-merchant gateway, confirm the notification belongs to **you** — constant-time
   compare the field the provider uses to *name the recipient* against your configured id
   (Rule 3). For Braintree that is `sourceMerchantId` / `source_merchant_id`, which is present
   only on OAuth/Connect notifications; a *merchant account* id (`merchantAccountId`, a
   sub-account like `usd_marketplace`) is a different identifier and never equals your merchant
   id, so comparing it either passes vacuously or rejects every genuine event.
7. Dedup as the preamble does. When the provider ships no stable event id, compose one; a bare
   timestamp collides. If `payload_authoritative` is `false`, re-fetch in the job — a verified
   envelope is not an authoritative record.

**Status codes** are the preamble's: `413` over 256 KB, `400` with an empty body when the SDK
rejects or the fields are absent, `200` on a duplicate, `200` plus a logged TODO for an
unrecognised `kind` — a 4xx there gets the endpoint disabled — and `500` only when a verified
event's handler threw.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import braintree from 'braintree';         // <from sdks.node.pkg>, pinned EXACTLY in package.json
import { safeEqual } from './webhook-crypto';

// Rule 1: credentials from the environment. No `!` without a guard — the deploy that forgets one
// should fail at boot, not verify every event against `undefined`.
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set. See .env.example.`);
  return v;
}

const MERCHANT_ID = requireEnv('BRAINTREE_MERCHANT_ID');
const gateway = new braintree.BraintreeGateway({   // built once, not per request
  environment: braintree.Environment.Production,   // Sandbox outside production
  merchantId: MERCHANT_ID,
  publicKey: requireEnv('BRAINTREE_PUBLIC_KEY'),
  privateKey: requireEnv('BRAINTREE_PRIVATE_KEY'), // <from webhook.secret_env>
});

const SIGNATURE_FIELD = 'bt_signature'; // <from webhook.signature_header>
const PAYLOAD_FIELD = 'bt_payload';

/**
 * The community `WebhookNotification` type is a union with one resource per kind, and it models
 * neither `sourceMerchantId` (which the runtime does send on Connect notifications) nor a common
 * resource field. Reading them off the union is a compile error; casting the whole notification
 * to `any` throws away the `kind` discriminant you actually want. Widen exactly the four fields
 * this file reads, and nothing else.
 */
type NotificationView = braintree.WebhookNotification & {
  sourceMerchantId?: string;
  subscription?: { id?: string };
  dispute?: { id?: string };
  transaction?: { id?: string };
};

/**
 * Rule 3. The SDK owns the scheme — including its constant-time comparison, which is one more
 * reason not to hand-roll it. Do not add an `===` check on top "for belt and braces": you would
 * reintroduce exactly the timing leak the SDK avoids, and you cannot succeed anyway, since the
 * scheme is the thing you do not have.
 * @pagokit:signature-verified — SDK-owned verification (verification_family: sdk_verifier)
 */
export async function verifySdkWebhook(rawBody: string) {
  // signature_location == "form_field": parse the form from the RAW bytes ourselves (Rule 5)
  const form = new URLSearchParams(rawBody);
  const signature = form.get(SIGNATURE_FIELD);
  const payload = form.get(PAYLOAD_FIELD);
  if (!signature || !payload) return null;

  let notification: NotificationView;
  try {
    notification = await gateway.webhookNotification.parse(signature, payload);
  } catch {
    return null; // invalid signature → the handler returns 400. Never continue past this.
  }

  // Rule 3: one gateway can serve several merchants (OAuth / Connect). Bind the event to ours.
  // sourceMerchantId is absent on a single-merchant account, so this only bites when the
  // provider actually names a recipient — check the type, do not `?? MERCHANT_ID` the miss away,
  // which turns the whole check into a compare of a value with itself.
  const source = notification.sourceMerchantId;
  if (typeof source === 'string' && !safeEqual(source, MERCHANT_ID)) return null;
  return notification;
}

/** The provider ships no stable event id, so compose one — a bare timestamp collides. */
export function dedupKey(n: NotificationView): string {
  // Cover every resource shape: a dispute notification has no `subscription` at all, and a key
  // of `dispute_opened::<ts>` collides with the next dispute in the same second.
  const resourceId = n.subscription?.id ?? n.dispute?.id ?? n.transaction?.id ?? '';
  // `timestamp` is an ISO-8601 *string* here, not a Date — `.toISOString()` is a TypeError on
  // every event, and the SDK's own types will not catch it for you.
  return `${n.kind}:${resourceId}:${n.timestamp}`; // <from webhook.event_id_pointer>
}
```

The handler is the preamble's, with step 4 replaced by `verifySdkWebhook(rawBody)` and `null` → a
`400`. Raw-body capture needs one change: `express.raw({ type: '*/*', limit: '256kb' })`, because
`'application/json'` never matches a form-encoded callback. In the App Router keep
`await request.text()` with `runtime = 'nodejs'` — `request.formData()` consumes the stream before
the SDK sees the values it must hash — and `await request.body()` in FastAPI. Route unrecognised
`kind`s to a **200** plus a logged TODO: a 4xx gets the endpoint disabled and you lose every future
event, not just this one.

## Python

```python
# app/payments/<provider>_verify.py
import os
from urllib.parse import parse_qs
import braintree                    # <from sdks.python.pkg>, pinned EXACTLY in requirements.txt
from app.payments.webhook_crypto import safe_equal

MERCHANT_ID = os.environ["BRAINTREE_MERCHANT_ID"]
gateway = braintree.BraintreeGateway(          # built once, not per request
    braintree.Configuration(
        environment=braintree.Environment.Production,
        merchant_id=MERCHANT_ID,
        public_key=os.environ["BRAINTREE_PUBLIC_KEY"],
        private_key=os.environ["BRAINTREE_PRIVATE_KEY"],   # <from webhook.secret_env>
    )
)
SIGNATURE_FIELD = "bt_signature"    # <from webhook.signature_header>
PAYLOAD_FIELD = "bt_payload"


def verify_sdk_webhook(raw_body: bytes):
    """Rule 3. The SDK owns the scheme, including its constant-time comparison.
    @pagokit:signature-verified — SDK-owned verification (verification_family: sdk_verifier)
    """
    form = parse_qs(raw_body.decode("utf-8", "replace"))   # signature_location == "form_field"
    signature = (form.get(SIGNATURE_FIELD) or [None])[0]
    payload = (form.get(PAYLOAD_FIELD) or [None])[0]
    if not signature or not payload:
        return None
    try:
        notification = gateway.webhook_notification.parse(signature, payload)
    except braintree.exceptions.InvalidSignatureError:     # class per the PINNED version
        return None            # → 400. Never swallow this and continue.

    # Rule 3: bind the event to us, constant-time. `source_merchant_id` names the recipient and
    # is present only on OAuth/Connect notifications — absent means "the one merchant configured
    # here", so an absent value is not a failure. Do not fall back to MERCHANT_ID: that compares
    # a value with itself and the check silently becomes a no-op.
    source = getattr(notification, "source_merchant_id", None)
    if isinstance(source, str) and not safe_equal(source, MERCHANT_ID):
        return None
    return notification


def dedup_key(n) -> str:
    """No stable event id is shipped, so compose one — a bare timestamp collides. Cover every
    resource shape: a dispute notification carries no `subscription` attribute at all."""
    resource_id = (getattr(getattr(n, "subscription", None), "id", None)
                   or getattr(getattr(n, "dispute", None), "id", None)
                   or getattr(getattr(n, "transaction", None), "id", None) or "")
    return f"{n.kind}:{resource_id}:{n.timestamp}"
```

## Pinning

```json
// package.json — exact, because this dependency IS the signature verifier
{ "dependencies": { "braintree": "3.31.0" } }
```

Every SDK member named above — the `kind` constants, `timestamp`, the nested resource objects, the
exception classes — tracks the pinned version. Read them from that version's docs rather than from
memory, and re-check when the pin moves. A Renovate or Dependabot bump to this package is a
**security review**, not a routine upgrade: read the changelog for verification changes before
merging, and re-run `/pagokit:test` afterwards. Where `api_versioning.pin_required` is true, pin
the API version in the gateway config too — an SDK that silently follows the provider's latest API
version can change the notification shape your switch depends on.

Some providers here also answer a GET verification challenge (Braintree's `bt_challenge`) with an
SDK helper of its own. Route the GET to that helper; do not hand-roll the response, for the same
reason you did not hand-roll the signature.

## Anti-patterns

- ❌ Reverse-engineering the digest from captured sandbox events. It works right up until the
  provider changes an implementation detail it never promised to keep.
- ❌ `"braintree": "^3.31.0"` — the verifier updates itself with no review.
- ❌ Omitting `// @pagokit:signature-verified`; the Rule 3 check then fails, and the usual "fix" is
  a decoy `createHmac` that verifies nothing but satisfies the validator.
- ❌ `express.raw({ type: 'application/json' })` on a form-encoded callback — no match, empty body,
  SDK handed `""`, and the failure looks like a bad key.
- ❌ `await request.json()` or `request.formData()` before the SDK sees the values (Rule 5).
- ❌ `try { parse() } catch { /* keep going */ }` — that comment is the vulnerability.
- ❌ Constructing the gateway inside the handler — new TLS state and config parsing per event, on
  the one code path with an ack deadline.
- ❌ Adding your own `signature === expected` on top of the SDK — reintroduces the timing leak the
  SDK avoids.
- ❌ Deduping on the notification timestamp alone — two notifications share a second and the second
  one is silently dropped as a duplicate. Reading only `subscription.id` is the same bug wearing a
  disguise: a dispute notification has no `subscription`, so every dispute in a given second
  collapses to one key.
- ❌ Binding on a *merchant account* id instead of the field that names the recipient, and
  defaulting the miss to your own id. Absent on a single-merchant account, the compare passes
  vacuously; populated in a marketplace, it never matches and every genuine event is rejected.
  Either way the log line says "merchant verified".
- ❌ Calling Date methods on the SDK's `timestamp` without checking its type. Braintree's Node
  notification carries an ISO-8601 string; `.toISOString()` throws on the first real event.
- ❌ Hand-building a test POST with a raw base64 payload: an unescaped `+` decodes to a space in
  both `URLSearchParams` and `parse_qs`, so the signature fails for a reason unrelated to your
  code. Use `curl --data-urlencode`.
- ❌ Logging the parsed notification object — it carries customer PII (Rule 6).

## Security rules cited

- **Rule 1:** merchant id and keys come from the environment, through a guard that fails at boot.
- **Rule 3:** the SDK's parse call is the verification, `@pagokit:signature-verified` makes it
  visible to `hooks/checks/webhook-has-signature.js`, and the merchant-account binding is a
  constant-time compare.
- **Rule 5:** raw bytes reach the SDK — `request.text()` with `runtime = 'nodejs'`,
  `express.raw({ type: '*/*' })` before the body parsers, `await request.body()` in FastAPI.
- **Rule 6:** the preamble logs `kind` and timestamp; the notification object never reaches a log.
- **Rule 9:** the preamble's dedup, keyed on the composed `dedupKey` because no stable event id
  exists.
- **Rule 10:** the preamble's 256 KB cap.
