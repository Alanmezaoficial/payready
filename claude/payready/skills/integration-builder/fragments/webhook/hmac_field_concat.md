# `hmac_field_concat` — HMAC over a template of selected fields

The provider does **not** hash the request body. It hashes a short string it assembles from a handful of named values — an id pulled out of the body, a correlation header, a timestamp — glued together in a fixed order with fixed punctuation. Mercado Pago's is `id:<data.id>;request-id:<x-request-id>;ts:<ts>;` and nothing else about your payload is covered. This is the family developers break most, because the reflex is to reach for `HMAC(secret, rawBody)`, and that verifier fails **100% of the time, on every single event, including the genuine ones**. The error surfaces as "invalid signature", which reads as a wrong secret, so the standard response is to rotate the webhook secret two or three times and open a support ticket. The second, quieter half of the family: since the signature covers three fields, **everything else in the body is attacker-controlled** even after verification succeeds.

**Providers in this family:** Mercado Pago — the only entry carrying `verification_family: "hmac_field_concat"` today. Two more describe the shape in `webhook.algorithm` while still reading `verification_family: "unverified"`: **Tap Payments** (`"x_id" + id + "x_amount" + amount + …`, HMAC keyed with the merchant's secret API key, and `amount` must carry the ISO-4217 exponent for the currency or the string differs by a digit) and **ePayco** (six fields joined by `^` — and *not* an HMAC: the key is one of the six fields, so the MAC is a plain SHA-256 over the string, see step 5). The order and punctuation differ per provider and are not guessable — read the template from the entry.

**Catalog fields this fragment reads:** `webhook.signed_payload_template`, `webhook.signature_header`, `webhook.header_format`, `webhook.hash_algo`, `webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.timestamp_source`, `webhook.recommended_tolerance_seconds`, `webhook.signature_covers_body`, `webhook.payload_authoritative`, `webhook.refetch_endpoint`, `webhook.event_id_pointer`, `webhook.secret_env`.

## The contract

1. Read `webhook.signature_header` and unpack per `header_format` (Mercado Pago: `kv`, `ts=…,v1=…`).
2. **Parse the body now, before verifying.** This family inverts the preamble's ordering because the signed string is built from fields *inside* the body. That is safe: parsing a ≤256 KB string changes no state. Acting on the parse before step 6 is what is forbidden. (Rule 5)
3. Check the tolerance window against `webhook.recommended_tolerance_seconds` when `timestamp_source` is not `none`, before the MAC. (Rule 9)
4. Expand `webhook.signed_payload_template` with the placeholder vocabulary below. Reproduce it byte for byte — the trailing `;` in Mercado Pago's template is part of the signed string.
5. Hash, encode per `digest_encoding`, compare constant-time. (Rule 3) **Which hash depends on the template:** if it contains `{secret}` the secret is one of the concatenated fields, so this is a plain digest (`createHash`) and there is no HMAC key; if it does not, the secret is the key (`createHmac`). That is exactly how `scripts/lib/webhook-sign.js` decides, and the two must agree or the CI round-trip fails.
6. **Re-fetch before acting.** `payload_authoritative` is almost always `false` in this family; call `webhook.refetch_endpoint` with the verified id and use the response, never the posted body.

### Placeholder vocabulary

| Placeholder | Resolves to | Notes |
|---|---|---|
| `{body:/json/pointer}` | RFC 6901 lookup into the parsed body | `~1` = `/`, `~0` = `~`; missing or null → empty string |
| `{header:NAME}` | request header, case-insensitive | joined duplicates are a trap, see below |
| `{timestamp}` | the value unpacked from the signature header | the same string you range-checked |
| `{secret}` | the shared secret, hashed **into** the string | its presence switches the MAC to a plain digest — see step 5 |
| `{raw_body}` | the exact bytes | rare here; if present you are probably in `hmac_raw_body` |

Values are stringified with JavaScript's `String()` semantics, because that is what `scripts/lib/webhook-sign.js` does and CI round-trips against it: a numeric id signs as `42`, not `"42"`; `true` signs as `true`; `1.0` signs as `1`. Python must imitate that coercion rather than use `str()`, which would emit `1.0` and break the MAC.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { safeEqual, secretKey, encodeDigest, headerValue, unpackSignatureHeader, pointer } from './webhook-crypto';

const SIGNATURE_HEADER = '<from webhook.signature_header>';            // e.g. 'x-signature'
const HEADER_FORMAT    = <from webhook.header_format>;                 // { kind:'kv', signature_key:'v1', timestamp_key:'ts', separator:',', assign:'=' }
const TEMPLATE         = '<from webhook.signed_payload_template>';     // 'id:{body:/data/id};request-id:{header:x-request-id};ts:{timestamp};'
const HASH_ALGO        = '<from webhook.hash_algo>';
const SECRET_ENCODING  = '<from webhook.secret_encoding>';
const DIGEST_ENCODING  = '<from webhook.digest_encoding>';
const TOLERANCE_S      = <from webhook.recommended_tolerance_seconds>; // e.g. 300

/** Expands the catalog template. Unknown placeholders are left visible on purpose:
 *  a silently blanked field is an invisible hole in what the signature covers. */
function buildSignedString(template: string, ctx: {
  rawBody: string; timestamp?: string; headers: Headers; parsedBody: any; secret: string;
}): string {
  return template.replace(/\{([^}]+)\}/g, (match, token: string) => {
    if (token === 'raw_body')  return ctx.rawBody;
    if (token === 'timestamp') return String(ctx.timestamp ?? '');
    if (token === 'secret')    return ctx.secret;   // hashed IN, not used as a key — step 5
    if (token.startsWith('header:')) return String(headerValue(ctx.headers, token.slice(7)) ?? '');
    if (token.startsWith('body:')) {
      const v = pointer(ctx.parsedBody, token.slice(5));
      return v === undefined || v === null ? '' : String(v);
    }
    return match;
  });
}

export function verifySignature(rawBody: string, headers: Headers, secret: string): boolean {
  const raw = headerValue(headers, SIGNATURE_HEADER);
  if (!raw) return false;

  // Rule 5: parsing before verifying is CORRECT here — the signed fields live in the body.
  // Nothing below acts on `parsedBody`; it is only read to rebuild the signed string.
  let parsedBody: any;
  try { parsedBody = JSON.parse(rawBody); } catch { return false; }

  const { signatures, timestamp } = unpackSignatureHeader(raw, HEADER_FORMAT);
  if (signatures.length === 0) return false;

  // Rule 9: window before the MAC; NaN from a non-numeric ts must reject, not pass through
  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(skew) || skew > TOLERANCE_S) return false;

  const signedString = buildSignedString(TEMPLATE, { rawBody, timestamp, headers, parsedBody, secret });

  // Step 5: a template carrying {secret} has already hashed the secret into the string,
  // so there is no key left to give createHmac. Same rule as scripts/lib/webhook-sign.js.
  const mac = TEMPLATE.includes('{secret}')
    ? crypto.createHash(HASH_ALGO).update(signedString, 'utf8').digest()
    : crypto.createHmac(HASH_ALGO, secretKey(secret, SECRET_ENCODING)).update(signedString, 'utf8').digest();
  const expected = encodeDigest(mac, DIGEST_ENCODING);

  let matched = false; // Rule 3: constant-time, no early exit
  for (const presented of signatures) if (safeEqual(expected, presented)) matched = true;
  return matched;
}
```

## Python

```python
# app/payments/<provider>_verify.py
import hashlib, hmac, json, re, time
from app.payments.webhook_crypto import safe_equal, secret_key, encode_digest, pointer

SIGNATURE_HEADER = "<from webhook.signature_header>"
TEMPLATE         = "<from webhook.signed_payload_template>"
SEPARATOR, ASSIGN = "<from webhook.header_format.separator>", "<from webhook.header_format.assign>"
TIMESTAMP_KEY, SIGNATURE_KEY = "<from webhook.header_format.timestamp_key>", "<from webhook.header_format.signature_key>"
HASH_ALGO, SECRET_ENCODING, DIGEST_ENCODING = "<from webhook.hash_algo>", "<from webhook.secret_encoding>", "<from webhook.digest_encoding>"
TOLERANCE_S = <from webhook.recommended_tolerance_seconds>

def _js_str(v) -> str:
    """JavaScript String() semantics — the reference signer's coercion, which CI round-trips."""
    if v is None: return ""
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, float) and v.is_integer(): return str(int(v))   # 1.0 -> '1', not '1.0'
    return str(v)

def build_signed_string(template, *, raw_body, timestamp, headers, parsed, secret):
    def sub(m):
        tok = m.group(1)
        if tok == "raw_body":  return raw_body
        if tok == "timestamp": return "" if timestamp is None else str(timestamp)
        if tok == "secret":    return secret        # hashed IN, not used as a key — step 5
        if tok.startswith("header:"): return _js_str(headers.get(tok[7:]))
        if tok.startswith("body:"):   return _js_str(pointer(parsed, tok[5:]))
        return m.group(0)                       # unknown placeholder stays visible
    return re.sub(r"\{([^}]+)\}", sub, template)

def verify_signature(raw_body: bytes, headers, secret: str) -> bool:
    header = headers.get(SIGNATURE_HEADER)
    if not header:
        return False
    try:
        parsed = json.loads(raw_body)           # Rule 5: parsing first is correct in this family
    except ValueError:
        return False

    timestamp, signatures = None, []
    for part in header.split(SEPARATOR):
        key, sep, value = part.partition(ASSIGN)    # first '=' only
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == SIGNATURE_KEY: signatures.append(value)
        elif key == TIMESTAMP_KEY: timestamp = value
    if not signatures:
        return False

    try:                                            # Rule 9: window before the MAC
        if abs(int(time.time()) - int(timestamp)) > TOLERANCE_S:
            return False
    except (TypeError, ValueError):
        return False

    # errors="replace" so a non-UTF-8 body fails the MAC (a 400) instead of raising inside
    # the verifier (a 500). Templates in this family rarely name {raw_body} at all.
    signed = build_signed_string(TEMPLATE, raw_body=raw_body.decode("utf-8", "replace"),
                                 timestamp=timestamp, headers=headers, parsed=parsed,
                                 secret=secret)
    if "{secret}" in TEMPLATE:                      # step 5: plain digest, no HMAC key
        mac = getattr(hashlib, HASH_ALGO)(signed.encode("utf-8")).digest()
    else:
        mac = hmac.new(secret_key(secret, SECRET_ENCODING), signed.encode("utf-8"),
                       getattr(hashlib, HASH_ALGO)).digest()
    expected = encode_digest(mac, DIGEST_ENCODING)

    matched = False                                 # Rule 3: no early exit
    for presented in signatures:
        if safe_equal(expected, presented):
            matched = True
    return matched
```

## A verified signature is not an authentic payload

This is the part people skip. The signature covers three fields; the body has forty. An attacker who captures one genuine notification can append or rewrite **every field the template does not name** and the MAC still validates, because none of those bytes were ever hashed. Verified against Mercado Pago's real scheme: adding `"status":"approved"` and `"transaction_amount":999999` to a signed event leaves verification passing.

So the catalog sets `signature_covers_body: false` and `payload_authoritative: false`, and the handler must:

```ts
// Rule 3: the signature authenticated ONE id, nothing more. Re-fetch with that id — the one
// the template signs. Two different ids travel in a Mercado Pago notification and they are
// easy to swap: webhook.event_id_pointer is `/id`, the notification's own id, which is what
// the dedup row is keyed on; the signed, re-fetchable payment id is `/data/id`, which is what
// webhook.refetch_endpoint (`…/v1/payments/{data.id}`) takes. Re-fetching with `/id` 404s.
const paymentId = String(pointer(body, '/data/id') ?? '');   // the id inside the signed string
const payment = await mpPayment.get({ id: paymentId });      // webhook.refetch_endpoint
if (payment.status === 'approved') await grantAccess(payment); // decide on the FETCH, never on `body`
```

Treat the webhook as a *ping carrying a verified id*. Every amount, status, currency and email you act on comes from `webhook.refetch_endpoint`. Re-fetching also fixes a second problem for free: these payloads are minimal and often lag the real state, so even an honest body can be stale.

## Anti-patterns

- ❌ `crypto.createHmac(algo, secret).update(rawBody)` — the defining mistake of the family. Rejects every genuine event, and the message reads like a wrong secret. If a provider's webhook has *never once* verified, check the family before rotating the secret again.
- ❌ Rebuilding the template by hand as `` `id:${body.data.id};request-id:${reqId};ts:${ts}` `` and dropping the trailing `;`. The punctuation is inside the hash.
- ❌ Acting on `body.status`, `body.amount` or `body.payer.email`. Unsigned, therefore attacker-controlled. Re-fetch. (Rule 3)
- ❌ Reading `{header:...}` from a duplicated header. Node's `req.headers` joins repeated headers with `", "`, so a proxy that adds its own `x-request-id` turns the value into `a, b` and the MAC breaks. Take the value the provider sent, and do not put a header-rewriting proxy in front of the webhook path.
- ❌ Letting a missing pointer resolve to `"undefined"`. Empty string is the reference behaviour; `String(undefined)` gives you a MAC over the literal text `undefined` that will never match.
- ❌ `JSON.parse` on a body whose id is a >15-digit number. `12345678901234567890` parses to `12345678901234567000`, the rebuilt string differs, and verification fails for that one merchant's events only. Use a big-int-safe parser, or pull the id out of the raw text, when a `{body:...}` pointer targets a long numeric id.
- ❌ Skipping the window because "the id is unguessable". The template is short and its inputs are visible; the window and the dedup row are what stop a captured event being resent. (Rule 9)
- ❌ Re-fetching with `webhook.event_id_pointer`. The id the signature covers and the id the re-fetch endpoint takes are different fields here — `/data/id` versus `/id` for Mercado Pago — and swapping them turns every notification into a 404.
- ❌ `createHmac` on a template that contains `{secret}`. The secret is already inside the hashed string; keying an HMAC with it as well produces a digest no provider will ever send. (Step 5)
- ❌ Verifying with the API token. `webhook.secret_env` (`MP_WEBHOOK_SECRET`) is not `MP_ACCESS_TOKEN`.

## Security rules cited

- **Rule 3:** the MAC is checked before any field is used, constant-time and without early exit; because `signature_covers_body` is false, authorisation decisions are taken on the re-fetched record rather than the posted one.
- **Rule 5:** the body is parsed before verification *by design* here, and nothing acts on that parse until the MAC passes; `{raw_body}`, when a template uses it, is still the untouched bytes.
- **Rule 6:** the preamble logs `id`, `type`, `created` only — these payloads carry payer email.
- **Rule 9:** tolerance window enforced before the MAC, plus the preamble's event-id dedup keyed on `webhook.event_id_pointer` (`replay_mitigation_strategy: both`).
- **Rule 10:** the 256 KB cap runs in the preamble, before this fragment parses anything.
