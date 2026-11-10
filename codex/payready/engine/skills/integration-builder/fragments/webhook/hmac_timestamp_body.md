# `hmac_timestamp_body` — HMAC over `{timestamp}{separator}{raw_body}`

The provider puts a timestamp *inside the signed string* and ships it beside the signature in a key-value header (`t=1780000000,v1=<hex>`). That one design choice is what turns a signature into a **credential that expires**, and the whole family exists to exploit it. The mistake is mechanical and extremely common: developers read `t` out of the header, hash `t + "." + body`, get a match, and never check that `t` is recent — or check it *after* computing the MAC. Both leave you exactly where `hmac_raw_body` sits, with a signature that verifies forever. The timestamp is only a replay defence because you reject on it; being signed just stops the attacker editing it.

**Providers in this family:** Stripe — the only entry carrying `verification_family: "hmac_timestamp_body"` today. Four more entries document the same shape in `webhook.algorithm` while still reading `verification_family: "unverified"`, and every one of them differs from Stripe in a detail that a Stripe-shaped verifier gets wrong: **Fintoc** (`t=…,v1=…`, `{timestamp}.{raw_body}` — the closest), **Paddle** (`Paddle-Signature: ts=…;h1=…` — `;` separator, `h1` key, and a **`:`** in the signed string, not a `.`), **Airwallex** (the timestamp arrives in its own `x-timestamp` header, so `timestamp_source: "header"`, and Airwallex prescribes no tolerance — the number is your decision to document), **Revolut Merchant** (`v1.<timestamp>.<raw_body>`, and its `Revolut-Request-Timestamp` is in **milliseconds** — comparing it to `Date.now()/1000` puts every event ~53,000 years in the future). Kushki fits here too, not in `hmac_body_transform`: `X-Kushki-Signature` signs `{raw_body}.<X-Kushki-Id>` with the id being unix seconds. Read the separator, keys, unit and tolerance from the entry rather than assuming Stripe's.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.header_format` (`kind: kv`, `separator`, `assign`, `timestamp_key`, `signature_key`), `webhook.signed_payload_template`, `webhook.hash_algo`, `webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.recommended_tolerance_seconds`, `webhook.timestamp_source`, `webhook.replay_mitigation_strategy`, `webhook.secret_env`.

## The contract

1. Read `webhook.signature_header`. Absent → `400`.
2. Split it per `webhook.header_format`: on `separator` (`,`), then at the first `assign` (`=`). Split at the **first** `=` only — a base64 digest ends in `=` padding, and `part.split('=')` destroys it.
3. Pull the timestamp from `timestamp_key` (Stripe `t`, others `ts`) and **collect every** value under `signature_key` (`v1`). A provider mid-secret-rotation sends two `v1=` entries, one per active secret; keeping only the last one makes every rotation an outage. When `timestamp_source` is `header`, the timestamp is not in the signature header at all — read `webhook.timestamp_pointer` as a header name instead; nothing else in this fragment changes.
4. **Check the window before computing the MAC.** `|now − t| > webhook.recommended_tolerance_seconds` → `400`. Cheap rejection first, and it means a stale-but-cryptographically-valid event never reaches the hash.
5. Reject a non-numeric or absent `t` in the same branch: `Number('abc')` is `NaN`, and every comparison against `NaN` is false, so a naive `skew > TOL` test *accepts* it.
6. Build the signed string from `webhook.signed_payload_template` (`{timestamp}.{raw_body}`). The separator lives in the template — it is not always `.`.
7. HMAC, encode per `digest_encoding`, compare constant-time against each candidate. (Rule 3)
8. Keep the preamble's event-id dedup even though `replay_mitigation_strategy` is `timestamp-window`: a 300-second window is 300 seconds of free replays, and Stripe's own retries make duplicates a routine event, not an attack.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { safeEqual, secretKey, encodeDigest, headerValue, unpackSignatureHeader } from './webhook-crypto';

const SIGNATURE_HEADER = '<from webhook.signature_header>';            // e.g. 'Stripe-Signature'
const HEADER_FORMAT    = <from webhook.header_format>;                 // { kind:'kv', separator:',', assign:'=', timestamp_key:'t', signature_key:'v1' }
const TEMPLATE         = '<from webhook.signed_payload_template>';     // e.g. '{timestamp}.{raw_body}'
const HASH_ALGO        = '<from webhook.hash_algo>';                   // e.g. 'sha256'
const SECRET_ENCODING  = '<from webhook.secret_encoding>';             // e.g. 'raw'
const DIGEST_ENCODING  = '<from webhook.digest_encoding>';             // e.g. 'hex'
const TOLERANCE_S      = <from webhook.recommended_tolerance_seconds>; // e.g. 300

export function verifySignature(rawBody: string, headers: Headers, secret: string): boolean {
  const raw = headerValue(headers, SIGNATURE_HEADER);
  if (!raw) return false;

  const { signatures, timestamp } = unpackSignatureHeader(raw, HEADER_FORMAT);
  if (signatures.length === 0 || timestamp === undefined) return false;

  // Rule 9: the window, BEFORE the MAC. Number.isFinite also catches a non-numeric or
  // empty t — without it, NaN > TOLERANCE_S is false and the stale event sails through.
  const skew = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(skew) || skew > TOLERANCE_S) return false;

  // Rule 5: the exact bytes go in unmodified. The replacer is a FUNCTION on purpose —
  // with a string replacement, a body containing $& or $' is rewritten by String.replace
  // and the MAC silently changes. JSON payloads do contain those sequences.
  const signedString = TEMPLATE
    .replace('{timestamp}', () => String(timestamp))
    .replace('{raw_body}', () => rawBody);

  const expected = encodeDigest(
    crypto.createHmac(HASH_ALGO, secretKey(secret, SECRET_ENCODING)).update(signedString, 'utf8').digest(),
    DIGEST_ENCODING,
  );

  // Rule 3: constant-time against every candidate, no early exit (secret rotation).
  let matched = false;
  for (const presented of signatures) if (safeEqual(expected, presented)) matched = true;
  return matched;
}
```

## Python

```python
# app/payments/<provider>_verify.py
import hashlib, hmac, time
from app.payments.webhook_crypto import safe_equal, secret_key, encode_digest

SIGNATURE_HEADER = "<from webhook.signature_header>"
SEPARATOR        = "<from webhook.header_format.separator>"      # ','
ASSIGN           = "<from webhook.header_format.assign>"         # '='
TIMESTAMP_KEY    = "<from webhook.header_format.timestamp_key>"  # 't'
SIGNATURE_KEY    = "<from webhook.header_format.signature_key>"  # 'v1'
TEMPLATE         = "<from webhook.signed_payload_template>"      # '{timestamp}.{raw_body}'
HASH_ALGO        = "<from webhook.hash_algo>"
SECRET_ENCODING  = "<from webhook.secret_encoding>"
DIGEST_ENCODING  = "<from webhook.digest_encoding>"
TOLERANCE_S      = <from webhook.recommended_tolerance_seconds>  # 300

def verify_signature(raw_body: bytes, headers, secret: str) -> bool:
    header = headers.get(SIGNATURE_HEADER)
    if not header:
        return False

    timestamp, signatures = None, []
    for part in header.split(SEPARATOR):
        key, sep, value = part.partition(ASSIGN)   # partition = split on the FIRST '=' only,
        if not sep:                                # so base64 '=' padding survives intact
            continue
        key, value = key.strip(), value.strip()
        if key == SIGNATURE_KEY:
            signatures.append(value)               # a rotating secret sends two
        elif key == TIMESTAMP_KEY:
            timestamp = value
    if not signatures or timestamp is None:
        return False

    # Rule 9: window first, and a non-numeric t is a rejection, not an exception
    try:
        skew = abs(int(time.time()) - int(timestamp))
    except ValueError:
        return False
    if skew > TOLERANCE_S:
        return False

    # Rule 5: substitute into BYTES so the body is never decoded. raw_body.decode("utf-8")
    # raises UnicodeDecodeError on a body that is not valid UTF-8 — an unhandled exception
    # inside the verifier, which the framework turns into a 500 with a traceback instead of
    # the 400 this deserves. Anyone can post those bytes.
    signed = TEMPLATE.replace("{timestamp}", timestamp).encode("utf-8").replace(b"{raw_body}", raw_body)
    mac = hmac.new(secret_key(secret, SECRET_ENCODING),
                   signed, getattr(hashlib, HASH_ALGO)).digest()
    expected = encode_digest(mac, DIGEST_ENCODING)

    matched = False
    for presented in signatures:                   # Rule 3: no early exit
        if safe_equal(expected, presented):
            matched = True
    return matched
```

## Why the signed timestamp is what makes the window meaningful

A window over an *unsigned* timestamp is decoration. If `t` travelled in its own unsigned header, an attacker replaying a captured event would simply rewrite `t` to `now` and the MAC — computed over the body alone — would still match. Because `t` is inside the hashed string, changing it invalidates the signature, and the attacker's only options are to replay the original `t` (rejected by the window) or forge a new MAC (needs the secret). That is the entire security argument, and it collapses the moment you skip step 4.

Two practical consequences:

- **Clock skew is now a security parameter.** `Math.abs()` bounds the window in both directions, so a server running 6 minutes fast rejects every genuine event with a 300s tolerance. Run NTP; do not "fix" the outage by widening the tolerance to an hour, which is what the incident channel will suggest.
- **The window bounds the damage, it does not eliminate it.** Within the tolerance the same event is replayable freely, which is why `_preamble.md`'s dedup transaction stays on even when `replay_mitigation_strategy` is `timestamp-window` alone.

## Anti-patterns

- ❌ Verifying the MAC first and checking `t` afterwards — or not at all. A signature that never expires is `hmac_raw_body` with extra steps. (Rule 9)
- ❌ `header.split(',').map(p => p.split('='))` — splits base64 padding apart and drops the second `v1` during a secret rotation.
- ❌ `TEMPLATE.replace('{raw_body}', rawBody)` with a **string** replacement, in JavaScript. `$&`, `` $` ``, `$'` and `$$` in the body are expanded by `String.replace`, so a payload carrying any of them silently changes the hashed input and the event is rejected. Use `() => rawBody`. (Verified against a signed event whose body contains all four sequences: it passes with the function replacer and the naive string form produces a different signed string.) Python's `str.replace` is literal, so this trap is JavaScript-only — which is exactly why it survives code review by a Python-shaped reader.
- ❌ Reconstructing the signed string as `` `${t}.${JSON.stringify(body)}` ``. Re-serialisation is not the received bytes. (Rule 5)
- ❌ `if (skew > TOLERANCE_S) return false` without `Number.isFinite` — `t=abc` yields `NaN`, the comparison is false, and the check passes the event through.
- ❌ `raw_body.decode("utf-8")` on the way into the hash, in Python. A body that is not valid UTF-8 raises inside the verifier, and an exception there is a `500` with a traceback where the answer was a silent `400`. Substitute into bytes instead.
- ❌ Hardcoding `300` or `.` — Wompi's tolerance is 600s, Paddle's separator is `:`, and Revolut's timestamp is in milliseconds. Take all three from the entry.
- ❌ Dropping event-id dedup because there is a window. 300 seconds is plenty for a replay, and provider retries produce duplicates with no attacker at all. (Rule 9)

## Security rules cited

- **Rule 3:** MAC verified before the payload is used; constant-time comparison over every candidate signature; a detail-free `400` on failure.
- **Rule 5:** `{raw_body}` is substituted with the untouched bytes from the stack's raw-body API, via a function replacer so the substitution itself cannot alter them.
- **Rule 9:** the tolerance window is enforced *before* the MAC and rejects non-numeric timestamps, layered on top of the preamble's event-id dedup.
- **Rule 10:** the 256 KB cap runs in the preamble, before these bytes reach the hash.
