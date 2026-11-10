# `hmac_raw_body` — HMAC over the exact request bytes

The baseline family: `HMAC(secret, rawBody)`, encoded, compared against one header. There is no timestamp, no template, no transform — which is exactly why it is the family people ship broken. Two defaults do it. The first is the hash: a generator that assumes SHA-256 is wrong for roughly one provider in four (Paystack signs with **SHA-512**), and the failure surfaces as a signature mismatch that reads like a bad secret. The second is worse and silent: when the scheme signs no timestamp, there is nothing in the signature that expires, so **a captured event stays valid forever** and event-id dedup is not a nice-to-have, it is the entire replay defence.

**Providers in this family:** Lemon Squeezy — the only entry carrying `verification_family: "hmac_raw_body"` today. Several more entries describe this exact scheme in their `webhook.algorithm` prose but still read `verification_family: "unverified"` until someone verifies them, and this fragment resolves for them the day that changes: **Paystack** (HMAC-**SHA-512**, hex, over the raw body — its own entry calls the algorithm the most-hallucinated detail about it), **Razorpay** (SHA-256 hex, dedup on the `x-razorpay-event-id` header), **Mollie's next-generation webhooks** (`X-Mollie-Signature: sha256=<hex>`, so `header_format.kind: "prefixed"`). Mollie is also the warning: its *classic* webhooks carry no signature and no timestamp at all — just `id=tr_…` to re-fetch — which is why its entry is `verification_family: "none"` and not this family. Read every value from the entry, never from this sentence.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.hash_algo`, `webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.signed_payload_template` (always `{raw_body}` here), `webhook.header_format`, `webhook.timestamp_source`, `webhook.recommended_tolerance_seconds`, `webhook.replay_mitigation_strategy`, `webhook.event_id_pointer`, `webhook.secret_env`, `webhook.payload_authoritative`.

## The contract

1. Read the header named by `webhook.signature_header`. Absent → `400`.
2. Unpack it per `webhook.header_format`: `raw` is the bare value; `prefixed` means strip `prefix` (`sha256=…`, as Mollie's next-gen webhooks send) before comparing — comparing the prefixed form against a bare digest fails on length and looks like a mismatch.
3. Compute `HMAC(key, rawBody)` where the key is the secret decoded per `webhook.secret_encoding` and the hash is `webhook.hash_algo`. **Never default the algorithm.**
4. Encode the MAC per `webhook.digest_encoding` and compare constant-time against the unpacked header. Length first — `timingSafeEqual` throws on a length mismatch, and an uncaught throw here is a 500 where you wanted a 400.
5. Compare in the encoding the provider sent. `hex_upper` exists as a distinct value because some providers send uppercase hex; lowercasing both sides to "be safe" widens the accepted set for no benefit.
6. `webhook.timestamp_source: none` → skip the window entirely and make event-id dedup mandatory (see below). Any other value means you are in the wrong fragment: use `hmac_timestamp_body`.
7. Everything else — size cap, parse ordering, dedup transaction, logging, ack — comes from `_preamble.md`.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { safeEqual, secretKey, encodeDigest, headerValue, unpackSignatureHeader } from './webhook-crypto';

// Every literal below is copied from the provider's catalog entry at generation time.
const SIGNATURE_HEADER = '<from webhook.signature_header>'; // e.g. 'X-Signature'
const HASH_ALGO        = '<from webhook.hash_algo>';        // e.g. 'sha256' — Paystack: 'sha512'
const SECRET_ENCODING  = '<from webhook.secret_encoding>';  // e.g. 'raw'
const DIGEST_ENCODING  = '<from webhook.digest_encoding>';  // e.g. 'hex'
const HEADER_FORMAT    = <from webhook.header_format>;      // e.g. { kind: 'raw' }

/**
 * Rule 3: HMAC over the exact bytes received. `rawBody` MUST be the string from
 * request.text() / req.body.toString() — never JSON.stringify(anything).
 */
export function verifySignature(rawBody: string, headers: Headers, secret: string): boolean {
  const raw = headerValue(headers, SIGNATURE_HEADER);
  if (!raw) return false;

  const { signatures } = unpackSignatureHeader(raw, HEADER_FORMAT); // strips 'sha256=' when prefixed
  if (signatures.length === 0) return false;

  const expected = encodeDigest(
    crypto.createHmac(HASH_ALGO, secretKey(secret, SECRET_ENCODING))
      .update(rawBody, 'utf8')   // Rule 5: the received bytes, verbatim
      .digest(),
    DIGEST_ENCODING,
  );

  // Rule 3: constant-time, and no early return on the first miss — a rotating secret can
  // present two candidates, and short-circuiting reintroduces the timing signal.
  let matched = false;
  for (const presented of signatures) if (safeEqual(expected, presented)) matched = true;
  return matched;
}
```

## Python

```python
# app/payments/<provider>_verify.py
import hashlib, hmac
from app.payments.webhook_crypto import safe_equal, secret_key, encode_digest

SIGNATURE_HEADER = "<from webhook.signature_header>"
HASH_ALGO        = "<from webhook.hash_algo>"        # 'sha256' | 'sha512' | …
SECRET_ENCODING  = "<from webhook.secret_encoding>"
DIGEST_ENCODING  = "<from webhook.digest_encoding>"
HEADER_PREFIX    = ""   # <from webhook.header_format.prefix> when kind == 'prefixed'

def verify_signature(raw_body: bytes, headers, secret: str) -> bool:
    """Rule 3: HMAC over the exact bytes received."""
    presented = headers.get(SIGNATURE_HEADER)
    if not presented:
        return False
    if HEADER_PREFIX and presented.startswith(HEADER_PREFIX):
        presented = presented[len(HEADER_PREFIX):]

    mac = hmac.new(
        secret_key(secret, SECRET_ENCODING),
        raw_body,                                  # Rule 5: bytes straight off the wire
        getattr(hashlib, HASH_ALGO),               # never hashlib.sha256 hardcoded
    ).digest()

    return safe_equal(encode_digest(mac, DIGEST_ENCODING), presented)
```

## When the scheme signs no timestamp

`webhook.timestamp_source: "none"` (Lemon Squeezy) means the signature has no expiry built into it. `HMAC(secret, body)` is a pure function of the body, so the signature an attacker captured from a proxy log, a Sentry breadcrumb or a shared ngrok tunnel in March still verifies in December. There is no window to shrink and no tolerance to tune. The only thing that makes an event single-use is your own record that you already saw it:

- `webhook.replay_mitigation_strategy` will be `event-id-dedup` — the preamble's dedup transaction is **mandatory**, not defence-in-depth.
- Key it on `webhook.event_id_pointer` (Lemon Squeezy: `/meta/event_id`). If the provider ships no event id at all, key on `sha256(rawBody)` — for this family that is exactly as unique as the signature, since both are pure functions of the same bytes.
- Set the TTL to at least the provider's retry horizon, not 24 hours because 24 hours sounds round. A row that expires before the provider stops retrying reopens the replay window it was there to close.
- `scripts/test-signatures.js` enforces this: a provider with no signed timestamp that does not declare `event-id-dedup` *and* an `event_id_pointer` fails the round-trip suite.

## Proving it locally

This family is fully signable offline, so there is no excuse for shipping it untested:

```bash
node scripts/sign-event.js --provider <provider> --curl          # valid    → expect 200
node scripts/sign-event.js --provider <provider> --mode forged   # tampered → expect 400
node scripts/sign-event.js --provider <provider> --curl          # run the SAME command twice
```

Read the third line carefully. `--mode replay` works by backdating the timestamp, so for this family it produces **bytes identical to `--mode valid`** — the signature covers only the body, and the timestamp is neither signed nor sent. (Confirmed against Lemon Squeezy: both modes emit the same `x-signature`, though the tool still prints its family-generic `"expected_result": "400 (must be rejected)"`, which does not apply here.) The real replay test for a no-timestamp provider is therefore just sending the same valid event twice, and the correct second answer is `200 {"received":true,"duplicate":true}`. A plain `200 {"received":true}` means the handler processed the same payment twice.

## Anti-patterns

- ❌ `crypto.createHmac('sha256', …)` with the algorithm hardcoded — Paystack signs SHA-512, and the handler rejects every genuine event while the logs say only "invalid signature".
- ❌ `JSON.stringify(await request.json())` as the hashed input. Re-serialisation loses whitespace, key order, unicode escapes and number formatting; see `hmac_body_transform.md` for what actually survives a round trip. (Rule 5)
- ❌ `computed === presented`. Constant-time or it is a timing oracle. (Rule 3)
- ❌ `crypto.timingSafeEqual(a, b)` without the length check — it throws `RangeError` on unequal lengths, so a two-character signature turns a `400` into an unhandled `500`.
- ❌ Verifying with the API key. `webhook.secret_env` is a different credential (`LEMONSQUEEZY_WEBHOOK_SECRET`, not `LEMONSQUEEZY_API_KEY`); the mistake is a permanent, silent rejection of every event.
- ❌ Skipping dedup because "the signature is valid". For this family a valid signature says nothing about *when* the event was sent. (Rule 9)
- ❌ Trusting the body because `signature_covers_body` is true here. It means the bytes are authentic, not that the state is current — if `payload_authoritative` is false, re-fetch anyway.
- ❌ Comparing after `.toLowerCase()` on both sides when `digest_encoding` is `hex_upper`. Emit the encoding the catalog names.

## Security rules cited

- **Rule 3:** HMAC verified before the payload is used, constant-time comparison over every candidate signature, no early exit, no reason returned to the caller.
- **Rule 5:** the hashed input is the raw string/bytes from the stack's raw-body API — never a re-serialised object.
- **Rule 9:** with `timestamp_source: none` there is no window to enforce, so event-id dedup from `_preamble.md` is the sole replay defence and is mandatory.
- **Rule 10:** the 256 KB cap runs in the preamble, before these bytes are ever hashed.
