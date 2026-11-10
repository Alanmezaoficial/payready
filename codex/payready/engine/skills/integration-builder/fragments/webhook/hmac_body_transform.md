# `hmac_body_transform` — HMAC over a transform of the body, not the bytes

The MAC input is derived from the body rather than being the body: base64 of it, a JSON re-serialisation of it, or the body with something prepended. The trap is that `webhook.signed_payload_template` still reads `{raw_body}`, so a generator that expands the template literally produces a `hmac_raw_body` verifier — which rejects every genuine event while looking completely reasonable. **In this family the `verification_family` value is itself a parameter:** it tells you that `{raw_body}` does not mean "the bytes as received", and the specific transform comes from the provider's `webhook.algorithm` prose and `overrides/<provider>/notes.md`. Never infer it from the template alone.

**Providers in this family:** no entry carries `verification_family: "hmac_body_transform"` yet — this fragment ships ahead of the wave that promotes them. Two catalog entries describe the shape in their `webhook.algorithm` prose:

| Provider | Signed string | Shape | Where it is written down |
|---|---|---|---|
| Bold | `base64(body)` | encoding transform | `providers/bold.json` — "the signed message is the BASE64 encoding of the request body, not the raw body" |
| Square | `notification_url + body` | prefix, bytes untouched | `providers/square.json` — "computed over `<notification URL> + <raw body>`" |
| — | `compact_json(body)` | re-serialisation | **no provider.** Defensive only: see below |

The Square shape is expressible as a template (`{notification_url}{raw_body}`, which `scripts/lib/webhook-sign.js` already resolves); Bold's transform has to be applied in code. The third row has no member in the catalog and you must not give it one on a hunch — a provider that signs a re-serialisation says so in its own documentation, and until an entry says so with `evidence.confidence: high`, `BODY_TRANSFORM = 'reserialize'` is a fallback you enable knowingly, never a default. (Kushki looks like it belongs here and does not: `X-Kushki-Signature` signs `{raw_body}.<X-Kushki-Id>` over the untouched bytes with a unix-seconds suffix, which is `hmac_timestamp_body` — and it means a tolerance window is available there, which this family mostly cannot offer.)

**Catalog fields this fragment reads:** `webhook.verification_family`, `webhook.signed_payload_template`, `webhook.signature_header`, `webhook.header_format`, `webhook.hash_algo`, `webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.timestamp_source`, `webhook.replay_mitigation_strategy`, `webhook.event_id_pointer`, `webhook.secret_env`.

## The contract

1. Read and unpack the signature header exactly as `hmac_raw_body` does.
2. Identify the transform from the provider entry — encoding (`base64`), re-serialisation (`JSON.stringify`), or prefix/suffix. It is a documented per-provider fact, never a guess.
3. Apply the transform to the **raw bytes**, then expand the template around the result. The prefix cases (`{notification_url}{raw_body}`) leave the bytes untouched; only the surrounding string changes.
4. For a re-serialisation scheme, build **two candidates** — one from the raw bytes, one from `JSON.stringify(JSON.parse(rawBody))` — and accept either. See below for why.
5. HMAC, encode, compare constant-time against every candidate. (Rule 3)
6. `timestamp_source` is typically `none` in this family, so event-id dedup from `_preamble.md` is the sole replay defence, exactly as in `hmac_raw_body`. (Rule 9)

## Why re-serialisation is fragile

`JSON.stringify(JSON.parse(text))` is **not** an identity function, and every difference changes the MAC. Measured, not assumed:

| Received bytes | After a parse/stringify round trip |
|---|---|
| `{"b":1,"2":2,"a":3,"1":4}` | `{"1":4,"2":2,"b":1,"a":3}` — integer-like keys jump to the front, ascending |
| `{"a":1.0,"b":1e2,"c":1.50}` | `{"a":1,"b":100,"c":1.5}` — numbers renormalise |
| `{"id":12345678901234567890}` | `{"id":12345678901234567000}` — precision gone past 2^53 |
| `{"n":"caf\u00e9"}` | `{"n":"café"}` — escapes decode; 17 bytes become 13 |
| `{"u":"a\/b"}` | `{"u":"a/b"}` — the escaped solidus is dropped |
| `{"a":1,"a":2}` | `{"a":2}` — duplicate keys collapse |
| pretty-printed JSON | whitespace and indentation gone |

Any one of these makes an authentic event fail verification, intermittently, for whichever merchant happens to have an accented name or a long numeric id. Python is worse: `json.dumps` defaults to `", "` / `": "` separators and `ensure_ascii=True`, so `{"n":"café","a":1}` comes back as `{"n": "café", "a": 1}` — three differences at once. It needs `json.dumps(obj, separators=(",", ":"), ensure_ascii=False)` even to be in the running.

**How to handle it safely:** never re-serialise when the raw bytes will do, and when the scheme genuinely signs a re-serialisation, verify against both candidates. Accepting either costs one extra HMAC and weakens nothing — both candidates are MACs under the same secret, so an attacker gains no forgery they did not already have. Log which candidate matched, and you will learn within a day whether your provider's bytes actually survive the round trip.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { safeEqual, secretKey, encodeDigest, headerValue, unpackSignatureHeader } from './webhook-crypto';

const SIGNATURE_HEADER = '<from webhook.signature_header>';
const HEADER_FORMAT    = <from webhook.header_format>;
const TEMPLATE         = '<from webhook.signed_payload_template>'; // e.g. '{notification_url}{raw_body}'
const HASH_ALGO        = '<from webhook.hash_algo>';
const SECRET_ENCODING  = '<from webhook.secret_encoding>';
const DIGEST_ENCODING  = '<from webhook.digest_encoding>';

// The transform is a documented per-provider fact — see overrides/<provider>/notes.md.
// 'identity' | 'base64' | 'reserialize'
const BODY_TRANSFORM: 'identity' | 'base64' | 'reserialize' = '<from the provider scheme>';

// Square-style schemes prepend the endpoint URL. It MUST be the URL configured in the
// provider dashboard, byte for byte — scheme, host, path, trailing slash. Behind a proxy
// or a tunnel, request.url is a different string, so read it from config, never the request.
const NOTIFICATION_URL = process.env.<PROVIDER>_NOTIFICATION_URL ?? '';

function expand(template: string, bodyPart: string, headers: Headers): string {
  return template.replace(/\{([^}]+)\}/g, (match, token: string) => {
    if (token === 'raw_body')         return bodyPart;
    if (token === 'notification_url') return NOTIFICATION_URL;
    if (token.startsWith('header:'))  return String(headerValue(headers, token.slice(7)) ?? '');
    return match;
  });
}

export function verifySignature(rawBody: string, headers: Headers, secret: string): boolean {
  const raw = headerValue(headers, SIGNATURE_HEADER);
  if (!raw) return false;
  const { signatures } = unpackSignatureHeader(raw, HEADER_FORMAT);
  if (signatures.length === 0) return false;

  // Rule 5: candidates are derived from the received bytes; the bytes themselves are never
  // mutated. Candidate 0 is always the untransformed path — the one that should win.
  const candidates: string[] = [];
  if (BODY_TRANSFORM === 'base64') {
    candidates.push(expand(TEMPLATE, Buffer.from(rawBody, 'utf8').toString('base64'), headers));
  } else {
    candidates.push(expand(TEMPLATE, rawBody, headers));
    if (BODY_TRANSFORM === 'reserialize') {
      // Fallback for providers that sign a compact re-serialisation while sending other bytes.
      try { candidates.push(expand(TEMPLATE, JSON.stringify(JSON.parse(rawBody)), headers)); } catch { /* not JSON */ }
    }
  }

  const key = secretKey(secret, SECRET_ENCODING);
  let matched = false; // Rule 3: constant-time, and no early exit on the first miss
  for (const candidate of candidates) {
    const expected = encodeDigest(crypto.createHmac(HASH_ALGO, key).update(candidate, 'utf8').digest(), DIGEST_ENCODING);
    for (const presented of signatures) if (safeEqual(expected, presented)) matched = true;
  }
  return matched;
}
```

## Python

```python
# app/payments/<provider>_verify.py
import base64, hashlib, hmac, json, os, re
from app.payments.webhook_crypto import safe_equal, secret_key, encode_digest

SIGNATURE_HEADER = "<from webhook.signature_header>"
TEMPLATE         = "<from webhook.signed_payload_template>"
HASH_ALGO, SECRET_ENCODING, DIGEST_ENCODING = "<from webhook.hash_algo>", "<from webhook.secret_encoding>", "<from webhook.digest_encoding>"
BODY_TRANSFORM   = "<from the provider scheme>"   # 'identity' | 'base64' | 'reserialize'
NOTIFICATION_URL = os.environ.get("<PROVIDER>_NOTIFICATION_URL", "")

def _expand(template: str, body_part: str, headers) -> str:
    def sub(m):
        tok = m.group(1)
        if tok == "raw_body":         return body_part
        if tok == "notification_url": return NOTIFICATION_URL
        if tok.startswith("header:"):
            v = headers.get(tok[7:]); return "" if v is None else str(v)
        return m.group(0)
    return re.sub(r"\{([^}]+)\}", sub, template)

def verify_signature(raw_body: bytes, headers, secret: str) -> bool:
    presented = headers.get(SIGNATURE_HEADER)
    if not presented:
        return False

    candidates = []
    if BODY_TRANSFORM == "base64":
        # b64encode takes the wire bytes — no decode, so a non-UTF-8 body cannot raise here.
        candidates.append(_expand(TEMPLATE, base64.b64encode(raw_body).decode("ascii"), headers))
    else:
        try:
            text = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            return False        # unverifiable, so a 400 — never an exception the framework
                                # turns into a 500 with a traceback. Anyone can post those bytes.
        candidates.append(_expand(TEMPLATE, text, headers))       # Rule 5: bytes as received
        if BODY_TRANSFORM == "reserialize":
            try:
                # separators/ensure_ascii are mandatory: the defaults add spaces and escape
                # every non-ASCII character, which no provider signs.
                compact = json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False)
                candidates.append(_expand(TEMPLATE, compact, headers))
            except ValueError:
                pass

    key = secret_key(secret, SECRET_ENCODING)
    matched = False                                               # Rule 3: no early exit
    for candidate in candidates:
        mac = hmac.new(key, candidate.encode("utf-8"), getattr(hashlib, HASH_ALGO)).digest()
        if safe_equal(encode_digest(mac, DIGEST_ENCODING), presented):
            matched = True
    return matched
```

## Anti-patterns

- ❌ Expanding `signed_payload_template` literally because it says `{raw_body}`. That is the whole reason this family has its own name — you get a `hmac_raw_body` verifier that rejects 100% of genuine events. (Rule 3)
- ❌ `JSON.stringify(await request.json())` as the *only* candidate. It is the fragile path; make the raw bytes candidate 0 so the common case never depends on a round trip. (Rule 5)
- ❌ `json.dumps(body)` in Python without `separators=(",", ":")` and `ensure_ascii=False`. The defaults differ from JavaScript in three ways at once.
- ❌ Deriving Square's `notification_url` from `request.url`. Behind a load balancer, an ngrok tunnel or a rewrite, that string is not what the dashboard was configured with, and the prefix must match byte for byte — trailing slash included.
- ❌ Base64-encoding the *decoded string* rather than the bytes when the body is non-ASCII. `Buffer.from(rawBody, 'utf8')` and `base64.b64encode(raw_body)` both take the wire bytes; re-encoding through another charset changes the digest.
- ❌ Treating this family as timestamped. `timestamp_source` is normally `none`, so a captured event replays forever without the preamble's dedup row. (Rule 9)
- ❌ `raw_body.decode("utf-8")` unguarded, in Python. A body that is not valid UTF-8 raises inside the verifier, and the framework answers `500` with a traceback where the answer was a silent `400`.
- ❌ Guessing the transform. If the provider's scheme is not documented in the catalog with `evidence.confidence: high`, emit the re-fetch path and a TODO instead of a verifier that looks authoritative and is wrong. Filing a provider here because its signed string merely *looks* derived is the same mistake — Kushki's `{raw_body}.<timestamp>` is a suffix over untouched bytes, so it is `hmac_timestamp_body` and gets a replay window this family would have thrown away.

## Security rules cited

- **Rule 3:** MAC verified before the payload is used; constant-time comparison across every candidate and every presented signature, with no early exit.
- **Rule 5:** the transform is computed *from* the raw bytes captured by the stack's raw-body API; the untransformed candidate is tried first so the correct path never depends on a JSON round trip.
- **Rule 6:** logging stays in the preamble — `id`, `type`, `created` only.
- **Rule 9:** with `timestamp_source: none` there is no window, so the preamble's event-id dedup is the only replay defence and is mandatory.
- **Rule 10:** the 256 KB cap runs in the preamble — relevant here because base64 expands the hashed input by a third.
