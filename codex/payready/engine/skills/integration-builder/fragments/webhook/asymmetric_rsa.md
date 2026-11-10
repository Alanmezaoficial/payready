# `asymmetric_rsa` — RSA signature verified with the provider's public key

The provider signs with its own private key; you verify with the public key it publishes. Nothing
you hold is confidential — and that is what goes wrong. Developers treat the public key like a
webhook secret and resolve it *at request time*, from a URL or PEM the event itself supplies. An
attacker generates a keypair, signs a forged `payment.succeeded`, points that field at a host they
control, and the verifier agrees with them. The key is configuration, cached in memory; the
payload never chooses the key that validates it. The second trap is quieter: with no shared
secret there is often no signed timestamp either, and then event-id dedup is not defence in depth,
it is the only defence.

**Providers in this family:** none assigned yet — no entry in
`skills/payment-advisor/data/providers.json` (42 providers) carries `asymmetric_rsa`. Two are
waiting on it, both `integration_level: advise`, `verification_family: "unverified"`:

- **Conekta** (wave 1) — `Digest` header, RSA over SHA-256 of the raw UTF-8 body, base64, verified
  with a Conekta-issued public key; the merchant creates the keypair once via `POST /webhook_keys`.
  **No timestamp is covered**, so no window is possible and dedup carries replay alone.
- **Antom** (wave 5) — header `algorithm=RSA256,keyVersion=1,signature=<url-encoded base64>`,
  SHA256withRSA over `httpMethod + requestPath + clientId + Request-Time + rawBody`. The catalog
  records the signature as **URL-encoded** base64, so unescape it before decoding — `%2B` fed
  straight to a base64 decoder is silently dropped, and you get a rejection that reads like a
  wrong key. `Request-Time` **is** signed, so a window applies, and `keyVersion` is the rotation
  handle. The docs also warn explicitly: hash the HTTP body as received, never a re-serialised
  copy.

Between them they cover both shapes: no signed timestamp (dedup only) and a signed one (window
first). Ships ahead of EBANX, Trustly, Satispay, WeChat Pay and Bridge, none yet in the catalog.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.hash_algo`
(`rsa-sha256` | `rsa-sha1`), `webhook.digest_encoding`, `webhook.secret_encoding` (`"pem"`),
`webhook.secret_env`, `webhook.signed_payload_template`, `webhook.header_format`,
`webhook.timestamp_source`, `webhook.timestamp_pointer`, `webhook.recommended_tolerance_seconds`,
`webhook.replay_mitigation_strategy`, `webhook.payload_authoritative`, `webhook.weak_crypto`.

## The contract

`_preamble.md` owns the size cap, the raw-body read, the parse ordering, the dedup transaction,
the logging and the ack. This fragment owns **step 4, the verification**, and two things unique to
asymmetric schemes: where the key comes from, and what to do when it rotates.

1. Read `webhook.signature_header` case-insensitively and decode per `webhook.digest_encoding`.
   A malformed encoding is a `400`, not a thrown exception — `Buffer.from(v, 'hex')` on odd-length
   input silently truncates, so validate rather than trust it.
2. Resolve the key **from `webhook.secret_env`, through a cache**. Never from a URL, `kid` or PEM
   in the request. `secret_encoding: "pem"` is the catalog's signal that the "secret" is a public
   key and `createHmac` has no place in this file.
3. Build the signed string from `webhook.signed_payload_template`. `{raw_body}` alone for Conekta;
   Antom's expands to `httpMethod + requestPath + clientId + Request-Time + rawBody`. Resolve it
   the way `scripts/lib/webhook-sign.js` `resolveTemplate` does, so CI and production agree.
4. When `webhook.timestamp_source != "none"`, check the window **before** verifying. RSA
   verification costs ~100× an HMAC, so window-first is both the cheap check and a DoS control
   (Rule 9). When it *is* `"none"`, `replay_mitigation_strategy` must be `event-id-dedup` and the
   preamble's dedup is the whole defence.
5. Verify with `webhook.hash_algo` mapped exactly as `webhook-sign.js` `NODE_HASH` maps it.
   Failure → `400`, empty body (Rule 3).

**On constant-time comparison (Rule 3).** RSA verification is not recompute-and-compare, so there
is no MAC of yours to compare: `crypto.verify` and `key.verify()` compare inside the primitive,
over data that is public anyway. `safeEqual` from `webhook-crypto` belongs on the *other*
comparison in this family — Antom's `keyVersion`, or an endpoint token — never `===`.

**Status codes** are the preamble's table: `413` over 256 KB, `400` with an empty body for a
missing, malformed, invalid or stale signature, `200` on a duplicate, `200` plus a logged TODO for
an unrouted event type, `500` only when a verified event's handler threw.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { headerValue } from './webhook-crypto';

const SIGNATURE_HEADER = '<from webhook.signature_header>'; // Conekta: 'Digest'
const HASH_ALGO        = '<from webhook.hash_algo>';        // 'rsa-sha256' | 'rsa-sha1'
const DIGEST_ENCODING  = '<from webhook.digest_encoding>';  // 'base64' | 'hex'
const SECRET_ENV       = '<from webhook.secret_env>';       // holds a PEM: secret_encoding 'pem'

// Same table as NODE_HASH in scripts/lib/webhook-sign.js. Diverging here means CI round-trips one
// algorithm while production verifies another.
const NODE_HASH: Record<string, string> = {
  'rsa-sha256': 'sha256', 'rsa-sha1': 'sha1',
  sha256: 'sha256', sha384: 'sha384', sha512: 'sha512', sha1: 'sha1',
};

function decodeSignature(v: string, enc: string): Buffer | null {
  try {
    if (enc === 'base64') return Buffer.from(v, 'base64');
    if (enc === 'base64url') return Buffer.from(v, 'base64url');
    if (!/^[0-9a-fA-F]+$/.test(v) || v.length % 2) return null; // Buffer.from(hex) truncates silently
    return Buffer.from(enc === 'hex_upper' ? v.toLowerCase() : v, 'hex');
  } catch { return null; }
}

// Rule 3: parsed once per distinct PEM, never per request, never named by the payload. Both slots
// are live during a rotation, so rotating is a deploy: publish _NEXT, let the provider cut over,
// promote it, drop the old one. Antom's keyVersion header tells you when the cut-over happened.
const keyCache = new Map<string, crypto.KeyObject>();
function acceptedKeys(primaryPem: string): crypto.KeyObject[] {
  const pems = [primaryPem, process.env[`${SECRET_ENV}_NEXT`]].filter(Boolean) as string[];
  return pems.map((pem) => {
    let key = keyCache.get(pem);
    if (!key) {
      key = crypto.createPublicKey(pem);
      // An EC or Ed25519 key here means the catalog family is wrong — fail loudly, not silently.
      if (!key.asymmetricKeyType?.startsWith('rsa')) throw new Error(`${SECRET_ENV} is not an RSA key`);
      keyCache.set(pem, key);
    }
    return key;
  });
}

/** Rule 3. `publicKeyPem` is what _preamble.md passes as `secret` — for this family it is a PEM. */
export function verifySignature(rawBody: string, headers: Headers, publicKeyPem: string): boolean {
  const presented = headerValue(headers, SIGNATURE_HEADER);
  const hash = NODE_HASH[HASH_ALGO];
  if (!presented || !hash) return false;
  const sig = decodeSignature(presented.trim(), DIGEST_ENCODING);
  if (!sig || sig.length === 0) return false;

  // <from webhook.signed_payload_template> — '{raw_body}' here; expand the template for schemes
  // that also sign the method, path or a Request-Time header (Antom).
  const signedString = rawBody;

  // PKCS#1 v1.5 is what payment providers document. Use PSS only where the provider does:
  // { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
  const data = Buffer.from(signedString, 'utf8');
  for (const key of acceptedKeys(publicKeyPem)) {
    try {
      if (crypto.verify(hash, data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig)) return true;
    } catch { /* signature malformed for this key — try the next */ }
  }
  return false;
}
```

Raw-body capture is the preamble's job and unchanged here: `await request.text()` with
`export const runtime = 'nodejs'` (App Router), `express.raw({ type: 'application/json',
limit: '256kb' })` registered **before** `app.use(express.json())`, `await request.body()` in
FastAPI. It matters more in this family than in an HMAC one: `JSON.stringify(JSON.parse(raw))`
changes key order and Unicode escaping, so the signature fails only for events carrying accented
names — a bug that reaches production because the test fixtures are all ASCII.

## Python

```python
# app/payments/<provider>_verify.py
import base64, binascii, os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGNATURE_HEADER = "<from webhook.signature_header>"
HASH_ALGO        = "<from webhook.hash_algo>"        # 'rsa-sha256' | 'rsa-sha1'
DIGEST_ENCODING  = "<from webhook.digest_encoding>"  # 'base64' | 'hex'
SECRET_ENV       = "<from webhook.secret_env>"

# Mirrors NODE_HASH in scripts/lib/webhook-sign.js.
HASH_FROM_CATALOG = {"rsa-sha256": hashes.SHA256, "rsa-sha1": hashes.SHA1,
                     "sha256": hashes.SHA256, "sha384": hashes.SHA384,
                     "sha512": hashes.SHA512, "sha1": hashes.SHA1}
_key_cache: dict[str, rsa.RSAPublicKey] = {}


def _accepted_keys(primary_pem: str) -> list:
    """Rule 3: parsed once per distinct PEM, never per request, never chosen by the payload."""
    keys = []
    for pem in [p for p in (primary_pem, os.getenv(f"{SECRET_ENV}_NEXT")) if p]:
        key = _key_cache.get(pem)
        if key is None:
            key = serialization.load_pem_public_key(pem.encode())
            if not isinstance(key, rsa.RSAPublicKey):
                raise RuntimeError(f"{SECRET_ENV} is not an RSA public key")
            _key_cache[pem] = key
        keys.append(key)
    return keys


def verify_signature(raw_body: bytes, headers, public_key_pem: str) -> bool:
    """Rule 3. `public_key_pem` is what _preamble.md passes as `secret` for this family."""
    presented = headers.get(SIGNATURE_HEADER)
    hash_cls = HASH_FROM_CATALOG.get(HASH_ALGO)
    if not presented or hash_cls is None:
        return False
    try:
        v = presented.strip()
        sig = (base64.b64decode(v, validate=True) if DIGEST_ENCODING == "base64"
               else base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)) if DIGEST_ENCODING == "base64url"
               else binascii.unhexlify(v.lower()))
    except (binascii.Error, ValueError):
        return False
    if not sig:
        return False

    algo = hash_cls()
    # PKCS1v15 unless the provider documents PSS:
    # padding.PSS(mgf=padding.MGF1(algo), salt_length=padding.PSS.DIGEST_LENGTH)
    for key in _accepted_keys(public_key_pem):
        try:
            key.verify(sig, raw_body, padding.PKCS1v15(), algo)   # <from signed_payload_template>
            return True
        except InvalidSignature:
            continue
    return False
```

## Rotating keys, and RSA-SHA1

Prefer the env var and the `_NEXT` slot above — a rotation becomes a deploy. When the provider
rotates on its own schedule and publishes a key endpoint, fetch from a **pinned constant URL**,
never one the payload names, behind a TTL cache and a single-flight guard so N concurrent events
cause one fetch. Put a cooldown on refresh-after-failure: without it, "signature failed → refresh
the key" is a free way for an attacker to make you hammer the provider until it rate-limits you
and every genuine event starts failing.

Some providers here still sign with `rsa-sha1` (`hash_algo: "rsa-sha1"`, `weak_crypto: true`).
Implement **what is documented**. "Upgrading" to SHA-256 rejects 100% of genuine events; that
looks like a broken key, and the usual next move is someone disabling verification to ship. Put
the warning in `PAGOKIT_INTEGRATION.md` instead. SHA-1 collisions need control of both signed
messages, which an inbound webhook does not give the attacker — a reason to press the provider,
not to break the integration.

## Anti-patterns

- ❌ Taking the key from a URL, `kid` or PEM inside the event — the attacker picks the key, so
  every forged event verifies. The defining mistake of the family.
- ❌ Fetching the key per request — makes the provider's key endpoint a hard dependency of your
  ack deadline; one outage there silently drops every payment event.
- ❌ `crypto.createHmac(...)` anywhere in this file. `secret_encoding: "pem"` means there is no
  shared secret; reaching for an HMAC means the catalog family is wrong.
- ❌ Verifying `JSON.stringify(JSON.parse(raw))` — passes every ASCII test fixture, fails on the
  first customer named Muñoz.
- ❌ Rewriting `rsa-sha1` as SHA-256 "for security" — rejects every genuine event.
- ❌ PSS padding against a PKCS#1 v1.5 signature, or the reverse — silent 100% failure.
- ❌ Assuming a timestamp window exists. Conekta signs no timestamp; skipping dedup there leaves a
  captured event replayable forever.
- ❌ `{ error: 'signature mismatch' }` on the 400 — a signature oracle, one bit at a time.

## Security rules cited

- **Rule 3:** `verifySignature` / `verify_signature` run before any parse, are named so
  `hooks/checks/webhook-has-signature.js` recognises them, and the key comes from configuration
  rather than from the message.
- **Rule 5:** the preamble's `request.text()` / `express.raw` / `await request.body()` reach this
  verifier as unmodified bytes; re-serialising breaks RSA exactly as it breaks an HMAC.
- **Rule 6:** this fragment logs nothing at all — identity and logging belong to the preamble.
- **Rule 9:** window first when `timestamp_source != "none"`; otherwise `event-id-dedup` is the
  entire replay defence, which is Conekta's case.
- **Rule 10:** the 256 KB cap is the preamble's, and matters more here — RSA verification is the
  most expensive thing an unauthenticated caller can make you do.
