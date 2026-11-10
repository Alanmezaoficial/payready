# `asymmetric_jws` — JWS/JWT signature, algorithm pinned

The callback carries a compact JWS — `protected.payload.signature`, base64url — signed with the
provider's private key. The one thing everybody gets wrong is reading the algorithm out of the
token's own header and using it. That header is attacker-controlled: it is the *claim*, not the
fact. Set it to `none` and a naive verifier skips verification entirely. Set it to `HS256` and a
library that dispatches on the header will HMAC the token using your **public key** as the
secret — and the public key is public, so the attacker computes that MAC too. Pin the algorithm
from configuration, compare, and reject everything else.

**Providers in this family:** none assigned yet — no entry in
`skills/payment-advisor/data/providers.json` carries `asymmetric_jws`. **Lago** (wave 7, currently
`advise` / `unverified`) is the one waiting: headers `X-Lago-Signature` and
`X-Lago-Signature-Algorithm`, JWT with **RS256 by default**, verified against a public key fetched
once from Lago's webhooks API and cached — and the merchant chooses JWT or HMAC when creating the
endpoint.

That last detail is this fragment's rule in the wild. The algorithm is *a deployment choice you
made*, so it lives in your configuration; `X-Lago-Signature-Algorithm` is the sender restating it,
which is worth nothing. Pin what you configured. Self-hosted Lago generates its own RSA keys at
first deploy, so issuer and key source differ per install — one more reason the key is
configuration, never something the message names. Ships ahead of TrueLayer (ES512, detached) and
Plaid (ES256), neither yet in the catalog.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.hash_algo`
(`es256` | `es512` | `rs256`), `webhook.digest_encoding` (`base64url` — JWS always is),
`webhook.secret_env`, `webhook.signed_payload_template`, `webhook.timestamp_source`,
`webhook.recommended_tolerance_seconds`, `webhook.replay_mitigation_strategy`,
`webhook.payload_authoritative`, `webhook.evidence.confidence`.

## The contract

`_preamble.md` owns the size cap, raw-body read, parse ordering, dedup, logging and ack. This
fragment owns **step 4**. One deviation the composer must apply: JWKS resolution is I/O, so this
family's verifier is `async` and the preamble's call site becomes
`if (!(await verifySignature(...)))`.

1. Split on `.` — exactly three segments, or `400` — and decode the protected header.
2. **Pin the algorithm.** `header.alg` must equal the JOSE name of `webhook.hash_algo`. One pin,
   one algorithm; not an allow-list that mixes HMAC with public-key families, which reopens the
   attack it was meant to close (Rule 3).
3. Reject any `crit` entry you do not implement. `crit` means "fail if you do not understand this";
   ignoring it lets the signer change what the signature covers.
4. Select the key **by `kid` from a JWKS cached behind a constant URL**. Never from `jku`, `x5u` or
   an embedded `jwk` — the same "payload picks the key" hole as `asymmetric_rsa`, in a
   standards-shaped hat. Then check the key type matches the pin: `ES*` needs EC, `RS*`/`PS*` RSA.
5. Rebuild the signing input exactly: attached → `protected + "." + payload`; detached →
   `protected + "." + base64url(rawBody)`, or `protected + "." + rawBody` verbatim when the header
   carries `b64: false` with `crit: ["b64"]` (RFC 7797).
6. Verify. **ECDSA signatures in JWS are raw `R||S`, not DER** — Node needs
   `dsaEncoding: 'ieee-p1363'`, Python needs `encode_dss_signature`. Omit it and every genuine
   event is rejected while nothing looks broken; the symptom reads as a wrong key.
7. Bind the token to the request: for an attached JWS the decoded payload segment must equal the
   raw body byte for byte, or you verify one document and act on another.
8. Replay: check `exp`/`iat` where the provider sets them; otherwise `timestamp_source` is `none`,
   `replay_mitigation_strategy` must be `event-id-dedup`, and the preamble's dedup carries it alone
   (Rule 9).

**On constant-time comparison (Rule 3).** As in `asymmetric_rsa`, there is no MAC of yours to
compare: `crypto.verify` and `key.verify()` do it inside the primitive, over public data. The
comparisons this fragment *does* make — `header.alg` against the pin, `kid` against the JWKS — are
over attacker-supplied values whose expected forms are not secret, so an early return leaks
nothing. `safeEqual` from `webhook-crypto` still belongs on any endpoint token you add alongside.

**Status codes** are the preamble's table: `413` over 256 KB, `400` empty-bodied for a missing,
malformed, mis-`alg`ed, unknown-`kid` or invalid token, `200` on a duplicate, `200` plus a logged
TODO for an unrouted event type, `500` only when a verified event's handler threw.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import crypto from 'node:crypto';
import { headerValue } from './webhook-crypto';

const SIGNATURE_HEADER = '<from webhook.signature_header>'; // Lago: 'X-Lago-Signature'
// Rule 3: the pin. From the catalog and your endpoint configuration — never from the token, and
// never from a sibling header like X-Lago-Signature-Algorithm that the sender also controls.
const ALG_FROM_CATALOG: Record<string, string> = { es256: 'ES256', es512: 'ES512', rs256: 'RS256' };
const EXPECTED_ALG = ALG_FROM_CATALOG['<from webhook.hash_algo>'];
const JWKS_URL = 'https://api.<provider>.com/.well-known/jwks.json'; // pinned constant
const KNOWN_CRIT = new Set(['b64']);  // extensions this verifier actually implements
const DETACHED = false;               // true when signed_payload_template omits the payload segment

// Hashes match NODE_HASH in scripts/lib/webhook-sign.js (rs256/es256 → sha256, es512 → sha512).
const SPEC: Record<string, { hash: string; keyType: string; opts: object }> = {
  ES256: { hash: 'sha256', keyType: 'ec', opts: { dsaEncoding: 'ieee-p1363' } },
  ES512: { hash: 'sha512', keyType: 'ec', opts: { dsaEncoding: 'ieee-p1363' } },
  RS256: { hash: 'sha256', keyType: 'rsa', opts: { padding: crypto.constants.RSA_PKCS1_PADDING } },
};

let jwksCache: { keys: Map<string, crypto.KeyObject>; at: number } | null = null;
let inflight: Promise<Map<string, crypto.KeyObject>> | null = null;
let lastMiss = 0;
const JWKS_TTL_MS = 6 * 60 * 60 * 1000;
const MISS_COOLDOWN_MS = 60_000; // an unknown kid must not be a free way to make us hammer the JWKS

async function jwks(force = false): Promise<Map<string, crypto.KeyObject>> {
  if (!force && jwksCache && Date.now() - jwksCache.at < JWKS_TTL_MS) return jwksCache.keys;
  if (inflight) return inflight; // single-flight: N concurrent events cause one fetch, not N
  inflight = (async () => {
    const res = await fetch(JWKS_URL, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error(`jwks ${res.status}`);
    const keys = new Map<string, crypto.KeyObject>();
    for (const jwk of (await res.json()).keys as Array<Record<string, string>>) {
      if (!jwk.kid) continue;
      keys.set(jwk.kid, crypto.createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' }));
    }
    jwksCache = { keys, at: Date.now() };
    return keys;
  })().finally(() => { inflight = null; });
  return inflight;
}

/** Rule 3. Async because JWKS resolution is I/O — see the call-site note above. */
export async function verifySignature(rawBody: string, headers: Headers, _secret: string): Promise<boolean> {
  const token = headerValue(headers, SIGNATURE_HEADER);
  if (!token) return false;
  const parts = token.trim().split('.');
  if (parts.length !== 3) return false;
  const [h64, p64, s64] = parts;

  let header: Record<string, unknown>;
  try { header = JSON.parse(Buffer.from(h64, 'base64url').toString('utf8')); } catch { return false; }
  // JSON.parse('null') is null, and `null.alg` throws — a 500 on a one-byte header the attacker
  // chose. Every shape check below is a `return false` (400) for the same reason.
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return false;

  // Rule 3: the pin. Rejects alg:none and every HMAC alg — an HS256 token MACed with our own
  // (public) JWKS key would otherwise verify. This single line is the family's whole point.
  if (header.alg !== EXPECTED_ALG) return false;
  const crit = header.crit;
  // `crit: "b64"` is not an array, and `.some` on a string is a TypeError, not a rejection.
  if (crit !== undefined && (!Array.isArray(crit) || crit.some((c) => !KNOWN_CRIT.has(c)))) return false;
  if (typeof header.kid !== 'string') return false;

  // A JWKS outage must return false (→ 400) and never throw: an exception here becomes a 500,
  // the provider retries, and the retries hammer the JWKS you already cannot reach.
  const empty = new Map<string, crypto.KeyObject>();
  let key = (await jwks().catch(() => jwksCache?.keys ?? empty)).get(header.kid);
  if (!key && Date.now() - lastMiss > MISS_COOLDOWN_MS) {
    lastMiss = Date.now();                    // rotation: refresh once, then wait out the cooldown
    key = (await jwks(true).catch(() => empty)).get(header.kid);
  }
  if (!key) return false;

  const spec = SPEC[EXPECTED_ALG];
  if (!key.asymmetricKeyType?.startsWith(spec.keyType)) return false; // ES* needs EC, RS* needs RSA

  let signingInput: Buffer;
  if (DETACHED) {
    if (p64 !== '') return false; // a detached JWS must arrive with an empty payload segment
    const payloadSeg = header.b64 === false
      ? Buffer.from(rawBody, 'utf8')                                   // RFC 7797, b64:false
      : Buffer.from(Buffer.from(rawBody, 'utf8').toString('base64url'), 'ascii');
    signingInput = Buffer.concat([Buffer.from(`${h64}.`, 'ascii'), payloadSeg]);
  } else {
    // Bind the token to THIS request. Verifying one document and acting on another is the bug.
    if (Buffer.from(p64, 'base64url').toString('utf8') !== rawBody) return false;
    signingInput = Buffer.from(`${h64}.${p64}`, 'ascii');
  }

  const sig = Buffer.from(s64, 'base64url'); // JWS ECDSA is raw R||S — hence dsaEncoding above
  try {
    return crypto.verify(spec.hash, signingInput, { key, ...spec.opts }, sig);
  } catch { return false; }
}
```

With `jose` and an attached, standard token, prefer
`await jwtVerify(token, keySet, { algorithms: ['ES512'] })` — the `algorithms` option **is** the
pin, and omitting it reopens the attack. `jose` has no RFC 7797 detached mode, which is why the
hand-rolled path above exists. Raw-body capture is the preamble's (`request.text()` with
`runtime = 'nodejs'`, `express.raw` before `express.json()`, `await request.body()` in FastAPI) and
is load-bearing twice here: for a detached JWS the raw body *is* the payload segment.

## Python

```python
# app/payments/<provider>_verify.py
import base64, binascii, json, time
import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils

SIGNATURE_HEADER = "<from webhook.signature_header>"
ALG_FROM_CATALOG = {"es256": "ES256", "es512": "ES512", "rs256": "RS256"}
EXPECTED_ALG = ALG_FROM_CATALOG["<from webhook.hash_algo>"]   # the pin — never from the token
JWKS_URL = "https://api.<provider>.com/.well-known/jwks.json"  # pinned constant
KNOWN_CRIT = {"b64"}
DETACHED = False
SPEC = {"ES256": (hashes.SHA256, "ec"), "ES512": (hashes.SHA512, "ec"), "RS256": (hashes.SHA256, "rsa")}
CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
MISS_COOLDOWN_S = 60
_jwks: dict = {}
_jwks_at = 0.0
_last_miss = 0.0


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _seg(s: str) -> bytes | None:
    """The three token segments are attacker-chosen: bad padding raises binascii.Error, which
    would leave the verifier as a 500 (and a provider retry) instead of a 400. Total, not strict."""
    try:
        return _b64u(s)
    except (ValueError, binascii.Error):
        return None


def _key_from_jwk(jwk: dict):
    if jwk.get("kty") == "EC":
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64u(jwk["x"]), "big"), int.from_bytes(_b64u(jwk["y"]), "big"),
            CURVES[jwk["crv"]](),
        ).public_key()
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(
            int.from_bytes(_b64u(jwk["e"]), "big"), int.from_bytes(_b64u(jwk["n"]), "big"),
        ).public_key()
    raise ValueError("unsupported kty")


def _jwks_keys(force: bool = False) -> dict:
    global _jwks, _jwks_at
    if force or not _jwks or time.time() - _jwks_at > 6 * 3600:
        doc = httpx.get(JWKS_URL, timeout=3.0).raise_for_status().json()
        if not isinstance(doc, dict):
            raise ValueError("JWKS response is not an object")   # caught below, not a 500
        keys = {}
        for k in (doc.get("keys") or []):
            try:
                if k.get("kid"):
                    keys[k["kid"]] = _key_from_jwk(k)
            except (KeyError, TypeError, ValueError):
                continue          # one unusable JWK must not hide the others behind a 500
        _jwks, _jwks_at = keys, time.time()
    return _jwks


def _resolve_key(kid: str):
    """A rotation miss refreshes at most once per cooldown, and a JWKS outage returns None
    (-> 400) rather than raising (-> 500, and a provider retry storm)."""
    global _last_miss
    try:
        key = _jwks_keys().get(kid)
    except (httpx.HTTPError, ValueError):        # ValueError covers a non-JSON JWKS body
        key = _jwks.get(kid)                     # serve from the last good copy
    if key is None and time.time() - _last_miss > MISS_COOLDOWN_S:
        _last_miss = time.time()
        try:
            key = _jwks_keys(force=True).get(kid)
        except (httpx.HTTPError, ValueError):
            return None
    return key


def verify_signature(raw_body: bytes, headers, _secret: str) -> bool:
    """Rule 3: pinned algorithm, JWKS key by kid, signature over the exact bytes."""
    token = headers.get(SIGNATURE_HEADER)
    if not token:
        return False
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    h64, p64, s64 = parts
    raw_header = _seg(h64)
    if raw_header is None:
        return False
    try:
        header = json.loads(raw_header)
    except ValueError:
        return False
    if not isinstance(header, dict):     # json.loads("null") is None, and None.get raises
        return False

    # Rule 3: the pin. Rejects "none" and every HS* algorithm — the algorithm-confusion attack.
    if header.get("alg") != EXPECTED_ALG:
        return False
    crit = header.get("crit", [])        # `crit: 7` is not iterable — a 500, not a rejection
    if not isinstance(crit, list) or any(c not in KNOWN_CRIT for c in crit):
        return False
    kid = header.get("kid")
    if not isinstance(kid, str):
        return False
    key = _resolve_key(kid)
    if key is None:
        return False

    hash_cls, kind = SPEC[EXPECTED_ALG]
    if kind == "ec" and not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    if kind == "rsa" and not isinstance(key, rsa.RSAPublicKey):
        return False

    if DETACHED:
        if p64 != "":
            return False
        payload_seg = (raw_body if header.get("b64") is False
                       else base64.urlsafe_b64encode(raw_body).rstrip(b"="))
        signing_input = h64.encode() + b"." + payload_seg
    else:
        if _seg(p64) != raw_body:                # bind the token to THIS request
            return False
        signing_input = f"{h64}.{p64}".encode()

    sig = _seg(s64)
    if sig is None:
        return False
    algo = hash_cls()
    try:
        if kind == "ec":
            n = (key.curve.key_size + 7) // 8
            if len(sig) != 2 * n:                # JWS carries raw R||S; cryptography wants DER
                return False
            key.verify(
                asym_utils.encode_dss_signature(int.from_bytes(sig[:n], "big"),
                                                int.from_bytes(sig[n:], "big")),
                signing_input, ec.ECDSA(algo),
            )
        else:
            key.verify(sig, signing_input, padding.PKCS1v15(), algo)
        return True
    except InvalidSignature:
        return False
```

With PyJWT and an attached token, `jwt.decode(token, key, algorithms=["ES512"])` is correct — the
`algorithms` argument is mandatory precisely because it is the pin. PyJWT has no detached-payload
mode, so a `b64:false` provider needs the code above.

## Anti-patterns

- ❌ Dispatching on `header.alg` (`if (alg === 'HS256') hmac(...) else rsa(...)`) — this *is* the
  algorithm-confusion attack. Your JWKS key is public, so the attacker can produce that HMAC.
- ❌ Reading the algorithm from a sibling header such as `X-Lago-Signature-Algorithm`. Same
  mistake wearing a different header name: the sender controls both.
- ❌ Accepting `alg: "none"`, or an `algorithms` list that mixes `HS*` with `ES*`/`RS*`.
- ❌ Taking the key from `jku`, `x5u` or an embedded `jwk` header — the payload picks the key.
- ❌ Fetching the JWKS per request, or on every unknown `kid` — an attacker sends random `kid`s
  until the provider rate-limits you and genuine events start failing.
- ❌ Omitting `dsaEncoding: 'ieee-p1363'` (Node) or the DER conversion (Python) for `ES*` — every
  genuine event is rejected, and it looks like a wrong key.
- ❌ Verifying an attached JWS and then acting on a separately-parsed body without checking the
  payload segment equals the raw body — two documents, one signature.
- ❌ Letting a JWKS fetch throw out of the verifier — that is a 500, a retry, and a storm.
- ❌ Trusting the *shape* of the decoded header. `alg`, `crit`, `kid` and all three segments are
  attacker-chosen: a `null` header, a `crit` that is not an array, or a segment with bad base64
  padding must each return `false`. A `TypeError` there is the same 500-and-retry storm, reached
  through the parser instead of the network.
- ❌ Ignoring `crit`. It means "reject if unknown"; skipping it lets the signer redefine what the
  signature covers.

## Security rules cited

- **Rule 3:** the algorithm is pinned from `webhook.hash_algo`, the key comes from a pinned JWKS by
  `kid`, and `verifySignature` / `verify_signature` run before any parse of the body.
- **Rule 5:** the preamble's raw-body capture reaches this verifier unmodified — twice load-bearing,
  since a detached JWS signs those bytes directly.
- **Rule 6:** this fragment logs nothing; identity and logging belong to the preamble.
- **Rule 9:** `exp`/`iat` where the provider sets them, otherwise `event-id-dedup` is the whole
  replay defence — a JWS with no time claims is replayable forever.
- **Rule 10:** the preamble's 256 KB cap; base64url decoding a huge segment before the cap is a
  cheap way to burn your memory.
