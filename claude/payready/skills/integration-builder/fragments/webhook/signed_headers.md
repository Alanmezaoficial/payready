# Canonical string over method, URI and headers (`signed_headers`)

The signature covers a string you assemble yourself — request method, path, a few named headers, and the body
or a hash of it — and nothing in the request tells you how to assemble it. The delimiters **are** the spec. A
canonical string of the shape `<method> <uri>\n<client-id>.<request-time>.<body>` is one space, one newline
and two dots; send `\r\n` instead of `\n`, or a colon where a dot belongs, and you get a digest that is wrong
in a way no error message will ever explain, because every byte of your inputs was correct. The second trap is
the URI itself: the value must be the path the *provider* signed, so a proxy rewrite, an added trailing slash
or a reordered query string breaks verification while the payment sits there looking unpaid.

**Providers in this family:** no entry carries `verification_family: "signed_headers"` yet, and the fragment
is deliberately written against `<provider>` rather than against a named one. Two boundaries matter:

- **This family is the canonical string, not the primitive.** `antom.json` documents exactly this shape —
  `httpMethod + requestPath + clientId + Request-Time + rawBody`, header
  `algorithm=RSA256,keyVersion=1,signature=<url-encoded base64>` — but its last step is **SHA256withRSA
  against Antom's public key, not an HMAC you share**. `asymmetric_rsa.md` owns Antom for that reason; do not
  build an HMAC verifier for it, and do not restate its scheme here. When `webhook.secret_encoding` is `"pem"`
  or `hash_algo` starts `rsa-`, the canonical-string discipline below still applies and the compare step does
  not — see the note at the end of the Node section.
- **The Azure API Management shape** (`Authorization: HMAC <base64>` over `x-ms-date`, `host` and
  `x-ms-content-sha256`) is a platform convention rather than any one provider's scheme, and it is worked
  below because it carries the second trap: a MAC over a *hash header* does not bind the body.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.header_format` (`kv` for
`algorithm=…,keyVersion=…,signature=…`; `prefixed` with `prefix: "HMAC "` for the APIM shape),
`webhook.hash_algo`, `webhook.secret_encoding`, `webhook.digest_encoding` (`base64`),
`webhook.signed_payload_template`, `webhook.timestamp_source` (`header`), `webhook.timestamp_pointer`,
`webhook.recommended_tolerance_seconds`, `webhook.replay_mitigation_strategy`, `webhook.event_id_pointer`,
`webhook.secret_env`.

## The template is the spec

`signed_payload_template` carries the canonical string, with the placeholders
`{raw_body} {timestamp} {header:NAME} {notification_url}` that `scripts/lib/webhook-sign.js` expands. Two
consequences the catalog author has to know:

- **`{notification_url}` does not round-trip.** `signEvent` takes the path from `opts.notificationUrl`, but
  `verifyEvent` builds its context without it, so the placeholder expands to `''` on the verify side and
  `scripts/test-signatures.js` fails the entry. Since PayReady always mounts webhooks at
  `/api/webhook/<provider>` (integration-builder composition rule 1), write the path **literally** into the
  template. In the handler, read it from a config constant for the same reason: behind a rewrite the observed
  path is not the path the provider signed.
- **A content-hash header is not the body.** In the APIM shape the canonical string names
  `x-ms-content-sha256`, not the payload, so the MAC does not bind the body at all — swap the entire JSON,
  leave the headers alone, and the signature still verifies. Recompute that hash from the raw bytes and
  compare it in constant time yourself; the reference verifier expands the header as given and will not.
  (Proven: with that recomputation removed, a body swap that leaves the headers untouched passes.)

## The contract

1. Cap the body at 256 KB before reading, and re-check the byte length after.
2. Read the raw bytes once. Every component of the canonical string is a header or that byte string.
3. Require every header the template names. One missing → 400, before any hashing.
4. Check the timestamp window. Parse it with a date parser when the provider stamps ISO-8601 rather than epoch
   seconds — `Number("2026-05-20T10:00:00+08:00")` is `NaN`, and `Math.abs(now - NaN) > tol` is `false`, so a
   naive check passes every stale event.
5. If a content-hash header participates, recompute it from the raw body and compare it constant-time first.
6. Build the canonical string byte for byte: method upper-case, the path exactly as registered (no host, no
   scheme, no added trailing slash, query preserved verbatim), delimiters copied from the template.
7. Compute the MAC, decode the presented digest (URL-decoding it first if the provider percent-encodes),
   compare in constant time with the length checked first.
8. Parse, dedup on `event_id_pointer`, log id/type/created, enqueue, return 200.

## Node / TypeScript

```ts
// app/api/webhook/<provider>/route.ts   — family: signed_headers
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';

export const runtime = 'nodejs'; // Rule 5
const MAX_BODY_BYTES = 256 * 1024;    // Rule 10
const TOLERANCE_SECONDS = 300;        // <from webhook.recommended_tolerance_seconds>
// The path the provider signs. A constant, never `new URL(request.url).pathname`: a rewrite in front of
// the app changes what you observe but not what was signed.
const WEBHOOK_PATH = '/api/webhook/<provider>';
const SIGNATURE_HEADER = 'signature';  // <from webhook.signature_header>
// Every header the canonical string names, in the order it names them.
// <from webhook.signed_payload_template: "POST /api/webhook/<provider>\n{header:client-id}.{header:request-time}.{raw_body}">
const SIGNED_HEADERS = ['client-id', 'request-time'];
const TIMESTAMP_HEADER = 'request-time'; // <from webhook.timestamp_pointer>
const ROUTED = new Set<string>([/* <from webhook.required_events_minimum> */]);

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10
  }
  const secret = process.env.PROVIDER_WEBHOOK_SECRET; // <from webhook.secret_env>
  if (!secret) { // Rule 3: an unset secret fails closed rather than throwing mid-verification
    console.error('[<provider>.webhook] PROVIDER_WEBHOOK_SECRET is not set — refusing all callbacks');
    return new NextResponse(null, { status: 500 });
  }

  // Every term of the canonical string must be present. A missing header is not an empty string:
  // substituting '' for it builds a *different* canonical string that still hashes to something.
  const signed: Record<string, string> = {};
  for (const name of SIGNED_HEADERS) {
    const value = request.headers.get(name);
    if (!value) return new NextResponse(null, { status: 400 });
    signed[name] = value;
  }
  const signatureHeader = request.headers.get(SIGNATURE_HEADER);
  if (!signatureHeader) return new NextResponse(null, { status: 400 });

  const rawBody = await request.text(); // Rule 5: the exact bytes are part of the canonical string
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10: Content-Length was only a claim
  }
  // Rule 3 + Rule 9: MAC and freshness together, before the payload is touched
  if (!verifySignedHeaders(rawBody, signed, signatureHeader, WEBHOOK_PATH, secret, TOLERANCE_SECONDS)) {
    return new NextResponse(null, { status: 400 }); // no detail — a prober learns nothing
  }

  let event: any;
  try { event = JSON.parse(rawBody); } catch { return new NextResponse(null, { status: 400 }); }

  const eventId = String(event?.id ?? ''); // <from webhook.event_id_pointer>
  if (!eventId) return new NextResponse(null, { status: 400 }); // no id, no dedup key, no replay bound
  const eventType = String(event?.type ?? ''); // <from webhook.event_type_pointer>
  try {
    await db.pagokitWebhookEventProcessed.create({
      data: { event_id: `<provider>:${eventId}`, provider: '<provider>', event_type: eventType,
              expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
    });
  } catch {
    return NextResponse.json({ received: true, duplicate: true }); // Rule 9: idempotent 200
  }
  // Rule 6: metadata only
  console.log('[<provider>.webhook]', { id: eventId, type: eventType, created: signed[TIMESTAMP_HEADER] });
  if (!ROUTED.has(eventType)) {
    console.log('[<provider>.webhook] unhandled event type', eventType); // TODO: route it if needed
    return NextResponse.json({ received: true }); // 200: a 4xx gets the endpoint disabled
  }
  await enqueue({ name: '<provider>.event', payload: { id: eventId } });
  return NextResponse.json({ received: true }); // fast ack; the worker does the slow work
}

function verifySignedHeaders(
  rawBody: string,
  signed: Record<string, string>,
  signatureHeader: string,
  path: string, secret: string, toleranceSeconds: number, nowMs = Date.now(),
): boolean {
  // Rule 9: when the stamp is ISO-8601, parse it as a date. Number('2026-05-20T10:00:00+08:00') is NaN,
  // and every comparison with NaN is false, so a naive window check passes every stale event.
  const sentMs = Date.parse(signed[TIMESTAMP_HEADER] ?? '');
  if (Number.isNaN(sentMs)) return false;
  if (Math.abs(nowMs - sentMs) > toleranceSeconds * 1000) return false;

  const presentedB64 = readKvSignature(signatureHeader, 'signature');
  if (!presentedB64) return false;

  // <from webhook.signed_payload_template> — one space after the method, ONE \n, dots between the rest
  const canonical = `POST ${path}\n${signed['client-id']}.${signed['request-time']}.${rawBody}`;
  const expected = crypto.createHmac('sha256', secret) // <from webhook.hash_algo> + secret_encoding
    .update(canonical, 'utf8').digest();
  const presented = Buffer.from(presentedB64, 'base64'); // <from webhook.digest_encoding>
  if (presented.length !== expected.length) return false; // Rule 3: timingSafeEqual throws otherwise
  return crypto.timingSafeEqual(presented, expected);
}

// header_format kv: `algorithm=…,keyVersion=…,signature=<percent-encoded base64>`. Read the named key;
// never positionally, the order is not guaranteed and `keyVersion` moves during a rotation.
function readKvSignature(headerValue: string, key: string): string {
  const parts = new Map<string, string>();
  for (const part of headerValue.split(',')) { // <from webhook.header_format.separator>
    const i = part.indexOf('=');               // base64 padding is '=', so split on the FIRST one only
    if (i === -1) continue;
    parts.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  const raw = parts.get(key) ?? '';            // <from webhook.header_format.signature_key>
  if (!raw) return '';
  // Percent-decode ONCE. decodeURIComponent THROWS URIError on a malformed escape ('%E0%A4%A'), and an
  // attacker picks the header: unguarded, that is a 500 — which the provider reads as "retry", not "no".
  try { return decodeURIComponent(raw); } catch { return ''; }
}

// Azure APIM shape: the canonical string names a HASH of the body, so bind that hash to the
// bytes yourself or the body is unauthenticated.
function verifyApimHmac(rawBody: string, headers: Record<string, string | null>, path: string, secret: string): boolean {
  const auth = headers['authorization'], date = headers['x-ms-date'];
  const host = headers['host'], contentSha = headers['x-ms-content-sha256'];
  if (!auth || !date || !host || !contentSha || !auth.startsWith('HMAC ')) return false;

  // Rule 3: the MAC never covers the payload — this comparison is what makes the body authentic
  const actual = crypto.createHash('sha256').update(rawBody, 'utf8').digest();
  const claimed = Buffer.from(contentSha, 'base64');
  if (claimed.length !== actual.length || !crypto.timingSafeEqual(claimed, actual)) return false;

  // <from webhook.signed_payload_template: "POST\n/api/webhook/<provider>\n{header:x-ms-date};{header:host};…">
  const canonical = `POST\n${path}\n${date};${host};${contentSha}`;
  const expected = crypto.createHmac('sha256', secret).update(canonical, 'utf8').digest();
  const presented = Buffer.from(auth.slice('HMAC '.length), 'base64'); // header_format prefixed
  if (presented.length !== expected.length) return false;
  return crypto.timingSafeEqual(presented, expected);
}
```

When the entry says `secret_encoding: "pem"` or `hash_algo: "rsa-sha256"` / `"rs256"`, the canonical string
above is unchanged and only the last step differs — `crypto.createVerify('RSA-SHA256').update(canonical)
.verify(publicKeyPem, presentedB64, 'base64')`, with no constant-time compare, because a public-key verify
holds no secret of yours. That provider belongs to `asymmetric_rsa.md`, which owns key resolution and
rotation; this fragment owns only the string it verifies over.

Express — the raw body must survive, and `host` must be the public host the provider called:

```ts
app.set('trust proxy', true); // so req.headers.host / X-Forwarded-Host reflect the signed value
app.post('/api/webhook/<provider>',
  express.raw({ type: 'application/json', limit: '256kb' }), // Rule 5 + Rule 10
  handler);                                                  // const rawBody = req.body.toString('utf8')
app.use(express.json()); // ← AFTER the webhook route
```

## Python

```python
# app/webhooks/<provider>.py
import base64, hashlib, hmac, json, os
from datetime import datetime, timezone
from urllib.parse import unquote
from fastapi import APIRouter, Request, Response

router = APIRouter()
MAX_BODY_BYTES = 256 * 1024           # Rule 10
TOLERANCE_SECONDS = 300               # <from webhook.recommended_tolerance_seconds>
WEBHOOK_PATH = "/api/webhook/<provider>"   # the registered path, not the observed one
SIGNED_HEADERS = ("client-id", "request-time")   # <from webhook.signed_payload_template>
TIMESTAMP_HEADER = "request-time"                # <from webhook.timestamp_pointer>

@router.post(WEBHOOK_PATH)
async def provider_webhook(request: Request) -> Response:
    if int(request.headers.get("content-length", 0)) > MAX_BODY_BYTES:   # Rule 10
        return Response(status_code=413)
    secret = os.environ.get("PROVIDER_WEBHOOK_SECRET", "")               # <from webhook.secret_env>
    if not secret:                                                       # Rule 3: fail closed
        return Response(status_code=500)
    raw_body = await request.body()                                      # Rule 5: bytes, never .json()
    if len(raw_body) > MAX_BODY_BYTES:
        return Response(status_code=413)
    if not verify_signed_headers(raw_body, request.headers, WEBHOOK_PATH,   # Rule 3 + Rule 9
                                 secret, TOLERANCE_SECONDS):
        return Response(status_code=400)                                 # no detail to the caller
    try:
        event = json.loads(raw_body)
    except ValueError:
        return Response(status_code=400)

    event_id = str(event.get("id") or "")                                # <from webhook.event_id_pointer>
    if not event_id:
        return Response(status_code=400)                                 # no id, no replay bound
    event_type = event.get("type")                                       # <from webhook.event_type_pointer>
    if not claim_event(f"<provider>:{event_id}", event_type):
        return Response(status_code=200)                                 # Rule 9: duplicate → 200
    log.info("<provider>.webhook", extra={"id": event_id, "type": event_type,
                                          "created": request.headers.get(TIMESTAMP_HEADER)})  # Rule 6
    enqueue("<provider>.event", {"id": event_id})
    return Response(status_code=200)                                     # fast ack


def verify_signed_headers(raw_body: bytes, headers, path: str, secret: str,
                          tolerance_seconds: int, now: datetime | None = None) -> bool:
    signed = {name: headers.get(name) for name in SIGNED_HEADERS}
    signature_header = headers.get("signature")                # <from webhook.signature_header>
    if not signature_header or not all(signed.values()):       # a missing term is not an empty term
        return False
    try:
        sent = datetime.fromisoformat(signed[TIMESTAMP_HEADER])   # Rule 9: ISO-8601, not epoch seconds
    except ValueError:
        return False
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    if abs((now - sent).total_seconds()) > tolerance_seconds:
        return False

    # header_format kv — read the key by name and strip it; the order is not guaranteed
    parts = {}
    for part in signature_header.split(","):
        key, sep, value = part.partition("=")   # base64 padding is '=', so split on the FIRST one
        if sep:
            parts[key.strip()] = value.strip()
    presented_b64 = unquote(parts.get("signature", ""))
    if not presented_b64:
        return False
    # one space, one \n, two dots — copied from webhook.signed_payload_template
    canonical = (f"POST {path}\n{signed['client-id']}.{signed['request-time']}.").encode() + raw_body
    expected = hmac.new(secret.encode(), canonical, hashlib.sha256).digest()
    try:
        presented = base64.b64decode(presented_b64, validate=True)
    except Exception:
        return False
    return hmac.compare_digest(presented, expected)      # Rule 3: constant time, over bytes
```

## Anti-patterns

- ❌ Signing the full URL when the spec says path, or the path when the spec says path-and-query. Both produce
  a valid-looking mismatch. Test with a query string present at least once.
- ❌ Normalising the URI: adding or stripping a trailing slash, lower-casing it, re-encoding `%20`, or sorting
  the query parameters. The provider signed the string it sent, characters and order included.
- ❌ Building the path from the incoming request (`new URL(request.url).pathname`, `req.originalUrl`) when a
  proxy, a rewrite or a framework base path can change it. Use the registered constant.
- ❌ Template-literal newlines that become `\r\n` — an editor, a Windows checkout or a `.gitattributes` rule
  can do this to you silently. Build the canonical string from explicit `\n`, never from a heredoc.
- ❌ Comparing the percent-encoded signature without URL-decoding it first, or decoding it twice.
- ❌ Verifying the APIM canonical string without recomputing `x-ms-content-sha256` from the body. The MAC
  covers the header; the header is the attacker's to choose unless you bind it to the bytes.
- ❌ Taking `host` from your own config while the provider signed the `Host` header it sent. Read the header,
  and set `trust proxy` so a forwarded host is visible.
- ❌ `Number(requestTime)` on an ISO-8601 stamp. It yields `NaN`, the comparison is `false`, and every replay
  sails through the window check that looked correct in review.
- ❌ `decodeURIComponent` on the presented signature without a `try`. The header is the attacker's; a
  malformed escape throws `URIError`, the route 500s instead of 400ing, and the provider retries the forgery.
- ❌ Substituting `''` for a header the canonical string names but the request omitted. You have not failed
  the check, you have quietly changed which string you are verifying.
- ❌ Reaching for `createHmac` because the scheme "signs headers". Read `hash_algo` and `secret_encoding`
  first: `rsa-*` / `"pem"` means the provider signed with a private key you do not have, and the file that
  owns it is `asymmetric_rsa.md`.

## Security rules cited

- **Rule 3:** the canonical string is rebuilt and the MAC checked before the payload is parsed; comparison is
  `timingSafeEqual` / `hmac.compare_digest` with the length checked first.
- **Rule 5:** raw bytes via `request.text()` / `express.raw` / `await request.body()` — here the body is
  literally a term in the signed string, so a re-serialised body cannot verify.
- **Rule 6:** id, event type and the request time are logged; the payload is not.
- **Rule 9:** the timestamp is signed, so the window applies (`timestamp_source: "header"`), and the event id
  is deduped for replays inside it — `replay_mitigation_strategy: "both"`.
- **Rule 10:** 256 KB, from `Content-Length` and again from the bytes actually read.
