# Standard Webhooks (`webhook-id` · `webhook-timestamp` · `webhook-signature`)

A published spec that a growing number of providers adopt verbatim, most of them by running Svix underneath:
three fixed headers, one signed string, one digest encoding. Nothing is negotiable, so — unusually — an
off-the-shelf verifier is the right answer. The one thing developers get wrong is the secret: `whsec_…` is not
the key, it is a prefix in front of **base64-encoded key material**. Keying the HMAC with the string copied out
of the dashboard rejects every genuine event, and the usual next move is to delete the verification, not the bug.

**Providers in this family:** no entry carries `verification_family: "standard_webhooks"` yet. Three catalog
entries quote the spec verbatim in `webhook.algorithm`, all at `integration_level: advise`: **Yoco** and
**Polar**, which send the spec's own `webhook-id` / `webhook-timestamp` / `webhook-signature`, and
**Recurrente**, which runs Svix and sends the legacy `svix-id` / `svix-timestamp` / `svix-signature` names —
identical signed string, identical digest, different header names. That is the reason every header name below
comes from `webhook.signature_header`, `webhook.timestamp_pointer` and the `{header:…}` placeholders in
`webhook.signed_payload_template` instead of being hardcoded: a handler wired to `webhook-id` reads `null`
from a Recurrente callback and rejects every genuine event. When one of those entries is typed with
`verification_family: "standard_webhooks"`, integration-builder resolves to this file and no new template is
written.

**Catalog fields this fragment reads:** `webhook.signature_header`, `webhook.header_format` (`kind:
"prefixed"`, `prefix: "v1,"`), `webhook.hash_algo`, `webhook.secret_encoding` (`base64_decode`),
`webhook.digest_encoding` (`base64`), `webhook.signed_payload_template`, `webhook.timestamp_source`
(`header`), `webhook.timestamp_pointer` (`webhook-timestamp`), `webhook.recommended_tolerance_seconds`,
`webhook.event_id_pointer`, `webhook.replay_mitigation_strategy`, `webhook.secret_env`,
`webhook.required_events_minimum`.

## Lead with the library

Install `svix` and let it verify: it already does the three-header parse, the base64 secret decode, the
tolerance window, the rotation-tolerant multi-signature loop and the constant-time compare — every place this
scheme is normally got wrong. Hand-roll only when the dependency is impossible, and read the manual version
below anyway, because it is what you need to debug a `WebhookVerificationError` you do not understand.

```bash
npm install svix --save-exact     # pin it; verification is no place for a floating range
pip install svix
```

## The contract

1. Cap the body at 256 KB before reading, then re-check the byte length after reading (`Content-Length` is a
   claim, and a chunked request carries none).
2. Read `webhook-id`, `webhook-timestamp`, `webhook-signature`. Any one missing → 400.
3. Capture the raw bytes. Do not parse yet.
4. Reject a timestamp outside the tolerance **in either direction** — a future one is as suspicious as a stale one.
5. Decode the secret: strip `whsec_`, base64-decode the rest. That is the HMAC key.
6. Build `{webhook-id}.{webhook-timestamp}.{raw body}` — dots, that order, header values exactly as received.
7. HMAC-SHA256 it with the key; the digest is base64.
8. Split `webhook-signature` on spaces; each entry is `<version>,<base64 digest>`. Accept if **any** `v1` entry
   matches in constant time, and skip entries whose version is not `v1`.
9. Only now parse. Dedup on `webhook-id`, log id/type/created, enqueue, return 200.

## Node / TypeScript

```ts
// app/api/webhook/<provider>/route.ts
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { Webhook, WebhookVerificationError } from 'svix';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';

export const runtime = 'nodejs'; // Rule 5: Edge has no node:crypto and no reliable raw body

const MAX_BODY_BYTES = 256 * 1024;   // Rule 10
const TOLERANCE_SECONDS = 300;       // <from webhook.recommended_tolerance_seconds>
const ROUTED = new Set<string>([/* <from webhook.required_events_minimum> */]);

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10: refuse before doing any work
  }
  const id = request.headers.get('webhook-id');
  const timestamp = request.headers.get('webhook-timestamp');
  const signature = request.headers.get('webhook-signature'); // <from webhook.signature_header>
  if (!id || !timestamp || !signature) return new NextResponse(null, { status: 400 });

  const rawBody = await request.text(); // Rule 5: exact bytes, before any parse
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10: Content-Length was only a claim
  }

  const secret = process.env.PROVIDER_WEBHOOK_SECRET; // <from webhook.secret_env>
  if (!secret) { // Rule 3: an unset secret fails closed here, not as a thrown 500 further down
    console.error('[<provider>.webhook] PROVIDER_WEBHOOK_SECRET is not set — refusing all callbacks');
    return new NextResponse(null, { status: 500 });
  }
  // Rule 3 + Rule 9: the library checks the MAC and the timestamp window together
  const wh = new Webhook(secret);
  let event: any;
  try {
    event = wh.verify(rawBody, { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': signature });
  } catch (err) {
    if (!(err instanceof WebhookVerificationError)) throw err;
    return new NextResponse(null, { status: 400 }); // no detail — never tell a prober which check failed
  }

  // Rule 9: webhook-id is the spec's message id, stable across the provider's own retries
  try {
    await db.pagokitWebhookEventProcessed.create({
      data: { event_id: `<provider>:${id}`, provider: '<provider>', event_type: event.type,
              expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
    });
  } catch {
    return NextResponse.json({ received: true, duplicate: true }); // 200: a retry must settle, not loop
  }

  // Rule 6: id, type, created — never the payload
  console.log('[<provider>.webhook]', { id, type: event.type, created: event.created_at });

  if (!ROUTED.has(event.type)) {
    console.log('[<provider>.webhook] unhandled event type', event.type); // TODO: route it if the product needs it
    return NextResponse.json({ received: true }); // 200: a 4xx here gets the endpoint disabled
  }

  // Fast ack: enqueue and return. No email, no PDF, no third-party call inside the handler.
  await enqueue({ name: '<provider>.event', payload: { message_id: id, event_type: event.type } });
  return NextResponse.json({ received: true });
}
```

The manual verifier — same semantics, and what you read when the library says no:

```ts
function verifyStandardWebhook(
  rawBody: string,
  headers: { id: string; timestamp: string; signature: string },
  secret: string,
  toleranceSeconds: number,
  nowSec = Math.floor(Date.now() / 1000),
): boolean {
  const ts = Number(headers.timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(nowSec - ts) > toleranceSeconds) return false; // Rule 9: the signature itself expires

  // <from webhook.secret_encoding: "base64_decode"> — key material sits behind the whsec_ prefix
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  // <from webhook.signed_payload_template: "{header:webhook-id}.{timestamp}.{raw_body}">
  const expected = crypto.createHmac('sha256', key)
    .update(`${headers.id}.${headers.timestamp}.${rawBody}`, 'utf8').digest();

  // The header is a LIST: mid-rotation the provider sends `v1,<old> v1,<new>`. Accept if any
  // candidate matches; never take split(' ')[0]. No early return — the loop runs to the end so
  // it cannot leak which candidate matched.
  let ok = false;
  for (const part of headers.signature.split(' ')) {
    const comma = part.indexOf(',');
    if (comma === -1 || part.slice(0, comma) !== 'v1') continue; // unknown version: skip, don't guess
    const presented = Buffer.from(part.slice(comma + 1), 'base64');
    // Rule 3: length first — timingSafeEqual throws on a length mismatch
    if (presented.length === expected.length && crypto.timingSafeEqual(presented, expected)) ok = true;
  }
  return ok;
}
```

Express — the raw body only survives if `express.raw` is registered before the JSON parser:

```ts
app.post('/api/webhook/<provider>',
  express.raw({ type: 'application/json', limit: '256kb' }), // Rule 5 + Rule 10; req.body is a Buffer
  handler);
app.use(express.json()); // ← AFTER the webhook route, never before
```


## Python

```python
# app/webhooks/<provider>.py
import base64, hashlib, hmac, os, time
from fastapi import APIRouter, Request, Response
from svix.webhooks import Webhook, WebhookVerificationError

router = APIRouter()
MAX_BODY_BYTES = 256 * 1024      # Rule 10

@router.post("/api/webhook/<provider>")
async def provider_webhook(request: Request) -> Response:
    if int(request.headers.get("content-length", 0)) > MAX_BODY_BYTES:  # Rule 10
        return Response(status_code=413)
    raw_body = await request.body()                                     # Rule 5: bytes, never .json()
    if len(raw_body) > MAX_BODY_BYTES:                                  # Rule 10: the header was a claim
        return Response(status_code=413)
    secret = os.environ.get("PROVIDER_WEBHOOK_SECRET", "")              # <from webhook.secret_env>
    if not secret:                                                      # Rule 3: fail closed, loudly
        return Response(status_code=500)
    try:                                                                # Rule 3 + Rule 9 (svix does both)
        event = Webhook(secret).verify(raw_body, request.headers)
    except WebhookVerificationError:
        return Response(status_code=400)                                # no detail to the caller
    message_id = request.headers["webhook-id"]
    if not claim_event(f"<provider>:{message_id}", event["type"]):      # Rule 9: dedup insert
        return Response(status_code=200)                                # duplicate → idempotent 200
    log.info("<provider>.webhook", extra={"id": message_id, "type": event["type"],
                                          "created": event.get("created_at")})  # Rule 6
    enqueue("<provider>.event", {"message_id": message_id, "event_type": event["type"]})
    return Response(status_code=200)                                    # fast ack; the worker does the rest


def verify_standard_webhook(raw_body: bytes, headers, secret: str,
                            tolerance_seconds: int, now: int | None = None) -> bool:
    """Manual equivalent of Webhook.verify — read this when the library says no."""
    msg_id, timestamp = headers.get("webhook-id"), headers.get("webhook-timestamp")
    sig_header = headers.get("webhook-signature")
    if not (msg_id and timestamp and sig_header):
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else int(time.time())) - ts) > tolerance_seconds:
        return False                                                    # Rule 9: timestamp window
    key = base64.b64decode(secret.removeprefix("whsec_"))               # secret_encoding: base64_decode
    signed_content = msg_id.encode() + b"." + timestamp.encode() + b"." + raw_body
    expected = hmac.new(key, signed_content, hashlib.sha256).digest()
    ok = False
    for part in sig_header.split(" "):                                  # rotation: several candidates
        version, _, value = part.partition(",")
        if version != "v1" or not value:
            continue
        try:
            presented = base64.b64decode(value, validate=True)
        except Exception:
            continue
        if hmac.compare_digest(presented, expected):                    # Rule 3: constant time
            ok = True
    return ok
```

## Anti-patterns

- ❌ `createHmac('sha256', secret)` with the raw `whsec_…` string — the key is the base64 behind that prefix.
  Every genuine event is rejected and nothing tells you why.
- ❌ `signature.split(' ')[0]` or a bare `startsWith('v1,')` — mid-rotation the matching signature is often the
  *second* entry, so the endpoint breaks for exactly the window the rotation was meant to make safe.
- ❌ Verifying `JSON.stringify(await request.json())`. Re-serialising changes key order and whitespace; the
  digest covers the bytes on the wire, not your reconstruction of them.
- ❌ Passing only `webhook-signature` to `verify` — the id and timestamp are inside the signed string.
- ❌ Deduping on a business id (order, subscription) instead of `webhook-id` — one order legitimately produces
  many messages, and you would drop all but the first.
- ❌ Hardcoding `webhook-id` for a provider whose entry says `svix-id`. The spec renamed the headers; Svix
  still emits the old names for older accounts, and the verifier that assumes one rejects the other outright.
- ❌ Hand-rolling the verifier and skipping the tolerance check "because svix does it" — the signature then
  never expires and a captured event replays forever.
- ❌ Returning 400 for an event type you do not handle — providers disable endpoints that 4xx.

## Security rules cited

- **Rule 3:** the MAC is checked before the payload is trusted, with `timingSafeEqual` / `hmac.compare_digest`
  and a length check first so the comparison cannot throw.
- **Rule 5:** `await request.text()` under `runtime = 'nodejs'`; `express.raw` before `express.json()`;
  `await request.body()` on FastAPI.
- **Rule 6:** only `webhook-id`, type and created reach the log.
- **Rule 9:** the timestamp is signed, so the window applies *and* `webhook-id` is deduped
  (`replay_mitigation_strategy: "both"`): the window bounds the attack, the dedup row neutralises what is
  left of it.
- **Rule 10:** 256 KB, checked from `Content-Length` and again from the bytes actually read.
