# Shared secret in a header (`shared_secret_header`)

There is no MAC here. The provider puts a static token in a header, you check it against the one in your env,
and that is the whole scheme. It authenticates *the caller* and says nothing about the bytes, so it is a
password sent on every request rather than a signature over the request. The mistake is treating it as if it
were the second thing: verify the token, then act on the payload. Anyone who ever sees that token — a proxy
access log, an APM trace with headers attached, a screenshot, an old `.env` — can post any payment event they
like, with any amount, forever, and it will verify. Everything below exists to make that outcome survivable.

**Providers in this family:** no entry carries `verification_family: "shared_secret_header"` yet. Three
catalog entries document exactly this scheme in `webhook.algorithm` and are waiting to be typed, all at
`integration_level: advise`: **Asaas** (`asaas-access-token`, the 32–255 character authToken you set on the
webhook), **Xendit** (`x-callback-token`, one static token per account — its entry is typed
`verification_family: "none"` today, so it resolves to `none_refetch` until someone re-types it) and
**Flutterwave v3** (`verif-hash`, the dashboard secret hash echoed in plaintext; v4 moved to an HMAC of the
raw body and belongs in `hmac_raw_body`, so a generator must branch on the API version). The header name
differs per provider and is always read from `webhook.signature_header` — never hardcoded here.

**Catalog fields this fragment reads:** `webhook.verification_family`, `webhook.signature_header`,
`webhook.hash_algo` (`none` — there is nothing to hash), `webhook.replay_mitigation_strategy`
(`event-id-dedup`), `webhook.event_id_pointer`, `webhook.event_type_pointer`,
`webhook.signature_covers_body` (`false`), `webhook.payload_authoritative` (`false`),
`webhook.refetch_endpoint`, `webhook.ip_allowlist_available`, `webhook.ip_allowlist`, `webhook.secret_env`,
`webhook.required_events_minimum`.

## What this scheme does not give you

- **No payload integrity.** The token is unrelated to the body. A valid token plus a body you wrote yourself
  is a valid request. `signature_covers_body` is `false` for every provider in this family, by construction.
- **No replay defence.** Nothing in the scheme expires, because nothing in the scheme is time-bound. The
  identical request works tomorrow. `replay_mitigation_strategy` is therefore `event-id-dedup`, always.
- **The secret travels on every request.** An HMAC secret never leaves your server; this one crosses the
  internet continuously and lands in whatever logs headers on the way. Treat it as a credential with a
  rotation plan, scrub it from request-logging middleware, and keep it out of error reports.

Because there is no MAC, the comparison **is** the security control. There is no second line to fall back on
if it is written with `===`, so it is constant-time here for the same reason a password check is.

## The contract

1. Cap the body at 256 KB before reading it, then re-check the byte length after reading.
2. Refuse to start if the configured secret is missing or empty — an unset env var must never degrade into
   "everything matches".
3. Where the provider publishes an allowlist (`ip_allowlist_available: true`), check the source address first,
   at the CDN or load balancer if you can put it there. It is the only control that is not a bearer token.
4. Read the header named by `webhook.signature_header`. Absent → 400.
5. Compare it to the configured secret in constant time, hashing both sides to a fixed length first so the
   comparison cannot throw and does not leak the secret's length.
6. Read the raw body, then parse it. A parse failure → 400.
7. Dedup on `webhook.event_id_pointer`. With no timestamp anywhere in the scheme, this is the *only* thing
   standing between a captured request and an unlimited replay.
8. **Re-fetch the object from the provider API before acting on it.** This is the compensating control that
   replaces the missing integrity: the token says who called, the API says what is true.
9. Log id, type and created; enqueue; return 200.

## Node / TypeScript

```ts
// app/api/webhook/<provider>/route.ts   — family: shared_secret_header
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';
import { fetchPayment } from '@/lib/payments/<provider>';

export const runtime = 'nodejs'; // Rule 5
const MAX_BODY_BYTES = 256 * 1024; // Rule 10
const CALLBACK_TOKEN_HEADER = 'x-callback-token'; // <from webhook.signature_header>
const ROUTED = new Set<string>([/* <from webhook.required_events_minimum> */]);

export async function POST(request: Request) {
  const configured = process.env.PROVIDER_WEBHOOK_SECRET; // <from webhook.secret_env>
  // Rule 3: an empty secret must fail closed, never match everything
  if (!configured) {
    console.error('[<provider>.webhook] PROVIDER_WEBHOOK_SECRET is not set — refusing all callbacks');
    return new NextResponse(null, { status: 500 });
  }
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10
  }

  // Rule 3: this comparison is the entire security control — constant time, no shortcuts
  const presented = request.headers.get(CALLBACK_TOKEN_HEADER);
  if (!sharedSecretMatches(presented, configured)) {
    return new NextResponse(null, { status: 400 }); // no detail: never confirm a partial guess
  }

  const rawBody = await request.text(); // Rule 5: raw first, parse second
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10: Content-Length was only a claim
  }
  let event: any;
  try { event = JSON.parse(rawBody); } catch { return new NextResponse(null, { status: 400 }); }

  const eventId = String(event?.id ?? ''); // <from webhook.event_id_pointer>
  if (!eventId) return new NextResponse(null, { status: 400 }); // no id means no replay defence at all

  // Rule 9: with no signed timestamp, the dedup row IS the replay defence
  try {
    await db.pagokitWebhookEventProcessed.create({
      data: { event_id: `<provider>:${eventId}`, provider: '<provider>', event_type: event.type,
              expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }, // keep it long: nothing expires
    });
  } catch {
    return NextResponse.json({ received: true, duplicate: true }); // idempotent 200
  }

  // Rule 6: metadata only
  console.log('[<provider>.webhook]', { id: eventId, type: event.type, created: event.created_at });

  if (!ROUTED.has(event.type)) {
    console.log('[<provider>.webhook] unhandled event type', event.type); // TODO: route it if needed
    return NextResponse.json({ received: true }); // 200: providers disable endpoints that 4xx
  }

  // payload_authoritative: false — the body is a rumour from an authenticated caller. Ask the API.
  const authoritative = await fetchPayment(eventId); // <from webhook.refetch_endpoint>
  if (!authoritative) {
    // The caller knew the token but the object does not exist: log loudly, change nothing.
    console.error('[<provider>.webhook] event references an unknown object', { id: eventId });
    return NextResponse.json({ received: true });
  }
  await enqueue({ name: '<provider>.event', payload: { id: eventId, status: authoritative.status } });
  return NextResponse.json({ received: true }); // fast ack; the worker does the slow work
}

function sharedSecretMatches(presented: string | null, configured: string): boolean {
  if (typeof presented !== 'string' || configured.length === 0) return false;
  // Rule 3: hash both sides to a fixed 32 bytes first. timingSafeEqual throws on a length mismatch,
  // and a raw length comparison would leak how long the secret is before comparing anything.
  const a = crypto.createHash('sha256').update(presented, 'utf8').digest();
  const b = crypto.createHash('sha256').update(configured, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}
```

Express — `express.raw` before `express.json()`, and the allowlist in front of both when there is one:

```ts
app.post('/api/webhook/<provider>',
  ipAllowlist(process.env.PROVIDER_WEBHOOK_IPS?.split(',') ?? []), // <from webhook.ip_allowlist>
  express.raw({ type: 'application/json', limit: '256kb' }),       // Rule 5 + Rule 10
  handler);                                                        // req.body is a Buffer
app.use(express.json()); // ← AFTER the webhook route
```

## Python

```python
# app/webhooks/<provider>.py
import hashlib, hmac, json, os
from fastapi import APIRouter, Request, Response

router = APIRouter()
MAX_BODY_BYTES = 256 * 1024                  # Rule 10
CALLBACK_TOKEN_HEADER = "x-callback-token"   # <from webhook.signature_header>

def shared_secret_matches(presented: str | None, configured: str) -> bool:
    """The whole security control. Fixed-length digests so the compare cannot throw or leak a length."""
    if not isinstance(presented, str) or not configured:
        return False
    return hmac.compare_digest(hashlib.sha256(presented.encode()).digest(),
                               hashlib.sha256(configured.encode()).digest())   # Rule 3

@router.post("/api/webhook/<provider>")
async def provider_webhook(request: Request) -> Response:
    configured = os.environ.get("PROVIDER_WEBHOOK_SECRET", "")   # <from webhook.secret_env>
    if not configured:                                           # Rule 3: fail closed
        return Response(status_code=500)
    if int(request.headers.get("content-length", 0)) > MAX_BODY_BYTES:
        return Response(status_code=413)                         # Rule 10
    if not shared_secret_matches(request.headers.get(CALLBACK_TOKEN_HEADER), configured):
        return Response(status_code=400)                         # no detail to the caller

    raw_body = await request.body()                              # Rule 5: bytes, never .json()
    if len(raw_body) > MAX_BODY_BYTES:
        return Response(status_code=413)
    try:
        event = json.loads(raw_body)
    except ValueError:
        return Response(status_code=400)

    event_id = str(event.get("id") or "")                        # <from webhook.event_id_pointer>
    if not event_id:
        return Response(status_code=400)                         # no id means no replay defence at all
    if not claim_event(f"<provider>:{event_id}", event.get("type")):
        return Response(status_code=200)                         # Rule 9: duplicate → idempotent 200
    log.info("<provider>.webhook", extra={"id": event_id, "type": event.get("type"),
                                          "created": event.get("created_at")})   # Rule 6
    authoritative = fetch_payment(event_id)   # payload_authoritative: false → the API is the truth
    if authoritative:
        enqueue("<provider>.event", {"id": event_id, "status": authoritative["status"]})
    return Response(status_code=200)                             # fast ack
```

## Anti-patterns

- ❌ `if (token === process.env.SECRET)`. It is the only check in the scheme; a timing oracle on it is a
  timing oracle on the whole endpoint.
- ❌ Trusting the body once the token matches. The token proves the caller knew a secret, not that the amount,
  the status or the customer id in the JSON are real. Re-fetch before granting anything.
- ❌ Skipping event-id dedup "because we verify the token". Nothing in this scheme expires — the recording of
  one genuine `payment.succeeded` is a permanent free-money button until dedup exists.
- ❌ Accepting the token in a query parameter because the provider offers it. Query strings land in access
  logs, `Referer` headers and browser history in a way headers do not.
- ❌ Logging request headers on this route, or attaching them to Sentry breadcrumbs. That is how the secret
  leaves the building (Rule 6 covers the body; this is the same failure one layer up).
- ❌ Reusing the provider's API key as the callback token. Now a leaked callback token is also an API key.
- ❌ Treating an IP allowlist as sufficient on its own. Source addresses are spoofable at the edge and
  `X-Forwarded-For` is caller-controlled unless your proxy overwrites it — layer it, don't rely on it.
- ❌ Returning 401/403 with a message like "invalid token". Say nothing; a prober learns nothing from a 400.

## Security rules cited

- **Rule 3:** verification happens before the payload is read, and the comparison — the only control there is
  — runs in constant time over fixed-length digests, failing closed when the secret is unset.
- **Rule 5:** the raw body is still read as bytes (`request.text()` / `express.raw` / `await request.body()`)
  so the handler stays consistent with the validator and with Rule 10's byte count.
- **Rule 6:** id, type and created only; and on this family, the headers are as sensitive as the body.
- **Rule 9:** `event-id-dedup` is mandatory and the TTL is long (30 days here), because a scheme with no
  timestamp has no other replay bound. The re-fetch is the second compensating control.
- **Rule 10:** 256 KB, from `Content-Length` and again from the bytes read.
