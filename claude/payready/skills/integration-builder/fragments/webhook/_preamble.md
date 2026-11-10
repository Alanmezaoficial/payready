# Webhook handler preamble — the shell every family composes into

Every webhook handler does the same nine things in the same order; only *step 4, the signature check*, differs by provider. This fragment owns the other eight. The one thing developers get wrong is what a `200` means: they read it as "received", the provider reads it as **"you own this event now"** and stops retrying. Anything you skipped, swallowed or crashed past after committing to that ack is gone — no error, no retry, no alert. The sharpest instance: insert the dedup row, then throw, then return `500`; the provider's retry hits that row, is classed a duplicate, gets its `200`, and the event is lost forever with every dashboard green.

**Providers in this family:** not a family — the base layer. Every provider with `notification_model: webhook` composes onto it, which today is all but two entries in the catalog; Transbank (`return_url_commit`) and Flow (`ping_then_poll`) get no webhook route at all. The entries at `integration_level: build`, whose family fragment actually resolves, are Stripe, Mercado Pago, Lemon Squeezy and Wompi — every other entry is `advise` with `verification_family: "unverified"` until someone verifies its scheme.

**Catalog fields this fragment reads:** `notification_model`, `webhook.signature_header`, `webhook.event_id_pointer`, `webhook.event_type_pointer`, `webhook.replay_mitigation_strategy`, `webhook.required_events_minimum`, `webhook.ack_deadline_seconds`, `webhook.ack_body_literal`, `webhook.evidence.confidence`, `webhook.secret_env`.

## The contract

1. **Reject oversize before reading.** `Content-Length` over 256 KB → `413`, body unread. (Rule 10)
2. **Read the exact bytes,** never a parsed object, then re-check the real byte length: `Content-Length` is absent under `Transfer-Encoding: chunked` and is caller-supplied anyway, so the header check is a cheap filter, not the cap. (Rule 5, Rule 10)
3. **Read the signature header** named by `webhook.signature_header`, case-insensitively. Absent → `400`.
4. **Verify.** Supplied by the family fragment — the only provider-specific step. Invalid → `400`, empty body: never say *why*, or you have built a signature oracle. (Rule 3)
5. **Parse only now.** Two families invert this: `body_embedded_sig` (signature inside the body) and `hmac_field_concat` (signed fields inside the body) must parse first. Parsing a ≤256 KB string is not a state change; *acting* on an unverified parse is the sin, not parsing it.
6. **Extract identity** via `webhook.event_id_pointer` / `webhook.event_type_pointer`. Never hand-code `body.id` — Lemon Squeezy's lives at `/meta/event_id`, Wompi's at `/data/transaction/id`.
7. **Replay-protect** per `webhook.replay_mitigation_strategy`. The timestamp window belongs to the family fragment; **event-id dedup belongs here and runs for every provider**, window or not — a 300s window still permits 300 seconds of free replays. (Rule 9)
8. **One transaction:** insert the dedup row *and* apply the state change that must survive a crash. Unique violation → roll back, `200 {duplicate:true}`. Any other error → roll back **both**, `500`, so the retry lands on a clean slate.
9. **Log `id`, `type`, `created` — nothing else, ever** (Rule 6), **ack inside `webhook.ack_deadline_seconds`** (Stripe: 20s), and only then run the slow work from a queue.

| Situation | Status | Body |
|---|---|---|
| Body over 256 KB | `413` | empty |
| Signature missing, malformed, invalid, or stale | `400` | empty — no detail (Rule 3) |
| Event id already in `webhook_events_processed` | `200` | `{received:true,duplicate:true}` |
| Event type not in the switch | `200` | `{received:true}` + logged TODO |
| Handled successfully | `200` | `{received:true}`, or `webhook.ack_body_literal` |
| Verified, but the handler threw | `500` | empty — provider retries |

## Node / TypeScript

```ts
// lib/payments/webhook-crypto.ts — family-neutral primitives; every family fragment imports these.
import crypto from 'node:crypto';

export const MAX_BODY_BYTES = 256 * 1024; // Rule 10: 256 KB cap

/** Rule 3: constant-time compare. timingSafeEqual THROWS on a length mismatch, so length first. */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** <from webhook.secret_encoding> — how the shared secret becomes MAC key bytes. */
export function secretKey(secret: string, encoding: string): Buffer {
  switch (encoding) {
    case 'base64_decode': return Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
    case 'hex_decode':    return Buffer.from(secret, 'hex');
    case 'base64_encode': return Buffer.from(Buffer.from(secret, 'utf8').toString('base64'), 'utf8');
    default:              return Buffer.from(secret, 'utf8'); // 'raw' | 'none'
  }
}

/** <from webhook.digest_encoding> — how the MAC bytes become the string in the header. */
export function encodeDigest(mac: Buffer, encoding: string): string {
  switch (encoding) {
    case 'hex_upper': return mac.toString('hex').toUpperCase();
    case 'base64':    return mac.toString('base64');
    case 'base64url': return mac.toString('base64url'); // unpadded — matches Python's rstrip('=')
    default:          return mac.toString('hex');
  }
}

/** Header casing is not yours to assume: HTTP/2 lowercases everything. Never index directly. */
export function headerValue(headers: Headers | Record<string, unknown>, name: string): string | undefined {
  if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name) ?? undefined;
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === want) return String(v);
  return undefined;
}

/** RFC 6901 JSON pointer — resolves event_id_pointer, event_type_pointer, timestamp_pointer. */
export function pointer(obj: any, ptr: string): unknown {
  if (!ptr) return obj;
  return ptr.replace(/^\//, '').split('/').reduce<any>(
    (acc, key) => (acc == null ? undefined : acc[key.replace(/~1/g, '/').replace(/~0/g, '~')]),
    obj,
  );
}

/** <from webhook.header_format> — 'raw' | 'prefixed' (sha256=…) | 'kv' (t=…,v1=…). */
export function unpackSignatureHeader(
  value: string,
  fmt: { kind?: string; prefix?: string; separator?: string; assign?: string; signature_key?: string; timestamp_key?: string } = {},
): { signatures: string[]; timestamp?: string } {
  if (fmt.kind === 'kv') {
    const sep = fmt.separator ?? ',', eq = fmt.assign ?? '=', sigKey = fmt.signature_key ?? 'v1';
    const signatures: string[] = []; let timestamp: string | undefined;
    for (const part of value.split(sep)) {
      const i = part.indexOf(eq);
      if (i === -1) continue;
      const k = part.slice(0, i).trim(), v = part.slice(i + 1).trim();
      if (k === sigKey) signatures.push(v);   // a secret mid-rotation sends two v1= values
      else if (fmt.timestamp_key && k === fmt.timestamp_key) timestamp = v;
    }
    return { signatures, timestamp };
  }
  if (fmt.kind === 'prefixed') {
    const p = fmt.prefix ?? '';
    return { signatures: [value.startsWith(p) ? value.slice(p.length) : value] };
  }
  return { signatures: [value] };
}
```

```ts
// app/api/webhook/<provider>/route.ts — Next.js App Router
import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';
import { MAX_BODY_BYTES, pointer } from '@/lib/payments/webhook-crypto';
import { verifySignature } from '@/lib/payments/<provider>-verify'; // ← from the family fragment

export const runtime = 'nodejs'; // Rule 5: Edge has no node:crypto and no Buffer

export async function POST(request: Request) {
  // Rule 10: cheap filter before a byte is read
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 });
  }

  const rawBody = await request.text(); // Rule 5: exact bytes, NOT request.json()

  // Rule 10: the real cap — content-length is absent on chunked bodies and is caller-supplied
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 });
  }

  // Rule 3: verify before anything else touches the payload; no reason is ever returned
  if (!verifySignature(rawBody, request.headers, process.env.<from webhook.secret_env>!)) {
    return new NextResponse(null, { status: 400 });
  }

  let body: any;
  try { body = JSON.parse(rawBody); } catch { return new NextResponse(null, { status: 400 }); }

  const eventId   = String(pointer(body, '<from webhook.event_id_pointer>') ?? '');
  const eventType = String(pointer(body, '<from webhook.event_type_pointer>') ?? 'unknown');
  if (!eventId) return new NextResponse(null, { status: 400 });

  // Rule 9 + contract step 8: dedup and the durable state change commit together, or neither does
  try {
    await db.$transaction(async (tx) => {
      await tx.pagokitWebhookEventProcessed.create({
        data: {
          event_id: `<provider>:${eventId}`, // namespaced: two providers can mint the same id
          provider: '<provider>',
          event_type: eventType,
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // TTL ≥ 24h (Rule 9)
        },
      });
      await applyStateChange(tx, eventType, body); // the part a crash must not lose
    });
  } catch (err: any) {
    if (err?.code === 'P2002') {                                     // unique violation
      return NextResponse.json({ received: true, duplicate: true }); // idempotent 200
    }
    // Rule 6: metadata only, on the error path too
    console.error('[<provider>.webhook] handler error', { id: eventId, type: eventType, error_code: err?.code ?? 'unknown' });
    return new NextResponse(null, { status: 500 }); // dedup row rolled back — the retry can win
  }

  // Rule 6: id, type, created. Never the payload — it carries email, address, last4.
  console.log('[<provider>.webhook]', { id: eventId, type: eventType, created: body.created ?? null });

  // Fast ack: everything slow happens after this line, off this request. With no queue in the
  // project, derive the side effect later from pagokit_payments — do NOT send the email here.
  // A 20s ack deadline (webhook.ack_deadline_seconds) and an SMTP timeout are a bad pair.
  await enqueue('<provider>.webhook', { event_id: eventId, type: eventType });

  return NextResponse.json({ received: true });
}

async function applyStateChange(tx: any, type: string, body: any) {
  switch (type) {
    // one case per entry in <from webhook.required_events_minimum>
    default:
      // TODO: route this event type if the product needs it. 200, never 4xx — a 4xx here
      // makes the provider disable the endpoint after enough failures. (Rule 9)
      console.log('[<provider>.webhook] unhandled event type', type);
  }
}
```

```ts
// Express — middleware ordering is the whole game (Rule 5). Same imports as the route above.
app.post('/api/webhook/<provider>',
  express.raw({ type: 'application/json', limit: '256kb' }), // Rule 5 + Rule 10
  async (req, res) => {
    // If another parser won the race, req.body is {} or a string, not a Buffer — and the HMAC
    // then fails forever with an error that reads exactly like a wrong secret. Fail loudly.
    if (!Buffer.isBuffer(req.body)) {
      console.error('[<provider>.webhook] body is not raw — express.json() is registered before this route');
      return res.status(500).send();
    }
    const rawBody = req.body.toString('utf8'); // Rule 5
    // Rule 3: same call as the route above — req.headers is a plain object, which is why
    // headerValue() looks the name up case-insensitively instead of indexing it.
    const secret = process.env.<from webhook.secret_env>;
    if (!secret) {
      // Never the value, only the name (Rule 6). Fail loudly: an empty key would just
      // reject every genuine event and read exactly like a wrong secret.
      console.error('[<provider>.webhook] <from webhook.secret_env> is not set');
      return res.status(500).send();
    }
    if (!verifySignature(rawBody, req.headers, secret)) {
      return res.status(400).send(); // empty body, no reason
    }
    // …identical from here: parse → dedup+commit → log → ack → enqueue
    res.status(200).json({ received: true });
  });

app.use(express.json()); // ← AFTER the webhook route, always
```

## Python

```python
# app/payments/webhook_crypto.py
import base64, hmac

MAX_BODY_BYTES = 256 * 1024  # Rule 10

def safe_equal(a: str, b: str) -> bool:
    """Rule 3: constant-time. compare_digest takes unequal lengths without raising."""
    return hmac.compare_digest(a.encode(), b.encode())

def secret_key(secret: str, encoding: str) -> bytes:   # <from webhook.secret_encoding>
    if encoding == "base64_decode":
        return base64.b64decode(secret[6:] if secret.startswith("whsec_") else secret)
    if encoding == "hex_decode":
        return bytes.fromhex(secret)
    if encoding == "base64_encode":
        return base64.b64encode(secret.encode("utf-8"))
    return secret.encode("utf-8")

def encode_digest(mac: bytes, encoding: str) -> str:   # <from webhook.digest_encoding>
    if encoding == "hex_upper":
        return mac.hex().upper()
    if encoding == "base64":
        return base64.b64encode(mac).decode("ascii")
    if encoding == "base64url":
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")  # unpadded, matches Node
    return mac.hex()

def pointer(obj, ptr: str):                            # RFC 6901
    if not ptr:
        return obj
    for key in ptr.lstrip("/").split("/"):
        if obj is None:
            return None
        obj = obj.get(key.replace("~1", "/").replace("~0", "~")) if isinstance(obj, dict) else None
    return obj
```

```python
# app/routers/webhook_<provider>.py — FastAPI. Same nine steps as the Node route above;
# only the raw-body capture and the dedup transaction differ in shape.
import json, os
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, Response
from sqlalchemy.exc import IntegrityError
from app.database import db
from app.models import PagokitWebhookEventProcessed
from app.payments.webhook_crypto import MAX_BODY_BYTES, pointer
from app.payments.<provider>_verify import verify_signature   # ← from the family fragment
from app.payments.<provider>_handlers import apply_state_change  # one branch per required_events_minimum
from app.queue import enqueue                                 # whatever the project already uses

router = APIRouter()

# NOTE: no Pydantic body model in the signature. Declaring one makes FastAPI parse and
# re-serialise the body, and the raw bytes you need are gone. (Rule 5)
@router.post("/api/webhook/<provider>")
async def handle(request: Request) -> Response:
    if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
        return Response(status_code=413)                      # Rule 10
    raw_body = await request.body()                           # Rule 5: bytes, not .json()
    if len(raw_body) > MAX_BODY_BYTES:
        return Response(status_code=413)                      # Rule 10: the real cap
    if not verify_signature(raw_body, request.headers, os.environ["<from webhook.secret_env>"]):
        return Response(status_code=400)                      # Rule 3: no reason returned
    try:
        body = json.loads(raw_body)
    except ValueError:
        return Response(status_code=400)

    event_id = str(pointer(body, "<from webhook.event_id_pointer>") or "")
    event_type = str(pointer(body, "<from webhook.event_type_pointer>") or "unknown")
    if not event_id:
        return Response(status_code=400)

    # Rule 9 + contract step 8: dedup row and durable state change share one transaction
    try:
        db.add(PagokitWebhookEventProcessed(
            event_id=f"<provider>:{event_id}", provider="<provider>", event_type=event_type,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        ))
        apply_state_change(db, event_type, body)
        db.commit()
    except IntegrityError:                       # already processed
        db.rollback()
        return Response(status_code=200, media_type="application/json",
                        content='{"received":true,"duplicate":true}')
    except Exception as err:
        db.rollback()   # the dedup row goes too, so the provider's retry can still succeed
        print("[<provider>.webhook] error", {"id": event_id, "error": type(err).__name__})
        return Response(status_code=500)

    print("[<provider>.webhook]", {"id": event_id, "type": event_type,
                                   "created": body.get("created")})            # Rule 6
    enqueue("<provider>.webhook", {"event_id": event_id, "type": event_type})  # fast ack
    return Response(status_code=200, content='{"received":true}', media_type="application/json")
```

## Anti-patterns

- ❌ `await request.json()`, a Pydantic body model, or `express.json()` before the route — the raw bytes are gone and the HMAC can never match again. The failure looks exactly like a wrong secret, which is why people rotate the secret three times before finding it. (Rule 5)
- ❌ `export const runtime = 'edge'` on the route — no `node:crypto`, no `Buffer`.
- ❌ Returning `400 {"error":"signature mismatch"}` next to `400 {"error":"stale timestamp"}` — that pair is a free oracle for an attacker tuning a forgery. Empty body, always.
- ❌ Returning `4xx` for an event type you do not handle — providers disable endpoints that keep failing. Log a TODO, return `200`.
- ❌ Inserting the dedup row outside the transaction that does the work — a later `500` is then permanently swallowed as a duplicate.
- ❌ Trusting `Content-Length` as the size cap. Absent on chunked bodies, set by the caller.
- ❌ `console.log(event)` / `print(payload)` — customer email, billing address and last4 into Datadog retention. (Rule 6)
- ❌ Sending the receipt email inside the handler, before the ack.
- ❌ Emitting any of this when `webhook.evidence.confidence` is not `high`. An unverified scheme yields a verifier that looks right and accepts forgeries — emit the re-fetch path and a loud TODO instead.

## Security rules cited

- **Rule 3:** verification precedes the parse, its failure returns a detail-free `400`, and every comparison is constant-time.
- **Rule 5:** `request.text()` / `express.raw` / `await request.body()`, plus `runtime = 'nodejs'` and the `Buffer.isBuffer` guard that catches a mis-ordered Express stack.
- **Rule 6:** the only fields logged are `id`, `type`, `created` — success path and error path alike.
- **Rule 9:** event-id dedup against `pagokit_webhook_events_processed`, 7-day TTL, keyed on `webhook.event_id_pointer`, namespaced by provider, rolled back with the work it guards.
- **Rule 10:** 256 KB enforced twice — on `Content-Length` before reading, on the real byte length after.
