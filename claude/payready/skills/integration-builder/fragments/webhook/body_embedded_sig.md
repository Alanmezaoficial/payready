# Signature embedded in the body (`body_embedded_sig`)

The signature travels inside the JSON, not in a header, and it does not cover the JSON: it covers a
concatenation of values pulled out of it. That makes this the one family where **parsing before verifying is
correct** — you cannot find the signature otherwise. The trap is what developers conclude next. A verified
checksum here does not mean "the payload is genuine"; it means "these named fields are genuine". Everything
else in the document is attacker-controlled, arrives with a perfectly valid signature, and will be believed by
any handler that reads it. That is why every provider in this family also sets `payload_authoritative: false`.

**Providers in this family:** Wompi is the only entry that carries `verification_family: "body_embedded_sig"`
today. Adyen (`additionalData.hmacSignature`) and Midtrans (`signature_key`) are in `data/providers/` already
but sit at `integration_level: advise` with `verification_family: "unverified"`, so nothing resolves to this
file for them yet; their schemes are quoted in `webhook.algorithm` on their entries and are worked below,
because this fragment is what will build them once someone types the fields. Read every value from the entry,
not from this sentence.

**Catalog fields this fragment reads:** `webhook.signature_location` (`body_field`),
`webhook.signature_pointer`, `webhook.signed_payload_template`, `webhook.hash_algo`,
`webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.timestamp_source` (`body_field`),
`webhook.timestamp_pointer`, `webhook.recommended_tolerance_seconds`, `webhook.replay_mitigation_strategy`,
`webhook.event_id_pointer`, `webhook.event_type_pointer`, `webhook.signature_covers_body` (`false`),
`webhook.payload_authoritative` (`false`), `webhook.refetch_endpoint`, `webhook.secret_env`,
`webhook.ack_body_literal`.

## Why this does not break Rule 5

Rule 5 exists so that what you hash is what the provider hashed. Here the provider hashed *extracted values*,
not the request bytes, so parsing first cannot corrupt the input. Two disciplines survive: read the body
**once** as text and parse that same string (`await request.text()` → `JSON.parse`, never `request.json()` —
`hooks/checks/raw-body.js` rejects it, Rule 10 needs the byte length, and a coercing parser destroys the exact
string Midtrans signs); and never re-serialise and hash, because `JSON.stringify(parsed)` is not the document
that arrived.

## The contract

1. Cap at 256 KB before reading, and re-check the byte length after.
2. Read the raw text and parse that exact string. A parse failure → 400.
3. Read the presented signature at `signature_pointer`; absent or not a string → 400.
4. Read the timestamp at `timestamp_pointer` and reject outside the tolerance, before hashing.
5. Rebuild the signed string from the property list **the event itself carries**, in its order. Never hardcode
   that list: it varies by event type, and it is what tells you which fields are covered.
6. Hash it. If `signed_payload_template` contains `{secret}`, the secret is *inside* the hashed input, so this
   is a plain digest (`createHash`), not an HMAC — Wompi's case; Adyen is a true HMAC.
7. Compare in constant time, length first.
8. Dedup on `event_id_pointer`; a duplicate returns 200.
9. **Re-fetch before acting.** Nothing outside the signed set may drive a state change.
10. Ack — with the exact body when `ack_body_literal` is set (Adyen's `[accepted]`); the wrong body is retried.

## Node / TypeScript

```ts
// app/api/webhook/wompi/route.ts   — family: body_embedded_sig
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';
import { fetchTransaction } from '@/lib/payments/wompi';

export const runtime = 'nodejs'; // Rule 5: Node runtime for node:crypto
const MAX_BODY_BYTES = 256 * 1024;   // Rule 10
const TOLERANCE_SECONDS = 600;       // <from webhook.recommended_tolerance_seconds>

export async function POST(request: Request) {
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10
  }
  const rawBody = await request.text(); // Rule 5: read once, parse this exact string
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) {
    return new NextResponse(null, { status: 413 }); // Rule 10: Content-Length was only a claim
  }

  let event: any;
  try { event = JSON.parse(rawBody); } catch { return new NextResponse(null, { status: 400 }); }

  // Rule 9: the timestamp is part of the hashed input, so the window is checked before the digest
  const now = Math.floor(Date.now() / 1000);
  const sentAt = Number(event?.timestamp); // <from webhook.timestamp_pointer>
  // `Math.abs(now - NaN) > TOLERANCE` is FALSE, so a missing or non-numeric timestamp walks straight
  // through a window check that looks correct. Demand a finite number before comparing anything.
  if (!Number.isFinite(sentAt) || Math.abs(now - sentAt) > TOLERANCE_SECONDS) {
    return new NextResponse(null, { status: 400 });
  }
  // Rule 3: verify before anything else touches the payload
  if (!verifyEmbeddedChecksum(event, process.env.WOMPI_EVENTS_SECRET!, 'sha256')) {
    return new NextResponse(null, { status: 400 }); // no detail leaked to the caller
  }

  const eventId = String(event?.data?.transaction?.id); // <from webhook.event_id_pointer>
  try {
    await db.pagokitWebhookEventProcessed.create({
      data: { event_id: `wompi:${eventId}:${event.timestamp}`, provider: 'wompi',
              event_type: event.event, expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
    });
  } catch {
    return NextResponse.json({ received: true, duplicate: true }); // Rule 9: idempotent 200
  }

  // Rule 6: id, type, created only
  console.log('[wompi.webhook]', { id: eventId, type: event.event, created: event.timestamp });

  if (event.event !== 'transaction.updated') { // <from webhook.required_events_minimum>
    console.log('[wompi.webhook] unhandled event type', event.event); // TODO: route it if needed
    return NextResponse.json({ received: true }); // 200: a 4xx here gets the endpoint disabled
  }

  // signature_covers_body: false → the payload is a notification, not a source of truth.
  // Re-fetch, then enqueue. Amount, status and reference come from the API answer, never from the event.
  const authoritative = await fetchTransaction(eventId);
  await enqueue({ name: 'wompi.transaction', payload: { id: eventId, status: authoritative.status } });
  return NextResponse.json({ received: true }); // fast ack; the worker does the slow work
}

function verifyEmbeddedChecksum(event: any, secret: string, hashAlgo: string): boolean {
  const presented = event?.signature?.checksum;      // <from webhook.signature_pointer>
  const properties = event?.signature?.properties;   // the event declares its own signed set
  const timestamp = event?.timestamp;
  if (typeof presented !== 'string' || !Array.isArray(properties) || timestamp === undefined) return false;

  // <from webhook.signed_payload_template: "{body_props}{timestamp}{secret}">
  const concatenated = properties
    .map((p: string) => resolveSignedProperty(event, p))
    .map((v) => (v === undefined || v === null ? '' : String(v)))
    .join('');
  // The template contains {secret}, so the secret is hashed input: plain digest, NOT an HMAC.
  const expected = crypto.createHash(hashAlgo)
    .update(`${concatenated}${timestamp}${secret}`, 'utf8').digest('hex'); // digest_encoding: hex

  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(presented, 'utf8');
  if (a.length !== b.length) return false;      // Rule 3: timingSafeEqual throws on a length mismatch
  return crypto.timingSafeEqual(a, b);
}

// Property paths come in two shapes in the wild: rooted at the document ("data.transaction.id",
// which is what scripts/lib/webhook-sign.js signs) and rooted at `data` ("transaction.id", which is
// what live Wompi events carry). Resolve from the root, fall back to `data`; both yield the same value.
function resolveSignedProperty(event: any, path: string): unknown {
  const read = (root: any) => path.split('.').reduce((n, k) => (n == null ? undefined : n[k]), root);
  const fromRoot = read(event);
  return fromRoot !== undefined ? fromRoot : read(event?.data);
}
```

Adyen and Midtrans are the same family with different string-building rules:

```ts
// Adyen: HMAC-SHA256 over an escaped, colon-joined field list. The key is hex, the digest base64.
// Each item in notificationItems[] carries its own signature and must be verified on its own.
function adyenDataToSign(item: any): string {
  const esc = (v: unknown) => String(v ?? '').replace(/\\/g, '\\\\').replace(/:/g, '\\:'); // escape \ and :
  return [item.pspReference, item.originalReference, item.merchantAccountCode, item.merchantReference,
          item.amount?.value, item.amount?.currency, item.eventCode, item.success].map(esc).join(':');
}
// `item` is a NotificationRequestItem — `body.notificationItems[i].NotificationRequestItem`, not the
// element that wraps it. Passing the wrapper reads `undefined` and returns false on every genuine event.
function verifyAdyenItem(item: any, hmacKeyHex: string): boolean {
  const presented = item?.additionalData?.hmacSignature; // <from webhook.signature_pointer>
  if (typeof presented !== 'string') return false;
  const expected = crypto.createHmac('sha256', Buffer.from(hmacKeyHex, 'hex')) // secret_encoding: hex_decode
    .update(adyenDataToSign(item), 'utf8').digest();
  const got = Buffer.from(presented, 'base64');          // digest_encoding: base64
  if (got.length !== expected.length) return false;
  return crypto.timingSafeEqual(got, expected);          // Rule 3
}
// Reply with the literal body Adyen expects (<from webhook.ack_body_literal>): `[accepted]`.

// Midtrans: plain SHA-512 over order_id + status_code + gross_amount + server key. No HMAC, no timestamp,
// so Rule 9 rests entirely on event-id dedup (order_id + status_code + transaction_status).
function verifyMidtransSignature(notification: any, serverKey: string): boolean {
  const presented = notification?.signature_key;
  if (typeof presented !== 'string') return false;
  // gross_amount is hashed as the EXACT string sent — "10000.00". Number("10000.00") + String() gives
  // "10000" and the digest never matches again. Never let it round-trip through a float.
  const signed = `${notification.order_id}${notification.status_code}${notification.gross_amount}${serverKey}`;
  const expected = crypto.createHash('sha512').update(signed, 'utf8').digest('hex');
  const a = Buffer.from(expected, 'utf8'), b = Buffer.from(presented, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);                   // Rule 3
}
```

Express — register the raw parser before the JSON one so `req.body` is still the bytes that arrived:

```ts
app.post('/api/webhook/wompi',
  express.raw({ type: 'application/json', limit: '256kb' }), // Rule 5 + Rule 10
  handler);                                                  // const rawBody = req.body.toString('utf8')
app.use(express.json()); // ← AFTER the webhook route
```

## Python

```python
# app/webhooks/wompi.py
import hashlib, hmac, json, os, time
from fastapi import APIRouter, Request, Response

router = APIRouter()
MAX_BODY_BYTES = 256 * 1024     # Rule 10
TOLERANCE_SECONDS = 600         # <from webhook.recommended_tolerance_seconds>

@router.post("/api/webhook/wompi")
async def wompi_webhook(request: Request) -> Response:
    if int(request.headers.get("content-length", 0)) > MAX_BODY_BYTES:   # Rule 10
        return Response(status_code=413)
    raw_body = await request.body()                                      # Rule 5: bytes, never .json()
    if len(raw_body) > MAX_BODY_BYTES:
        return Response(status_code=413)
    try:
        event = json.loads(raw_body)
    except ValueError:
        return Response(status_code=400)
    try:                                                                 # Rule 9: window before digest
        sent_at = int(event["timestamp"])                                # <from webhook.timestamp_pointer>
    except (KeyError, TypeError, ValueError):                            # a garbage stamp is a 400,
        return Response(status_code=400)                                 # never an unhandled 500
    if abs(int(time.time()) - sent_at) > TOLERANCE_SECONDS:
        return Response(status_code=400)
    if not verify_embedded_checksum(event, os.environ["WOMPI_EVENTS_SECRET"]):       # Rule 3
        return Response(status_code=400)

    event_id = str(event["data"]["transaction"]["id"])                   # <from webhook.event_id_pointer>
    if not claim_event(f"wompi:{event_id}:{event['timestamp']}", event["event"]):
        return Response(status_code=200)                                 # Rule 9: duplicate → 200
    log.info("wompi.webhook", extra={"id": event_id, "type": event["event"],
                                     "created": event["timestamp"]})     # Rule 6
    authoritative = fetch_transaction(event_id)     # payload_authoritative: false → re-fetch, always
    enqueue("wompi.transaction", {"id": event_id, "status": authoritative["status"]})
    return Response(status_code=200)                                     # fast ack, worker does the rest


def verify_embedded_checksum(event: dict, secret: str, hash_algo: str = "sha256") -> bool:
    sig = event.get("signature") or {}
    presented, properties, timestamp = sig.get("checksum"), sig.get("properties"), event.get("timestamp")
    if not isinstance(presented, str) or not isinstance(properties, list) or timestamp is None:
        return False

    def read(root, path):                       # root-relative first, then relative to `data` (see Node note)
        node = root
        for key in path.split("."):
            node = node.get(key) if isinstance(node, dict) else None
        return node

    values = [read(event, p) if read(event, p) is not None else read(event.get("data") or {}, p)
              for p in properties]
    concatenated = "".join("" if v is None else str(v) for v in values)
    expected = hashlib.new(hash_algo, f"{concatenated}{timestamp}{secret}".encode()).hexdigest()
    # Rule 3: constant time, over BYTES. compare_digest(str, str) raises TypeError the moment the
    # presented checksum carries a non-ASCII character — an attacker-chosen 500 instead of a 400.
    return hmac.compare_digest(expected.encode(), presented.encode())


def verify_midtrans(notification: dict, server_key: str) -> bool:
    presented = notification.get("signature_key")
    gross = notification.get("gross_amount")            # the exact string sent: "10000.00", never float()
    if not isinstance(presented, str):
        return False
    signed = f"{notification['order_id']}{notification['status_code']}{gross}{server_key}"
    expected = hashlib.sha512(signed.encode()).hexdigest()
    return hmac.compare_digest(expected.encode(), presented.encode())   # Rule 3: bytes, never str
```

## Anti-patterns

- ❌ Acting on a field the signature does not cover. A forged `reference`, `amount` or `customer_email` in a
  Wompi event verifies perfectly — only `signature.properties` is hashed. Re-fetch, then act.
- ❌ Hardcoding the property list — it changes per event type, and the event ships it so you rebuild in order.
- ❌ `crypto.createHmac('sha256', secret)` for Wompi. The template is `{body_props}{timestamp}{secret}` — the
  secret is hashed input, so it is `createHash`. An HMAC here rejects every genuine event.
- ❌ `Number(gross_amount)` or `float(gross_amount)` before hashing a Midtrans notification. `"10000.00"`
  becomes `10000`, and the signature can never match again.
- ❌ Verifying Adyen's `notificationItems` as one blob, or forgetting to escape `\` and `:` inside the values
  before joining — both silently produce a different data-to-sign. Each element wraps its payload in
  `NotificationRequestItem`; hand the verifier that inner object, not the wrapper.
- ❌ `Math.abs(now - Number(body.timestamp)) > TOLERANCE` with no finite check. `Number(undefined)` is `NaN`,
  every comparison with `NaN` is `false`, and the window you just wrote never rejects anything.
- ❌ `hmac.compare_digest` on two Python `str`s. It raises `TypeError` on non-ASCII input, so a one-character
  payload turns a 400 into a 500 — and a 500 is a retry, not a rejection. Compare `bytes`.
- ❌ Answering Adyen with `200 OK` and any body other than `[accepted]` — retried forever.
- ❌ Skipping the timestamp window because "the checksum covers the timestamp". It does, which is precisely why
  a captured event stays valid until the window and the dedup row bound it.
- ❌ Comparing digests with `===` / `==`. They are strings here; that is still a timing oracle.

## Security rules cited

- **Rule 3:** the checksum is verified before any field is read, in constant time, length checked first.
- **Rule 5:** the body is read once as raw text and parsed from that string; `request.json()` never appears.
  Parsing precedes verification because the signature lives in the document — the bytes are never re-serialised.
- **Rule 6:** transaction id, event type and timestamp are logged; the transaction object never is.
- **Rule 9:** `replay_mitigation_strategy: "both"` — the signed timestamp gives a window (600s for Wompi) and
  the dedup row catches replays inside it. Midtrans signs no timestamp, so dedup is the only defence.
- **Rule 10:** 256 KB, from `Content-Length` and again from the bytes read.
