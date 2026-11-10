# `none_refetch` — the callback is a ping; the API is the truth

The provider POSTs to your URL and signs nothing. The callback says "something happened, go look".
It is not evidence that anything happened, and certainly not evidence of *what*. The mistake is
reading `amount`, `status` or `customer_id` out of the body and granting access — anyone who
learns the URL can POST `{"status":"paid","amount":9999}` and get a free order. Take one
identifier, discard the rest of the body, and fetch the authoritative record over your
authenticated API before anything changes.

**Providers in this family:** none assigned yet — but seven catalog entries already sit at
`verification_family: "none"` ("no verification mechanism is documented"), all held at
`integration_level: advise`: **Culqi** (wave 2), **Transbank** (2), **Mobbex** (3), **Mollie** (4),
**Xendit** (5), **Paymob** (6), **Hyperswitch** (7). `none_refetch` is the promotion target for
those whose re-fetch path has actually been verified; moving an entry across is research, not
template work, and this fragment is what makes the move cheap. Two are textbook:

- **Mollie** classic webhooks — a form-encoded POST carrying **only** `id=tr_xxx`. No signature, no
  timestamp; the catalog's note says the only correct handling is `GET /v2/payments/{id}`. Note the
  body is form-encoded, not JSON — the extractor below handles both. **Check which Mollie endpoint
  you have first:** the catalog records two schemes for it, and the next-gen one *does* sign —
  `X-Mollie-Signature: sha256=<hex>`, HMAC-SHA256 over the raw body, no signed timestamp. That one
  composes as `hmac_raw_body`; only classic belongs here.
- **Culqi** (wave 2) — no signature header, algorithm or example is published at all. The catalog
  records "do not invent one": emit dedup plus a mandatory re-fetch of `GET /charges/{id}`.

**Transbank is the counter-example.** It has no webhooks; its `notification_model` is
`return_url_commit`, and generating any handler for it is a correctness bug, not a gap. Check
`notification_model` before selecting this fragment. Ships ahead of Mangopay, Moov, Maya, Clip and
Viva, none yet in the catalog.

**Catalog fields this fragment reads:** `notification_model`, `webhook.signature_covers_body`
(`false`), `webhook.payload_authoritative` (`false`), `webhook.refetch_endpoint`,
`webhook.event_id_pointer`, `webhook.replay_mitigation_strategy` (`event-id-dedup`),
`webhook.ip_allowlist_available`, `webhook.ip_allowlist`, `webhook.ack_deadline_seconds`,
`webhook.ack_body_literal`, `webhook.evidence.confidence`.

## The contract

There is no step 4 to implement. This fragment replaces it with compensating controls plus the
re-fetch; the preamble's size cap, raw body, dedup, logging and ack are unchanged.

1. **Harden the endpoint**, because nothing else gates it: an unguessable path segment compared in
   constant time, a per-IP rate limit, and `webhook.ip_allowlist` where the provider publishes one
   (see `mtls_or_ip.md` for the CIDR matcher). A path mismatch answers **404** — a `403` confirms
   the endpoint exists.
2. Be honest with the validator: `// pagokit-ignore: webhook-has-signature -- provider does not
   sign callbacks (verification_family: none_refetch); authority comes from the re-fetch`. Never
   `// @pagokit:signature-verified`. That tag is how the next auditor decides whether to look, and
   a false one is worse than no verifier at all.
3. **Take exactly one thing from the payload: the identifier** at `webhook.event_id_pointer`.
   Validate its shape — length and charset — before it reaches a URL or a query. Discard the rest.
4. Dedup that identifier (the preamble's transaction). With no signature and no timestamp, dedup is
   the entire replay defence (Rule 9), and `replay_mitigation_strategy` must be `event-id-dedup`.
5. Log the id only (Rule 6). Treat any claimed event type as a *hint*, never as the branch
   condition for something that grants value.
6. Ack within `webhook.ack_deadline_seconds` — M-Pesa Daraja retries aggressively past ~30s — with
   `webhook.ack_body_literal` when an exact string is required. The re-fetch runs in the job.
7. The job calls `webhook.refetch_endpoint` with the **server-side credential** and acts on that
   response only. If the resource does not exist, drop the event and count it: a spike of those is
   someone probing your URL.

**Status codes** are the preamble's, plus two of this family's own: `413` over 256 KB, **`404`**
(not `403`) on a bad path token, **`429`** when rate-limited, `400` when the identifier is missing
or malformed, `200` on a duplicate, `200` plus a logged TODO for an unrouted type, and `200` —
or `webhook.ack_body_literal` — on success.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import { safeEqual } from './webhook-crypto';

// Rule 1: from the environment, never inline. Generate with `openssl rand -hex 24`.
const PATH_TOKEN = process.env.PROVIDER_WEBHOOK_PATH_TOKEN;
const ID_SHAPE = /^[A-Za-z0-9_-]{6,64}$/;
const EVENT_ID_FIELD = 'id'; // <from webhook.event_id_pointer>

/** Rule 3 substitute: the URL is the only secret here, so compare it in constant time. */
export function callbackPathOk(token: string | undefined): boolean {
  if (!PATH_TOKEN) throw new Error('PROVIDER_WEBHOOK_PATH_TOKEN is not set. See .env.example.');
  return token !== undefined && safeEqual(token, PATH_TOKEN);
}

// Per-IP fixed window. Correct for one instance; behind a load balancer use Redis INCR + EXPIRE,
// or the effective limit is this number multiplied by your replica count.
const WINDOW_MS = 60_000, MAX_PER_WINDOW = 60, MAX_TRACKED_IPS = 10_000;
const hits = new Map<string, { n: number; resetAt: number }>();
export function rateLimited(ip: string): boolean {
  const now = Date.now();
  // The attacker picks the keys here — nothing authenticates this endpoint — so an unbounded
  // Map is a memory sink inside the control meant to prevent one. Sweep, then hard-cap.
  if (hits.size >= MAX_TRACKED_IPS) {
    for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
    if (hits.size >= MAX_TRACKED_IPS) hits.clear(); // a distributed flood: reset rather than grow
  }
  const cur = hits.get(ip);
  if (!cur || now > cur.resetAt) { hits.set(ip, { n: 1, resetAt: now + WINDOW_MS }); return false; }
  cur.n += 1;
  return cur.n > MAX_PER_WINDOW;
}

/**
 * The ONLY value taken from an unauthenticated body. Handles both shapes: JSON, and the
 * form-encoded `id=tr_xxx` that Mollie's classic webhook sends.
 */
export function extractEventId(rawBody: string, contentType: string | null): string | null {
  let id: unknown;
  if (contentType?.includes('application/x-www-form-urlencoded')) {
    id = new URLSearchParams(rawBody).get(EVENT_ID_FIELD);
  } else {
    try { id = (JSON.parse(rawBody) as Record<string, unknown>)[EVENT_ID_FIELD]; } catch { return null; }
  }
  return typeof id === 'string' && ID_SHAPE.test(id) ? id : null;
}

/**
 * The authority. Everything the application believes comes from HERE, never from the callback.
 * <from webhook.refetch_endpoint>
 */
export async function fetchAuthoritative(id: string) {
  const res = await fetch(`https://api.<provider>.com/v1/payments/${encodeURIComponent(id)}`, {
    headers: { authorization: `Bearer ${process.env.PROVIDER_SECRET_KEY}` }, // Rule 1
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 404) return null;                   // described something that is not there
  if (!res.ok) throw new Error(`refetch ${res.status}`); // let the queue retry
  return res.json();
}
```

The handler is the preamble's, with step 4 replaced and the route carrying the secret segment —
`app/api/webhook/<provider>/[token]/route.ts` in the App Router (still
`await request.text()` under `export const runtime = 'nodejs'`),
`app.post('/api/webhook/<provider>/:token', express.raw({ type: '*/*', limit: '256kb' }), …)` in
Express (`'*/*'`, not `'application/json'`, or Mollie's form-encoded body never matches and
`req.body` arrives empty), and `@router.post("/api/webhook/<provider>/{token}")` with
`await request.body()` in FastAPI. Order inside the handler: path token → rate limit → extract id →
dedup → enqueue → `200`.

## Python

```python
# app/payments/<provider>_verify.py
import os, re, time
from urllib.parse import parse_qs
import httpx
from app.payments.webhook_crypto import safe_equal

PATH_TOKEN = os.getenv("PROVIDER_WEBHOOK_PATH_TOKEN")   # Rule 1: env, never inline
ID_SHAPE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
EVENT_ID_FIELD = "id"                                   # <from webhook.event_id_pointer>
WINDOW_S, MAX_PER_WINDOW, MAX_TRACKED_IPS = 60, 60, 10_000
_hits: dict[str, tuple[int, float]] = {}


def callback_path_ok(token: str | None) -> bool:
    """Rule 3 substitute: the URL is the only secret — constant-time compare."""
    if not PATH_TOKEN:
        raise RuntimeError("PROVIDER_WEBHOOK_PATH_TOKEN is not set. See .env.example.")
    return safe_equal(token or "", PATH_TOKEN)


def rate_limited(ip: str) -> bool:
    """Per-process fixed window. With more than one worker, move this to Redis INCR/EXPIRE."""
    now = time.time()
    if len(_hits) >= MAX_TRACKED_IPS:      # unauthenticated endpoint: the attacker picks the keys
        for stale in [k for k, (_, r) in _hits.items() if now > r]:
            del _hits[stale]
        if len(_hits) >= MAX_TRACKED_IPS:
            _hits.clear()                  # distributed flood: reset rather than grow unbounded
    n, reset_at = _hits.get(ip, (0, 0.0))
    if now > reset_at:
        _hits[ip] = (1, now + WINDOW_S)
        return False
    _hits[ip] = (n + 1, reset_at)
    return n + 1 > MAX_PER_WINDOW


def extract_event_id(raw_body: bytes, content_type: str | None) -> str | None:
    """The ONLY value taken from an unauthenticated body. Handles JSON and Mollie's form encoding."""
    import json
    if content_type and "application/x-www-form-urlencoded" in content_type:
        event_id = (parse_qs(raw_body.decode("utf-8", "replace")).get(EVENT_ID_FIELD) or [None])[0]
    else:
        try:
            event_id = json.loads(raw_body).get(EVENT_ID_FIELD)
        except (ValueError, AttributeError):
            return None
    return event_id if isinstance(event_id, str) and ID_SHAPE.match(event_id) else None


async def fetch_authoritative(event_id: str) -> dict | None:
    """The authority. <from webhook.refetch_endpoint>"""
    async with httpx.AsyncClient(timeout=5.0) as client:
        res = await client.get(
            f"https://api.<provider>.com/v1/payments/{event_id}",
            headers={"authorization": f"Bearer {os.environ['PROVIDER_SECRET_KEY']}"},  # Rule 1
        )
    if res.status_code == 404:
        return None                    # described something that does not exist
    res.raise_for_status()             # anything else: let the queue retry
    return res.json()
```

## The Moov case: a signature that does not cover the body

Some providers here *do* sign something — just not the payload. Moov's signature covers
`timestamp|nonce|webhook-id`; the JSON body is not in the MAC. The catalog records that as
`signature_covers_body: false` with `payload_authoritative: false`, and the composer still selects
this fragment.

Verify it anyway — it authenticates the envelope, and the nonce plus timestamp give a real replay
window. But a passing signature says nothing about the body: anyone holding one valid header
triple can attach any JSON to it until the window closes, and a "verified" `amount: 999999` is
exactly as forged as an unsigned one. The mitigation does not change: take the id, re-fetch,
believe the API. The real danger is psychological — a green "signature verified" log line is why
someone stops re-fetching six months later. Say so in `PAGOKIT_INTEGRATION.md`.

## Anti-patterns

- ❌ Reading `status`, `amount` or `currency` from the callback and updating an order — the whole
  point of the family. Re-fetch, then act.
- ❌ `// @pagokit:signature-verified` on an unsigned handler — it silences the one check that would
  have caught this.
- ❌ Re-fetching *inside* the handler — you blow `ack_deadline_seconds`, the provider retries, and
  the retries become a thundering herd against your own API.
- ❌ Interpolating the callback's id into a URL or SQL unvalidated — it is unauthenticated input.
  Check the shape, then `encodeURIComponent` / parameterise.
- ❌ `express.raw({ type: 'application/json' })` for a form-encoded provider like Mollie — no
  match, empty body, and the id extraction silently returns null for every event.
- ❌ A guessable path with no allowlist and no rate limit — webhook URLs leak through Referer
  headers, browser history, CI logs and screenshots.
- ❌ Returning `403` on a bad path token — confirms the endpoint exists. `404`.
- ❌ Skipping dedup because "the provider does not resend" — with no signature and no timestamp,
  anyone can resend, forever.
- ❌ Logging the payload to work out what the provider sends. Use the sandbox: Rule 6 still holds,
  and this body is the one most likely to be attacker-authored.

## Security rules cited

- **Rule 1:** path token and API credential come from the environment.
- **Rule 3:** no signature exists, so the handler says so via `pagokit-ignore` and substitutes
  compensating controls — constant-time secret path, rate limit, IP allowlist — with the
  authoritative re-fetch as the real integrity mechanism.
- **Rule 5:** the preamble's raw-body capture is kept, so a future signed scheme drops in unchanged.
- **Rule 6:** the identifier only; the untrusted body never reaches a log.
- **Rule 9:** `event-id-dedup` is the entire replay defence.
- **Rule 10:** the preamble's 256 KB cap, which on an unauthenticated endpoint is the only thing
  between you and an unbounded read.
