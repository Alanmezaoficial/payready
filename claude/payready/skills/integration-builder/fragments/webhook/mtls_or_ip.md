# `mtls_or_ip` — authenticity from the transport, not the payload

Nothing in the body is signed. Authenticity comes from *how the connection was made*: the caller
presented a client certificate, or it came from an address the provider published. The mistake is
reading that fact out of an HTTP header and believing it. `X-Forwarded-For` and
`X-SSL-Client-Verify` are ordinary headers — your edge sets them, and so can anyone else who can
reach your origin. Unless the edge **strips the client's copy before writing its own**, and the
origin refuses connections that did not come through that edge, the control is decoration. And
because nothing is signed, a request that passes still says nothing about its *contents*:
re-fetch is not defence in depth here, it is the integrity mechanism.

**Providers in this family:** none assigned yet — no entry in
`skills/payment-advisor/data/providers.json` carries `mtls_or_ip`, and none is expected to rely on
transport authenticity *alone*. The IP half is already needed today as a **supplementary** control
by catalog providers that do sign:

- **Paystack** (wave 6) — HMAC-SHA512, no signed timestamp; the docs pair it with a published
  allowlist (`52.31.139.75`, `52.49.173.169`, `52.214.14.220`) and a `/transaction/verify` call
  before fulfilment.
- **Polar** (wave 1) — Standard Webhooks, plus an allowlist containing CIDR ranges
  (`74.220.50.0/24`, `74.220.58.0/24`) — which is why the matcher below is CIDR-aware, not a
  string compare.
- **Xendit** (wave 5) — no per-payload signature at all: a *static* `x-callback-token`, identical
  on every event, which is a bearer credential rather than a signature. The catalog's note pairs a
  constant-time token compare with dedup and IP allowlisting "where offered".
- **M-Pesa Daraja** (wave 6) — nothing signed, no header, no timestamp. The catalog records
  authenticity as something the integrator has to construct: an unguessable callback path,
  Safaricom source-IP allowlisting at the edge, and a Transaction Status re-confirmation.

So compose this fragment *alongside* a signature family, not only instead of one. It ships ahead
of Efí, Openpay, Swish and CCBill, none yet in the catalog.

**Catalog fields this fragment reads:** `webhook.ip_allowlist_available`, `webhook.ip_allowlist`,
`webhook.signature_covers_body` (`false` here), `webhook.payload_authoritative` (`false`),
`webhook.refetch_endpoint`, `webhook.replay_mitigation_strategy`, `webhook.ack_body_literal`,
`webhook.evidence.confidence`.

## The contract

This family **replaces** the preamble's step 4 rather than implementing it; every other step —
size cap, raw body, parse, dedup, logging, ack — is unchanged.

1. **Terminate mTLS at the edge** (nginx, Envoy, an ALB, an API gateway). The app never sees the
   certificate; it sees headers the edge wrote.
2. **The edge strips the client's `X-SSL-Client-*` and `X-Forwarded-*` before writing its own.**
   This is the entire security boundary. Without it, `curl -H 'X-SSL-Client-Verify: SUCCESS'` is a
   complete bypass.
3. **The origin refuses traffic that did not arrive through the edge** — private network, security
   group, or a shared secret between edge and origin. An internet-reachable origin makes step 2
   pointless.
4. Downstream, require `X-SSL-Client-Verify: SUCCESS` **and** a constant-time match of the
   certificate fingerprint against a pinned value. `SUCCESS` alone only says *some* CA in your
   trust store signed *some* certificate (Rule 3).
5. For the allowlist, derive the client address from the **trusted proxy chain** — count your own
   hops from the socket end — never the leftmost `X-Forwarded-For` entry, which the caller writes.
   Load ranges from `webhook.ip_allowlist` and match by CIDR.
6. There is no signature, so be honest with the validator: carry
   `// pagokit-ignore: webhook-has-signature -- authenticity is transport-level (mTLS / IP
   allowlist); see fragments/webhook/mtls_or_ip.md`. Do **not** write
   `// @pagokit:signature-verified` — that tag claims something untrue, and the next auditor
   believes it.
7. **Re-fetch before any state change.** `payload_authoritative` and `signature_covers_body` are
   both `false`: a request from an allowlisted IP can still carry an amount, status or reference
   that nobody authenticated.

## Edge configuration

```nginx
# nginx — mTLS termination. The lines that matter are ssl_verify_client and the header overwrites.
server {
  listen 443 ssl;
  ssl_client_certificate /etc/ssl/<provider>-ca.pem;
  ssl_verify_client on;          # a request without a valid client cert never reaches the app
  ssl_verify_depth 2;

  location /api/webhook/<provider> {
    proxy_set_header X-SSL-Client-Verify $ssl_client_verify;       # overwrites any inbound copy
    proxy_set_header X-SSL-Client-Fingerprint $ssl_client_fingerprint;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # appends the real peer
    proxy_pass http://origin;
  }
}
```

`proxy_set_header` overwrites — that is what strips the client's version — but only for headers you
name. Any `X-SSL-Client-*` header you *forget* to set is forwarded from the client untouched.
Enumerate every header you read downstream.

## Node / TypeScript

```ts
// lib/payments/<provider>-verify.ts
import net from 'node:net';
import { headerValue, safeEqual } from './webhook-crypto';

// <from webhook.ip_allowlist>. Matching by string prefix is wrong: '203.0.113.9'.startsWith('203.0.11')
// also matches 203.0.110.0/24, and it misses IPv4-mapped IPv6 peers entirely.
const ALLOWLIST = ['203.0.113.0/24', '198.51.100.7/32', '74.220.50.0/24'];
// How many proxies YOU operate in front of this handler: 1 for a single nginx/ALB, 2 with a CDN.
// Everything left of your hops in the chain is caller-written.
const TRUSTED_PROXY_HOPS = 1;
const PINNED_CERT_FINGERPRINT = process.env.PROVIDER_WEBHOOK_CERT_FINGERPRINT;

const blocks = (() => {
  const list = new net.BlockList();
  for (const cidr of ALLOWLIST) {
    const [addr, bits] = cidr.split('/');
    const family = net.isIPv6(addr) ? 'ipv6' : 'ipv4';
    if (bits === undefined) list.addAddress(addr, family);
    else list.addSubnet(addr, Number(bits), family);
  }
  return list;
})();

/** The real peer: count back from the socket through the proxies you actually run. */
export function clientIpFromChain(xff: string | null, remoteAddr: string): string | null {
  const chain = (xff ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  chain.push(remoteAddr);              // the socket peer is the one entry nobody can forge
  const i = chain.length - 1 - TRUSTED_PROXY_HOPS;
  return i >= 0 ? chain[i] : null;
}

export function ipAllowed(ip: string | null): boolean {
  if (!ip) return false;
  const family = net.isIPv6(ip) ? 'ipv6' : net.isIPv4(ip) ? 'ipv4' : null;
  if (!family) return false;           // garbage in the chain is a reject, not a throw
  return blocks.check(ip, family);     // handles ::ffff: mapped v4 correctly
}

/**
 * Rule 3 substitute. Replaces the preamble's verifySignature for this family — the handler must
 * also carry the `pagokit-ignore: webhook-has-signature` line, because nothing here is a signature.
 */
export function verifyTransport(headers: Headers | Record<string, unknown>, remoteAddr: string): boolean {
  // headerValue, not headers.get: Express hands you a plain object and `.get` is not a function
  // there — a TypeError, so a 500 and a provider retry on the very path that reads the peer.
  const verified = headerValue(headers, 'x-ssl-client-verify');
  if (verified !== undefined) {
    if (verified !== 'SUCCESS') return false;   // "SUCCESS" only means a trusted CA signed something
    // Fail LOUD, not closed: an unset pin would reject every genuine event forever while looking
    // like a provider outage. The 500 makes the provider retry and makes you notice.
    if (!PINNED_CERT_FINGERPRINT) throw new Error('PROVIDER_WEBHOOK_CERT_FINGERPRINT is not set. See .env.example.');
    const presented = headerValue(headers, 'x-ssl-client-fingerprint');
    return presented !== undefined && safeEqual(presented, PINNED_CERT_FINGERPRINT); // Rule 3
  }
  return ipAllowed(clientIpFromChain(headerValue(headers, 'x-forwarded-for') ?? null, remoteAddr));
}
```

Raw-body capture is the preamble's and does not change: `await request.text()` with
`export const runtime = 'nodejs'` in the App Router, `express.raw({ type: 'application/json',
limit: '256kb' })` registered **before** `app.use(express.json())`, and `await request.body()` in
FastAPI. Keep it even though nothing hashes those bytes — `hooks/checks/raw-body.js` enforces it,
and a provider that adds a signature later then drops in without a rewrite.

Status codes follow the preamble: `413` over 256 KB, `400` with an empty body when the transport
check fails (never say whether it was the certificate or the address), `200` on a duplicate, `200`
plus a logged TODO for an unrouted type.

Stack notes on top of that. **Express:** `app.set('trust proxy', 1)` — a numeric
hop count, never `true`, which makes `req.ip` the leftmost `X-Forwarded-For` entry and therefore
caller-written; read the peer as `req.socket.remoteAddress`. **Next.js App Router:** a `Request`
carries no socket address at all, so on a managed platform the IP check belongs in middleware or at
the edge, and `TRUSTED_PROXY_HOPS` must match that platform's real chain. **FastAPI:**
`request.client.host` is the peer, and uvicorn must run with `--forwarded-allow-ips` set to the
edge's address — with `*`, that value becomes whatever `X-Forwarded-For` says and the check inverts
into an attacker-controlled allow. Raw-body capture is unchanged from the preamble: keep it, so a
provider that adds a signature later drops in without a rewrite.

## Python

```python
# app/payments/<provider>_verify.py
import ipaddress, os
from app.payments.webhook_crypto import safe_equal

ALLOWLIST = [ipaddress.ip_network(c) for c in            # <from webhook.ip_allowlist>
             ("203.0.113.0/24", "198.51.100.7/32", "74.220.50.0/24")]
TRUSTED_PROXY_HOPS = 1        # proxies YOU run. Never trust the whole chain.
PINNED_CERT_FINGERPRINT = os.getenv("PROVIDER_WEBHOOK_CERT_FINGERPRINT")


def client_ip_from_chain(xff: str | None, remote_addr: str) -> str | None:
    chain = [p.strip() for p in (xff or "").split(",") if p.strip()]
    chain.append(remote_addr)          # the socket peer: the one entry nobody can forge
    i = len(chain) - 1 - TRUSTED_PROXY_HOPS
    return chain[i] if i >= 0 else None


def ip_allowed(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False                   # garbage in the chain is a reject, not a crash
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in ALLOWLIST)


def verify_transport(headers, remote_addr: str) -> bool:
    """Rule 3 substitute — NOT a payload signature. See the pagokit-ignore note in the handler."""
    verified = headers.get("x-ssl-client-verify")
    if verified is not None:
        if verified != "SUCCESS":      # "SUCCESS" only means a trusted CA signed something
            return False
        if not PINNED_CERT_FINGERPRINT:   # fail loud, not closed — see the Node note
            raise RuntimeError("PROVIDER_WEBHOOK_CERT_FINGERPRINT is not set. See .env.example.")
        return safe_equal(headers.get("x-ssl-client-fingerprint") or "", PINNED_CERT_FINGERPRINT)
    return ip_allowed(client_ip_from_chain(headers.get("x-forwarded-for"), remote_addr))
```

## Anti-patterns

- ❌ Trusting the leftmost `X-Forwarded-For` entry — that is the value the caller wrote. Count hops
  back from the socket instead.
- ❌ `app.set('trust proxy', true)`, `--forwarded-allow-ips '*'`, or any setting that trusts the
  whole chain — it turns the allowlist into an allow-anything.
- ❌ Reading `X-SSL-Client-Verify` without the edge overwriting it, or with the origin reachable
  from the internet — a one-header bypass.
- ❌ Accepting `SUCCESS` without pinning the certificate — any cert from any CA in your trust store
  passes, including the whole public web PKI if that is what you loaded.
- ❌ `fingerprint === expected` — Rule 3 wants `safeEqual` / `safe_equal`.
- ❌ Prefix-matching IPs (`ip.startsWith('203.0.113')`) — matches 203.0.1130.x too, and silently
  fails for `::ffff:`-mapped peers. Polar's `/24` ranges make CIDR matching mandatory anyway.
- ❌ Acting on the payload because the IP checked out. The IP authenticates the *sender*, not the
  *contents*. Re-fetch.
- ❌ `// @pagokit:signature-verified` on this handler — nothing verified a signature. Use the
  `pagokit-ignore` line with a reason, so the audit trail stays truthful.
- ❌ Hardcoding the ranges in the handler. Providers change them; read `webhook.ip_allowlist` and
  re-check `last_verified_at` before go-live, because a stale range fails closed on payment day.

## Security rules cited

- **Rule 3:** the handler authenticates the caller before parsing — pinned client certificate or a
  CIDR allowlist over the trusted chain — and declares via `pagokit-ignore` that this is not a
  payload signature. The fingerprint compare is constant-time.
- **Rule 5:** the preamble's raw-body capture is kept even though nothing hashes it, so a future
  signed scheme drops in unchanged and `hooks/checks/raw-body.js` stays green.
- **Rule 6:** logging belongs to the preamble; nothing here reaches a log.
- **Rule 9:** no timestamp is signed, so `event-id-dedup` is the entire replay defence and
  `replay_mitigation_strategy` must say so.
- **Rule 10:** the preamble's 256 KB cap — the only body limit an unauthenticated endpoint has.
