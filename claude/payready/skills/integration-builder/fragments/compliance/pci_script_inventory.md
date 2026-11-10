# PCI DSS payment-page script inventory and integrity

PCI DSS 4.0.1 req. **6.4.3** requires every script executing on a payment page to be authorised, inventoried with a written business justification, and integrity-assured; req. **11.6.1** requires a mechanism that alerts personnel when those scripts or the page's HTTP security headers change without authorisation. Both stopped being future-dated on **31 March 2025**, and almost nobody ships them. The one thing developers get wrong is the fix itself: they read "integrity-assured", add `integrity="sha384-…"` to the PSP's loader tag, and it works — until the PSP rotates that bundle. `js.stripe.com/v3` and its equivalents are **deliberately versionless**. A pinned hash on one means the browser silently refuses to execute the loader, and checkout dies for every user at once, in production, with nothing in your server logs. The catalog names those hosts in `pci.loader_exempt_from_sri` so the generator never demands a hash it will regret.

**Providers in this family:** four of the catalog's 42 providers set `pci.requires_script_inventory: true` — Stripe (`js.stripe.com`), Mercado Pago (`sdk.mercadopago.com`), Wompi (`checkout.wompi.co`), Lemon Squeezy (`app.lemonsqueezy.com`) — and those four hosts are the whole exemption list today. All four are `pan_touches_server: false` + `hosted_fields: true`; the first three are `pci.scope: "SAQ_A"`, Lemon Squeezy is `not_applicable` because it is the merchant of record, and the inventory is emitted for it anyway because the *page* is yours either way. The other 38 providers carry no `pci` block at all, and **absent is not exempt**: an empty `loader_exempt_from_sri` means "nobody has recorded whether this loader is versioned", which is a reason to read the provider's docs before adding SRI, never a licence to hash its loader.

**Catalog fields this fragment reads:** `pci.requires_script_inventory`, `pci.loader_exempt_from_sri`, `pci.scope`, `pci.pan_touches_server`, `pci.hosted_fields`, `mor.is_mor`.

## The contract

1. Decide whether the file is a payment page at all: it is, if it mounts a PSP element or loads a host from `pci.loader_exempt_from_sri`. A marketing page that merely has `<script>` tags is not, and treating it as one makes the control unusable.
2. Enumerate everything the page executes: `<script src>`, inline `<script>`, dynamic `import()`, whatever the bundler injects, and — the one people forget — whatever a tag manager can inject at runtime. A container you do not control is an unbounded script source; it cannot be inventoried, so it cannot be on the page.
3. Record each script in `payment-page-scripts.json` with a business justification, who authorised it, and when. **The review is the control; the file is only its artefact.** Re-review on every change and at least annually.
4. Third-party scripts you do control the version of: pin an exact version and add `integrity` + `crossorigin="anonymous"`, or self-host so the page loads nothing outside your origin.
5. Hosts in `pci.loader_exempt_from_sri`: **no `integrity` attribute.** Record the exemption and its reason, and constrain the host with CSP instead. This is the exemption, and it is load-bearing.
6. Serve a payment-page CSP allowlisting exactly the hosts in the inventory, with reporting pointed at your own endpoint.
7. Run the integrity check in CI on every build **and** on a schedule (11.6.1's baseline cadence is at least weekly): fetch each inventoried URL, recompute the digest, constant-time compare against the recorded value.
8. Alert a human on drift. 11.6.1 asks for a mechanism that *alerts personnel*; a log line nobody reads is not one.

## The inventory: `payment-page-scripts.json`

```json
{
  "reviewed_at": "2026-08-30",
  "reviewed_by": "security@example.com",
  "scripts": [
    {
      "src": "https://js.stripe.com/v3",
      "purpose": "PSP loader: tokenises the PAN inside a cross-origin iframe so no card data reaches our origin.",
      "approved_by": "security@example.com",
      "approved_at": "2026-08-30",
      "integrity": null,
      "integrity_exempt_reason": "pci.loader_exempt_from_sri — versionless by design; a pinned hash breaks live checkout."
    },
    {
      "src": "https://cdnjs.cloudflare.com/ajax/libs/zod/3.23.8/index.umd.min.js",
      "purpose": "Client-side validation of the billing form before submit.",
      "approved_by": "security@example.com",
      "approved_at": "2026-08-30",
      "integrity": "sha384-my85QA7gC81U8oJ/BUNsf+i53hYjCtuf4hJaE1u68P5YOrDV9tDpnS/o/KZAU5Ci"
    }
  ],
  "pages": ["app/checkout/page.tsx"]
}
```

`hooks/checks/pci-script-integrity.js` accepts any object with a non-empty array member — it returns on the **first** array it finds in key order — so a shorter shape passes the validator, and `scripts` goes first here so that the array it counts is the one that matters. (`pages` above `scripts` would satisfy the hook with an empty script list.) `approved_by` / `approved_at` are what an assessor asks for, and an inventory without them fails the human audit the file exists to survive. Generate a pinned hash with the recipe the validator suggests (verified below to agree byte-for-byte with the Node code):

```bash
curl -s "https://cdn.example.com/lib.js" | openssl dgst -sha384 -binary | openssl base64 -A
```

## Node / TypeScript

```ts
// scripts/verify-payment-page-scripts.ts — CI on every build, plus a weekly schedule (req. 11.6.1)
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

type Entry = { src: string; purpose: string; approved_by: string; approved_at: string;
               integrity: string | null; integrity_exempt_reason?: string };

const SRI_RE = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/;

/** SRI is `<algo>-<base64(digest)>`; the hash string declares its own algorithm. */
const sriDigest = (algo: string, bytes: Buffer) =>
  `${algo}-${createHash(algo).update(bytes).digest('base64')}`;

function sriMatches(expected: string, bytes: Buffer): boolean {
  const m = SRI_RE.exec(expected.trim());
  if (!m) return false;                              // an unparseable hash fails; it never passes
  const actual = Buffer.from(sriDigest(m[1], bytes), 'utf8');
  const want = Buffer.from(`${m[1]}-${m[2]}`, 'utf8');
  if (actual.length !== want.length) return false;   // timingSafeEqual throws on a length mismatch
  return timingSafeEqual(actual, want);              // constant-time comparison, always
}

/** Hosts the catalog declares un-SRI-able. Read them; never hardcode a PSP host. */
const exemptHosts = (providerIds: string[]) => providerIds.flatMap((id) =>
  (JSON.parse(readFileSync(`skills/payment-advisor/data/providers/${id}.json`, 'utf8'))
    .pci?.loader_exempt_from_sri ?? []).map((h: string) => h.toLowerCase())); // <from pci.loader_exempt_from_sri>

export async function verifyInventory(path = 'payment-page-scripts.json', providerIds = ['stripe']) {
  const inv = JSON.parse(readFileSync(path, 'utf8')) as { scripts: Entry[]; reviewed_at: string };
  const exempt = exemptHosts(providerIds);
  const isExempt = (h: string) => exempt.some((e) => h === e || h.endsWith(`.${e}`));
  const drift: string[] = [];

  for (const e of inv.scripts) {
    if (!/^https?:\/\//i.test(e.src)) continue;      // first-party: covered by the deploy artefact hash
    const host = new URL(e.src).hostname.toLowerCase();

    if (isExempt(host)) {
      // The exemption enforced in both directions: an SRI hash HERE is the bug.
      if (e.integrity) { drift.push(`${e.src}: PSP loader carries integrity= — breaks on the next PSP release`); continue; }
      if (!e.integrity_exempt_reason) drift.push(`${e.src}: exempt from SRI with no written reason (req. 6.4.3)`);
      continue;
    }
    if (!e.integrity) { drift.push(`${e.src}: third-party script, no integrity hash (req. 11.6.1)`); continue; }

    // `redirect: 'error'` REJECTS on a redirect rather than returning one, and an unreachable
    // host or a hung CDN rejects too. All three are drift to report, never an exception to
    // propagate: one uncaught throw here aborts the loop and loses every finding already
    // collected, so a single moved URL turns a failing audit into no audit at all.
    let bytes: Buffer;
    try {
      const res = await fetch(e.src, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
      if (!res.ok) { drift.push(`${e.src}: HTTP ${res.status}`); continue; }
      bytes = Buffer.from(await res.arrayBuffer());
    } catch (err) {
      // Rule 6: the error's name, never its message — a fetch failure can carry the URL and query.
      drift.push(`${e.src}: unreachable, redirected or timed out (${(err as Error).name})`);
      continue;
    }
    if (!sriMatches(e.integrity, bytes))
      drift.push(`${e.src}: CONTENT CHANGED — inventoried hash no longer matches`);
  }

  // Rule 6: counts and identifiers only — never the fetched script body or the page HTML.
  console.log('[pci.script-inventory]', { checked: inv.scripts.length, drift: drift.length, reviewed_at: inv.reviewed_at });
  if (drift.length) { drift.forEach((d) => console.error('  ✗', d)); process.exit(1); } // the exit code is the alert
}
```

```ts
// lib/security/payment-page-csp.ts — the HTTP-header half of req. 11.6.1
type Csp = { loaderHosts: string[]; apiHosts: string[]; nonce: string };

/** loaderHosts comes from `pci.loader_exempt_from_sri`. apiHosts is NOT in the catalog —
 *  read it from the provider's `docs_url` and pass it in rather than guessing. */
export function paymentPageCsp({ loaderHosts, apiHosts, nonce }: Csp): string {
  const loaders = loaderHosts.map((h) => `https://${h}`).join(' ');
  return [
    `default-src 'none'`,
    `script-src 'self' 'nonce-${nonce}' ${loaders}`, // no 'unsafe-inline' — it re-opens the skimming path
    `frame-src ${loaders}`,                          // the PSP iframe that actually touches the PAN
    `connect-src 'self' ${apiHosts.map((h) => `https://${h}`).join(' ')}`,
    `style-src 'self' 'nonce-${nonce}'`, `img-src 'self' data:`, `object-src 'none'`,
    `form-action 'self'`,        // stops an injected script re-pointing the form at its own collector
    `frame-ancestors 'none'`,    // Rule 12: the card form cannot be clickjacked into someone else's page
    `base-uri 'none'`,           // stops <base> silently rewriting every relative script URL
    `report-uri /api/security/csp-report`,
  ].join('; ');
}
```

Rendered for one provider, `script-src` and `frame-src` are literally `https://<from pci.loader_exempt_from_sri>` — one host per PSP mounted on that page, and nothing else.

```ts
// app/api/security/csp-report/route.ts — where header/script tampering is actually reported
import { NextResponse } from 'next/server';
import { enqueue } from '@/lib/queue';
export const runtime = 'nodejs'; // Rule 5: Node runtime, same as every PayReady route

const origin = (u: unknown) => { try { return new URL(String(u)).origin; } catch { return 'unparseable'; } };

export async function POST(request: Request) {
  // Rule 10: 256 KB cap checked before a byte is read. A real CSP report is under 4 KB.
  if (Number(request.headers.get('content-length') ?? 0) > 256 * 1024) return new NextResponse(null, { status: 413 });
  const raw = await request.text(); // Rule 5: raw body; browsers send csp-report or reports+json
  let body: any;
  try { const r = JSON.parse(raw); body = r['csp-report'] ?? r.body ?? r; }
  catch { return new NextResponse(null, { status: 400 }); }

  // Rule 6 + Rule 11: directive and ORIGINS only. blocked-uri and document-uri carry full URLs,
  // and a checkout URL carries order ids and sometimes an email.
  console.warn('[pci.csp-violation]', {
    directive: body['effective-directive'] ?? body.effectiveDirective ?? 'unknown',
    blocked_origin: origin(body['blocked-uri'] ?? body.blockedURL),
    page_origin: origin(body['document-uri'] ?? body.documentURL),
  });
  // Fire-and-forget: a queue outage must not turn a browser's report into a 500 the browser
  // then retries. Awaiting it here makes an unhandled rejection the response.
  void enqueue('security.csp_violation', { directive: body['effective-directive'] }).catch(() => {});
  return new NextResponse(null, { status: 204 });
}
```

This endpoint is **unauthenticated by design** — the sender is a browser, so there is no signature to verify and nothing in the report may be trusted, written back into the inventory, or echoed. Rate-limit and sample it: a broken CSP on a busy checkout emits reports at request volume. On Express, register it with `express.raw({ type: ['application/csp-report','application/reports+json'], limit: '256kb' })` **before** `express.json()`; on FastAPI, read `await request.body()` and never `await request.json()` first.

## Python

```python
# scripts/verify_payment_page_scripts.py — same digests, same verdicts as the Node version
import base64, hashlib, hmac, json, re, sys
from pathlib import Path
from urllib.parse import urlparse
import httpx

SRI_RE = re.compile(r"^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$")

def sri_digest(algo: str, data: bytes) -> str:
    return f"{algo}-{base64.b64encode(hashlib.new(algo, data).digest()).decode()}"

def sri_matches(expected: str, data: bytes) -> bool:
    m = SRI_RE.match(expected.strip())
    if not m:
        return False                     # an unparseable hash fails; it never passes
    actual = sri_digest(m.group(1), data).encode()
    want = f"{m.group(1)}-{m.group(2)}".encode()
    if len(actual) != len(want):          # compare_digest is only constant-time on equal lengths
        return False
    return hmac.compare_digest(actual, want)

def exempt_hosts(provider_ids):           # <from pci.loader_exempt_from_sri>
    out = []
    for pid in provider_ids:
        entry = json.loads(Path(f"skills/payment-advisor/data/providers/{pid}.json").read_text())
        out += [h.lower() for h in entry.get("pci", {}).get("loader_exempt_from_sri", [])]
    return out

def check(entry: dict, exempt: list[str], client: httpx.Client) -> str | None:
    """None means clean. A string is a req. 11.6.1 alert."""
    if not entry["src"].startswith(("http://", "https://")):
        return None                       # first-party: covered by the deploy artefact hash
    host = (urlparse(entry["src"]).hostname or "").lower()
    if any(host == x or host.endswith("." + x) for x in exempt):
        if entry.get("integrity"):        # the exemption, enforced in both directions
            return "PSP loader carries integrity= — breaks on the next PSP release"
        if not entry.get("integrity_exempt_reason"):
            return "exempt from SRI with no written reason (req. 6.4.3)"
        return None
    if not entry.get("integrity"):
        return "third-party script, no integrity hash (req. 11.6.1)"
    try:                                  # follow_redirects=False: a redirect is itself a change
        r = client.get(entry["src"])
    except httpx.HTTPError as exc:        # Rule 6: the class name, never the message
        return f"unreachable or timed out ({type(exc).__name__})"
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    return None if sri_matches(entry["integrity"], r.content) else "CONTENT CHANGED"

def verify(path="payment-page-scripts.json", provider_ids=("stripe",)) -> int:
    inv, exempt = json.loads(Path(path).read_text()), exempt_hosts(provider_ids)
    with httpx.Client(follow_redirects=False, timeout=10) as client:
        drift = [(e["src"], why) for e in inv["scripts"] if (why := check(e, exempt, client))]
    print("[pci.script-inventory]", {"checked": len(inv["scripts"]), "drift": len(drift)})  # Rule 6
    for src, why in drift:
        print("  x", src, why, file=sys.stderr)
    return 1 if drift else 0                  # the exit code is the alert

if __name__ == "__main__":
    sys.exit(verify())
```

## SAQ A vs SAQ A-EP vs SAQ D — the decision the inventory supports

| | Who delivers the card fields | PAN touches your server | Catalog shape |
|---|---|---|---|
| **SAQ A** | Entirely the PSP: a redirect, or a PSP-served iframe your page only positions | Never | `pci.scope: "SAQ_A"`, `pan_touches_server: false`, `hosted_fields: true` |
| **SAQ A-EP** | Your page. You host the form, your JS can read or relay the fields, or you direct-post to the PSP | Never — but your page can affect the transaction | Same catalog shape, *broken by what you added to the page* |
| **SAQ D** | Anything, once PAN reaches your systems | Yes — even briefly, even only in a log | `pan_touches_server: true`; Rule 12 refuses to generate this |

- **A → A-EP:** your page gains the ability to influence the payment form. A tag manager, a session recorder, a chat widget, an A/B snippet, or your own JS reading the fields. None of these touch the PAN; all of them can rewrite the DOM around it, which is the whole Magecart mechanism.
- **A-EP → D:** PAN reaches your infrastructure at all — a server-side card endpoint, a "temporary" proxy, an unredacted request log. Rule 12 is the wall.
- **Nothing moves you back automatically.** Removing the tag manager restores eligibility only once you can show the page's script set is known and monitored — which is what this inventory is.

The most-misread part of 4.0.1: in **January 2025** the Council revised SAQ A so 6.4.3 and 11.6.1 are no longer line items an SAQ A merchant reports on. In their place is an eligibility criterion — the merchant confirms its site cannot impact the security of the payment transaction. That is not a reprieve. The only defensible way to attest to it is to know every script on the page and be alerted when one changes: do 6.4.3 and 11.6.1 anyway, and skip the paperwork. SAQ A-EP, SAQ D and full-ROC merchants report on both outright.

## Anti-patterns

- ❌ `integrity="sha384-…"` on `js.stripe.com/v3`, `sdk.mercadopago.com`, `checkout.wompi.co` or `app.lemonsqueezy.com` — the PSP rotates the bundle, the browser refuses to execute it, and **every** checkout fails at once with nothing in your server logs. The most damaging possible way to "comply".
- ❌ Google Tag Manager on the payment page "because marketing needs the conversion event" — a container is an unbounded, remotely-mutable script source. Fire the conversion from the verified webhook or the post-payment page.
- ❌ Generating `payment-page-scripts.json` once at scaffold time and never re-reviewing it. 6.4.3 is a *process*; a stale inventory is evidence against you, not for you.
- ❌ An unversioned CDN URL (`…/zod/latest/index.js`) carrying an `integrity` hash — the hash pins what the URL does not, so the page breaks on the CDN's next publish.
- ❌ `script-src 'unsafe-inline'` on a payment page: it makes the CSP decorative, since an injected inline script is exactly the payload you are defending against.
- ❌ Treating your own bundle as out of scope. 6.4.3 covers every script the payment page *executes*, first-party included.

## Security rules cited

- **Rule 5** — the CSP report sink reads `await request.text()` (Next.js), `express.raw(...)` registered before `express.json()`, or `await request.body()` (FastAPI). Same raw-body discipline as every PayReady route.
- **Rule 6** — the verifier logs counts and identifiers; the sink logs directive and origins. Never the fetched script, never the report body.
- **Rule 10** — the sink checks `content-length` against the 256 KB cap before reading.
- **Rule 11** — origins are stripped of path and query, so violation telemetry never becomes an accidental PII sink.
- **Rule 12** — `frame-ancestors 'none'` and `form-action 'self'` keep the card form un-clickjackable and un-redirectable; the SAQ table exists to stop a merchant drifting into SAQ D, the same wall Rule 12 defends.
- Enforced by `hooks/checks/pci-script-integrity.js`, which reads the same `pci.loader_exempt_from_sri` field and denies a payment page that has no inventory.
