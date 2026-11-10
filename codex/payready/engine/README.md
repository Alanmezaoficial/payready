<div align="center">

**The agent that picks and implements the right payment method for your app — from your terminal, with Claude Code.**

[![Claude Code Plugin](https://img.shields.io/badge/Claude_Code-Plugin-E3754C?style=flat-square)](https://docs.claude.com/en/docs/claude-code/plugins)
[![License: MIT](https://img.shields.io/badge/License-MIT-000?style=flat-square)](./LICENSE)
[![CI](https://github.com/Hainrixz/agente-pagokit/actions/workflows/test.yml/badge.svg)](https://github.com/Hainrixz/agente-pagokit/actions/workflows/test.yml)

[`tododeia.com`](https://tododeia.com) · [`@soyenriquerocha`](https://instagram.com/soyenriquerocha) · `enrique@tododeia.com`

🇪🇸 **[Leer en español](./docs/README.es.md)** · 📖 **[About](./ABOUT.md)** · 🗺️ **[Coverage](./docs/COVERAGE.md)**

</div>

---

## Why it exists<span style="color:#E3754C">.</span>

Every guide frames payment integration as a *choice* problem: thirty gateways, pick one.
Choosing takes an afternoon. What takes weeks — and what silently fails in production — is
everything after:

- A webhook that verifies a signature but never checks a timestamp, so a captured event is replayable forever.
- A webhook verified against the API key instead of the signing secret. It fails every event, and the developer goes off to debug the hashing algorithm.
- `amount * 100` on a Japanese customer. JPY has no minor unit, so that is a **100× overcharge**.
- A refund endpoint on a Pix integration, where refunding a charge is not an operation that exists.
- A `payment_intent.succeeded` handler that grants access, on a URL anyone can post to.

None of these throw. Most pass code review. **PagoKit exists to make them hard to write.**

It analyses your project, asks three questions, and generates a vertical-complete integration:
frontend, checkout endpoint, authenticated webhook, database migration, customer portal, refund
path, error mapper, production checklist and an audit trail.

**Everything runs locally.** No account, no API key, no telemetry. The only network calls are the
ones your generated code makes to your own provider.

---

## Three deterministic engines<span style="color:#E3754C">.</span>

An LLM asked to write payment code produces something *plausible*. Plausible is exactly the
failure mode that matters here. So the parts that must be correct aren't left to the model —
they're ordinary programs, with tests.

| | What it does | Why it isn't the model's job |
|---|---|---|
| **Validators** | Node checks on `PreToolUse` / `PostToolUse` hooks that **block** an insecure write | The model cannot argue with a non-zero exit code |
| **Advisor** | `scripts/advise.js` — a pure function from situation to ranked providers | Same input, same answer, every rejection carries its reason. "Why not X?" has an exact answer |
| **Signer** | `scripts/sign-event.js` — generates a **validly signed** event for any provider | Testing a handler means a valid event accepted, a forged one rejected, a replayed one rejected |

<img src="https://raw.githubusercontent.com/Hainrixz/agente-pagokit/d3720d9fd292cc2cfffbd5b6f6fce5f45ede97fa/assets/architecture.svg" alt="PagoKit architecture — analyzer, advisor with the deterministic ranking engine, builder resolving fragments by capability family, specialist writing files, and hook validators blocking insecure writes" width="100%" />

---

## What it knows<span style="color:#E3754C">.</span>

<!-- pagokit:stats:start -->
**42 providers** · **136 payment methods** · **74 countries** (71 with a local provider) · **106 currencies** with their ISO 4217 exponent · **6 webhook verification families** in use.
<!-- pagokit:stats:end -->

<!-- pagokit:providers:start -->
### What PagoKit writes for you

| Provider | Level | Role | Buyer coverage | Subscriptions | MoR | Onboarding |
|---|---|---|---|---|---|---|
| **Lemon Squeezy** | full build | mor | Global | ✓ | ✓ | application_review |
| **Mercado Pago** | full build | psp | AR · BR · CL · CO · MX · PE · UY | ✓ | — | self_serve |
| **Stripe** | full build | psp | US · CA · UK · EU · MX · BR · SG · AU · … | ✓ | — | self_serve |
| **Wompi** | full build | acquirer | CO | — | — | application_review |

### What PagoKit knows and recommends, but doesn't write

Another 38 providers with verified catalog data: the advisor compares them, computes their fees and explains their constraints — and tells you plainly that the code is yours to write. They move up to `build` once their signature scheme is verified and transcribed.

- **Wave 1** — Asaas · Bold.co · Conekta · Kushki · Paddle (Paddle Billing) · Polar
- **Wave 2** — Culqi · Flow.cl · Pagar.me · Transbank Webpay Plus · dLocal Go
- **Wave 3** — Fintoc · Mobbex · Placetopay (Evertec) · Recurrente · ePayco
- **Wave 4** — Adyen · GoCardless · Mollie · Redsys (TPV Virtual) · Revolut Merchant (Revolut Business)
- **Wave 5** — Airwallex · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) · Midtrans (GoTo Financial) · PayMongo · Razorpay · Xendit
- **Wave 6** — Flutterwave · Paymob · Paystack · Safaricom M-Pesa (Daraja API) · Tap Payments · Yoco
- **Wave 7** — Authorize.Net (Visa Acceptance) · Hyperswitch (Juspay) · Lago · RevenueCat · Square
<!-- pagokit:providers:end -->

**Payment methods**, because outside card-mature markets the right question is which *rail*
you need, not which gateway:

<!-- pagokit:methods:start -->
| Category | Methods | Examples |
|---|---|---|
| Cards | 8 | Bancontact · Credit/Debit Card · mada · Meeza · OmanNet |
| Wallets | 43 | Airtel Money · Alipay · AlipayHK · Alipay+ · Apple Pay |
| Bank transfer | 31 | ACH Credit · Botón Bancolombia · Bancolombia Transfer · BenefitPay · Bre-B |
| QR / instant | 11 | Bizum · CoDi · DuitNow · NQR (NIBSS QR) · PayNow |
| Cash vouchers | 14 | Alfamart / Indomaret (cash over counter) · Baloto · Boleto Bancário · Efecty · Fawry |
| Direct debit | 8 | ACH Direct Debit · Bacs Direct Debit · BECS Direct Debit (Australia) · PAC (Chile direct debit) · PayTo |
| Mobile money | 2 | M-Pesa · MTN MoMo |
| BNPL | 11 | Afterpay / Clearpay · Akulaku PayLater · BillEase · Billie (B2B invoice / BNPL) · EMI / Cardless EMI (India) |
| Crypto | 2 | USDC Stablecoin · USDT Stablecoin |
| Open banking | 1 | Pay by Bank (open banking) |
| Card present | 1 | Card present (terminal) |
| Benefits (EBT/HSA) | 2 | SNAP EBT · HSA / FSA card |
| Store billing | 2 | Apple In-App Purchase · Google Play Billing |
<!-- pagokit:methods:end -->

Full country × provider matrix: [`docs/COVERAGE.md`](./docs/COVERAGE.md).

---

## What it will and won't build for you<span style="color:#E3754C">.</span>

A wide catalog is only useful if it's honest about its own edges. Every provider carries an
integration level, and the advisor **states it every time**:

| Level | What happens |
|---|---|
| **build** | PagoKit writes the full idiomatic integration. |
| **generic** | PagoKit writes a working scaffold from the provider's verification family, and tells you it's a scaffold. |
| **advise** | PagoKit gives you the recommendation, the fee maths and a checklist — and says plainly that the code is yours to write. |

Backing that up is one rule the build enforces:

> If a provider's webhook scheme isn't verified against its own documentation
> (`evidence.confidence != "high"`), the generator **must not emit a signature verifier**.
> It emits re-fetch, event-id dedup, and a loud TODO instead.

A verifier built on an unverified scheme is worse than none: it looks correct and accepts
forged events.

---

## How it works<span style="color:#E3754C">.</span>

| Step | What happens |
|---|---|
| **1. SCAN** | Reads `package.json`, route files, DB schema. Detects stack, ORM, deploy target, language, and use cases like marketplace or mobile IAP. |
| **2. ASK** | Three questions, capped at five. Country and buyers · one-time or recurring · which local rails you need. |
| **3. MATCH** | Runs the ranking engine. Hard filters first — including *can you even open an account there*, and *can you get keys in time*. Sanctioned markets are refused, not ranked. |
| **4. BUILD** | The `integration-specialist` subagent writes the files, with the validators watching every write. |

---

## Installation<span style="color:#E3754C">.</span>

```bash
git clone https://github.com/Hainrixz/agente-pagokit ~/agente-pagokit
cd ~/your-project
claude --plugin-dir ~/agente-pagokit
```

Then run `/pagokit:start`.

> Requires **Node.js ≥ 18** and **Claude Code 2.x**.

---

## Deterministic security<span style="color:#E3754C">.</span>

Security rules aren't advice in a markdown file the model may or may not follow. They're Node
processes wired to Claude Code's hooks. A write that breaks one is **denied**.

| Blocks | Because |
|---|---|
| A webhook handler with no signature verification | Anyone who knows the URL can mint a `succeeded` event |
| `request.json()` before verifying | The HMAC covers the exact bytes; parsing first breaks it permanently and silently |
| `Math.random()` or `Date.now()` as an idempotency key | Guessable keys collide across tenants and duplicate charges survive retries |
| A live key inline in source | Git history, screenshots, Sentry traces |
| `.env` written before `.gitignore` covers it | The single most common credential leak there is |
| `amount * 100` on a zero-decimal currency | A 100× overcharge that nothing throws on |
| `===` on a signature | A timing oracle — and on shared-secret schemes it *is* the whole security control |
| Card data crossing your own server | Moves you from PCI SAQ A to SAQ D, a six-figure project |
| A refund call on an irreversible rail | On Pix or SPEI, "refund the charge" isn't an operation |
| A webhook route that would overwrite an existing one | Clobbering someone's Clerk or Inngest endpoint |

When the tool is wrong and you're right:

```ts
// pagokit-ignore: webhook-has-signature -- custom verifier in lib/auth/payments.ts
```

Every bypass is logged to `.pagokit/audit.log`, so it's a decision on the record rather than a
silent hole.

Full rule set with enforcement tiers: [`SECURITY_RULES.md`](./skills/payment-advisor/SECURITY_RULES.md).

---

## Commands<span style="color:#E3754C">.</span>

| Command | What it does |
|---|---|
| `/pagokit:start` | The wizard: analyse, ask, recommend, implement. |
| `/pagokit:test` | Sends a valid, a **forged** and a **replayed** event to your local handler. Works for every provider whose scheme is signable — not just the one with a CLI. |
| `/pagokit:doctor` | Read-only audit of an existing integration: credentials, key modes, signature verification, routed events, schema, replay protection. |

---

## What gets generated<span style="color:#E3754C">.</span>

For a Next.js App Router + Prisma project:

```
app/api/checkout/route.ts        Server-side price lookup · UUID idempotency · correct minor units
app/api/webhook/<provider>/      Raw body · signature · replay window · event-id dedup · fast ack
app/api/portal/route.ts          Customer self-service (subscriptions)
app/api/refund/route.ts          Authorisation-checked — or the payout path on irreversible rails
components/CheckoutButton.tsx    Hosted, embedded or widget, per the provider
lib/payments/<provider>.ts       SDK init · API version pinned
lib/payments/errors.ts           Cross-provider error taxonomy · ES/EN
prisma/schema.prisma             payments · subscriptions · customers · idempotency_keys
                                 · webhook_events_processed
payment-page-scripts.json        PCI DSS 4.0.1 §6.4.3 authorised-script inventory
.env.example                     Test-mode values only
PAGOKIT_INTEGRATION.md           Audit trail · events routed · what's still TODO
PAGOKIT_PRODUCTION_CHECKLIST.md  Steps to go live
PAGOKIT_TAX_TODO.md              Only where the market mandates e-invoicing
```

Other stacks adapt the structure; the guarantees don't change.

---

## Local rails it knows about<span style="color:#E3754C">.</span>

Outside card-mature markets, the rail matters more than the gateway. The advisor recommends the
rail before the provider:

<!-- pagokit:rails:start -->
| Country | Dominant instant rail |
|---|---|
| `AR` | Transferencias 3.0 |
| `AU` | PayTo |
| `BR` | Pix |
| `CO` | PSE (Pagos Seguros en Línea) |
| `CR` | Sinpe Movil |
| `DE` | SEPA Instant Credit Transfer |
| `ES` | Bizum |
| `FR` | SEPA Instant Credit Transfer |
| `HK` | FPS |
| `IN` | UPI |
| `IT` | SEPA Instant Credit Transfer |
| `KE` | M-Pesa |
| `MX` | SPEI |
| `NG` | NIBSS Instant Payment |
| `NL` | SEPA Instant Credit Transfer |
| `PE` | Yape |
| `PT` | MB WAY |
| `SG` | PayNow |
| `UK` | Faster Payments |
| `US` | RTP (Real-Time Payments) |
| `ZA` | PayShap |
<!-- pagokit:rails:end -->

---

## Roadmap<span style="color:#E3754C">.</span>

Waves are ordered by *evidence quality × rails unlocked ÷ template cost*, not by market size. A
provider whose signature scheme can't be verified isn't a wave item — it's a research ticket.

| Wave | Focus | What it unlocks |
|---|---|---|
| **0** ✅ | Foundation | Typed webhook specs, the recommendation engine, the event signer, the currency exponent table, catalog-driven validators |
| **1** | MoR continuity + LATAM verification families | Paddle · Polar · Conekta · Bold · Asaas · Kushki → Ecuador, and the RSA / body-transform / shared-secret families a dozen later providers reuse |
| **2** | "The payload is not authoritative" | Transbank · Flow · dLocal Go · Culqi · Pagar.me → Chile and Peru properly, plus the `return_url_commit` and `ping_then_poll` models |
| **3** | LATAM long tail | Fintoc · Recurrente · ePayco · Mobbex · Placetopay → Central America gets a real answer |
| **4** | Europe self-serve | Mollie · Revolut · Redsys · GoCardless · Adyen → iDEAL, Bancontact, BLIK, Bizum, SEPA and Bacs mandates |
| **5** | Asia | Razorpay · Xendit · Midtrans · PayMongo · Airwallex · Antom → UPI, QRIS, PayNow, PromptPay, Alipay+ |
| **6** | Africa & MENA | Paystack · Yoco · Flutterwave · Paymob · Tap · M-Pesa → mada, KNET, M-Pesa, MoMo, PayShap |
| **7** | New categories | Square · Authorize.Net · RevenueCat · Lago · Hyperswitch · Forage → card-present, high-risk verticals, mobile IAP, metered billing, orchestration, SNAP EBT |

---

## Development<span style="color:#E3754C">.</span>

```bash
npm install
npm run verify            # everything: schemas, integrity invariants, all test suites
npm run generate:all      # regenerate every derived file
./scripts/dev-link.sh /path/to/test-project
```

| Gate | Catches |
|---|---|
| `validate:data` | Schema violations, duplicate ids, dangling references, coverage lies, and the two invariants: no LLM claim marked high-confidence, no build-level provider without a verified scheme |
| `test:validators` | Validator fixtures — the violation, the correct code, the near-miss that must **not** false-positive, the bypass |
| `test:advisor` | Every wrong recommendation PagoKit could give, locked as a fixture |
| `test:signatures` | Per provider: sign → verify → and reject a tampered body, a wrong secret, a missing header, a replay |
| `check:*` | Drift in any generated file — coverage, signatures, doctor table, README tables, catalog |

Nothing generated is edited by hand. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

### Why the file count doesn't explode

<img src="https://raw.githubusercontent.com/Hainrixz/agente-pagokit/d3720d9fd292cc2cfffbd5b6f6fce5f45ede97fa/assets/verification-families.svg" alt="Fragments keyed by verification family are additive rather than multiplicative: 40 providers map onto 14 webhook families" width="100%" />

Providers differ in a small number of ways, and those ways repeat. Writing one template per
provider makes the file count `providers × stacks × billing modes`. Writing one fragment per
**capability family** makes it additive — and adding provider 41 costs a JSON entry plus a
small override, not two dozen documents.

---

## Security<span style="color:#E3754C">.</span>

Found a vulnerability? Please **don't open a public issue.** Email `security@tododeia.com` or use
[GitHub Security Advisories](https://github.com/Hainrixz/agente-pagokit/security/advisories/new).
Response within 48 hours. Full policy: [`SECURITY.md`](./SECURITY.md).

---

## Author<span style="color:#E3754C">.</span>

**Enrique Rocha** · [`tododeia.com`](https://tododeia.com) · [`@soyenriquerocha`](https://instagram.com/soyenriquerocha) · `enrique@tododeia.com`

AI consulting · agents · automations · sprints in Miami.

If it saved you days, send me a screenshot. If it broke something, open an issue.

---

[MIT](./LICENSE) · 2026 Enrique Rocha · `tododeia.`

<!-- marca-agua:inicio -->

---

<sub>Hecho por **Enrique Rocha (@soyenriquerocha)** · [tododeia.com](https://www.tododeia.com)⁠​‌‌​​‌​‌​‌‌‌​​‌​​​‌​‌‌​‌​‌‌​​‌‌​​‌‌​​‌​‌​‌‌​​‌​‌​​‌‌​‌​‌​​‌‌​​‌​​‌‌​​‌‌​​‌‌​​​​‌​​‌‌‌​​‌⁠</sub>
<!-- marca-agua:fin -->
