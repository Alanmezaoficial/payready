# PagoKit error codes

> **Generated from `hooks/checks/*.js` and the PHASE_CHECKS map.** Run `npm run generate:errors`.
> Do not edit by hand — a document describing code should be derived from that code.

## The stderr contract

Each finding is one JSON object per line on **stderr**:

```json
{"tool":"pagokit-validate","file":"app/api/webhook/route.ts","rule":"webhook-has-signature","level":"deny","code":"ERR_WEBHOOK_NO_SIG","message_en":"...","message_es":"...","suggested_fix":"..."}
```

| Exit code | Meaning |
|---|---|
| `0` | Pass, or warnings only. The write proceeds. |
| `2` | At least one **deny**. The write is blocked and the finding is appended to `.pagokit/audit.log`. |

A `deny` is not a bug report. It means the write would have introduced a failure that does not
throw — an unsigned webhook, a wrong currency exponent, a secret compared with `===`. Read the
`suggested_fix` and change the code.

If a rule is genuinely wrong for your case, use the escape hatch. It is logged, which makes it a
decision on the record rather than a silent hole:

```ts
// pagokit-ignore: <rule-id> -- <why this is safe here>
```

## All codes

| Code | Rule | Level | Phase | Security rule |
|---|---|---|---|---|
| `ERR_SPT_UNSCOPED` | `agentic-token-scope` | **deny** | post | Rule 16 |
| `ERR_CURRENCY_UNSUPPORTED` | `currency-mismatch` | **warn** | post | Rule 28 |
| `ERR_EINVOICE_MISSING` | `einvoice-obligation` | **warn / deny** | post | Rule 22 |
| `ERR_WEBHOOK_COLLISION` | `existing-webhook-check` | **deny** | pre | Rule 7 |
| `ERR_ENV_NOT_GITIGNORED` | `gitignore-check` | **deny** | pre | Rule 2 |
| `ERR_IDEMPOTENCY_WEAK` | `idempotency-canonical` | **deny** | post | Rule 4 |
| `ERR_IDEMPOTENCY_MISSING` | `idempotency-canonical` | **warn** | post | Rule 4 |
| `ERR_MINOR_UNITS` | `minor-units` | **warn / deny** | post | Rule 13 |
| `ERR_MOR_CONFLICT` | `mor-capability-conflict` | **deny** | post | Rule 20 |
| `ERR_MIT_NO_TLID` | `network-txn-id-persistence` | **warn / deny** | stop | Rule 21 |
| `ERR_CLIENT_AMOUNT` | `no-client-amount-trust` | **deny** | post | Rule 25 |
| `ERR_HARDCODED_KEY` | `no-hardcoded-keys` | **deny** | post, stop | Rule 1 |
| `ERR_PAN_IN_TRANSIT` | `no-pan-in-transit` | **deny** | post | Rule 24 |
| `ERR_PII_LOG` | `no-pii-logs` | **warn** | post | Rule 6 |
| `ERR_TIMING_UNSAFE` | `no-plaintext-secret-compare` | **deny** | post | Rule 19 |
| `ERR_REFUND_IRREVERSIBLE` | `no-refund-on-irreversible` | **warn / deny** | post | Rule 17 |
| `ERR_PCI_SCRIPT_INVENTORY` | `pci-script-integrity` | **deny** | post | Rule 15 |
| `ERR_LIVE_KEY_IN_PROMPT` | `prompt-preflight` | **deny** | prompt | — |
| `ERR_CONTROL_DISABLE_REQUEST` | `prompt-preflight` | **warn** | prompt | — |
| `ERR_RAW_BODY_PARSED` | `raw-body` | **warn / deny** | post, stop | Rule 5 |
| `ERR_SECRET_CLIENT_BUNDLE` | `secret-in-client-bundle` | **deny** | post | Rule 26 |
| `ERR_EVENT_UNBOUNDED` | `webhook-event-allowlist` | **deny** | post | Rule 14 |
| `ERR_ACK_TOO_SLOW` | `webhook-fast-ack` | **warn** | post | Rule 18 |
| `ERR_WEBHOOK_NO_SIG` | `webhook-has-signature` | **deny** | post, stop | Rule 3 |
| `ERR_ENCODING_MISMATCH` | `webhook-secret-encoding` | **deny** | post | Rule 23 |
| `ERR_WRONG_WEBHOOK_SECRET` | `webhook-secret-not-api-key` | **deny** | post | Rule 27 |

## Internal codes

These come from the dispatcher, never from a check, and **never block**. A validator that
crashes fails open by design — a broken check must not stop a developer working.

| Code | Meaning |
|---|---|
| `ERR_CHECK_LOAD_FAILED` | A check file could not be `require`d. |
| `ERR_CHECK_RUNTIME` | A check threw while running. |
| `ERR_DISPATCHER_CRASHED` | The dispatcher itself failed. |

## Per-rule detail

### `agentic-token-scope`

`ERR_SPT_UNSCOPED` (deny) · Rule 16 · runs at: post

A shared payment token is a single-use credential the buyer's agent hands the merchant with a ceiling attached: a maximum amount, an expiry, and a currency. Redeeming it without checking all three is how an agent gets charged 400 USD for a 40 USD cart, and how an expired token turns into a chargeback with no cardholder to argue with. Storing or logging it defeats the point of a scoped credential entirely. The third failure is a training artefact: x402 V1 sent the payment in an `X-PAYMENT` header and advertised requirements in a `PAYMENT-REQUIRED` header. The current shape uses `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` and carries the requirements in the 402 response BODY. Emitting the V1 header produces a 402 loop that logs nothing and fails silently — the single most likely thing a 2025-trained model writes here.

Bypass: `// pagokit-ignore: agentic-token-scope -- <reason>`

### `currency-mismatch`

`ERR_CURRENCY_UNSUPPORTED` (warn) · Rule 28 · runs at: post

A `currency: 'USD'` inside a Wompi integration is not a typo the compiler catches: it fails at the API, in production, on the first real checkout. This check resolves which provider a file belongs to (path segment or SDK import, matched against the catalog) and compares every hardcoded currency literal against that provider's verified currency list. Always 'warn', never 'deny': the catalog records the currencies verified for the provider, and an individual merchant account can have more enabled. This is advice, not a defect.

Bypass: `// pagokit-ignore: currency-mismatch -- <reason>`

### `einvoice-obligation`

`ERR_EINVOICE_MISSING` (warn / deny) · Rule 22 · runs at: post

part of the sale, with nothing in the project that can issue it. In Mexico and Brazil (and Chile, Peru, Colombia, Ecuador, Italy) issuing the fiscal document is a legal obligation attached to the sale, not an accounting chore that can follow later. An integration that charges the card but cannot emit the CFDI or the NF-e is not "missing a feature": it is not shippable. That is a business fact, not a code defect, which is exactly why this check warns instead of blocking — a validator that blocks a legitimate write is a validator that gets uninstalled. Set PAGOKIT_STRICT=1 to make it a hard stop in CI. at the project root that records the decision.

Bypass: `// pagokit-ignore: einvoice-obligation -- <reason>`

### `existing-webhook-check`

`ERR_WEBHOOK_COLLISION` (deny) · Rule 7 · runs at: pre

Pre-write check. If the target file path matches a webhook pattern AND a webhook route already exists in the project at the SAME path, deny with a suggestion to namespace. PagoKit's default convention is `/api/webhook/<provider>/...` so collisions should be rare in practice — this check catches the case where the LLM tries to write `/api/webhook/route.ts` while an existing `/api/webhook/route.ts` already serves Clerk / Inngest / Resend. 10 lines of the new file's content.

Bypass: `// pagokit-ignore: existing-webhook-check -- <reason>`

### `gitignore-check`

`ERR_ENV_NOT_GITIGNORED` (deny) · Rule 2 · runs at: pre

created. Pre-write check. If the file being written is named `.env`, `.env.local`, `.env.production`, etc. (anything matching `.env*` EXCEPT `.env.example`/`.env.sample`/`.env.template`), require `.gitignore` covers it. Walks up from the project directory looking for `.gitignore` (handles monorepos). If found and `.env` is covered, allow. Otherwise deny with a specific suggestion.

Bypass: `// pagokit-ignore: gitignore-check -- <reason>`

### `idempotency-canonical`

`ERR_IDEMPOTENCY_WEAK` (deny) · `ERR_IDEMPOTENCY_MISSING` (warn) · Rule 4 · runs at: post

Triggers on files that look like checkout/payment/refund endpoints. If the file passes an `idempotencyKey` or sends an `Idempotency-Key` header but does NOT use a canonical UUID generator, deny. If idempotency is used but no canonical generator is detected (might be in a helper), warn.

Bypass: `// pagokit-ignore: idempotency-canonical -- <reason>`

### `minor-units`

`ERR_MINOR_UNITS` (warn / deny) · Rule 13 · runs at: post

A reflexive `Math.round(amount * 100)` is only correct for two-decimal currencies. In a zero-decimal currency (JPY, CLP, KRW, PYG, VND...) the amount is already in its smallest unit, so the ×100 charges the customer 100x. In a three-decimal currency (KWD, BHD, OMR, JOD, TND...) the smallest unit is 1/1000, so ×100 is off by 10x — and for the providers that hash the amount at its ISO exponent it also breaks the signature, which sends the developer debugging HMAC instead of the exponent. Deny needs three independent signals: an amount-shaped ×100 (or ÷100), a zero/three-decimal currency literal in the same file, and the file looking payments-related. When the only currency signal is an SDK call the finding drops to 'warn', because ×100 is also how percentages are computed.

Bypass: `// pagokit-ignore: minor-units -- <reason>`

### `mor-capability-conflict`

`ERR_MOR_CONFLICT` (deny) · Rule 20 · runs at: post

When a merchant-of-record (MoR) provider owns the sale, the MoR is the seller: it settles, it invoices, it remits the tax, it eats the chargeback. Code in the same integration that ALSO tries to act as the merchant — creating connected accounts, splitting payouts, building its own card form, issuing its own invoices, or computing a VAT/IVA rate the MoR already remits — compiles cleanly, fails at runtime (or worse, silently double-taxes the buyer), and the developer blames the payment plugin. Gating: the file's PRIMARY provider must resolve to a catalog provider with `mor.is_mor === true`. Primary is the provider named by a path segment (app/api/lemonsqueezy/...), or — when no path segment names one — the single provider whose SDK the file imports. A file that imports two providers and lives in no provider-named directory is ambiguous and is never denied.

Bypass: `// pagokit-ignore: mor-capability-conflict -- <reason>`

### `network-txn-id-persistence`

`ERR_MIT_NO_TLID` (warn / deny) · Rule 21 · runs at: stop

Mastercard requires the stored Trace ID (TLID) on every economically-related merchant-initiated transaction from 23 October 2026, and Visa's Original Transaction ID already drives approval rates today. A merchant-initiated charge that cannot be linked back to the cardholder-initiated transaction that authorised it is not a warning: it is a decline, on a subscription renewal, silently, for every customer at once. The check pairs two facts that live in different files: this file sets up a saved card (setup_future_usage / SetupIntent / off_session / vaulting), and the project's schema has no column to hold the id the network will hand back. It runs at the Stop phase because that is the only moment both halves are on disk — from a single mid-edit ctx it degrades to a warning, because the migration may simply not be written yet.

Bypass: `// pagokit-ignore: network-txn-id-persistence -- <reason>`

### `no-client-amount-trust`

`ERR_CLIENT_AMOUNT` (deny) · Rule 25 · runs at: post

If a server endpoint reads `amount` / `price` / `monto` from what the browser posted and hands that value to the payment provider, anyone can re-post the request with amount = 1 and buy the cart for a cent. The amount has to be looked up server-side (catalog, cart, order row) and only then charged. Deny needs the full chain, not a keyword: a server-shaped, payments-relevant file, an amount-named value bound from the request, and that exact value reaching a provider SDK call or an `amount`-shaped key of the charge payload. A refund endpoint that also loads the original payment is exempt — partial refunds legitimately take an amount.

Bypass: `// pagokit-ignore: no-client-amount-trust -- <reason>`

### `no-hardcoded-keys`

`ERR_HARDCODED_KEY` (deny) · Rule 1 · runs at: post, stop

Loads provider key patterns from providers.json and scans the file content (after stripping comments) for any real-looking key literal. Allowlist: tests/fixtures (skipped at dispatcher level). `.env.example` files are checked specifically to ensure they only contain test prefixes, not live keys.

Bypass: `// pagokit-ignore: no-hardcoded-keys -- <reason>`

### `no-pan-in-transit`

`ERR_PAN_IN_TRANSIT` (deny) · Rule 24 · runs at: post

Promotes SECURITY_RULES Rule 12 from prose to enforcement. The moment a card number or a CVV is accepted by your route handler, read out of your request body, stored in a column, or forwarded in a fetch body, the merchant leaves SAQ A (about 20 questions, self-assessed) and lands in SAQ D (about 300 questions, plus quarterly ASV scans and, above the volume thresholds, an on-site QSA). It is the most expensive mistake available in this space, and it is invisible until an auditor arrives. Gating, because this check blocks a write: - Only "strong" tokens (card_number / creditCardNumber / ccNumber, cvv, cvc, track1/2, numero_tarjeta) can deny on their own, and only from an accept/forward position — an object key, a destructured name, a property assignment, a form field name, a DB column, or a request-body read. - `security_code` is strong only when the file carries card vocabulary at all: on its own it is an order pickup code or a 2FA code at least as often as it is a CVV. - "Weak" tokens (pan, exp_month, exp_year, expiry_date) are ambiguous in ordinary code (`pan` is map/zoom vocabulary, and exp_month is legitimate token metadata), so two distinct weak tokens in accept positions are required before they say anything. - Anything destructured out of a provider token response (paymentMethod.card, charge.source, token.card) is skipped: last4 / brand / exp_month read back from the PSP is not PAN. - Stories, Cypress/Playwright specs and other harness files are skipped outright: an E2E suite types a Stripe test PAN into a hosted field on purpose.

Bypass: `// pagokit-ignore: no-pan-in-transit -- <reason>`

### `no-pii-logs`

`ERR_PII_LOG` (warn) · Rule 6 · runs at: post

WARN-only (not deny). Flags lines that log the entire `event`, `req.body`, or `payload` variable. Allows logging specific fields like `event.id`.

Bypass: `// pagokit-ignore: no-pii-logs -- <reason>`

### `no-plaintext-secret-compare`

`ERR_TIMING_UNSAFE` (deny) · Rule 19 · runs at: post

Detects a non-constant-time comparison of a signature, token or secret inside a payments-relevant file. `sig !== expected` leaks the position of the first differing byte through timing, which is enough to forge a signature byte by byte. For the `shared_secret_header` verification family the comparison IS the whole security control — there is no HMAC behind it — so the finding is reported as such. Gating. Naming a secret is NOT enough: `savedTokens.filter((t) => t !== token)`, `cached.digest !== bodyDigest` and `order.verified !== event.verified` all mention a secret and none of them is a verification. So a comparison fires only when it has the SHAPE of a verification: 1. the file is source code AND payments-relevant (webhook path, payment SDK import, catalog verifier/SDK call, or a catalog credential env var); 2. both operands are real expressions in comment-and-string stripped code — a literal on either side (`type === 'signature'`, `sig === null`, `x.length !== 64`) dies here; 3. neither operand ends in a descriptor segment (`.length`, `.type`, `.id`, `.status`), so length guards and event-type switches never fire; 4. at least one operand carries a secret word; and 5. the two sides are cast in opposing roles — one of them is qualified as the expected/computed/received/header value, or the two sides name DIFFERENT secrets (a token compared against a secret), or one side reads a credential out of the environment. Two mentions of the same secret with no role qualifier is a lookup, not a verification, and passes; 6. the comparison does not already use a constant-time primitive. Operands are read from the RAW line (offsets survive stripping), so the secret word inside an accessor — `req.headers.get('stripe-signature')`, `req.headers['x-signature']` — is seen. The stripped line still decides whether an operand is an expression at all, so a bare string literal can never supply the secret word.

Bypass: `// pagokit-ignore: no-plaintext-secret-compare -- <reason>`

### `no-refund-on-irreversible`

`ERR_REFUND_IRREVERSIBLE` (warn / deny) · Rule 17 · runs at: post

On account-to-account rails — Pix, SPEI, PSE, Yape, Nequi, Bre-B, UPI, PayNow — a completed transfer is final. There is no refund endpoint and no chargeback: the only way to return money is to originate a NEW payout to the payer's account, which needs their bank details, a separate payout balance, and its own reconciliation. Code written against `refunds.create` compiles, ships, passes review, and then fails the first time a customer asks for money back — in exactly the rails growing fastest in LATAM. The reversibility of every method comes from the catalog (`methods[].reversibility`), not from a list in this file, so a method added to the catalog is enforced without a code change. A method id counts only from a payment-method position: a *_method_types array, the value of a method-ish key, a `case` label under `switch (payment.rail)`, or an UPPER_SNAKE constant that names the rail. Deliberate non-rule: an outbound payout or transfer on an irreversible rail is correct — it is the actual fix — so `transfers.create` / `payouts.create` are never flagged. The same goes for the guard clause itself: when the branch a rail sits in already originates a payout or refuses the rail with a 4xx, that rail is dropped. Denying `if (m === 'pix') return payout()` would be denying the fix this rule exists to ask for.

Bypass: `// pagokit-ignore: no-refund-on-irreversible -- <reason>`

### `pci-script-integrity`

`ERR_PCI_SCRIPT_INVENTORY` (deny) · Rule 15 · runs at: post

PCI DSS 4.0.1 requirements 6.4.3 and 11.6.1 became mandatory on 31 March 2025: every script that executes on a payment page must be authorised, inventoried, and integrity checked. Almost nobody generates that inventory, and the scripts that break SAQ A eligibility (a tag manager, a session recorder) are exactly the ones a developer drops onto a checkout page without thinking. This check only speaks when the file actually MOUNTS a payment element (Stripe Elements, a Mercado Pago Brick, a Wompi widget, a Lemon Squeezy overlay, or a PSP loader script). A page that merely has a `<script>` tag is not a payment page, and a server file never is. Deliberate non-rule: PSP loader scripts (js.stripe.com/v3, sdk.mercadopago.com, ...) are versionless by design and rotate their bundles. Demanding SRI on them would break a live checkout, so hosts listed in a provider's `pci.loader_exempt_from_sri` are never asked for an integrity attribute. That exemption is read from the catalog, not hardcoded. Same shape, different reason: Turnstile / reCAPTCHA / hCaptcha are generated per request and cannot carry a stable hash at all, so for those the ask is req. 6.4.3 (name it in the inventory) rather than req. 11.6.1 (hash it) — advice a developer can actually follow.

Bypass: `// pagokit-ignore: pci-script-integrity -- <reason>`

### `prompt-preflight`

`ERR_LIVE_KEY_IN_PROMPT` (deny) · `ERR_CONTROL_DISABLE_REQUEST` (warn) · runs at: prompt

UserPromptSubmit preflight. Two things worth catching before Claude ever sees the prompt: 1. A LIVE API key pasted into the conversation. This is the most common real-world credential leak in agent workflows — the key ends up in the transcript, in any logging, and often in a screenshot. No other payments tool catches it. 2. An instruction to disable a security control. "Skip the signature check", "turn off the hook", "just ignore the validator". The user is allowed to do that — but through the documented, logged escape hatch, not by talking the model out of it. Blocking a prompt is heavy-handed, so the gating is tight: only LIVE key shapes (never test keys), and only explicit disable-the-control phrasing.

Bypass: `// pagokit-ignore: prompt-preflight -- <reason>`

### `raw-body`

`ERR_RAW_BODY_PARSED` (warn / deny) · Rule 5 · runs at: post, stop

Triggers on files that look like webhook handlers. Detects the stack and applies the correct rule. - Next.js App Router / generic JS: must NOT call `request.json()` / `await req.json()` / `req.body` (after JSON parse) before signature verification. Must use `request.text()` or `request.arrayBuffer()`. - Express: must register `express.raw(...)` middleware on the route, OR use `req.body` as a Buffer (i.e., the route has `express.raw` applied). - FastAPI: must use `await request.body()` (returns bytes), not `.json()`.

Bypass: `// pagokit-ignore: raw-body -- <reason>`

### `secret-in-client-bundle`

`ERR_SECRET_CLIENT_BUNDLE` (deny) · Rule 26 · runs at: post

Detects a server-only credential that is reachable from client-side code. Two shapes: (a) a public-prefixed env var (NEXT_PUBLIC_*, VITE_*, PUBLIC_*, REACT_APP_*, …) whose name is a catalog server credential, or contains SECRET / PRIVATE, or contains API_KEY / TOKEN / WEBHOOK together with a catalog provider name. The bundler inlines these into JavaScript that every visitor downloads. (b) a client-side file reading `process.env.X` / `import.meta.env.X` where X is a catalog credential whose scope is 'server'. This is a credential disclosure, not a style issue: a leaked secret key lets anyone charge, refund and read the merchant's account, so the level is 'deny'. Gating (a leaked-secret check that cries wolf gets uninstalled, so): - a credential the catalog scopes to 'client' (publishable / public keys) never fires; - broad words (API_KEY, TOKEN, WEBHOOK) only fire when the var name also names a catalog provider, so NEXT_PUBLIC_MAPBOX_TOKEN and NEXT_PUBLIC_ALGOLIA_API_KEY pass; - shape (b) needs a real client signal ('use client', or JSX plus interactivity) and backs off entirely when the file imports a SERVER payment SDK, because that is a server component and reading the secret there is correct.

Bypass: `// pagokit-ignore: secret-in-client-bundle -- <reason>`

### `webhook-event-allowlist`

`ERR_EVENT_UNBOUNDED` (deny) · Rule 14 · runs at: post

A webhook handler that dispatches on the event type without a bounded set of accepted types will run fulfilment logic for events it was never designed for: a `default:` branch that grants access, an if/else-if chain closed by an `else` that grants access, or a `handlers[event.type]()` lookup that reaches `constructor`/`__proto__`. The provider can add a new event type at any time and the handler silently starts acting on it. What makes a dispatch unbounded is a catch-all branch that ACTS, not the absence of one: a `switch` with no `default:` and an if/else-if chain with no terminal `else` are both bounded — an event type nobody named runs nothing. Fires only when the file is a webhook handler AND it dispatches on an event-type expression AND the dispatch is unbounded in one of three concrete ways. A `default:` that only logs or records the delivery, a handler with an explicit allowlist on the event type, and any non-webhook file all pass.

Bypass: `// pagokit-ignore: webhook-event-allowlist -- <reason>`

### `webhook-fast-ack`

`ERR_ACK_TOO_SLOW` (warn) · Rule 18 · runs at: post

Providers that declare an ack deadline retry the delivery when the handler does not answer in time. Blocking the response on a third-party HTTP call, an email send, a PDF/image render or a sleep is the classic way to blow the deadline: the provider retries, the handler runs again, and the order is fulfilled twice. Warn-only by design. Whether a given call is "slow" cannot be decided from source, so this rule never blocks a write — it names the deadline and the consequence and leaves the judgement to the developer.

Bypass: `// pagokit-ignore: webhook-fast-ack -- <reason>`

### `webhook-has-signature`

`ERR_WEBHOOK_NO_SIG` (deny) · Rule 3 · runs at: post, stop

Triggers on files that look like webhook handlers (path or content heuristics). Requires presence of at least one canonical verifier call OR the explicit `// @pagokit:signature-verified` tag for custom wrappers.

Bypass: `// pagokit-ignore: webhook-has-signature -- <reason>`

### `webhook-secret-encoding`

`ERR_ENCODING_MISMATCH` (deny) · Rule 23 · runs at: post

declared encodings. This is the number one cause of "the secret is right and verification always fails": the secret is decoded with the wrong encoding, the digest is emitted as base64 where the provider sends hex, or the HMAC uses a different hash than the provider signs with. Every expected value is catalog data (`webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.hash_algo`), so the mismatch is mechanically checkable — no heuristics involved. Fires only when the provider resolves from the path or the SDK import, the file is webhook context, and the file actually hand-rolls createHmac / createHash. Calling the provider SDK's own verifier always passes.

Bypass: `// pagokit-ignore: webhook-secret-encoding -- <reason>`

### `webhook-secret-not-api-key`

`ERR_WRONG_WEBHOOK_SECRET` (deny) · Rule 27 · runs at: post

Detects signature verification performed with the API key instead of the webhook signing secret. The two credentials live next to each other in every dashboard, so the mix-up is common — and silent: every signature fails to verify, and the developer spends the afternoon blaming the HMAC algorithm, the raw body, or the encoding. Resolution is catalog-driven: the provider is resolved from the file, then `credentials[].kind` / `env_vars` say which var is the api_key and which is the webhook_secret. Credentials of any other kind (Wompi's integrity signing_salt, for example) are deliberately not api keys, so signing with them never fires. Gating (all must hold before denying): 1. the file is webhook-related source code; 2. exactly one provider resolves from the file, and its two roles are distinct vars; 3. the file never READS the webhook-secret var — if the developer reads it at all, the value passed here is probably derived from it. Merely naming it in a string (`throw new Error('STRIPE_WEBHOOK_SECRET is required')`) does not count, or the check would disarm itself on the most common error message in the file; 4. the api-key var — or a local const it was assigned to, since most codebases lift env vars to the top of the file — appears inside the ARGUMENT LIST of the verification call (paren-balanced), not merely somewhere nearby, so an adjacent `new Stripe(process.env.STRIPE_SECRET_KEY)` cannot trigger it. `new Sdk(...)` sub-expressions are blanked inside that list too: handing the verifier a client built from the api key is correct, passing the api key itself is the bug.

Bypass: `// pagokit-ignore: webhook-secret-not-api-key -- <reason>`
