# Webhook Signatures — Per-Provider Reference

> **Generated from `skills/payment-advisor/data/providers/`.** Run `npm run generate:signatures`.
> Do not edit by hand: this file restates data, and a signature fact that disagrees with the
> catalog produces a handler that silently accepts forged events.

Every scheme below is one of 15 **verification families**. There are far fewer families than
providers, which is why PayReady writes one fragment per family instead of one per provider.

| Family | Providers in the catalog | What it means |
|---|---|---|
| `hmac_raw_body` | Lemon Squeezy | HMAC over the exact request bytes. |
| `hmac_timestamp_body` | Stripe | HMAC over a timestamp concatenated with the raw body, so the signature itself expires. |
| `hmac_field_concat` | Mercado Pago | HMAC over a template of selected fields — the raw body is never hashed, so a raw-body verifier fails 100% of the time. |
| `hmac_body_transform` | — | HMAC over a TRANSFORM of the body (base64 of it, or a re-serialisation) rather than the received bytes. |
| `standard_webhooks` | — | The Standard Webhooks spec. Verify with the off-the-shelf `svix` package rather than hand-rolling crypto. |
| `asymmetric_rsa` | — | RSA signature verified with the provider public key. There is no shared secret. |
| `asymmetric_jws` | — | A JWS/JWT signature. Verify the algorithm explicitly; never trust the `alg` header. |
| `body_embedded_sig` | Wompi | The signature travels INSIDE the body, not in a header. You must parse before you can verify — which is the one case where parsing first is correct. |
| `shared_secret_header` | — | No MAC at all: the header carries a static shared secret. That comparison is the entire security control, so it must be constant-time. |
| `signed_headers` | — | A canonical string built from method, URI and headers is signed. |
| `mtls_or_ip` | — | Authenticity comes from the transport (mutual TLS or an IP allowlist), not from a payload signature. |
| `none_refetch` | — | The callback is unsigned. Treat it purely as a ping and re-fetch the authoritative record. |
| `sdk_verifier` | — | The provider's own SDK owns verification; there is no documented hand-rollable recipe. |
| `unverified` | Adyen · Airwallex · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) · Asaas · Authorize.Net (Visa Acceptance) · Bold.co · Conekta · dLocal Go · ePayco · Fintoc · Flow.cl · Flutterwave · GoCardless · Kushki · Lago · Midtrans (GoTo Financial) · Paddle (Paddle Billing) · Pagar.me · PayMongo · Paystack · Placetopay (Evertec) · Polar · Razorpay · Recurrente · Redsys (TPV Virtual) · RevenueCat · Revolut Merchant (Revolut Business) · Safaricom M-Pesa (Daraja API) · Square · Tap Payments · Yoco | The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say. |
| `none` | Culqi · Hyperswitch (Juspay) · Mobbex · Mollie · Paymob · Transbank Webpay Plus · Xendit | No verification mechanism is documented. |

**Locally signable families** (PayReady can generate a valid test event): `hmac_raw_body`, `hmac_timestamp_body`, `hmac_field_concat`, `hmac_body_transform`, `body_embedded_sig`, `standard_webhooks`, `shared_secret_header`, `signed_headers`.
For the rest, capture a real event from the provider sandbox.

---

## Adyen

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider adyen --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.adyen.com*

---
## Airwallex

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider airwallex --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://www.airwallex.com/docs*

---
## Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider antom --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.antom.com/*

---
## Asaas

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider asaas --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.asaas.com/docs/sobre-os-webhooks*

---
## Authorize.Net (Visa Acceptance)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider authorize_net --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.authorize.net/api/reference/features/webhooks.html*

---
## Bold.co

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider bold --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developers.bold.co/webhook*

---
## Conekta

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider conekta --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developers.conekta.com/docs/autenticaci%C3%B3n-webhooks*

---
## Culqi

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider culqi --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://docs.culqi.com/es/documentacion/pagos-online/llaves*

---
## dLocal Go

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider dlocal_go --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.dlocal.com/*

---
## ePayco

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider epayco --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.epayco.com/docs/url-de-confirmacion*

---
## Fintoc

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider fintoc --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.fintoc.com/docs/webhooks-validating*

---
## Flow.cl

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `ping_then_poll`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider flow_cl --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developers.flow.cl/en/docs/intro*

---
## Flutterwave

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider flutterwave --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://developer.flutterwave.com/docs*

---
## GoCardless

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider gocardless --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.gocardless.com*

---
## Hyperswitch (Juspay)

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider hyperswitch --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.hyperswitch.io/integration-guide/webhooks*

---
## Kushki

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider kushki --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.kushki.com/cl/en/notifications/overview/*

---
## Lago

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider lago --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://www.getlago.com/docs/api-reference/webhooks/format---signature*

---
## Lemon Squeezy

- **Verification family:** `hmac_raw_body` — HMAC over the exact request bytes.
- **Signature header:** `X-Signature`
- **Hash:** `sha256`
- **Digest encoding:** `hex`
- **Signed string:** `{raw_body}`
- **Timestamp signed:** **no**
- **Replay mitigation:** `event-id-dedup` (dedup on `/meta/event_id`)
- **Webhook secret env var:** `LEMONSQUEEZY_WEBHOOK_SECRET` — **different from `LEMONSQUEEZY_API_KEY`**. Verifying with the API key is a silent, permanent failure.
- **Notification model:** `webhook`

**Required events (must be routed):**

- `order_created`
- `subscription_created`
- `subscription_updated`
- `subscription_cancelled`
- `subscription_payment_failed`
- `subscription_payment_refunded`

**Generate a signed test event:** `node scripts/sign-event.js --provider lemonsqueezy --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

**Anti-patterns specific to Lemon Squeezy:**

- Do not try to collect tax IDs yourself for VAT — Lemon Squeezy does it as the merchant of record.
- Webhooks are not timestamped — always dedup by event id stored in your DB.

*Verified 2026-05-20 · confidence `high` · human · https://docs.lemonsqueezy.com*

---
## Mercado Pago

- **Verification family:** `hmac_field_concat` — HMAC over a template of selected fields — the raw body is never hashed, so a raw-body verifier fails 100% of the time.
- **Signature header:** `x-signature` (`ts=<ts>,v1=<sig>`)
- **Hash:** `sha256`
- **Digest encoding:** `hex`
- **Signed string:** `id:{body:/data/id};request-id:{header:x-request-id};ts:{timestamp};`
- **Timestamp signed:** yes (tolerance 300s)
- **Replay mitigation:** `both` (dedup on `/id`)
- **Webhook secret env var:** `MP_WEBHOOK_SECRET` — **different from `MP_ACCESS_TOKEN`**. Verifying with the API key is a silent, permanent failure.
- **Notification model:** `webhook`
- **The payload is NOT authoritative.** Re-fetch before acting: `GET https://api.mercadopago.com/v1/payments/{data.id}`
- **The signature does not cover the whole body.** Fields outside the signed set are attacker-controllable.

**Required events (must be routed):**

- `payment.created`
- `payment.updated`

**Generate a signed test event:** `node scripts/sign-event.js --provider mercadopago --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

**Anti-patterns specific to Mercado Pago:**

- Do not omit the X-Idempotency-Key header on POST /payments — duplicate charges are common without it.
- Sandbox availability varies by country; always verify the test environment for your target country.

*Verified 2026-05-20 · confidence `high` · human · https://www.mercadopago.com/developers/en*

---
## Midtrans (GoTo Financial)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider midtrans --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.midtrans.com/*

---
## Mobbex

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider mobbex --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://mobbex.dev/webhooks*

---
## Mollie

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider mollie --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.mollie.com*

---
## Paddle (Paddle Billing)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider paddle --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.paddle.com*

---
## Pagar.me

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider pagarme --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://docs.pagar.me/reference/vis%C3%A3o-geral-sobre-webhooks*

---
## Paymob

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider paymob --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://developers.paymob.com/hub/egypt*

---
## PayMongo

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider paymongo --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://docs.paymongo.com/*

---
## Paystack

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider paystack --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://paystack.com/docs*

---
## Placetopay (Evertec)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider placetopay --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `unverified` · llm-generated · https://docs.placetopay.dev/en/gateway/authentication*

---
## Polar

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider polar --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://polar.sh/docs/integrate/webhooks/delivery*

---
## Razorpay

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider razorpay --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://razorpay.com/docs*

---
## Recurrente

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider recurrente --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.recurrente.com/*

---
## Redsys (TPV Virtual)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider redsys --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://pagosonline.redsys.es/desarrolladores-inicio/*

---
## RevenueCat

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider revenuecat --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://www.revenuecat.com/docs/integrations/webhooks*

---
## Revolut Merchant (Revolut Business)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider revolut_merchant --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.revolut.com/docs/merchant*

---
## Safaricom M-Pesa (Daraja API)

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider mpesa_daraja --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.safaricom.co.ke/*

---
## Square

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider square --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.squareup.com/docs/webhooks/step3validate*

---
## Stripe

- **Verification family:** `hmac_timestamp_body` — HMAC over a timestamp concatenated with the raw body, so the signature itself expires.
- **Signature header:** `Stripe-Signature` (`t=<ts>,v1=<sig>`)
- **Hash:** `sha256`
- **Digest encoding:** `hex`
- **Signed string:** `{timestamp}.{raw_body}`
- **Timestamp signed:** yes (tolerance 300s)
- **Replay mitigation:** `timestamp-window` (dedup on `/id`)
- **Webhook secret env var:** `STRIPE_WEBHOOK_SECRET` — **different from `STRIPE_SECRET_KEY`**. Verifying with the API key is a silent, permanent failure.
- **Notification model:** `webhook`
- **Ack deadline:** 20s

**Required events (must be routed):**

- `payment_intent.succeeded`
- `payment_intent.payment_failed`
- `charge.refunded`
- `charge.dispute.created`
- `invoice.payment_failed`
- `customer.subscription.deleted`
- `customer.subscription.updated`

**Generate a signed test event:** `node scripts/sign-event.js --provider stripe --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

**Anti-patterns specific to Stripe:**

- Do not use stripe.charges.create — it is the legacy Charges API. Use payment_intents instead so 3DS/SCA works.
- Do not call request.json() before signature verification — Stripe needs the raw body.

*Verified 2026-05-20 · confidence `high` · human · https://stripe.com/docs*

---
## Tap Payments

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider tap_payments --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developers.tap.company/docs/get-started*

---
## Transbank Webpay Plus

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `return_url_commit`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider transbank --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://www.transbankdevelopers.cl/documentacion/webpay*

---
## Wompi

- **Verification family:** `body_embedded_sig` — The signature travels INSIDE the body, not in a header. You must parse before you can verify — which is the one case where parsing first is correct.
- **Signature location:** inside the body at `/signature/checksum`
- **Hash:** `sha256`
- **Digest encoding:** `hex`
- **Signed string:** `{body_props}{timestamp}{secret}`
- **Timestamp signed:** yes (tolerance 600s)
- **Replay mitigation:** `both` (dedup on `/data/transaction/id`)
- **Webhook secret env var:** `WOMPI_EVENTS_SECRET` — **different from `WOMPI_PRIVATE_KEY`**. Verifying with the API key is a silent, permanent failure.
- **Notification model:** `webhook`
- **The payload is NOT authoritative.** Re-fetch before acting: `GET https://production.wompi.co/v1/transactions/{data.transaction.id}`
- **The signature does not cover the whole body.** Fields outside the signed set are attacker-controllable.

**Required events (must be routed):**

- `transaction.updated`

**Generate a signed test event:** `node scripts/sign-event.js --provider wompi --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

**Anti-patterns specific to Wompi:**

- Do not implement a card tokenization endpoint on your backend — Wompi tokenizes client-side via the Widget.
- Never expose the private key (prv_) to the browser. Only the public key (pub_) is safe client-side.
- Do not trust payload fields outside event.signature.properties - they are not covered by the checksum. Re-fetch the transaction before acting.

*Verified 2026-05-20 · confidence `high` · human · https://docs.wompi.co*

---
## Xendit

- **Verification family:** `none` — No verification mechanism is documented.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider xendit --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://docs.xendit.co/*

---
## Yoco

- **Verification family:** `unverified` — The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PayReady will not generate a verifier for it — see the note on each provider for what the docs say.
- **Timestamp signed:** **no**
- **Replay mitigation:** `none`
- **Notification model:** `webhook`

**Required events (must be routed):**


**Generate a signed test event:** `node scripts/sign-event.js --provider yoco --curl`
Forged and replayed variants: `--mode forged`, `--mode replay`. Both must be rejected with a 400.

*Verified 2026-08-31 · confidence `medium` · llm-generated · https://developer.yoco.com/online/*

---
## Summary table

| Provider | Family | Location | Hash | Digest | Timestamp signed | Tolerance | Replay | Payload authoritative |
|---|---|---|---|---|---|---|---|---|
| Adyen | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Airwallex | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Asaas | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Authorize.Net (Visa Acceptance) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Bold.co | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Conekta | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Culqi | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| dLocal Go | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| ePayco | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Fintoc | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Flow.cl | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Flutterwave | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| GoCardless | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Hyperswitch (Juspay) | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| Kushki | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Lago | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Lemon Squeezy | `hmac_raw_body` | `X-Signature` | sha256 | hex | **no** | — | `event-id-dedup` | yes |
| Mercado Pago | `hmac_field_concat` | `x-signature` | sha256 | hex | yes | 300s | `both` | **no — re-fetch** |
| Midtrans (GoTo Financial) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Mobbex | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| Mollie | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| Paddle (Paddle Billing) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Pagar.me | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Paymob | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| PayMongo | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Paystack | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Placetopay (Evertec) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Polar | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Razorpay | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Recurrente | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Redsys (TPV Virtual) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| RevenueCat | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Revolut Merchant (Revolut Business) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Safaricom M-Pesa (Daraja API) | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Square | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Stripe | `hmac_timestamp_body` | `Stripe-Signature` | sha256 | hex | yes | 300s | `timestamp-window` | yes |
| Tap Payments | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
| Transbank Webpay Plus | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| Wompi | `body_embedded_sig` | body `/signature/checksum` | sha256 | hex | yes | 600s | `both` | **no — re-fetch** |
| Xendit | `none` | `undefined` | — | — | **no** | — | `none` | yes |
| Yoco | `unverified` | `undefined` | — | — | **no** | — | `none` | yes |
