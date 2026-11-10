# Doctor — per-provider audit checks

> **Generated from `skills/payment-advisor/data/providers/`.** Run `npm run generate:doctor`.
> Do not edit by hand. The doctor skill reads this file so it audits every provider in the
> catalog rather than the four that happened to be hardcoded in its prose.

Severity legend: `[FAIL]` blocks a production sign-off · `[WARN]` should be fixed · `[OK]` passes.

---

### Adyen `adyen`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `ADYEN_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `ADYEN_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `ADYEN_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Airwallex `airwallex`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `AIRWALLEX_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `AIRWALLEX_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) `antom`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `ANTOM_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `ANTOM_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `ANTOM_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Asaas `asaas`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `ASAAS_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `ASAAS_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Authorize.Net (Visa Acceptance) `authorize_net`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `AUTHORIZE_NET_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `AUTHORIZE_NET_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Bold.co `bold`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `BOLD_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `BOLD_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Conekta `conekta`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `CONEKTA_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `CONEKTA_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `CONEKTA_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Culqi `culqi`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `CULQI_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `CULQI_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `CULQI_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### dLocal Go `dlocal_go`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `DLOCAL_GO_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `DLOCAL_GO_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### ePayco `epayco`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `EPAYCO_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `EPAYCO_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `EPAYCO_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Fintoc `fintoc`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `FINTOC_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `FINTOC_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Flow.cl `flow_cl`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `FLOW_CL_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `FLOW_CL_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Flutterwave `flutterwave`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `FLUTTERWAVE_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `FLUTTERWAVE_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `FLUTTERWAVE_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### GoCardless `gocardless`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `GOCARDLESS_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `GOCARDLESS_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Hyperswitch (Juspay) `hyperswitch`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `HYPERSWITCH_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `HYPERSWITCH_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Kushki `kushki`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `KUSHKI_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `KUSHKI_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `KUSHKI_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Lago `lago`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `LAGO_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `LAGO_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Lemon Squeezy `lemonsqueezy`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `LEMONSQUEEZY_API_KEY` | api_key | server | must start with `lmnsq_test_` | `lmnsq_live_` → `[WARN]` live key in setup | `[FAIL]` if missing |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- The verifier must be passed `LEMONSQUEEZY_WEBHOOK_SECRET`, **not** `LEMONSQUEEZY_API_KEY`. Passing the API key is a silent, permanent verification failure.
- Replay strategy is `event-id-dedup`: confirm a `webhook_events_processed` lookup keyed on `/meta/event_id`. `[FAIL]` if absent.
- Merchant of record: flag any local tax calculation or marketplace_payouts/custom_tax_engine/deep_checkout_branding usage. `[FAIL]` — the provider rejects it.

**Events that must be routed** (`[WARN]` per missing event):

- `order_created`
- `subscription_created`
- `subscription_updated`
- `subscription_cancelled`
- `subscription_payment_failed`
- `subscription_payment_refunded`

---

### Mercado Pago `mercadopago`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `MP_ACCESS_TOKEN` | api_key | server | must start with `TEST-` | `APP_USR-` → `[WARN]` live key in setup | `[FAIL]` if missing |
| `MP_PUBLIC_KEY` | publishable_key | client | must match `^(APP_USR|TEST)-[a-z0-9-]{30,}$` | — | `[WARN]` if missing |
| `MP_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- The verifier must be passed `MP_WEBHOOK_SECRET`, **not** `MP_ACCESS_TOKEN`. Passing the API key is a silent, permanent verification failure.
- The payload is not authoritative: the handler must re-fetch via `GET https://api.mercadopago.com/v1/payments/{data.id}` before acting. `[FAIL]` if absent.
- Replay strategy is `both`: confirm a `webhook_events_processed` lookup keyed on `/id`. `[FAIL]` if absent.
- Confirm a timestamp tolerance of ~300s. `[WARN]` if absent or wildly different.

**Events that must be routed** (`[WARN]` per missing event):

- `payment.created`
- `payment.updated`

---

### Midtrans (GoTo Financial) `midtrans`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `MIDTRANS_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `MIDTRANS_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Mobbex `mobbex`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `MOBBEX_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `MOBBEX_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Mollie `mollie`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `MOLLIE_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `MOLLIE_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Paddle (Paddle Billing) `paddle`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PADDLE_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PADDLE_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Merchant of record: flag any local tax calculation or  usage. `[FAIL]` — the provider rejects it.

**Events that must be routed** (`[WARN]` per missing event):



---

### Pagar.me `pagarme`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PAGARME_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PAGARME_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `PAGARME_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Paymob `paymob`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PAYMOB_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PAYMOB_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `PAYMOB_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### PayMongo `paymongo`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PAYMONGO_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PAYMONGO_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `PAYMONGO_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Paystack `paystack`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PAYSTACK_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PAYSTACK_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `PAYSTACK_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Placetopay (Evertec) `placetopay`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `PLACETOPAY_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `PLACETOPAY_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Polar `polar`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `POLAR_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `POLAR_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Merchant of record: flag any local tax calculation or  usage. `[FAIL]` — the provider rejects it.

**Events that must be routed** (`[WARN]` per missing event):



---

### Razorpay `razorpay`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `RAZORPAY_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `RAZORPAY_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Recurrente `recurrente`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `RECURRENTE_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `RECURRENTE_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `RECURRENTE_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Redsys (TPV Virtual) `redsys`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `REDSYS_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `REDSYS_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### RevenueCat `revenuecat`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `REVENUECAT_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `REVENUECAT_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `REVENUECAT_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Revolut Merchant (Revolut Business) `revolut_merchant`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `REVOLUT_MERCHANT_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `REVOLUT_MERCHANT_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Safaricom M-Pesa (Daraja API) `mpesa_daraja`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `MPESA_DARAJA_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `MPESA_DARAJA_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Square `square`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `SQUARE_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `SQUARE_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Stripe `stripe`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `STRIPE_SECRET_KEY` | api_key | server | must start with `sk_test_` | `sk_live_` → `[WARN]` live key in setup | `[FAIL]` if missing |
| `STRIPE_PUBLISHABLE_KEY` | publishable_key | client | must start with `pk_test_` | `pk_live_` → `[WARN]` live key in setup | `[WARN]` if missing |
| `STRIPE_WEBHOOK_SECRET` | webhook_secret | server | must match `^whsec_[A-Za-z0-9]{20,}$` | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- The verifier must be passed `STRIPE_WEBHOOK_SECRET`, **not** `STRIPE_SECRET_KEY`. Passing the API key is a silent, permanent verification failure.
- Confirm a timestamp tolerance of ~300s. `[WARN]` if absent or wildly different.

**Events that must be routed** (`[WARN]` per missing event):

- `payment_intent.succeeded`
- `payment_intent.payment_failed`
- `charge.refunded`
- `charge.dispute.created`
- `invoice.payment_failed`
- `customer.subscription.deleted`
- `customer.subscription.updated`

---

### Tap Payments `tap_payments`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `TAP_PAYMENTS_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `TAP_PAYMENTS_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `TAP_PAYMENTS_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Transbank Webpay Plus `transbank`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `TRANSBANK_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `TRANSBANK_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `TRANSBANK_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- This provider does not send webhooks. Confirm the commit call exists — an uncommitted transaction auto-reverses. `[FAIL]` if absent.

**Events that must be routed** (`[WARN]` per missing event):



---

### Wompi `wompi`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `WOMPI_PRIVATE_KEY` | api_key | server | must start with `prv_test_` | `prv_prod_` → `[WARN]` live key in setup | `[FAIL]` if missing |
| `WOMPI_PUBLIC_KEY` | publishable_key | client | must start with `pub_test_` | `pub_prod_` → `[WARN]` live key in setup | `[WARN]` if missing |
| `WOMPI_EVENTS_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |
| `WOMPI_INTEGRITY_SECRET` | signing_salt | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- The verifier must be passed `WOMPI_EVENTS_SECRET`, **not** `WOMPI_PRIVATE_KEY`. Passing the API key is a silent, permanent verification failure.
- The payload is not authoritative: the handler must re-fetch via `GET https://production.wompi.co/v1/transactions/{data.transaction.id}` before acting. `[FAIL]` if absent.
- Replay strategy is `both`: confirm a `webhook_events_processed` lookup keyed on `/data/transaction/id`. `[FAIL]` if absent.
- Confirm a timestamp tolerance of ~600s. `[WARN]` if absent or wildly different.

**Events that must be routed** (`[WARN]` per missing event):

- `transaction.updated`

---

### Xendit `xendit`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `XENDIT_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `XENDIT_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `XENDIT_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `none` family.

**Events that must be routed** (`[WARN]` per missing event):



---

### Yoco `yoco`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
| `YOCO_API_KEY` | api_key | server | no format constraint | — | `[FAIL]` if missing |
| `YOCO_PUBLIC_KEY` | publishable_key | client | no format constraint | — | `[WARN]` if missing |
| `YOCO_WEBHOOK_SECRET` | webhook_secret | server | no format constraint | — | `[FAIL]` if missing |

**Webhook handler must contain:**

- Signature verification for the `unverified` family.

**Events that must be routed** (`[WARN]` per missing event):



---

## Checks that apply to every provider

| Check | How | Severity |
|---|---|---|
| `.gitignore` covers `.env` | grep the nearest `.gitignore` | `[FAIL]` |
| `.env` is not committed | `git ls-files .env` returns nothing | `[FAIL]` |
| `.env.example` exists | file check | `[WARN]` |
| `.env.example` holds only test-mode values | compare against each credential's `live_prefix` | `[FAIL]` |
| Idempotency key is a real UUID | canonical generator present in the checkout path | `[FAIL]` |
| The five tables exist | `payments`, `subscriptions`, `customers`, `idempotency_keys`, `webhook_events_processed` | `[WARN]` per missing table |
| Amounts respect the currency exponent | zero-decimal and three-decimal currencies must not be multiplied by 100 | `[FAIL]` |
| `PAGOKIT_PRODUCTION_CHECKLIST.md` exists | file check | `[WARN]` |
