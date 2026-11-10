# Country × Provider coverage

> Auto-generated from `skills/payment-advisor/data/`. Run `npm run generate:coverage` to regenerate.
> Reflects catalog data verified through **2026-08-31**.

**Integration level** is what PagoKit will actually do for you:

| Badge | Level | What PagoKit does |
|---|---|---|
| `B` | build | Writes the full idiomatic integration from hand-written fragments |
| `G` | generic | Writes a working scaffold composed from the provider's verification family |
| `A` | advise | Recommends and explains, but **will not write the code** — you get docs and a checklist |

The digit after the badge is the delivery wave (`0` = already shipped).

**Totals:** 74 supported countries · 6 unsupported · 42 providers (38 advise, 4 build) · 136 payment methods · 106 currencies.

---

## LATAM (19 countries)

| Country | Code | Primary providers | Fallback MoR | Notes |
|---|---|---|---|---|
| Argentina | `AR` | Mercado Pago (B0) · dLocal Go (A2) · Mobbex (A3) | Lemon Squeezy (B0) | rail: `transferencias_30` |
| Bolivia | `BO` | — | Lemon Squeezy (B0) | — |
| Brazil | `BR` | Mercado Pago (B0) · Stripe (B0) · Asaas (A1) · Kushki (A1) · Pagar.me (A2) · dLocal Go (A2) | Lemon Squeezy (B0) | rail: `pix` · e-invoice: NFE |
| Chile | `CL` | Mercado Pago (B0) · Kushki (A1) · Flow.cl (A2) · Transbank Webpay Plus (A2) · dLocal Go (A2) · Fintoc (A3) · Placetopay (Evertec) (A3) | Lemon Squeezy (B0) | e-invoice: DTE |
| Colombia | `CO` | Wompi (B0) · Mercado Pago (B0) · Bold.co (A1) · Kushki (A1) · dLocal Go (A2) · Placetopay (Evertec) (A3) · ePayco (A3) | Lemon Squeezy (B0) | rail: `pse` · e-invoice: DIAN |
| Costa Rica | `CR` | Placetopay (Evertec) (A3) · Recurrente (A3) | Lemon Squeezy (B0) | rail: `sinpe_movil` |
| Dominican Republic | `DO` | Placetopay (Evertec) (A3) | Lemon Squeezy (B0) | — |
| Ecuador | `EC` | Kushki (A1) · Placetopay (Evertec) (A3) | Lemon Squeezy (B0) | e-invoice: SRI |
| Guatemala | `GT` | Placetopay (Evertec) (A3) · Recurrente (A3) | Lemon Squeezy (B0) | — |
| Honduras | `HN` | Placetopay (Evertec) (A3) · Recurrente (A3) | Lemon Squeezy (B0) | — |
| Mexico | `MX` | Mercado Pago (B0) · Stripe (B0) · Conekta (A1) · Kushki (A1) · dLocal Go (A2) · Fintoc (A3) | Lemon Squeezy (B0) | rail: `spei` · e-invoice: CFDI |
| Nicaragua | `NI` | Recurrente (A3) | Lemon Squeezy (B0) | — |
| Panama | `PA` | Placetopay (Evertec) (A3) · Recurrente (A3) | Lemon Squeezy (B0) | — |
| Peru | `PE` | Mercado Pago (B0) · Kushki (A1) · Culqi (A2) · dLocal Go (A2) · Placetopay (Evertec) (A3) | Lemon Squeezy (B0) | rail: `yape` · e-invoice: SUNAT |
| Puerto Rico | `PR` | Stripe (B0) · Lemon Squeezy (B0) | Lemon Squeezy (B0) | — |
| Paraguay | `PY` | — | Lemon Squeezy (B0) | — |
| El Salvador | `SV` | Recurrente (A3) | Lemon Squeezy (B0) | — |
| Uruguay | `UY` | Mercado Pago (B0) · dLocal Go (A2) | Lemon Squeezy (B0) | — |
| Venezuela | `VE` | — | Lemon Squeezy (B0) | — |

---

## Rest of world (55 countries)

| Country | Code | Primary providers | Fallback MoR | Notes |
|---|---|---|---|---|
| United Arab Emirates | `AE` | Paymob (A6) · Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Austria | `AT` | Adyen (A4) · GoCardless (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| Australia | `AU` | Stripe (B0) · Lemon Squeezy (B0) · GoCardless (A4) · Airwallex (A5) · Authorize.Net (Visa Acceptance) (A7) · Square (A7) | Lemon Squeezy (B0) | rail: `payto` |
| Belgium | `BE` | Adyen (A4) · GoCardless (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| Bahrain | `BH` | Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Canada | `CA` | Stripe (B0) · Lemon Squeezy (B0) · GoCardless (A4) · Authorize.Net (Visa Acceptance) (A7) · Square (A7) | Lemon Squeezy (B0) | — |
| Switzerland | `CH` | Adyen (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| Côte d’Ivoire | `CI` | Flutterwave (A6) · Paystack (A6) | Lemon Squeezy (B0) | — |
| Cameroon | `CM` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| China | `CN` | Airwallex (A5) · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) | Lemon Squeezy (B0) | — |
| Germany | `DE` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) | Lemon Squeezy (B0) | rail: `sepa_inst` |
| Denmark | `DK` | Adyen (A4) · GoCardless (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| Egypt | `EG` | Flutterwave (A6) · Paymob (A6) · Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Spain | `ES` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Redsys (TPV Virtual) (A4) · Revolut Merchant (Revolut Business) (A4) · Square (A7) | Lemon Squeezy (B0) | rail: `bizum` |
| Finland | `FI` | Adyen (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| France | `FR` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) · Square (A7) | Lemon Squeezy (B0) | rail: `sepa_inst` |
| Ghana | `GH` | Flutterwave (A6) · Paystack (A6) | Lemon Squeezy (B0) | — |
| Hong Kong SAR China | `HK` | Stripe (B0) · Lemon Squeezy (B0) · Airwallex (A5) · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) | Lemon Squeezy (B0) | rail: `fps` |
| Indonesia | `ID` | Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · Midtrans (GoTo Financial) (A5) · Xendit (A5) | Lemon Squeezy (B0) | — |
| Ireland | `IE` | Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) · Square (A7) | Lemon Squeezy (B0) | — |
| India | `IN` | Razorpay (A5) | Lemon Squeezy (B0) | local acquirer required · rail: `upi` |
| Italy | `IT` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) | Lemon Squeezy (B0) | rail: `sepa_inst` · e-invoice: SDI |
| Jordan | `JO` | Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Japan | `JP` | Stripe (B0) · Lemon Squeezy (B0) · Airwallex (A5) · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · Square (A7) | Lemon Squeezy (B0) | — |
| Kenya | `KE` | Flutterwave (A6) · Paystack (A6) · Safaricom M-Pesa (Daraja API) (A6) | Lemon Squeezy (B0) | rail: `mpesa` |
| South Korea | `KR` | Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) | Lemon Squeezy (B0) | — |
| Kuwait | `KW` | Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Lebanon | `LB` | Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Lithuania | `LT` | Revolut Merchant (Revolut Business) (A4) | Lemon Squeezy (B0) | — |
| Luxembourg | `LU` | Mollie (A4) | Lemon Squeezy (B0) | — |
| Malawi | `MW` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| Malaysia | `MY` | Airwallex (A5) · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · Razorpay (A5) · Xendit (A5) | Lemon Squeezy (B0) | — |
| Nigeria | `NG` | Lemon Squeezy (B0) · Flutterwave (A6) · Paystack (A6) | Lemon Squeezy (B0) | rail: `nibss_instant` |
| Netherlands | `NL` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) | Lemon Squeezy (B0) | rail: `sepa_inst` |
| Norway | `NO` | Adyen (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| New Zealand | `NZ` | Stripe (B0) · Lemon Squeezy (B0) · GoCardless (A4) · Airwallex (A5) | Lemon Squeezy (B0) | — |
| Oman | `OM` | Paymob (A6) · Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Philippines | `PH` | Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · PayMongo (A5) · Xendit (A5) | Lemon Squeezy (B0) | — |
| Pakistan | `PK` | Paymob (A6) | Lemon Squeezy (B0) | — |
| Poland | `PL` | Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) | Lemon Squeezy (B0) | — |
| Portugal | `PT` | Stripe (B0) · Lemon Squeezy (B0) · Adyen (A4) · GoCardless (A4) · Mollie (A4) | Lemon Squeezy (B0) | rail: `mbway` |
| Qatar | `QA` | Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Rwanda | `RW` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| Saudi Arabia | `SA` | Paymob (A6) · Tap Payments (A6) | Lemon Squeezy (B0) | — |
| Sweden | `SE` | Adyen (A4) · GoCardless (A4) · Mollie (A4) | Lemon Squeezy (B0) | — |
| Singapore | `SG` | Stripe (B0) · Lemon Squeezy (B0) · Airwallex (A5) · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) | Lemon Squeezy (B0) | rail: `paynow` |
| Senegal | `SN` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| Thailand | `TH` | Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · Xendit (A5) | Lemon Squeezy (B0) | — |
| Tanzania | `TZ` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| Uganda | `UG` | Flutterwave (A6) | Lemon Squeezy (B0) | — |
| United Kingdom | `UK` | Stripe (B0) · Lemon Squeezy (B0) · Paddle (Paddle Billing) (A1) · Polar (A1) · Adyen (A4) · GoCardless (A4) · Mollie (A4) · Revolut Merchant (Revolut Business) (A4) · Authorize.Net (Visa Acceptance) (A7) · Square (A7) | Lemon Squeezy (B0) | rail: `faster_payments` |
| United States | `US` | Stripe (B0) · Lemon Squeezy (B0) · Polar (A1) · GoCardless (A4) · Revolut Merchant (Revolut Business) (A4) · Authorize.Net (Visa Acceptance) (A7) · Square (A7) | Lemon Squeezy (B0) | rail: `rtp` |
| Vietnam | `VN` | Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) (A5) · Xendit (A5) | Lemon Squeezy (B0) | — |
| South Africa | `ZA` | Lemon Squeezy (B0) · Flutterwave (A6) · Paystack (A6) · Yoco (A6) | Lemon Squeezy (B0) | rail: `payshap` |
| Zambia | `ZM` | Flutterwave (A6) | Lemon Squeezy (B0) | — |

---

## Unsupported (6 countries)

Sanctioned or otherwise blocked. The advisor refuses to recommend a provider here.

| Country | Code | Reason | Comment |
|---|---|---|---|
| Cuba | `CU` | `sanctions:OFAC` | Cuba: OFAC SDN. US persons restricted. |
| Iran | `IR` | `sanctions:OFAC` | Iran: OFAC SDN. |
| North Korea | `KP` | `sanctions:OFAC` | North Korea: OFAC SDN. |
| Myanmar (Burma) | `MM` | `sanctions:multilateral` | Myanmar: limited US/EU sanctions post-2021. |
| Russia | `RU` | `sanctions:multilateral` | Russia: EU/US/UK sanctions. No active provider operates. |
| Syria | `SY` | `sanctions:OFAC` | Syria: OFAC SDN. |
