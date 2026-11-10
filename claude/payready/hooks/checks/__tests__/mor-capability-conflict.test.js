// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../mor-capability-conflict');

/* 1 — MoR resolved from the SDK import + a local IVA rate table = double taxation. */
const BAD_LOCAL_IVA_TABLE = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const ivaPorPais = {
  'MX': 0.16,
  'CO': 0.19,
  'BR': 0.17,
};

export async function POST(req) {
  const body = await req.json();
  const rate = ivaPorPais[body.country] ?? 0;
  const total = Math.round(body.subtotal * (1 + rate));
  return createCheckout(STORE_ID, VARIANT_ID, { checkoutData: { custom: { total } } });
}
`;

/* 2 — MoR resolved from the path segment + a third-party tax engine. */
const BAD_TAX_ENGINE = `
import Avatax from 'avatax';
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const client = new Avatax({ appName: 'shop' });

export async function POST(req) {
  const { subtotal, address } = await req.json();
  const quote = await client.createTransaction({ amount: subtotal, address });
  return createCheckout(STORE_ID, VARIANT_ID, { checkoutData: { custom: { tax: quote.totalTax } } });
}
`;

/* 3 — MoR + marketplace split settlement (a capability the MoR disables). */
const BAD_TRANSFER_DATA = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

export async function POST(req) {
  const { subtotal, sellerAccount } = await req.json();
  return createCheckout(STORE_ID, VARIANT_ID, {
    checkoutData: { custom: { subtotal } },
    transfer_data: { destination: sellerAccount },
  });
}
`;

/* 4 — Correct: the MoR is asked for the tax and the invoice, nothing is recomputed. */
const GOOD_READS_BACK_FROM_MOR = `
import { createCheckout, getOrder } from '@lemonsqueezy/lemonsqueezy.js';

export async function POST(req) {
  const { variantId } = await req.json();
  const checkout = await createCheckout(STORE_ID, variantId, {
    checkoutOptions: { embed: true },
  });
  return Response.json({ url: checkout.data.attributes.url });
}

export async function receipt(orderId) {
  const order = await getOrder(orderId);
  return {
    total: order.data.attributes.total,
    tax: order.data.attributes.tax,
    invoiceUrl: order.data.attributes.urls.invoice_url,
  };
}
`;

/* 5 — Edge case that MUST NOT fire: Stripe is not a merchant of record, so Connect
       marketplace payouts and a tax engine are entirely legitimate here. */
const GOOD_NON_MOR_MARKETPLACE = `
import Stripe from 'stripe';
import Taxjar from 'taxjar';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const taxjar = new Taxjar({ apiKey: process.env.TAXJAR_KEY });

export async function POST(req) {
  const { sellerAccountId, amount } = await req.json();
  const account = await stripe.accounts.create({ type: 'express' });
  const rate = await taxjar.ratesForLocation('90210');
  return stripe.paymentIntents.create({
    amount,
    currency: 'usd',
    on_behalf_of: sellerAccountId,
    transfer_data: { destination: account.id },
  });
}
`;

/* 6 — Edge case that MUST NOT fire: a dispatcher that knows about two providers is
       ambiguous, so no provider is "primary" and nothing is denied. */
const GOOD_AMBIGUOUS_ROUTER = `
import Stripe from 'stripe';
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function route(provider, input) {
  if (provider === 'lemonsqueezy') {
    return createCheckout(input.store, input.variant, {});
  }
  return stripe.paymentIntents.create({
    amount: input.amount,
    currency: input.currency,
    transfer_data: { destination: input.sellerAccountId },
  });
}
`;

/* 7 — The forbidden tokens exist only inside a comment and a string literal. */
const GOOD_COMMENT_AND_STRING_ONLY = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

// Do NOT add transfer_data or on_behalf_of here: Lemon Squeezy is the merchant of
// record, so avalara / taxjar style engines are its job, not ours.
const DOCS_NOTE = 'we used to compute IVA with avalara before moving to the MoR';

export async function POST(req) {
  const { variantId } = await req.json();
  return createCheckout(STORE_ID, variantId, {});
}
`;

/* 8 — Bypass tag present. */
const IGNORE_TAGGED = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';
// pagokit-ignore: mor-capability-conflict -- legacy Avalara nexus report, not used for checkout
import Avatax from 'avatax';

const client = new Avatax({ appName: 'nexus-report' });

export async function nexusReport() {
  return client.listTransactions();
}
`;

/* 9 — Unrelated, non-payment file that happens to hold a rate-shaped map. */
const UNRELATED_SHIPPING_FILE = `
const shippingSurcharge = {
  'MX': 0.16,
  'CO': 0.19,
  'BR': 0.17,
};

export function quote(country, weight) {
  return weight * (1 + (shippingSurcharge[country] ?? 0));
}
`;

/* 9 — Adversarial FP: the app's OWN user table, in a Lemon Squeezy webhook. */
const OWN_ACCOUNTS_TABLE = `
import { accounts } from '@/lib/auth/accounts';

export async function POST(req) {
  const event = await req.json();
  if (event.meta.event_name === 'order_created') {
    await accounts.create({ email: event.data.attributes.user_email, plan: 'pro' });
  }
  return new Response(null, { status: 200 });
}
`;

/* 10 — Adversarial FP: a VAT *registration number* validator. The values (9, 11, 12)
        sit in the same range as VAT percentages, so only the identifier tells them apart. */
const VAT_NUMBER_LENGTH_TABLE = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const vatNumberLength = { ES: 9, DE: 9, FR: 11, IT: 11, PT: 9, NL: 12 };

export function isValidVatNumber(country, value) {
  return value.length === vatNumberLength[country];
}

export async function POST(req) {
  const { variantId } = await req.json();
  return createCheckout(STORE_ID, variantId, {});
}
`;

/* 11 — Adversarial FP: an "invoiceItems" collection in the app's own ledger, mirroring
        the receipt Lemon Squeezy already issued. No customer, no price: not a Stripe item. */
const OWN_LEDGER_INVOICE_ITEMS = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';
import { invoiceItems } from '@/lib/ledger';

export async function POST(req) {
  const order = await req.json();
  await invoiceItems.create({ orderId: order.id, note: 'mirror of the LS receipt' });
  return Response.json({ ok: true });
}
`;

/* 12 — Adversarial bypass: the same double-taxation bug with lowercase country keys. */
const LOWERCASE_IVA_TABLE = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const iva = { mx: 0.16, co: 0.19, br: 0.17 };

export async function POST(req) {
  const b = await req.json();
  const total = Math.round(b.subtotal * (1 + iva[b.country.toLowerCase()]));
  return createCheckout(STORE_ID, VARIANT_ID, { checkoutData: { custom: { total } } });
}
`;

/* 13 — Adversarial bypass: the most obvious name for the table carries neither
        `vat`, `iva` nor `taxRate`. */
const TAX_BY_COUNTRY_TABLE = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

const taxByCountry = { MX: 0.16, CO: 0.19, BR: 0.17 };

export async function POST(req) {
  const b = await req.json();
  const total = Math.round(b.subtotal * (1 + taxByCountry[b.country]));
  return createCheckout(STORE_ID, VARIANT_ID, { checkoutData: { custom: { total } } });
}
`;

/* 14 — Adversarial bypass: Avalara over raw fetch. No SDK to import, and AVATAX_KEY's
        underscore defeats a \b-anchored identifier match. */
const AVALARA_OVER_RAW_FETCH = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

export async function POST(req) {
  const b = await req.json();
  const r = await fetch('https://rest.avatax.com/api/v2/transactions/create', {
    method: 'POST',
    headers: { Authorization: 'Basic ' + process.env.AVATAX_KEY },
    body: JSON.stringify({ amount: b.subtotal, addresses: b.address }),
  });
  const quote = await r.json();
  return createCheckout(STORE_ID, VARIANT_ID, { checkoutData: { custom: { tax: quote.totalTax } } });
}
`;

module.exports = [
  {
    name: 'MoR (import) + local IVA rate table → deny',
    check,
    ctx: {
      filePath: 'app/api/checkout/route.ts',
      content: BAD_LOCAL_IVA_TABLE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
  {
    name: 'MoR (path segment) + Avalara tax engine → deny',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: BAD_TAX_ENGINE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
  {
    name: 'MoR + transfer_data marketplace split → deny',
    check,
    ctx: {
      filePath: 'app/api/checkout/route.ts',
      content: BAD_TRANSFER_DATA,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
  {
    name: 'MoR checkout that reads tax/invoice back from the MoR → pass',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: GOOD_READS_BACK_FROM_MOR,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'edge: non-MoR provider (Stripe Connect + TaxJar) → pass',
    check,
    ctx: {
      filePath: 'app/api/stripe/connect/route.ts',
      content: GOOD_NON_MOR_MARKETPLACE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'edge: two providers imported, no provider-named directory → pass',
    check,
    ctx: {
      filePath: 'lib/payments/router.ts',
      content: GOOD_AMBIGUOUS_ROUTER,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'comment-only and string-literal mentions → pass',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: GOOD_COMMENT_AND_STRING_ONLY,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass → pass',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/nexus/route.ts',
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'unrelated non-payment file with a rate map → pass',
    check,
    ctx: {
      filePath: 'lib/shipping/quote.ts',
      content: UNRELATED_SHIPPING_FILE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: "adversarial: accounts.create against the app's own user table → pass",
    check,
    ctx: {
      filePath: 'app/api/webhooks/lemonsqueezy/route.ts',
      content: OWN_ACCOUNTS_TABLE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: EU VAT-registration-number length table → pass',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: VAT_NUMBER_LENGTH_TABLE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: "adversarial: invoiceItems.create on the app's own ledger → pass",
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/orders/route.ts',
      content: OWN_LEDGER_INVOICE_ITEMS,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: local IVA rate table with lowercase country keys → deny',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: LOWERCASE_IVA_TABLE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
  {
    name: 'adversarial: rate table named taxByCountry (no vat/iva/taxRate subword) → deny',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: TAX_BY_COUNTRY_TABLE,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
  {
    name: 'adversarial: Avalara called over raw fetch with an AVATAX_KEY env var → deny',
    check,
    ctx: {
      filePath: 'app/api/lemonsqueezy/checkout/route.ts',
      content: AVALARA_OVER_RAW_FETCH,
      toolName: 'Write',
      projectDir: '/tmp/pagokit-mor',
    },
    expected: 'deny',
  },
];
