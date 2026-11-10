// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const mod = require('../currency-mismatch');
// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both: `run` comes through the prototype,
// and string interpolation yields the rule id.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

const WARN_WOMPI_USD = `
import { WidgetCheckout } from '@wompi/widget';

export async function createTransaction(order) {
  return WidgetCheckout({
    amountInCents: order.totalCents,
    currency: 'USD',
    reference: order.id,
    publicKey: process.env.WOMPI_PUBLIC_KEY,
  });
}
`;

const WARN_MERCADOPAGO_USD = `
export async function POST(req) {
  const preference = {
    items: [{ title: 'Plan Pro', quantity: 1, unit_price: 4999, currency_id: "USD" }],
  };
  return Response.json(preference);
}
`;

const PASS_WOMPI_COP = `
import { WidgetCheckout } from '@wompi/widget';

export async function createTransaction(order) {
  return WidgetCheckout({
    amountInCents: order.totalCents,
    currency: 'COP',
    reference: order.id,
  });
}
`;

const PASS_WOMPI_LOWERCASE_COP = `
import { WidgetCheckout } from '@wompi/widget';

export const config = { currency: 'cop', country: 'CO' };
`;

const PASS_CURRENCY_FROM_VARIABLE = `
import { WidgetCheckout } from '@wompi/widget';

export async function createTransaction(order) {
  const currency = order.currency ?? resolveCurrency(order.country);
  return WidgetCheckout({ amountInCents: order.totalCents, currency });
}
`;

const PASS_COMMENT_ONLY = `
import { WidgetCheckout } from '@wompi/widget';

export async function createTransaction(order) {
  // TODO: when we launch in Miami this becomes currency: 'USD'
  /* legacy build used currency: "MXN" here */
  return WidgetCheckout({ amountInCents: order.totalCents, currency: 'COP' });
}
`;

const PASS_IGNORE_TAG = `
import { WidgetCheckout } from '@wompi/widget';
// pagokit-ignore: currency-mismatch -- USD enabled on this Wompi account by the acquirer
export async function createTransaction(order) {
  return WidgetCheckout({ amountInCents: order.totalCents, currency: 'USD' });
}
`;

const PASS_UNRELATED_FILE = `
export const LOCALE_DEFAULTS = {
  'ar-KW': { currency: 'KWD', dateStyle: 'medium' },
  'ja-JP': { currency: 'JPY', dateStyle: 'short' },
};
`;

const PASS_AMBIGUOUS_TWO_PROVIDERS = `
import Stripe from 'stripe';
import { MercadoPagoConfig } from 'mercadopago';

export async function charge(order) {
  if (order.country === 'AR') {
    return mp.create({ currency_id: 'USD', transaction_amount: order.total });
  }
  return stripe.paymentIntents.create({ amount: order.totalCents, currency: 'USD' });
}
`;

const PASS_STRIPE_SUPPORTED = `
import Stripe from 'stripe';

export async function POST(request) {
  const intent = await stripe.paymentIntents.create({
    amount: 4999,
    currency: 'usd',
  });
  return Response.json({ secret: intent.client_secret });
}
`;


/* ------------------------------------------------------------------ *
 * Adversarial round 2 — snippets that broke the first cut of the rule.
 * ------------------------------------------------------------------ */

// Formatting a converted price for display is not a charge.
const PASS_INTL_DISPLAY = `
import { WidgetCheckout } from '@wompi/widget';

const USD_FMT = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });

export function usdEquivalent(cop, rate) {
  return USD_FMT.format(cop / rate);
}

export async function createTransaction(order) {
  return WidgetCheckout({ amountInCents: order.totalCents, currency: 'COP' });
}
`;

const PASS_TO_LOCALE_STRING = `
import { WidgetCheckout } from '@wompi/widget';

export function renderTotal(order) {
  return (order.totalCents / 100).toLocaleString('en-US', { style: 'currency', currency: 'EUR' });
}
`;

// A screaming-case constant is the same hardcoded currency.
const WARN_UPPERCASE_CONSTANT = `
import { WidgetCheckout } from '@wompi/widget';

const CURRENCY = 'USD';

export async function createTransaction(order) {
  return WidgetCheckout({ amountInCents: order.totalCents, currency: CURRENCY });
}
`;

// So is one written with backticks.
const WARN_TEMPLATE_LITERAL = `
import { WidgetCheckout } from '@wompi/widget';

export async function createTransaction(order) {
  return WidgetCheckout({ amountInCents: order.totalCents, currency: \`USD\` });
}
`;

// A provider named only by a commented-out import is not the provider of this file.
const PASS_COMMENTED_OUT_IMPORT = `
// import { WidgetCheckout } from '@wompi/widget';   // removed when we moved to Stripe Checkout

export const config = { currency: 'USD', country: 'US' };
`;

// The key must be code: a currency named inside a string body is prose.
const PASS_LITERAL_INSIDE_A_STRING = `
import { WidgetCheckout } from '@wompi/widget';

const HINT = "Wompi settles COP only. Do not set currency: 'USD' in the widget config.";

export async function createTransaction(order) {
  return WidgetCheckout({ amountInCents: order.totalCents, currency: 'COP', hint: HINT });
}
`;

// ...but a quoted key is still code.
const WARN_QUOTED_JSON_KEY = `
import { WidgetCheckout } from '@wompi/widget';

export const payload = { "amount_in_cents": 1000, "currency": "USD" };
`;

const base = { toolName: 'Write', projectDir: '/tmp/x' };

module.exports = [
  {
    name: 'Wompi integration hardcoding USD -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: WARN_WOMPI_USD },
    expected: 'warn',
  },
  {
    name: 'Mercado Pago webhook path with currency_id USD -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/webhook/mercadopago/route.ts', content: WARN_MERCADOPAGO_USD },
    expected: 'warn',
  },
  {
    name: 'correct code: Wompi charging COP -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_WOMPI_COP },
    expected: 'pass',
  },
  {
    name: 'edge case: supported currency written in lowercase -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_WOMPI_LOWERCASE_COP },
    expected: 'pass',
  },
  {
    name: 'edge case: currency comes from a variable, not a literal -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_CURRENCY_FROM_VARIABLE },
    expected: 'pass',
  },
  {
    name: 'unsupported currency mentioned only in comments -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_COMMENT_ONLY },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_IGNORE_TAG },
    expected: 'pass',
  },
  {
    name: 'unrelated file (i18n locale table, no provider) -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/src/i18n/locales.ts', content: PASS_UNRELATED_FILE },
    expected: 'pass',
  },
  {
    name: 'two providers imported, provider undetermined -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_AMBIGUOUS_TWO_PROVIDERS },
    expected: 'pass',
  },
  {
    name: 'Stripe charging a currency it supports -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/stripe/route.ts', content: PASS_STRIPE_SUPPORTED },
    expected: 'pass',
  },
  {
    name: 'edge case: Intl.NumberFormat display currency in a Wompi module -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_INTL_DISPLAY },
    expected: 'pass',
  },
  {
    name: 'edge case: toLocaleString display currency in a Wompi receipt -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi-receipt.ts', content: PASS_TO_LOCALE_STRING },
    expected: 'pass',
  },
  {
    name: 'bypass: screaming-case CURRENCY constant -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: WARN_UPPERCASE_CONSTANT },
    expected: 'warn',
  },
  {
    name: 'bypass: currency written as a template literal -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: WARN_TEMPLATE_LITERAL },
    expected: 'warn',
  },
  {
    name: 'edge case: provider named only by a commented-out import -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/checkout-config.ts', content: PASS_COMMENTED_OUT_IMPORT },
    expected: 'pass',
  },
  {
    name: 'edge case: currency named only inside a string body -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: PASS_LITERAL_INSIDE_A_STRING },
    expected: 'pass',
  },
  {
    name: 'edge case: quoted JSON key is still code -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/wompi.ts', content: WARN_QUOTED_JSON_KEY },
    expected: 'warn',
  },
];
