// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const mod = require('../minor-units');
// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both: `run` comes through the prototype,
// and string interpolation yields the rule id.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

const DENY_JPY_CHECKOUT = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(request) {
  const total = 4200;
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price_data: { currency: 'JPY', unit_amount: Math.round(total * 100) }, quantity: 1 }],
  });
  return Response.json({ id: session.id });
}
`;

const DENY_KWD_PYTHON = `
import stripe

def create_charge(importe):
    monto_menor = int(importe * 100)
    return stripe.PaymentIntent.create(amount=monto_menor, currency="KWD")
`;

const DENY_CLP_DIVIDE = `
import { mpPayment } from '@/lib/payments/mp';

export async function POST(req) {
  const payment = await mpPayment.create({
    body: { transaction_amount: 15000, currency_id: 'CLP' },
  });
  const display = payment.transaction_amount / 100;
  return Response.json({ display });
}
`;

const PASS_CURRENCY_AWARE_TERNARY = `
import Stripe from 'stripe';

export function toCharge(total, currency) {
  return currency === 'JPY' ? Math.round(total) : Math.round(total * 100);
}
`;

const PASS_PERCENTAGE_MATHS = `
import Stripe from 'stripe';

export async function POST(request) {
  const ratio = paidSoFar / goal;
  const pct = ratio * 100;
  const barWidth = pct;
  const fade = alphaLevel * 100;
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: 'JPY', unit_amount: 4200 }, quantity: 1 }],
  });
  return Response.json({ pct, barWidth, fade, id: session.id });
}
`;

const PASS_USD_ONLY = `
import Stripe from 'stripe';

export async function POST(request) {
  const total = 49.99;
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency: 'usd',
  });
  return Response.json({ secret: intent.client_secret });
}
`;

const PASS_COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';

export async function POST(request) {
  // legacy path: const cents = Math.round(total * 100);
  const note = "we used to compute total * 100 right here";
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: 'JPY', unit_amount: 4200 }, quantity: 1 }],
  });
  return Response.json({ id: session.id, note });
}
`;

const PASS_IGNORE_TAG = `
import Stripe from 'stripe';
// pagokit-ignore: minor-units -- upstream ERP already sends JPY in minor units
export async function POST(request) {
  const total = 4200;
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: 'JPY', unit_amount: Math.round(total * 100) }, quantity: 1 }],
  });
  return Response.json({ id: session.id });
}
`;

const PASS_UNRELATED_FILE = `
export function barHeight(total, max) {
  const scaled = total * 100;
  return Math.min(scaled / max, 100);
}
`;

const WARN_SDK_NO_CURRENCY_LITERAL = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(request) {
  const { total, currency } = await request.json();
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency,
  });
  return Response.json({ secret: intent.client_secret });
}
`;

const PASS_ZERO_DECIMAL_ALLOWLIST = `
import Stripe from 'stripe';

const NO_CENTS = ['JPY', 'KRW', 'CLP'];

export function toCharge(total, currency) {
  if (NO_CENTS.includes(currency)) return total;
  return Math.round(total * 100);
}
`;


/* ------------------------------------------------------------------ *
 * Adversarial round 2 — snippets that broke the first cut of the rule.
 * ------------------------------------------------------------------ */

// The charge pins usd on the line below the maths; the JPY belongs to a display formatter.
const PASS_NEAREST_LITERAL_IS_USD = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const YEN = new Intl.NumberFormat('ja-JP', { style: 'currency', currency: 'JPY' });

export async function POST(request) {
  const total = 49.99;
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency: 'usd',
  });
  return Response.json({ secret: intent.client_secret, yenHint: YEN.format(7500) });
}
`;

// `paidCarts / totalCarts * 100` is a conversion rate: the amount-named chain is the divisor.
const PASS_PERCENTAGE_OF_A_TOTAL = `
import { db } from '@/lib/db';

export async function GET() {
  const paidCarts = await db.cart.count({ where: { paid: true, currency: 'JPY' } });
  const totalCarts = await db.cart.count({ where: { currency: 'JPY' } });
  const conversion = Math.round(paidCarts / totalCarts * 100);
  return Response.json({ conversion });
}
`;

// Metres to centimetres inside a checkout shipping module.
const PASS_UNIT_OF_MEASURE = `
import Stripe from 'stripe';

const JP_FLAT_RATE = { currency: 'JPY', unit_amount: 800 };

export function girthCm(box) {
  const totalMeters = box.length + 2 * (box.width + box.height);
  return totalMeters * 100;
}
`;

// Rendering a usd receipt from Stripe's minor units, with JPY only in a locale map.
const PASS_DIVIDE_WITH_USD_NEARER = `
import Stripe from 'stripe';

const LOCALE = { ja: 'JPY' };

export function receiptLine(charge) {
  const total = charge.amount_captured;
  return { display: total / 100, currency: 'usd' };
}
`;

// The x100 is money because of where it lands, not because of what it is called.
const DENY_MONEY_BY_POSITION = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(request) {
  const cost = 4200;
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(cost * 100),
    currency: 'JPY',
  });
  return Response.json({ secret: intent.client_secret });
}
`;

// Python and PHP write the float form of the same mistake.
const DENY_FLOAT_HUNDRED = `
import stripe

def create_charge(importe):
    monto_menor = int(importe * 100.0)
    return stripe.PaymentIntent.create(amount=monto_menor, currency="KWD")
`;

// A locale map naming two zero-decimal codes must not switch the rule off for the charge.
const DENY_TABLE_LINE_ELSEWHERE = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const ASIA_LOCALES = { 'JPY': 'ja-JP', 'KRW': 'ko-KR' };

export async function POST(request) {
  const total = 4200;
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency: 'JPY',
  });
  return Response.json({ secret: intent.client_secret, locales: ASIA_LOCALES });
}
`;

// `decimalPlaces` for a chart axis is not exponent reasoning.
const DENY_LOOSE_EXPONENT_WORD = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const backoff = (n) => Math.min(2 ** n, 30);
const decimalPlaces = 2;

export async function POST(request) {
  const total = 4200;
  const intent = await stripe.paymentIntents.create({
    amount: Math.round(total * 100),
    currency: 'JPY',
    metadata: { decimalPlaces: String(decimalPlaces) },
  });
  return Response.json({ secret: intent.client_secret });
}
`;

// The scaling happens one variable away from the charge.
const DENY_ONE_HOP_TO_AMOUNT = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(request) {
  const yen = 4200;
  const minor = Math.round(yen * 100);
  const intent = await stripe.paymentIntents.create({ amount: minor, currency: 'JPY' });
  return Response.json({ secret: intent.client_secret });
}
`;

const base = { toolName: 'Write', projectDir: '/tmp/x' };

module.exports = [
  {
    name: 'JPY checkout multiplying the total by 100 -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_JPY_CHECKOUT },
    expected: 'deny',
  },
  {
    name: 'three-decimal KWD charge with int(importe * 100) in Python -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/checkout/service.py', content: DENY_KWD_PYTHON },
    expected: 'deny',
  },
  {
    name: 'zero-decimal CLP amount divided by 100 -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/payments/route.ts', content: DENY_CLP_DIVIDE },
    expected: 'deny',
  },
  {
    name: 'correct code: exponent chosen per currency before scaling -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/amounts.ts', content: PASS_CURRENCY_AWARE_TERNARY },
    expected: 'pass',
  },
  {
    name: 'edge case: percentage / opacity maths in a JPY checkout file -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_PERCENTAGE_MATHS },
    expected: 'pass',
  },
  {
    name: 'two-decimal currency pinned (usd) -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_USD_ONLY },
    expected: 'pass',
  },
  {
    name: 'the x100 exists only in a comment and a string literal -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_COMMENT_AND_STRING_ONLY },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_IGNORE_TAG },
    expected: 'pass',
  },
  {
    name: 'unrelated file (chart geometry, no payments signal) -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/src/ui/chart.ts', content: PASS_UNRELATED_FILE },
    expected: 'pass',
  },
  {
    name: 'payments SDK call with no currency literal visible -> warn',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/orders/route.ts', content: WARN_SDK_NO_CURRENCY_LITERAL },
    expected: 'warn',
  },
  {
    name: 'zero-decimal allowlist table guarding the x100 -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/charge.ts', content: PASS_ZERO_DECIMAL_ALLOWLIST },
    expected: 'pass',
  },
  {
    name: 'edge case: charge pins usd, JPY only in a display formatter -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_NEAREST_LITERAL_IS_USD },
    expected: 'pass',
  },
  {
    name: 'edge case: conversion rate, amount-named chain is the divisor -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/billing/analytics/route.ts', content: PASS_PERCENTAGE_OF_A_TOTAL },
    expected: 'pass',
  },
  {
    name: 'edge case: metres to centimetres in a checkout shipping module -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/shipping/route.ts', content: PASS_UNIT_OF_MEASURE },
    expected: 'pass',
  },
  {
    name: 'edge case: usd receipt divided back from minor units, JPY in a locale map -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/lib/payments/receipt.ts', content: PASS_DIVIDE_WITH_USD_NEARER },
    expected: 'pass',
  },
  {
    name: 'bypass: x100 named `cost` but landing in the amount key -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_MONEY_BY_POSITION },
    expected: 'deny',
  },
  {
    name: 'bypass: float literal `* 100.0` -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/checkout/service.py', content: DENY_FLOAT_HUNDRED },
    expected: 'deny',
  },
  {
    name: 'bypass: a two-code locale map elsewhere in the file -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_TABLE_LINE_ELSEWHERE },
    expected: 'deny',
  },
  {
    name: 'bypass: the word decimalPlaces used for a chart axis -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_LOOSE_EXPONENT_WORD },
    expected: 'deny',
  },
  {
    name: 'bypass: scaling one variable away from the charge -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_ONE_HOP_TO_AMOUNT },
    expected: 'deny',
  },
];
