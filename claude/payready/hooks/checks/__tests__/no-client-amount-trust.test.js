// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const mod = require('../no-client-amount-trust');
// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both: `run` comes through the prototype,
// and string interpolation yields the rule id.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

const DENY_NEXT_ROUTE = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { amount, currency } = await request.json();
  const intent = await stripe.paymentIntents.create({ amount, currency });
  return Response.json({ secret: intent.client_secret });
}
`;

const DENY_EXPRESS_CONTROLLER = `
const { mpPayment } = require('mercadopago');

router.post('/pay', async (req, res) => {
  const price = req.body.price;
  const payment = await mpPayment.create({
    body: { transaction_amount: price, description: 'order', payer: { email: req.body.email } },
  });
  res.json(payment);
});
`;

const DENY_FETCH_PAYLOAD = `
export async function POST(request) {
  const body = await request.json();
  const res = await fetch('https://production.wompi.co/v1/transactions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.WOMPI_PRIVATE_KEY },
    body: JSON.stringify({
      amount_in_cents: body.amount,
      currency: 'COP',
      reference: body.reference,
    }),
  });
  return Response.json(await res.json());
}
`;

const DENY_PYTHON_FASTAPI = `
import stripe

@app.post("/api/checkout")
async def checkout(request: Request):
    data = await request.json()
    monto = data["amount"]
    intent = stripe.PaymentIntent.create(amount=int(monto), currency="usd")
    return {"client_secret": intent.client_secret}
`;

const DENY_REFUND_WITHOUT_LOOKUP = `
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

router.post('/refund', async (req, res) => {
  const { chargeId, amount } = req.body;
  const refund = await stripe.refunds.create({ payment_intent: chargeId, amount });
  res.json(refund);
});
`;

const PASS_SERVER_SIDE_LOOKUP = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { productId, quantity } = await request.json();
  const product = await db.product.findUnique({ where: { id: productId } });
  const intent = await stripe.paymentIntents.create({
    amount: product.priceCents * quantity,
    currency: 'usd',
  });
  return Response.json({ secret: intent.client_secret });
}
`;

const PASS_REFUND_WITH_LOOKUP = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { paymentIntentId, amount } = await request.json();
  const original = await stripe.paymentIntents.retrieve(paymentIntentId);
  if (amount > original.amount) {
    return Response.json({ error: 'refund exceeds capture' }, { status: 400 });
  }
  const refund = await stripe.refunds.create({ payment_intent: paymentIntentId, amount });
  return Response.json(refund);
}
`;

const PASS_CLIENT_VALUE_ONLY_CROSSCHECKED = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { cartId, amount } = await request.json();
  const cart = await db.cart.findUnique({ where: { id: cartId } });
  if (amount !== cart.totalCents) {
    return Response.json({ error: 'price changed' }, { status: 409 });
  }
  const intent = await stripe.paymentIntents.create({
    amount: cart.totalCents,
    currency: 'usd',
  });
  return Response.json({ secret: intent.client_secret });
}
`;

const PASS_COMMENT_AND_STRING_ONLY = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  // const { amount } = await request.json();
  const legacy = "const amount = req.body.amount";
  const order = await db.order.findFirst({ where: { userId: session.userId } });
  const intent = await stripe.paymentIntents.create({ amount: order.totalCents, currency: 'usd' });
  return Response.json({ secret: intent.client_secret, legacy });
}
`;

const PASS_IGNORE_TAG = `
import { stripe } from '@/lib/payments/stripe';
// pagokit-ignore: no-client-amount-trust -- donation endpoint, the donor picks the amount
export async function POST(request) {
  const { amount, currency } = await request.json();
  const intent = await stripe.paymentIntents.create({ amount, currency });
  return Response.json({ secret: intent.client_secret });
}
`;

const PASS_CLIENT_COMPONENT = `
'use client';

export function CheckoutButton({ amount }) {
  async function pay() {
    const res = await fetch('/api/checkout', {
      method: 'POST',
      body: JSON.stringify({ amount, currency: 'usd' }),
    });
    const { secret } = await res.json();
    return secret;
  }
  return <button onClick={pay}>Pay</button>;
}
`;

const PASS_UNRELATED_API = `
export async function POST(request) {
  const body = await request.json();
  await db.events.insert({ name: body.event, value: body.amount, at: new Date() });
  return Response.json({ ok: true });
}
`;


/* ------------------------------------------------------------------ *
 * Adversarial round 2 — snippets that broke the first cut of the rule.
 * ------------------------------------------------------------------ */

// The claimed amount rides an analytics beacon; the charge uses the cart of record.
const PASS_ANALYTICS_BEACON = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const body = await request.json();
  await fetch('https://api.segment.io/v1/track', {
    method: 'POST',
    body: JSON.stringify({
      event: 'checkout_started',
      properties: { amount: body.amount, currency: body.currency },
    }),
  });
  const cart = await db.cart.findUnique({ where: { id: body.cartId } });
  const intent = await stripe.paymentIntents.create({ amount: cart.totalCents, currency: 'usd' });
  return Response.json({ secret: intent.client_secret });
}
`;

// Logging what the browser claimed is not charging it.
const PASS_LOGGED_NOT_CHARGED = `
import { stripe } from '@/lib/payments/stripe';
import { logger } from '@/lib/logger';

export async function POST(request) {
  const { amount, cartId } = await request.json();
  logger.info('checkout requested', { cartId, amount: amount });
  const cart = await db.cart.findUnique({ where: { id: cartId } });
  const intent = await stripe.paymentIntents.create({ amount: cart.totalCents, currency: 'usd' });
  return Response.json({ secret: intent.client_secret });
}
`;

// A signature-verified event is provider-signed data, not browser input.
const PASS_VERIFIED_EVENT_AMOUNT = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const raw = await request.text();
  const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature'), process.env.WHSEC);
  const amount = event.data.object.amount;
  const intent = await stripe.paymentIntents.create({ amount, currency: 'usd' });
  return Response.json({ id: intent.id });
}
`;

// Arithmetic does not launder the value.
const DENY_NUMERIC_HOP = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { amount, currency } = await request.json();
  const cents = Math.round(amount * 100);
  const intent = await stripe.paymentIntents.create({ amount: cents, currency });
  return Response.json({ secret: intent.client_secret });
}
`;

// Spreading the body forwards the amount without ever naming it.
const DENY_BODY_SPREAD = `
import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const body = await request.json();
  const intent = await stripe.paymentIntents.create({ ...body, currency: 'usd' });
  return Response.json({ secret: intent.client_secret });
}
`;

// A verifier call on an unrelated value must not exempt the whole file.
const DENY_UNRELATED_VERIFIER_CALL = `
import { stripe } from '@/lib/payments/stripe';

function decodeSession(raw) {
  return constructEvent(raw);
}

export async function POST(request) {
  const { amount, currency } = await request.json();
  const intent = await stripe.paymentIntents.create({ amount, currency });
  return Response.json({ secret: intent.client_secret });
}
`;

// A lookup standing between the body and the payload is not a DB write.
const DENY_LOOKUP_BEFORE_PAYLOAD = `
export async function POST(request) {
  const body = await request.json();
  const order = await db.order.findUnique({ where: { id: body.orderId } });
  const payload = {
    reference: order.reference,
    amount_in_cents: body.amount,
    currency: 'COP',
  };
  const res = await fetch('https://production.wompi.co/v1/transactions', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return Response.json(await res.json());
}
`;

// A provider SDK named only by a commented-out import is not a payments file.
const PASS_COMMENTED_OUT_SDK_IMPORT = `
// import { stripe } from '@/lib/payments/stripe';

export async function POST(request) {
  const { amount, sku } = await request.json();
  const quote = { sku, amount: amount, status: 'draft' };
  return quote;
}
`;

const base = { toolName: 'Write', projectDir: '/tmp/x' };

module.exports = [
  {
    name: 'Next route charges the amount destructured from request.json() -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_NEXT_ROUTE },
    expected: 'deny',
  },
  {
    name: 'Express controller passes req.body.price into mpPayment.create -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/src/controllers/payments.js', content: DENY_EXPRESS_CONTROLLER },
    expected: 'deny',
  },
  {
    name: 'body.amount forwarded as amount_in_cents in a raw fetch payload -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/wompi/route.ts', content: DENY_FETCH_PAYLOAD },
    expected: 'deny',
  },
  {
    name: 'FastAPI handler charges data["amount"] as a kwarg -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout.py', content: DENY_PYTHON_FASTAPI },
    expected: 'deny',
  },
  {
    name: 'refund endpoint that never loads the original payment -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/src/routes/payments.js', content: DENY_REFUND_WITHOUT_LOOKUP },
    expected: 'deny',
  },
  {
    name: 'correct code: only productId/quantity from the body, price from the DB -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_SERVER_SIDE_LOOKUP },
    expected: 'pass',
  },
  {
    name: 'partial refund that retrieves the original payment first -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/refunds/route.ts', content: PASS_REFUND_WITH_LOOKUP },
    expected: 'pass',
  },
  {
    name: 'edge case: client amount only cross-checked, DB total charged -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_CLIENT_VALUE_ONLY_CROSSCHECKED },
    expected: 'pass',
  },
  {
    name: 'the body read exists only in a comment and a string literal -> pass',
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
    name: 'client component posting an amount to its own API -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/components/CheckoutButton.tsx', content: PASS_CLIENT_COMPONENT },
    expected: 'pass',
  },
  {
    name: 'unrelated analytics endpoint storing body.amount in a DB row -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/analytics/route.ts', content: PASS_UNRELATED_API },
    expected: 'pass',
  },
  {
    name: 'edge case: claimed amount only sent to an analytics beacon -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_ANALYTICS_BEACON },
    expected: 'pass',
  },
  {
    name: 'edge case: claimed amount only logged, DB total charged -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: PASS_LOGGED_NOT_CHARGED },
    expected: 'pass',
  },
  {
    name: 'edge case: amount taken off a signature-verified event -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/payments/reconcile/route.ts', content: PASS_VERIFIED_EVENT_AMOUNT },
    expected: 'pass',
  },
  {
    name: 'bypass: client amount rounded into cents before the charge -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_NUMERIC_HOP },
    expected: 'deny',
  },
  {
    name: 'bypass: whole request body spread into the charge -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_BODY_SPREAD },
    expected: 'deny',
  },
  {
    name: 'bypass: an unrelated constructEvent() call in the file -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/route.ts', content: DENY_UNRELATED_VERIFIER_CALL },
    expected: 'deny',
  },
  {
    name: 'bypass: a DB lookup between the body read and the provider payload -> deny',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/checkout/wompi/route.ts', content: DENY_LOOKUP_BEFORE_PAYLOAD },
    expected: 'deny',
  },
  {
    name: 'edge case: payments SDK named only by a commented-out import -> pass',
    check,
    ctx: { ...base, filePath: '/tmp/x/app/api/billing/quotes/route.ts', content: PASS_COMMENTED_OUT_SDK_IMPORT },
    expected: 'pass',
  },
];
