// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../webhook-event-allowlist');

// 1. Unbounded switch: default: fulfils whatever arrives.
const SWITCH_MUTATING_DEFAULT = `
import Stripe from 'stripe';
export async function POST(request) {
  const raw = await request.text();
  const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.data.object.id }, data: { status: 'paid' } });
      break;
    case 'charge.refunded':
      break;
    default:
      await prisma.order.update({ where: { id: event.data.object.id }, data: { status: 'paid' } });
      await grantAccess(event.data.object.customer);
  }
  return new Response(null, { status: 200 });
}
`;

// 2. The correct shape: default only logs and acks.
const SWITCH_LOGGING_DEFAULT = `
import Stripe from 'stripe';
export async function POST(request) {
  const raw = await request.text();
  const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      break;
    case 'charge.refunded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
      break;
    default:
      console.log('unhandled stripe event', event.type);
      break;
  }
  return new Response(null, { status: 200 });
}
`;

// 3. THE false-positive trap: the default records the unknown event in an audit
//    table. That is a write, but it is the recommended pattern, not fulfilment.
const SWITCH_DEFAULT_LOGS_TO_DB = `
import Stripe from 'stripe';
export async function POST(request) {
  const raw = await request.text();
  const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      break;
    default:
      await prisma.webhookLog.create({ data: { type: event.type, payload: raw } });
      await db.unhandledEvents.insert({ id: event.id });
      break;
  }
  return new Response(null, { status: 200 });
}
`;

// 4. Second no-false-positive case: exhaustive switch, no default at all.
const SWITCH_NO_DEFAULT = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      await fulfillOrder(event.data.object);
      break;
    case 'charge.refunded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
      break;
  }
  return new Response(null, { status: 200 });
}
`;

// 5. Dispatch shapes that exist only inside a comment and a string literal.
const COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';
// switch (event.type) { default: await prisma.order.update({}); }
const DOC = 'handlers[event.type](event) is the shape we do NOT use';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await prisma.event.create({ data: { id: event.id } });
  return new Response(null, { status: 200 });
}
`;

// 6. Same violation as fixture 1, with the documented bypass.
const BYPASSED = `
import Stripe from 'stripe';
// pagokit-ignore: webhook-event-allowlist -- default branch is a queue producer, reviewed 2026-05
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      break;
    default:
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      await grantAccess(event.id);
  }
  return new Response(null, { status: 200 });
}
`;

// 7. Not a payments file at all: an analytics fan-out with the same shape.
const UNRELATED_ANALYTICS = `
export function routeAnalytics(event) {
  switch (event.type) {
    case 'page_view':
      break;
    default:
      await db.metrics.insert({ type: event.type });
      await sendEmail(event.owner);
  }
}
`;

// 8. Dynamic index dispatch with no own-property guard.
const DYNAMIC_INDEX_UNGUARDED = `
import Stripe from 'stripe';
const handlers = {
  'payment_intent.succeeded': onPaid,
  'charge.refunded': onRefund,
};
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await handlers[event.type](event);
  return new Response(null, { status: 200 });
}
`;

// 9. Same dispatch, guarded with Object.hasOwn.
const DYNAMIC_INDEX_GUARDED = `
import Stripe from 'stripe';
const handlers = {
  'payment_intent.succeeded': onPaid,
  'charge.refunded': onRefund,
};
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (!Object.hasOwn(handlers, event.type)) {
    return new Response(null, { status: 200 });
  }
  await handlers[event.type](event);
  return new Response(null, { status: 200 });
}
`;

// 10. if/else-if chain with no terminal else. Bounded exactly the way a switch
//     with no default: is — an event type nobody named runs nothing.
const IF_CHAIN_NO_ELSE = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') {
    await fulfillOrder(event.data.object);
  } else if (event.type === 'charge.refunded') {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
  }
  return new Response(null, { status: 200 });
}
`;

// 11. Same chain, closed with a terminal else that logs and acks.
const IF_CHAIN_WITH_ELSE = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') {
    await fulfillOrder(event.data.object);
  } else if (event.type === 'charge.refunded') {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
  } else {
    console.log('ignoring', event.type);
  }
  return new Response(null, { status: 200 });
}
`;

// 12. Unbounded-looking switch, but an explicit allowlist gates it first.
const EXPLICIT_ALLOWLIST = `
import Stripe from 'stripe';
const HANDLED_EVENTS = ['payment_intent.succeeded', 'charge.refunded'];
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (!HANDLED_EVENTS.includes(event.type)) {
    return new Response(null, { status: 200 });
  }
  switch (event.type) {
    case 'payment_intent.succeeded':
      await fulfillOrder(event.data.object);
      break;
    default:
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  }
  return new Response(null, { status: 200 });
}
`;

// 13. Lemon Squeezy: type lives at /meta/event_name, per the catalog pointer.
const LEMON_META_EVENT_NAME = `
import { lemonSqueezySetup } from '@lemonsqueezy/lemonsqueezy.js';
export async function POST(request) {
  const raw = await request.text();
  verifyLemonSignature(raw, request.headers.get('X-Signature'), process.env.LEMONSQUEEZY_WEBHOOK_SECRET);
  const event = JSON.parse(raw);
  switch (event.meta.event_name) {
    case 'order_created':
      await prisma.order.create({ data: { id: event.data.id } });
      break;
    default:
      await grantAccess(event.data.id);
  }
  return new Response(null, { status: 200 });
}
`;

// --- Added by adversarial audit -------------------------------------------------------

// 14. Two independent, individually bounded `if`s. Not a chain, nothing catch-all.
const TWO_INDEPENDENT_IFS = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  }
  if (event.type === 'charge.refunded') {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
  }
  return new Response(null, { status: 200 });
}
`;

// 15. The default persists the delivery to a webhook_events table. Same recording
//     pattern as fixture 3, only the table is not called *Log.
const DEFAULT_PERSISTS_DELIVERY = `
import Stripe from 'stripe';
export async function POST(request) {
  const raw = await request.text();
  const event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      break;
    default:
      await prisma.webhookEvent.create({ data: { id: event.id, type: event.type, payload: raw } });
      break;
  }
  return new Response(null, { status: 200 });
}
`;

// 16. A hard allowlist gate written in camelCase, dispatching on a local alias.
const CAMELCASE_ALLOWLIST_GATE = `
import Stripe from 'stripe';
const handledEvents = new Set(['payment_intent.succeeded', 'charge.refunded']);
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  const eventType = event.type;
  if (!handledEvents.has(eventType)) {
    return new Response(null, { status: 200 });
  }
  switch (eventType) {
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      break;
    default:
      await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
  }
  return new Response(null, { status: 200 });
}
`;

// 17. `default:` written above the cases. Its body ends at the next case label.
const DEFAULT_LISTED_FIRST = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    default:
      console.log('unhandled', event.type);
      break;
    case 'payment_intent.succeeded':
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      break;
  }
  return new Response(null, { status: 200 });
}
`;

// 18. The unbounded if-chain shape: a terminal `else` that fulfils everything.
const TERMINAL_ELSE_FULFILS = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') {
    await fulfillOrder(event.data.object);
  } else if (event.type === 'charge.refunded') {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'refunded' } });
  } else {
    await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
    await grantAccess(event.data.object.customer);
  }
  return new Response(null, { status: 200 });
}
`;

// 19. An ALLOWED_* list about something else entirely must not stand in for an
//     event-type allowlist.
const UNRELATED_ALLOWLIST = `
import Stripe from 'stripe';
const ALLOWED_CURRENCIES = ['usd', 'cop', 'mxn'];
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  if (!ALLOWED_CURRENCIES.includes(event.data.object.currency)) throw new Error('bad currency');
  switch (event.type) {
    case 'payment_intent.succeeded':
      break;
    default:
      await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      await grantAccess(event.data.object.customer);
  }
  return new Response(null, { status: 200 });
}
`;

// 20. Fire-and-forget fulfilment in the default. Unawaited still grants access.
const UNAWAITED_DEFAULT_FULFILMENT = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  switch (event.type) {
    case 'payment_intent.succeeded':
      break;
    default:
      prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
      void db.entitlements.insert({ user: event.data.object.customer });
  }
  return new Response(null, { status: 200 });
}
`;

// 21. A hasOwnProperty on an unrelated object guards nothing.
const STRAY_HAS_OWN_PROPERTY = `
import Stripe from 'stripe';
const handlers = { 'payment_intent.succeeded': onPaid };
function isPlain(o) { return Object.prototype.hasOwnProperty.call(o, 'id'); }
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await handlers[event.type](event);
  return new Response(null, { status: 200 });
}
`;

const D = '/tmp/pagokit-fixture-project';

module.exports = [
  {
    name: 'stripe webhook: switch default fulfils unknown events -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SWITCH_MUTATING_DEFAULT, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'stripe webhook: switch default only logs and acks -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SWITCH_LOGGING_DEFAULT, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: default records the unknown event in an audit table -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SWITCH_DEFAULT_LOGS_TO_DB, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: exhaustive switch with no default branch -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SWITCH_NO_DEFAULT, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'dispatch shapes appear only in a comment and a string literal -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: COMMENT_AND_STRING_ONLY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass on the violating handler -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: BYPASSED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'unrelated analytics router with the same shape -> pass',
    check,
    ctx: { filePath: 'src/lib/analytics/router.ts', content: UNRELATED_ANALYTICS, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'handlers[event.type]() with no own-property guard -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DYNAMIC_INDEX_UNGUARDED, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'handlers[event.type]() guarded by Object.hasOwn -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DYNAMIC_INDEX_GUARDED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: if/else-if chain with no terminal else is bounded -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: IF_CHAIN_NO_ELSE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'if/else-if chain closed by a terminal else -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: IF_CHAIN_WITH_ELSE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'explicit allowlist gates the switch -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: EXPLICIT_ALLOWLIST, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'lemonsqueezy meta.event_name dispatch with fulfilling default -> deny',
    check,
    ctx: { filePath: 'app/api/webhooks/lemonsqueezy/route.ts', content: LEMON_META_EVENT_NAME, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'no false positive: two independent bounded ifs, not a chain -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: TWO_INDEPENDENT_IFS, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: default persists the delivery to webhookEvent -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DEFAULT_PERSISTS_DELIVERY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: camelCase allowlist Set gating a local alias -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: CAMELCASE_ALLOWLIST_GATE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: default: written above the cases it precedes -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DEFAULT_LISTED_FIRST, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'terminal else fulfils every unnamed event type -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: TERMINAL_ELSE_FULFILS, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'an ALLOWED_* list about currencies is not an event allowlist -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: UNRELATED_ALLOWLIST, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'unawaited fulfilment in the default branch -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: UNAWAITED_DEFAULT_FULFILMENT, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'hasOwnProperty on an unrelated object does not guard the dispatch -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: STRAY_HAS_OWN_PROPERTY, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
];
