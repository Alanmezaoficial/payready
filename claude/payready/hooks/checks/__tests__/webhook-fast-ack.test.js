// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../webhook-fast-ack');

// 1. Third-party HTTP call blocking the ack.
const BLOCKING_EXTERNAL_FETCH = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  await fetch('https://api.acme-crm.example/v2/contacts', {
    method: 'POST',
    body: JSON.stringify({ id: event.id }),
  });
  return new Response(null, { status: 200 });
}
`;

// 2. The correct pattern: ack fast, queue the slow work.
const ENQUEUED = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await queue.add('sync-crm', { eventId: event.id });
  return new Response(null, { status: 200 });
}
`;

// 3. Edge case that MUST NOT fire: the slow work runs after the response.
const WORK_AFTER_ACK = `
import Stripe from 'stripe';
import transporter from '../mailer';
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  res.status(200).send();
  await transporter.sendMail({ to: event.data.object.email, subject: 'Receipt' });
});
`;

// 4. Slow work named only in a comment and a string literal.
const COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';
// await puppeteer.launch() used to render the invoice here — moved to a worker
const NOTE = 'do not call sgMail.send() before the ack';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  return new Response(null, { status: 200 });
}
`;

// 5. Same violation as fixture 1, bypassed.
const BYPASSED = `
import Stripe from 'stripe';
// pagokit-ignore: webhook-fast-ack -- the CRM call is a 20ms internal proxy, measured
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await fetch('https://api.acme-crm.example/v2/contacts', { method: 'POST' });
  return new Response(null, { status: 200 });
}
`;

// 6. Not a webhook: a plain sync route doing the same slow call.
const UNRELATED_SYNC_ROUTE = `
export async function POST(request) {
  const body = await request.json();
  await fetch('https://api.acme-crm.example/v2/contacts', { method: 'POST', body: JSON.stringify(body) });
  await sendMail({ to: body.email });
  return new Response(null, { status: 200 });
}
`;

// 7. Lemon Squeezy declares no ack_deadline_seconds in the catalog, so there is
//    no deadline to measure against and the rule must stay quiet.
const LEMONSQUEEZY_SLOW = `
import { lemonSqueezySetup } from '@lemonsqueezy/lemonsqueezy.js';
export async function POST(request) {
  const raw = await request.text();
  verifyLemonSignature(raw, request.headers.get('X-Signature'), process.env.LEMONSQUEEZY_WEBHOOK_SECRET);
  await sgMail.send({ to: 'buyer@example.com', subject: 'Receipt' });
  return new Response(null, { status: 200 });
}
`;

// 8. An explicit sleep in front of the ack.
const EXPLICIT_SLEEP = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await new Promise((resolve) => setTimeout(resolve, 5000));
  await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  return new Response(null, { status: 200 });
}
`;

// 9. Re-fetching from the provider's own API is the recommended pattern for a
//    non-authoritative payload — never flag the provider's own host.
const REFETCH_FROM_PROVIDER = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  const fresh = await fetch('https://api.stripe.com/v1/payment_intents/' + event.data.object.id, {
    headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY },
  });
  return new Response(null, { status: 200 });
}
`;

// 10. Email send blocking the ack.
const BLOCKING_EMAIL = `
import Stripe from 'stripe';
import { resend } from '../lib/resend';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await resend.emails.send({ to: event.data.object.receipt_email, subject: 'Your receipt' });
  return new Response(null, { status: 200 });
}
`;

// 11. No literal URL is visible, so externality is unknown — do not guess.
const FETCH_WITHOUT_LITERAL_URL = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await fetch(process.env.INTERNAL_SYNC_URL, { method: 'POST', body: JSON.stringify({ id: event.id }) });
  return new Response(null, { status: 200 });
}
`;

// --- Added by adversarial audit -------------------------------------------------------

// 12. The render is imported at the top but lives in a function a cron calls.
//     An import is not a call on the webhook's request path.
const PUPPETEER_IMPORT_ONLY = `
import puppeteer from 'puppeteer';
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await prisma.order.update({ where: { id: event.id }, data: { status: 'paid' } });
  return new Response(null, { status: 200 });
}
export async function renderReceiptForCron(orderId) {
  const browser = await puppeteer.launch();
  return browser;
}
`;

// 13. The fetch target is an env var; the only literal URL is a docs link in the
//     comment underneath it.
const URL_ONLY_IN_A_COMMENT = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  const res = await fetch(process.env.INTERNAL_LEDGER_URL, { method: 'POST', body: JSON.stringify({ id: event.id }) });
  // Payload shape documented at https://docs.acme-crm.example/v2/contacts#schema
  return new Response(null, { status: 200 });
}
`;

// 14. A single-label host is a container on a private network, not a third party.
const INTERNAL_SERVICE_HOST = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await fetch('http://ledger:8080/v1/entries', { method: 'POST', body: JSON.stringify({ id: event.id }) });
  return new Response(null, { status: 200 });
}
`;

// 15. Same for an RFC1918 address.
const PRIVATE_IP_HOST = `
import Stripe from 'stripe';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  await fetch('http://10.0.3.14:8080/v1/entries', { method: 'POST' });
  return new Response(null, { status: 200 });
}
`;

// 16. The 400 for a missing signature is a rejection, not the ack. Everything
//     after it is still on the request path.
const EARLY_400_THEN_SLOW_WORK = `
import Stripe from 'stripe';
export async function POST(request) {
  const sig = request.headers.get('stripe-signature');
  if (!sig) {
    return new Response('missing signature', { status: 400 });
  }
  const event = stripe.webhooks.constructEvent(await request.text(), sig, process.env.STRIPE_WEBHOOK_SECRET);
  await fetch('https://api.acme-crm.example/v2/contacts', { method: 'POST', body: JSON.stringify({ id: event.id }) });
  await new Promise((resolve) => setTimeout(resolve, 8000));
  return new Response(null, { status: 200 });
}
`;

// 17. The same rejection written as a catch block.
const CATCH_400_THEN_SLOW_WORK = `
import Stripe from 'stripe';
export async function POST(request) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return new Response('invalid', { status: 400 });
  }
  await fetch('https://api.acme-crm.example/v2/contacts', { method: 'POST' });
  return new Response(null, { status: 200 });
}
`;

// 18. An analytics .publish() is not a queue; the slow work is still inline.
const ANALYTICS_PUBLISH_IS_NOT_A_QUEUE = `
import Stripe from 'stripe';
import { analytics } from '../lib/segment';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(await request.text(), request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET);
  analytics.publish('webhook_received');
  await fetch('https://api.acme-crm.example/v2/contacts', { method: 'POST' });
  await new Promise((resolve) => setTimeout(resolve, 9000));
  return new Response(null, { status: 200 });
}
`;

const D = '/tmp/pagokit-fixture-project';

module.exports = [
  {
    name: 'stripe webhook blocks the ack on a third-party HTTP call -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: BLOCKING_EXTERNAL_FETCH, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
  {
    name: 'handler enqueues the work and acks -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: ENQUEUED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: slow work runs after res.status(200).send() -> pass',
    check,
    ctx: { filePath: 'src/routes/stripe-webhook.ts', content: WORK_AFTER_ACK, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'slow work named only in a comment and a string literal -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: COMMENT_AND_STRING_ONLY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass on the blocking handler -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: BYPASSED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'unrelated non-webhook route with the same slow calls -> pass',
    check,
    ctx: { filePath: 'app/api/crm/sync/route.ts', content: UNRELATED_SYNC_ROUTE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'provider declares no ack deadline (lemonsqueezy) -> pass',
    check,
    ctx: { filePath: 'app/api/webhooks/lemonsqueezy/route.ts', content: LEMONSQUEEZY_SLOW, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'explicit setTimeout sleep before the ack -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: EXPLICIT_SLEEP, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
  {
    name: 'no false positive: re-fetch from the provider own API host -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: REFETCH_FROM_PROVIDER, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'email send blocking the ack -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: BLOCKING_EMAIL, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
  {
    name: 'no false positive: fetch with no literal URL, externality unknown -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: FETCH_WITHOUT_LITERAL_URL, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: puppeteer imported, render used by a cron only -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: PUPPETEER_IMPORT_ONLY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: the only literal URL is in a nearby comment -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: URL_ONLY_IN_A_COMMENT, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: single-label internal service host -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: INTERNAL_SERVICE_HOST, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: RFC1918 host -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: PRIVATE_IP_HOST, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'an early 400 is not the ack; the slow work after it still counts -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: EARLY_400_THEN_SLOW_WORK, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
  {
    name: 'a catch-block 400 is not the ack either -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: CATCH_400_THEN_SLOW_WORK, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
  {
    name: 'analytics.publish() is not an enqueue; blocking work remains -> warn',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: ANALYTICS_PUBLISH_IS_NOT_A_QUEUE, toolName: 'Write', projectDir: D },
    expected: 'warn',
  },
];
