// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../webhook-secret-not-api-key');

const STRIPE_VERIFY_WITH_API_KEY = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_SECRET_KEY);
  return Response.json({ id: event.id });
}
`;

const STRIPE_VERIFY_WITH_WEBHOOK_SECRET = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);
  return Response.json({ id: event.id });
}
`;

// The api key IS in the file, one line above the call — but it is not an argument of the
// verification call, and the secret arrives through a config object. Must not fire.
const SECRET_FROM_CONFIG_OBJECT = `
import Stripe from 'stripe';
import { config } from '@/lib/config';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(raw, sig, config.stripeWebhookSecret);
  return Response.json({ received: true, id: event.id });
}
`;

const COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';

// Wrong, and the reason this rule exists:
// const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_SECRET_KEY);
const DOC = 'never call constructEvent(raw, sig, process.env.STRIPE_SECRET_KEY)';

export async function POST(req) {
  return new Response(DOC, { status: 200 });
}
`;

const BYPASS_TAGGED = `
import Stripe from 'stripe';
// pagokit-ignore: webhook-secret-not-api-key -- restricted key, signing secret injected by the gateway

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(raw, sig, process.env.STRIPE_SECRET_KEY);
  return Response.json({ id: event.id });
}
`;

const UNRELATED_FORMATTER = `
export function formatAmount(cents, currency) {
  return new Intl.NumberFormat('es-CO', { style: 'currency', currency }).format(cents / 100);
}
`;

const MERCADOPAGO_VERIFY_WITH_ACCESS_TOKEN = `
import crypto from 'node:crypto';
import { MercadoPagoConfig } from 'mercadopago';

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('x-signature');
  const manifest = 'id:' + dataId + ';request-id:' + requestId + ';ts:' + ts + ';';
  const digest = crypto.createHmac('sha256', process.env.MP_ACCESS_TOKEN).update(manifest).digest('hex');
  if (digest !== sig) return new Response('bad', { status: 401 });
  return new Response(null, { status: 200 });
}
`;

const UNRESOLVABLE_PROVIDER = `
import crypto from 'node:crypto';

export async function POST(req) {
  const raw = await req.text();
  const digest = crypto.createHmac('sha256', process.env.INTERNAL_API_KEY).update(raw).digest('hex');
  if (digest !== req.headers.get('x-signature')) return new Response('bad', { status: 400 });
  return new Response(null, { status: 200 });
}
`;

const MULTILINE_CALL_WITH_API_KEY = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(
    raw,
    req.headers.get('stripe-signature'),
    process.env.STRIPE_SECRET_KEY
  );
  return Response.json({ id: event.id });
}
`;

const PYTHON_VERIFY_WITH_API_KEY = `
import os
import stripe

def webhook(request):
    payload = request.body
    sig_header = request.headers["stripe-signature"]
    event = stripe.Webhook.construct_event(payload, sig_header, os.environ["STRIPE_SECRET_KEY"])
    return {"ok": True, "id": event.id}
`;

// The Wompi integrity secret is a signing_salt, not an api_key: signing with it is correct.
const WOMPI_INTEGRITY_SIGNATURE = `
import crypto from 'node:crypto';

export function integritySignature(reference, amountInCents, currency) {
  const payload = reference + amountInCents + currency;
  return crypto
    .createHmac('sha256', process.env.WOMPI_INTEGRITY_SECRET)
    .update(payload)
    .digest('hex');
}
`;

const WOMPI_VERIFY_WITH_PRIVATE_KEY = `
import crypto from 'node:crypto';

export async function POST(req) {
  const body = await req.json();
  const { checksum, properties } = body.signature;
  const concat = properties.map((p) => read(body.data, p)).join('') + body.timestamp;
  const computed = crypto.createHmac('sha256', process.env.WOMPI_PRIVATE_KEY).update(concat).digest('hex');
  if (computed !== checksum) return new Response('bad', { status: 401 });
  return new Response(null, { status: 200 });
}
`;

// --- Adversarial-audit fixtures -------------------------------------------------------

// The signing secret comes from a vault, and the SDK client — legitimately built from the
// api key — is handed to the verifier in the same options object.
const SECRET_FROM_VAULT_CLIENT_IN_ARGS = `
import Stripe from 'stripe';
import { vault } from '@/lib/vault';

export async function POST(req) {
  const rawBody = await req.text();
  const event = await verifyWebhook({
    body: rawBody,
    signature: req.headers.get('stripe-signature'),
    client: new Stripe(process.env.STRIPE_SECRET_KEY),
    secret: await vault.get('stripe/webhook'),
  });
  return Response.json({ received: true, type: event.type });
}
`;

const API_KEY_ALIASED_BUT_ONLY_FOR_API_CALLS = `
import crypto from 'node:crypto';

const apiKey = process.env.LEMONSQUEEZY_API_KEY;
const signingSecret = await vault.get('ls/webhook');

export async function POST(req) {
  const raw = await req.text();
  const digest = crypto.createHmac('sha256', signingSecret).update(raw).digest('hex');
  await fetch('https://api.lemonsqueezy.com/v1/orders', {
    headers: { Authorization: 'Bearer ' + apiKey },
  });
  return Response.json({ ok: digest === req.headers.get('x-signature') });
}
`;

const DESTRUCTURED_BOTH_CREDENTIALS = `
import Stripe from 'stripe';

const { STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET } = process.env;
const stripe = new Stripe(STRIPE_SECRET_KEY);

export async function POST(req) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(
    raw,
    req.headers.get('stripe-signature'),
    STRIPE_WEBHOOK_SECRET
  );
  return Response.json({ type: event.type });
}
`;

const PYTHON_DECOUPLE_CONFIG = `
import stripe
from decouple import config

stripe.api_key = config('STRIPE_SECRET_KEY')

def webhook(request):
    secret = config('STRIPE_WEBHOOK_SECRET')
    event = stripe.Webhook.construct_event(request.body, request.headers["stripe-signature"], secret)
    return 200
`;

// Most codebases lift env vars into a const, so the credential's own name never appears at
// the call site.
const API_KEY_ALIASED_INTO_THE_VERIFIER = `
import Stripe from 'stripe';

const apiKey = process.env.STRIPE_SECRET_KEY;
const stripe = new Stripe(apiKey);

export async function POST(req) {
  const raw = await req.text();
  const sig = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(raw, sig, apiKey);
  return Response.json({ type: event.type });
}
`;

// Naming the signing secret in an error message is not wiring it up.
const SECRET_NAMED_ONLY_IN_AN_ERROR_STRING = `
import crypto from 'node:crypto';

export async function POST(req) {
  const raw = await req.text();
  if (!process.env.LEMONSQUEEZY_API_KEY) throw new Error('LEMONSQUEEZY_WEBHOOK_SECRET is required');
  const digest = crypto.createHmac('sha256', process.env.LEMONSQUEEZY_API_KEY).update(raw).digest('hex');
  return Response.json({ ok: digest === req.headers.get('x-signature') });
}
`;

const API_KEY_DEEP_IN_THE_ARGUMENT_LIST = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const raw = await req.text();
  const event = stripe.webhooks.constructEvent(
    raw,
    req.headers.get('stripe-signature'),
    // TODO: move this to the endpoint secret
    process.env.STRIPE_SECRET_KEY
  );
  return Response.json({ type: event.type });
}
`;

const MP_ACCESS_TOKEN_AS_SIGNING_SECRET = `
import crypto from 'node:crypto';

export async function POST(req) {
  const raw = await req.text();
  const expected = crypto.createHmac('sha256', process.env.MP_ACCESS_TOKEN).update(raw).digest('hex');
  return Response.json({ ok: expected === req.headers.get('x-signature') });
}
`;

const RUBY_ENV_BRACKET_API_KEY = `
require 'stripe'

def webhook(payload, sig_header)
  event = Stripe::Webhook.construct_event(payload, sig_header, ENV['STRIPE_SECRET_KEY'])
  200
end
`;

module.exports = [
  {
    name: 'constructEvent called with STRIPE_SECRET_KEY denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: STRIPE_VERIFY_WITH_API_KEY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'constructEvent called with STRIPE_WEBHOOK_SECRET passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: STRIPE_VERIFY_WITH_WEBHOOK_SECRET,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'api key one line above the call, secret from a config object, passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: SECRET_FROM_CONFIG_OBJECT,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'the wrong call only in a comment and a string passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: COMMENT_AND_STRING_ONLY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: BYPASS_TAGGED,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'unrelated currency formatter passes',
    check,
    ctx: {
      filePath: 'src/lib/format-amount.ts',
      content: UNRELATED_FORMATTER,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'createHmac seeded with MP_ACCESS_TOKEN denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/mercadopago/route.ts',
      content: MERCADOPAGO_VERIFY_WITH_ACCESS_TOKEN,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'unresolvable provider passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/route.ts',
      content: UNRESOLVABLE_PROVIDER,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'multi-line constructEvent with the api key as third argument denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: MULTILINE_CALL_WITH_API_KEY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'python construct_event with os.environ["STRIPE_SECRET_KEY"] denies',
    check,
    ctx: {
      filePath: 'app/webhooks/stripe_webhook.py',
      content: PYTHON_VERIFY_WITH_API_KEY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'wompi integrity signing_salt is not an api key, passes',
    check,
    ctx: {
      filePath: 'src/payments/wompi-signature.ts',
      content: WOMPI_INTEGRITY_SIGNATURE,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'wompi checksum computed with WOMPI_PRIVATE_KEY denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/wompi/route.ts',
      content: WOMPI_VERIFY_WITH_PRIVATE_KEY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'vault-held secret with the SDK client in the same argument list passes',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SECRET_FROM_VAULT_CLIENT_IN_ARGS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'an aliased api key used only for API calls passes',
    check,
    ctx: { filePath: 'app/api/webhook/lemonsqueezy/route.ts', content: API_KEY_ALIASED_BUT_ONLY_FOR_API_CALLS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'both credentials destructured from process.env passes',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DESTRUCTURED_BOTH_CREDENTIALS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'python-decouple config() for both credentials passes',
    check,
    ctx: { filePath: 'app/webhooks/stripe_webhook.py', content: PYTHON_DECOUPLE_CONFIG, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'the api key aliased to a const and passed to constructEvent denies',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: API_KEY_ALIASED_INTO_THE_VERIFIER, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'naming the signing secret only in an error string does not disarm the check',
    check,
    ctx: { filePath: 'app/api/webhook/lemonsqueezy/route.ts', content: SECRET_NAMED_ONLY_IN_AN_ERROR_STRING, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'the api key on the fourth line of the argument list denies',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: API_KEY_DEEP_IN_THE_ARGUMENT_LIST, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'MP_ACCESS_TOKEN used as the mercadopago signing secret denies',
    check,
    ctx: { filePath: 'app/api/webhook/mercadopago/route.ts', content: MP_ACCESS_TOKEN_AS_SIGNING_SECRET, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: "ruby ENV['STRIPE_SECRET_KEY'] passed to construct_event denies",
    check,
    ctx: { filePath: 'app/webhooks/stripe_webhook.rb', content: RUBY_ENV_BRACKET_API_KEY, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
];
