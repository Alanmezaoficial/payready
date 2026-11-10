// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../no-plaintext-secret-compare');

const UNSAFE_STRICT_COMPARE = `
import Stripe from 'stripe';

export async function POST(req) {
  const raw = await req.text();
  const signature = req.headers.get('stripe-signature');
  const expectedSignature = computeHmac(raw);
  if (signature !== expectedSignature) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

const CONSTANT_TIME_COMPARE = `
import Stripe from 'stripe';
import crypto from 'node:crypto';

export async function POST(req) {
  const raw = await req.text();
  const signature = Buffer.from(req.headers.get('stripe-signature') || '', 'utf8');
  const expected = Buffer.from(computeHmac(raw), 'utf8');
  if (signature.length !== expected.length) {
    return new Response('bad signature', { status: 400 });
  }
  if (!crypto.timingSafeEqual(signature, expected)) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

// Presence checks, length checks and event-type checks all mention a secret word but
// compare against a literal or a descriptor. None of them is a timing oracle.
const PRESENCE_AND_TYPE_CHECKS = `
import Stripe from 'stripe';

export async function POST(req) {
  const signature = req.headers.get('stripe-signature');
  if (!signature) return new Response('missing', { status: 400 });
  if (signature === undefined || signature === null) return new Response('missing', { status: 400 });
  if (signature.length !== 64) return new Response('bad length', { status: 400 });
  const event = JSON.parse(await req.text());
  if (event.type === 'signature.verified') return new Response(null, { status: 200 });
  if (event.data.verification_status !== expectedStatus) return new Response(null, { status: 202 });
  if (event.data.tokenType === paymentTokenType) return new Response(null, { status: 202 });
  return new Response(null, { status: 200 });
}
`;

const COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';

// Old implementation: if (signature !== expectedSignature) return 401;
const DOC = 'signature === expected is a timing oracle';

export async function POST(req) {
  /* legacy path: if (token == secret) { accept(); } */
  return new Response(null, { status: 200 });
}
`;

const BYPASS_TAGGED = `
import Stripe from 'stripe';
// pagokit-ignore: no-plaintext-secret-compare -- compared inside the HSM boundary, see ADR-114

export async function POST(req) {
  const signature = req.headers.get('stripe-signature');
  if (signature !== expectedSignature) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

const UNRELATED_SESSION_HELPER = `
export function isSameSession(a, b) {
  if (a.sessionToken !== b.sessionToken) return false;
  if (a.csrfToken !== b.csrfToken) return false;
  return true;
}
`;

const PYTHON_UNSAFE = `
import stripe

def webhook(request):
    signature = request.headers["stripe-signature"]
    expected_signature = compute_hmac(request.body)
    if signature != expected_signature:
        return 400
    return 200
`;

const PYTHON_COMPARE_DIGEST = `
import hmac
import stripe

def webhook(request):
    signature = request.headers["stripe-signature"]
    # if signature != expected_signature: reject()   <- the old, unsafe version
    expected = compute_hmac(request.body)
    if not hmac.compare_digest(signature, expected):
        return 400
    return 200
`;

const PHP_HASH_EQUALS = `<?php
$signature = $_SERVER['HTTP_X_EVENT_CHECKSUM'];
$expected = hash_hmac('sha256', $body, getenv('WOMPI_EVENTS_SECRET'));
# if ($signature == $expected) { accept(); }
if (!hash_equals($expected, $signature)) {
    http_response_code(400);
}
`;

const BUFFER_EQUALS = `
import Stripe from 'stripe';

export async function POST(req) {
  const raw = await req.text();
  const sigHeader = req.headers.get('stripe-signature');
  if (Buffer.from(sigHeader).equals(Buffer.from(computeExpected(raw)))) {
    return new Response(null, { status: 200 });
  }
  return new Response('bad signature', { status: 400 });
}
`;

const SHARED_SECRET_VIA_SDK_IMPORT = `
import { MercadoPagoConfig } from 'mercadopago';

export function verifyCallback(req) {
  const token = req.headers.get('x-token');
  if (token === process.env.MP_WEBHOOK_SECRET) return true;
  return false;
}
`;

// --- Adversarial-audit fixtures -------------------------------------------------------
// Naming a secret is not comparing one. Each of these mentions a secret word inside a
// payments file and none of them is a verification, so none may block the write.

const FILTER_OUT_A_SAVED_TOKEN = `
import Stripe from 'stripe';

export function removeMethod(savedTokens, token) {
  const remaining = savedTokens.filter((t) => t !== token);
  return remaining;
}
`;

const DIGEST_CACHE_LOOKUP = `
import Stripe from 'stripe';

export async function POST(req) {
  const raw = await req.text();
  const bodyDigest = sha256(raw);
  const cached = await kv.get(bodyDigest);
  if (cached && cached.digest !== bodyDigest) { await kv.del(bodyDigest); }
  return new Response(null, { status: 200 });
}
`;

const VERIFIED_FLAG_RECONCILE = `
import Stripe from 'stripe';

export async function POST(req) {
  const event = await parse(req);
  const order = await db.order.find(event.data.object.id);
  if (order.verified !== event.data.object.verified) {
    await db.order.update(order.id, { verified: true });
  }
  return new Response(null, { status: 200 });
}
`;

const AMOUNT_RECONCILIATION = `
import Stripe from 'stripe';

export async function POST(req) {
  const event = await parse(req);
  const expectedAmount = order.totalMinor;
  const receivedAmount = event.data.object.amount_received;
  if (expectedAmount !== receivedAmount) return new Response('mismatch', { status: 409 });
  return new Response(null, { status: 200 });
}
`;

const IDEMPOTENCY_KEY_COMPARE = `
import Stripe from 'stripe';

export async function POST(req) {
  const stored = await db.get(req.headers.get('idempotency-key'));
  if (stored && stored.idempotencyKey !== req.headers.get('idempotency-key')) {
    return new Response(null, { status: 409 });
  }
  return new Response(null, { status: 200 });
}
`;

// The header is read inline, so the secret word lives inside the accessor argument rather
// than in an identifier. This is the single most common shape of the real bug.
const INLINE_HEADER_ACCESSOR = `
import Stripe from 'stripe';
import crypto from 'node:crypto';

export async function POST(req) {
  const raw = await req.text();
  const expected = crypto.createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(raw).digest('hex');
  if (req.headers.get('stripe-signature') !== expected) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

const BRACKET_HEADER_ACCESSOR = `
const { createHmac } = require('crypto');

module.exports = async function handler(req, res) {
  const expected = createHmac('sha256', process.env.MP_WEBHOOK_SECRET).update(req.rawBody).digest('hex');
  if (req.headers['x-signature'] !== expected) return res.status(400).end();
  return res.status(200).end();
};
`;

const SPANISH_IDENTIFIERS = `
import crypto from 'node:crypto';

export async function POST(req) {
  const evento = await req.json();
  const firmaEsperada = crypto
    .createHash('sha256')
    .update(cadena + process.env.WOMPI_EVENTS_SECRET)
    .digest('hex');
  const firmaRecibida = evento.signature.checksum;
  if (firmaEsperada !== firmaRecibida) {
    return new Response('firma invalida', { status: 401 });
  }
  return new Response(null, { status: 200 });
}
`;

const HASH_NAMED_OPERANDS = `
import crypto from 'node:crypto';

export async function POST(req) {
  const body = await req.json();
  const computedHash = crypto
    .createHash('sha256')
    .update(body.data.transaction.id + process.env.WOMPI_EVENTS_SECRET)
    .digest('hex');
  const providedHash = body.signature.checksum;
  if (computedHash !== providedHash) return new Response('bad', { status: 401 });
  return new Response(null, { status: 200 });
}
`;

// Prettier breaks a long comparison across lines. The comparison is still a comparison.
const WRAPPED_ACROSS_LINES = `
import Stripe from 'stripe';

export async function POST(req) {
  const signature = req.headers.get('stripe-signature');
  const expectedSignature = computeHmac(await req.text());
  if (
    signature !==
    expectedSignature
  ) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

// Neither compared variable is named after a secret; both inherit one from what they were
// assigned. Spanish-language code names things this way constantly.
const PHP_STRCMP_ON_INHERITED_SECRETS = `<?php
$evento = json_decode(file_get_contents('php://input'), true);
$esperado = hash('sha256', $cadena . getenv('WOMPI_EVENTS_SECRET'));
$recibido = $evento['signature']['checksum'];
if (strcmp($esperado, $recibido) !== 0) {
    http_response_code(401);
}
`;

module.exports = [
  {
    name: 'signature !== expectedSignature in a webhook route denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: UNSAFE_STRICT_COMPARE,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'crypto.timingSafeEqual with a length guard passes',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: CONSTANT_TIME_COMPARE,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'presence, length and event-type checks do not false-positive',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: PRESENCE_AND_TYPE_CHECKS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'comparison only inside comments and string literals passes',
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
    name: 'unrelated session helper comparing tokens passes (not payments-relevant)',
    check,
    ctx: {
      filePath: 'src/lib/session.ts',
      content: UNRELATED_SESSION_HELPER,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'python webhook using != on signatures denies',
    check,
    ctx: {
      filePath: 'app/webhooks/stripe_webhook.py',
      content: PYTHON_UNSAFE,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'python hmac.compare_digest passes, and the # comment above it is ignored',
    check,
    ctx: {
      filePath: 'app/webhooks/stripe_webhook.py',
      content: PYTHON_COMPARE_DIGEST,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'php hash_equals passes, and the # commented == is ignored',
    check,
    ctx: {
      filePath: 'app/Http/Controllers/webhook/wompi.php',
      content: PHP_HASH_EQUALS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'Buffer.from(sig).equals(...) denies',
    check,
    ctx: {
      filePath: 'app/api/webhook/stripe/route.ts',
      content: BUFFER_EQUALS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'token === process.env.MP_WEBHOOK_SECRET denies via SDK-import relevance',
    check,
    ctx: {
      filePath: 'src/payments/verify-callback.ts',
      content: SHARED_SECRET_VIA_SDK_IMPORT,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'filtering a saved token out of a list passes (a lookup, not a verification)',
    check,
    ctx: { filePath: 'src/lib/payments/methods.ts', content: FILTER_OUT_A_SAVED_TOKEN, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'comparing two body digests for an idempotency cache passes',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DIGEST_CACHE_LOOKUP, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'comparing two `verified` booleans passes',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: VERIFIED_FLAG_RECONCILE, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'expected/received amounts pass (role words, no secret)',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: AMOUNT_RECONCILIATION, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'idempotency-key comparison passes',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: IDEMPOTENCY_KEY_COMPARE, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'req.headers.get(\'stripe-signature\') !== expected denies',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: INLINE_HEADER_ACCESSOR, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: "req.headers['x-signature'] !== expected denies",
    check,
    ctx: { filePath: 'app/api/webhook/mercadopago/route.ts', content: BRACKET_HEADER_ACCESSOR, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'firmaEsperada !== firmaRecibida denies (spanish identifiers)',
    check,
    ctx: { filePath: 'app/api/webhook/wompi/route.ts', content: SPANISH_IDENTIFIERS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'computedHash !== providedHash denies',
    check,
    ctx: { filePath: 'app/api/webhook/wompi/route.ts', content: HASH_NAMED_OPERANDS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'a comparison prettier wrapped across two lines still denies',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: WRAPPED_ACROSS_LINES, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'php strcmp on variables that inherit their secret from assignment denies',
    check,
    ctx: { filePath: 'app/Http/Controllers/webhook/wompi.php', content: PHP_STRCMP_ON_INHERITED_SECRETS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
];
