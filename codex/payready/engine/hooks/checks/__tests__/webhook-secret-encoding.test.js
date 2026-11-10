// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../webhook-secret-encoding');

// 1. Stripe sends hex; this verifier emits base64.
const DIGEST_ENCODING_MISMATCH = `
import crypto from 'node:crypto';
export async function POST(request) {
  const raw = await request.text();
  const header = request.headers.get('stripe-signature');
  const [t, v1] = parseHeader(header);
  const expected = crypto
    .createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET)
    .update(t + '.' + raw)
    .digest('base64');
  if (expected !== v1) return new Response('bad signature', { status: 400 });
  return new Response(null, { status: 200 });
}
`;

// 2. The correct hand-rolled Stripe verifier: sha256, raw secret, hex digest.
const CORRECT_STRIPE_VERIFIER = `
import crypto from 'node:crypto';
export async function POST(request) {
  const raw = await request.text();
  const [t, v1] = parseHeader(request.headers.get('stripe-signature'));
  const expected = crypto
    .createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET)
    .update(\`\${t}.\${raw}\`)
    .digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1))) {
    return new Response('bad signature', { status: 400 });
  }
  return new Response(null, { status: 200 });
}
`;

// 3. Lemon Squeezy signs with sha256; this uses sha512.
const HASH_ALGO_MISMATCH = `
import crypto from 'node:crypto';
export async function POST(request) {
  const raw = await request.text();
  const signature = request.headers.get('X-Signature');
  const digest = crypto
    .createHmac('sha512', process.env.LEMONSQUEEZY_WEBHOOK_SECRET)
    .update(raw)
    .digest('hex');
  if (digest !== signature) return new Response('bad signature', { status: 400 });
  return new Response(null, { status: 200 });
}
`;

// 4. Stripe's secret is used raw; this base64-decodes it first.
const SECRET_ENCODING_MISMATCH = `
import crypto from 'node:crypto';
export function verifyStripeSignature(raw, header) {
  const key = Buffer.from(process.env.STRIPE_WEBHOOK_SECRET, 'base64');
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha256', key).update(t + '.' + raw).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(v1, 'hex'));
}
`;

// 5. THE false-positive trap: the file also computes an unrelated md5/base64
//    cache key. The webhook HMAC itself is correct, so nothing may fire.
const UNRELATED_HASH_ALONGSIDE_CORRECT = `
import crypto from 'node:crypto';
export function cacheKey(url) {
  return crypto.createHash('md5').update(url).digest('base64');
}
export function verifyStripeSignature(raw, header) {
  const [t, v1] = parseHeader(header);
  const expected = crypto
    .createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET)
    .update(t + '.' + raw)
    .digest('hex');
  return expected === v1;
}
`;

// 6. The SDK's own verifier does the checking; the local HMAC is for something
//    else entirely. Never second-guess the SDK.
const SDK_VERIFIER_USED = `
import Stripe from 'stripe';
import crypto from 'node:crypto';
export async function POST(request) {
  const event = stripe.webhooks.constructEvent(
    await request.text(),
    request.headers.get('stripe-signature'),
    process.env.STRIPE_WEBHOOK_SECRET
  );
  const dedupeKey = crypto.createHmac('sha512', process.env.INTERNAL_SALT).update(event.id).digest('base64');
  await prisma.webhookEvent.create({ data: { id: event.id, dedupeKey } });
  return new Response(null, { status: 200 });
}
`;

// 7. The wrong encodings appear only in a comment and a string literal.
const COMMENT_AND_STRING_ONLY = `
import crypto from 'node:crypto';
// const bad = crypto.createHmac('sha512', secret).digest('base64');
const DOCS = "never use .digest('base64') here — Stripe sends hex";
export function verifyStripeSignature(raw, header) {
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(t + '.' + raw).digest('hex');
  return expected === v1;
}
`;

// 8. Same violation as fixture 1, bypassed.
const BYPASSED = `
import crypto from 'node:crypto';
// pagokit-ignore: webhook-secret-encoding -- mirroring a legacy proxy that re-encodes the digest
export function verifyStripeSignature(raw, header) {
  const expected = crypto
    .createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET)
    .update(raw)
    .digest('base64');
  return expected === header;
}
`;

// 9. Unrelated file: no provider resolves, so there is nothing to compare against.
const UNRELATED_HMAC_UTIL = `
import crypto from 'node:crypto';
export function signCookie(value) {
  return crypto.createHmac('sha512', process.env.COOKIE_SECRET).update(value).digest('base64');
}
`;

// 10. digest() with no argument, compared as buffers — valid, must not fire.
const DIGEST_BUFFER_COMPARE = `
import crypto from 'node:crypto';
export function verifyWompiChecksum(props, timestamp, checksum) {
  const expected = crypto
    .createHash('sha256')
    .update(props.join('') + timestamp + process.env.WOMPI_EVENTS_SECRET)
    .digest();
  return crypto.timingSafeEqual(expected, Buffer.from(checksum, 'hex'));
}
`;

// 11. Mercado Pago concat template, correct algo and digest.
const CORRECT_MERCADOPAGO_VERIFIER = `
import crypto from 'node:crypto';
export function verifyMpSignature(dataId, requestId, ts, v1) {
  const manifest = \`id:\${dataId};request-id:\${requestId};ts:\${ts};\`;
  const expected = crypto
    .createHmac('sha256', process.env.MP_WEBHOOK_SECRET)
    .update(manifest)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(v1, 'hex'));
}
`;

// --- Added by adversarial audit -------------------------------------------------------

// 12. The verifier uses the recommended digest() + timingSafeEqual, so it names
//     no encoding at all. The only literal in the file belongs to a cache key.
const TIMING_SAFE_DIGEST_PLUS_CACHE_KEY = `
import crypto from 'node:crypto';
export function cacheKey(url) {
  return crypto.createHash('sha256').update(url).digest('base64');
}
export function verifyStripeSignature(raw, header) {
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(t + '.' + raw).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(v1, 'hex'));
}
`;

// 13. The env var stores the secret base64-wrapped; the code unwraps it to the
//     raw string before keying the HMAC. The buffer is never the key.
const BASE64_WRAPPED_ENV_UNWRAPPED = `
import crypto from 'node:crypto';
export function verifyStripeSignature(raw, header) {
  const secret = Buffer.from(process.env.STRIPE_WEBHOOK_SECRET, 'base64').toString('utf8');
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha256', secret).update(t + '.' + raw).digest('hex');
  return expected === v1;
}
`;

// 14. A webhook route that verifies nothing (the edge does) and md5-hashes the
//     body for dedupe. No hashing touches the secret, so there is no mismatch.
const MD5_DEDUPE_IN_A_WEBHOOK_ROUTE = `
import crypto from 'node:crypto';
export async function POST(request) {
  const raw = await request.text();
  const dedupe = crypto.createHash('md5').update(raw).digest('hex');
  await prisma.webhookEvent.create({ data: { dedupe, payload: raw } });
  return new Response(null, { status: 200 });
}
`;

// 15. The verifier itself emits base64. An unrelated hex digest elsewhere in the
//     file must not stand in for it.
const WRONG_VERIFIER_MASKED_BY_HEX_DIGEST = `
import crypto from 'node:crypto';
export function traceId(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}
export function verifyStripeSignature(raw, header) {
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(t + '.' + raw).digest('base64');
  return expected === v1;
}
`;

// 16. Same masking, for the hash algorithm.
const SHA1_VERIFIER_MASKED_BY_SHA256_HASH = `
import crypto from 'node:crypto';
export function traceId(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}
export function verifyStripeSignature(raw, header) {
  const [t, v1] = parseHeader(header);
  const expected = crypto.createHmac('sha1', process.env.STRIPE_WEBHOOK_SECRET).update(t + '.' + raw).digest('hex');
  return expected === v1;
}
`;

// 17. The secret is renamed to something with no "secret" in it before the
//     wrong decode. The rename must not hide the mismatch.
const ALIASED_SECRET_HIDES_BASE64_DECODE = `
import crypto from 'node:crypto';
const eventsKey = process.env.WOMPI_EVENTS_SECRET;
export function verifyWompiChecksum(props, timestamp, checksum) {
  const key = Buffer.from(eventsKey, 'base64');
  const expected = crypto.createHmac('sha256', key).update(props.join('') + timestamp).digest('hex');
  return expected === checksum;
}
`;

const D = '/tmp/pagokit-fixture-project';

module.exports = [
  {
    name: 'stripe sends hex, verifier emits base64 -> deny',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: DIGEST_ENCODING_MISMATCH, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'correct hand-rolled stripe verifier (sha256 / raw secret / hex) -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: CORRECT_STRIPE_VERIFIER, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'lemonsqueezy signs sha256, verifier uses sha512 -> deny',
    check,
    ctx: { filePath: 'app/api/webhooks/lemonsqueezy/route.ts', content: HASH_ALGO_MISMATCH, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'stripe secret is raw, verifier base64-decodes it -> deny',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: SECRET_ENCODING_MISMATCH, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'no false positive: unrelated md5/base64 cache key next to a correct verifier -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: UNRELATED_HASH_ALONGSIDE_CORRECT, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'SDK verifier does the checking, local hmac is unrelated -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: SDK_VERIFIER_USED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'wrong encodings only in a comment and a string literal -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: COMMENT_AND_STRING_ONLY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass on the mismatched digest -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: BYPASSED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'unrelated cookie-signing util, no provider resolves -> pass',
    check,
    ctx: { filePath: 'src/lib/cookies.ts', content: UNRELATED_HMAC_UTIL, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'wompi checksum with digest() buffer compare -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/wompi.ts', content: DIGEST_BUFFER_COMPARE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'correct mercadopago manifest verifier -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/mercadopago.ts', content: CORRECT_MERCADOPAGO_VERIFIER, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: timing-safe digest() next to an unrelated base64 key -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: TIMING_SAFE_DIGEST_PLUS_CACHE_KEY, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: base64-wrapped env unwrapped with .toString() -> pass',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: BASE64_WRAPPED_ENV_UNWRAPPED, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'no false positive: md5 dedupe hash in a webhook route, no secret hashed -> pass',
    check,
    ctx: { filePath: 'app/api/webhook/stripe/route.ts', content: MD5_DEDUPE_IN_A_WEBHOOK_ROUTE, toolName: 'Write', projectDir: D },
    expected: 'pass',
  },
  {
    name: 'the verifier emits base64; an unrelated hex digest does not excuse it -> deny',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: WRONG_VERIFIER_MASKED_BY_HEX_DIGEST, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'the verifier uses sha1; an unrelated sha256 hash does not excuse it -> deny',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-stripe.ts', content: SHA1_VERIFIER_MASKED_BY_SHA256_HASH, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
  {
    name: 'renaming the secret does not hide the wrong buffer encoding -> deny',
    check,
    ctx: { filePath: 'src/lib/webhooks/verify-wompi.ts', content: ALIASED_SECRET_HIDES_BASE64_DECODE, toolName: 'Write', projectDir: D },
    expected: 'deny',
  },
];
