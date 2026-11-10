// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../agentic-token-scope');

/* 1 — Redeemed with no scope enforcement at all. */
const UNSCOPED_REDEEM = `
import { chargeSharedToken } from '@/lib/acp';

export async function POST(req) {
  const { cart, shared_payment_token } = await req.json();
  const charge = await chargeSharedToken(shared_payment_token, cart.total);
  return Response.json({ chargeId: charge.id });
}
`;

/* 2 — Amount and expiry checked, currency silently trusted. */
const PARTIAL_SCOPE_NO_CURRENCY = `
import { chargeSharedToken } from '@/lib/acp';

export async function POST(req) {
  const { cart, sharedPaymentToken } = await req.json();

  if (cart.total > sharedPaymentToken.usage_limits.max_amount) {
    return new Response('over limit', { status: 402 });
  }
  if (Date.now() >= Date.parse(sharedPaymentToken.expires_at)) {
    return new Response('expired', { status: 402 });
  }

  const charge = await chargeSharedToken(sharedPaymentToken, cart.total);
  return Response.json({ chargeId: charge.id });
}
`;

/* 3 — Fully scoped, and the token never leaves the request. */
const FULLY_SCOPED = `
import { chargeSharedToken } from '@/lib/acp';

export async function POST(req) {
  const { cart, sharedPaymentToken } = await req.json();

  if (cart.total > sharedPaymentToken.usage_limits.max_amount) {
    return new Response('over limit', { status: 402 });
  }
  if (Date.now() >= Date.parse(sharedPaymentToken.expires_at)) {
    return new Response('token expired', { status: 402 });
  }
  if (cart.currency !== sharedPaymentToken.currency) {
    return new Response('currency mismatch', { status: 402 });
  }

  const charge = await chargeSharedToken(sharedPaymentToken, cart.total);
  return Response.json({ chargeId: charge.id });
}
`;

/* 4 — Every scope check present, but the token is logged. */
const SCOPED_BUT_LOGGED = `
import { chargeSharedToken } from '@/lib/acp';

export async function POST(req) {
  const { cart, shared_payment_token } = await req.json();
  console.log('redeeming token', shared_payment_token);

  if (cart.total > shared_payment_token.usage_limits.max_amount) {
    return new Response('over limit', { status: 402 });
  }
  if (Date.now() >= Date.parse(shared_payment_token.expires_at)) {
    return new Response('token expired', { status: 402 });
  }
  if (cart.currency !== shared_payment_token.currency) {
    return new Response('currency mismatch', { status: 402 });
  }

  return Response.json(await chargeSharedToken(shared_payment_token, cart.total));
}
`;

/* 5 — The token written to a database row. */
const PERSISTED_TO_DB = `
import { db } from '@/lib/db';
import { agentTokens } from '@/lib/schema';

export async function saveGrant(sharedPaymentGrantedToken, userId) {
  await db.insert(agentTokens).values({
    userId,
    token: sharedPaymentGrantedToken,
  });
}
`;

/* 6 — The token written to browser storage. */
const PERSISTED_TO_STORAGE = `
export function rememberGrant(grant) {
  const agentPaymentToken = grant.value;
  sessionStorage.setItem('agent-grant', agentPaymentToken);
}
`;

/* 7 — x402 V1 header shape: the 2025 default that silently 402-loops. */
const X402_V1_HEADERS = `
export async function payAndFetch(url, signedPayload) {
  const res = await fetch(url, {
    headers: { 'X-PAYMENT': signedPayload },
  });
  if (res.status === 402) {
    const required = res.headers.get('PAYMENT-REQUIRED');
    return retryWithPayment(url, required);
  }
  return res.json();
}
`;

/* 8 — Edge case that MUST NOT fire: the current x402 header shape, requirements in the
       402 body. PAYMENT-SIGNATURE / PAYMENT-RESPONSE are correct and must stay silent. */
const X402_CURRENT_HEADERS = `
export async function payAndFetch(url, signedPayload) {
  const res = await fetch(url, {
    headers: { 'PAYMENT-SIGNATURE': signedPayload },
  });
  if (res.status === 402) {
    const requirements = await res.json();
    return requirements;
  }
  const receipt = res.headers.get('PAYMENT-RESPONSE');
  return { receipt, body: await res.json() };
}
`;

/* 9 — Comment and string-literal mentions only. */
const COMMENT_AND_STRING_ONLY = `
// A shared_payment_token arrives on the ACP request. Never log it, never store it.
// The old x402 clients sent it in an X-PAYMENT header; we do not.
const DOC = 'shared_payment_token must be checked against usage_limits.max_amount';

export function describeProtocol() {
  return DOC;
}
`;

/* 10 — Bypass tag. */
const IGNORE_TAGGED = `
import { chargeSharedToken } from '@/lib/acp';
// pagokit-ignore: agentic-token-scope -- scope is enforced by the ACP gateway in front of this route

export async function POST(req) {
  const { cart, shared_payment_token } = await req.json();
  return Response.json(await chargeSharedToken(shared_payment_token, cart.total));
}
`;

/* 11 — Unrelated file: browser session storage, no payment token anywhere. */
const UNRELATED_SESSION_STORE = `
const SESSION_KEY = 'app.session';

export function persistSession(session) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function readSession() {
  return JSON.parse(localStorage.getItem(SESSION_KEY) ?? 'null');
}
`;

/* 12 — Adversarial FP: the shape this rule PRESCRIBES. The token is redeemed and
       dropped; the ORDER row that follows carries the charge id, never the token. */
const REDEEM_THEN_INSERT_ORDER = `
export async function POST(req) {
  const { cart } = await req.json();
  const t = JSON.parse(atob(req.headers.get('x-agent-token')));
  if (cart.total > t.usage_limits.max_amount) throw new Error('over limit');
  if (Date.now() > t.expires_at) throw new Error('expired');
  if (cart.currency !== t.currency) throw new Error('currency mismatch');
  const charge = await psp.redeem(t.shared_payment_token);
  await db.orders.insertOne({ orderId: cart.id, chargeId: charge.id, total: cart.total });
  return Response.json({ ok: true });
}
`;

/* 13 — Adversarial FP: a type declaration. It names every field of the token and
       enforces none of them, which is exactly what a type is supposed to do. */
const TOKEN_TYPE_DECLARATIONS = `
export interface SharedPaymentToken {
  shared_payment_token: string;
  usage_limits: {
    max_amount: number;
    currency: string;
  };
  expires_at: number;
}

export type AgentCart = {
  id: string;
  total: number;
  currency: string;
};
`;

/* 14 — Adversarial FP: a helper that only enforces the scope and never charges. */
const SCOPE_VALIDATOR_HELPER = `
export function assertTokenScope(token, cart) {
  const t = token.shared_payment_token;
  if (!t) throw new Error('missing token');
  if (cart.total > token.usage_limits.max_amount) throw new Error('over limit');
  if (Date.now() > token.expires_at) throw new Error('expired');
  if (cart.currency !== token.currency) throw new Error('currency mismatch');
  return true;
}
`;

/* 15 — Adversarial bypass: expires_at is destructured, so the name is present, but the
       clock is never consulted. An expired token is charged. */
const EXPIRY_NAMED_NEVER_COMPARED = `
export async function POST(req) {
  const { cart } = await req.json();
  const { shared_payment_token, usage_limits, expires_at, currency } = await readGrant(req);
  if (cart.total > usage_limits.max_amount) throw new Error('over limit');
  if (cart.currency !== currency) throw new Error('currency mismatch');
  return charge(shared_payment_token, cart.total);
}
`;

/* 16 — Adversarial bypass: fully scoped, but the token is cached in Redis "for retries",
       which is a standing authorisation with a 24h TTL. */
const TOKEN_CACHED_IN_REDIS = `
import { redis } from '@/lib/redis';

export async function POST(req) {
  const { shared_payment_token, cart } = await req.json();
  if (cart.total > shared_payment_token.usage_limits.max_amount) throw new Error('over limit');
  if (Date.now() > shared_payment_token.expires_at) throw new Error('expired');
  if (cart.currency !== shared_payment_token.currency) throw new Error('currency mismatch');
  await redis.set('spt:' + cart.id, shared_payment_token.value, 'EX', 86400);
  return charge(shared_payment_token, cart.total);
}
`;

/* 17 — Adversarial bypass: the ORM shape. The token is assigned onto the record and the
       record is saved, so it never appears inside a write call's arguments. */
const TOKEN_ASSIGNED_THEN_SAVED = `
export async function POST(req) {
  const { cart } = await req.json();
  const t = JSON.parse(atob(req.headers.get('x-agent-token')));
  if (cart.total > t.usage_limits.max_amount) throw new Error('over limit');
  if (Date.now() > t.expires_at) throw new Error('expired');
  if (cart.currency !== t.currency) throw new Error('currency mismatch');
  const order = await Order.findById(cart.id);
  order.sharedPaymentToken = t.shared_payment_token;
  await order.save();
  return charge(t, cart.total);
}
`;

/* 18 — Adversarial bypass: the ceiling is compared and then used to CLAMP the amount
       instead of rejecting, so a 400 cart quietly ships for the 40 the token allows. */
const AMOUNT_CLAMPED_NOT_REJECTED = `
export async function POST(req) {
  const { shared_payment_token: t, cart } = await req.json();
  const max = t.usage_limits.max_amount;
  const amount = cart.total > max ? max : cart.total;
  if (Date.now() > t.expires_at) throw new Error('expired');
  if (cart.currency !== t.currency) throw new Error('currency mismatch');
  return charge(t, amount);
}
`;

const ctx = (filePath, content) => ({
  filePath,
  content,
  toolName: 'Write',
  projectDir: '/tmp/pagokit-agentic',
});

module.exports = [
  {
    name: 'shared payment token redeemed with no scope checks → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', UNSCOPED_REDEEM),
    expected: 'deny',
  },
  {
    name: 'amount and expiry checked but currency trusted → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', PARTIAL_SCOPE_NO_CURRENCY),
    expected: 'deny',
  },
  {
    name: 'all three scope checks present → pass',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', FULLY_SCOPED),
    expected: 'pass',
  },
  {
    name: 'fully scoped but the token is console.logged → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', SCOPED_BUT_LOGGED),
    expected: 'deny',
  },
  {
    name: 'token written to a database row → deny',
    check,
    ctx: ctx('lib/agent/grants.ts', PERSISTED_TO_DB),
    expected: 'deny',
  },
  {
    name: 'token written to sessionStorage → deny',
    check,
    ctx: ctx('lib/agent/remember.ts', PERSISTED_TO_STORAGE),
    expected: 'deny',
  },
  {
    name: 'x402 V1 X-PAYMENT / PAYMENT-REQUIRED headers → deny',
    check,
    ctx: ctx('lib/x402/client.ts', X402_V1_HEADERS),
    expected: 'deny',
  },
  {
    name: 'edge: current PAYMENT-SIGNATURE / PAYMENT-RESPONSE shape → pass',
    check,
    ctx: ctx('lib/x402/client.ts', X402_CURRENT_HEADERS),
    expected: 'pass',
  },
  {
    name: 'token and X-PAYMENT mentioned only in comments and a string → pass',
    check,
    ctx: ctx('lib/docs/acp-notes.ts', COMMENT_AND_STRING_ONLY),
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass → pass',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', IGNORE_TAGGED),
    expected: 'pass',
  },
  {
    name: 'unrelated file: session storage with no payment token → pass',
    check,
    ctx: ctx('lib/browser/session.ts', UNRELATED_SESSION_STORE),
    expected: 'pass',
  },
  {
    name: 'adversarial: token redeemed, then the ORDER row inserted with the charge id → pass',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', REDEEM_THEN_INSERT_ORDER),
    expected: 'pass',
  },
  {
    name: 'adversarial: a type declaration for the token, no redemption → pass',
    check,
    ctx: ctx('types/agentic-commerce.ts', TOKEN_TYPE_DECLARATIONS),
    expected: 'pass',
  },
  {
    name: 'adversarial: a scope-validator helper that never charges → pass',
    check,
    ctx: ctx('lib/agentic/verify.ts', SCOPE_VALIDATOR_HELPER),
    expected: 'pass',
  },
  {
    name: 'adversarial: expires_at destructured but never compared to a clock → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', EXPIRY_NAMED_NEVER_COMPARED),
    expected: 'deny',
  },
  {
    name: 'adversarial: fully scoped but the token is cached in Redis for 24h → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', TOKEN_CACHED_IN_REDIS),
    expected: 'deny',
  },
  {
    name: 'adversarial: token assigned onto an ORM record and saved → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', TOKEN_ASSIGNED_THEN_SAVED),
    expected: 'deny',
  },
  {
    name: 'adversarial: the ceiling clamps the amount instead of rejecting → deny',
    check,
    ctx: ctx('app/api/agent/checkout/route.ts', AMOUNT_CLAMPED_NOT_REJECTED),
    expected: 'deny',
  },
];
