// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const mod = require('../no-refund-on-irreversible');

// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

// --- Fixtures -------------------------------------------------------------------------

const PIX_REFUND = `import { stripe } from '@/lib/payments/stripe';

export async function createPixCharge(amountMinor: number) {
  return stripe.paymentIntents.create({
    amount: amountMinor,
    currency: 'brl',
    payment_method_types: ['pix'],
  });
}

export async function cancelOrder(paymentIntentId: string) {
  return stripe.refunds.create({ payment_intent: paymentIntentId });
}
`;

const SPEI_CREATE_REFUND = `const openpay = require('openpay');

async function chargeSpei(order) {
  return openpay.charges.create({ method: 'spei', amount: order.total });
}

async function undo(order) {
  return createRefund({ charge_id: order.chargeId, amount: order.total });
}

module.exports = { chargeSpei, undo };
`;

const PSE_REFUND_ROUTE = `import { wompi } from '@/lib/payments/wompi';

export async function POST(request: Request) {
  const { transactionId, amountInCents } = await request.json();
  const tx = await wompi.transactions.get(transactionId);
  if (tx.payment_method === 'pse') {
    return Response.json(await wompi.transactions.void(transactionId, amountInCents));
  }
  return Response.json({ error: 'unsupported' }, { status: 400 });
}
`;

const CARD_REFUND = `import { stripe } from '@/lib/payments/stripe';

export async function createCardCharge(amountMinor: number) {
  return stripe.paymentIntents.create({
    amount: amountMinor,
    currency: 'mxn',
    payment_method_types: ['card'],
  });
}

export async function refundOrder(paymentIntentId: string) {
  return stripe.refunds.create({ payment_intent: paymentIntentId });
}
`;

const MIXED_METHODS_REFUND = `import { mp } from '@/lib/payments/mercadopago';

export async function createCheckout(order) {
  return mp.preferences.create({
    payment_method_types: ['card', 'pix', 'boleto'],
    items: order.items,
  });
}

export async function refundOrder(paymentId: string) {
  return mp.refunds.create({ payment_id: paymentId });
}
`;

const PIX_PAYOUT_NOT_REFUND = `import { stripe } from '@/lib/payments/stripe';

export async function payMerchant(sellerId: string, amountMinor: number) {
  return stripe.transfers.create({
    amount: amountMinor,
    currency: 'brl',
    destination: sellerId,
    method: 'pix',
  });
}

export async function paySupplier(accountId: string, amountMinor: number) {
  return stripe.payouts.create({ amount: amountMinor, currency: 'brl', destination: accountId });
}
`;

const REFUND_MENTIONED_ONLY_IN_COMMENT = `import { stripe } from '@/lib/payments/stripe';

export async function createPixCharge(amountMinor: number) {
  // TODO: stripe.refunds.create() once Pix supports refunds. It does not, and it will not:
  // returning money on Pix means originating a new transfer with psp.transfers.create().
  return stripe.paymentIntents.create({
    amount: amountMinor,
    currency: 'brl',
    payment_method_types: ['pix'],
  });
}
`;

const IGNORE_TAGGED = `import { stripe } from '@/lib/payments/stripe';
// pagokit-ignore: no-refund-on-irreversible -- our PSP brokers a Pix devolucao behind this API

export async function createPixCharge(amountMinor: number) {
  return stripe.paymentIntents.create({ amount: amountMinor, currency: 'brl', payment_method_types: ['pix'] });
}

export async function cancelOrder(paymentIntentId: string) {
  return stripe.refunds.create({ payment_intent: paymentIntentId });
}
`;

const REFUND_WITH_NO_METHOD_LITERAL = `import { stripe } from '@/lib/payments/stripe';

export async function refundOrder(paymentIntentId: string, amountMinor?: number) {
  return stripe.refunds.create({
    payment_intent: paymentIntentId,
    amount: amountMinor,
  });
}
`;

const UNRELATED_LIBRARY_FILE = `export function releasePool(pool, bytes) {
  // "refund" here means returning capacity to the pool, not money to a customer.
  return pool.refund(bytes);
}

export const DEFAULTS = { method: 'gzip', rails: ['fast', 'slow'] };
`;

const PIX_ROUTED_TO_PAYOUT = `import { psp } from '@/lib/payments/psp';

export async function refundPayment(payment) {
  if (payment.payment_method === 'pix') {
    // Pix has no refund API: return the money as a new outbound transfer.
    return psp.transfers.create({
      amount: payment.amount,
      currency: 'brl',
      destination: payment.payerPixKey,
    });
  }
  return psp.refunds.create({ payment_intent: payment.id });
}
`;

const SPEI_REJECTED_WITH_409 = `import { stripe } from '@/lib/payments/stripe';

export async function POST(req: Request) {
  const { paymentIntentId, method } = await req.json();
  if (method === 'spei') {
    return Response.json(
      { error: 'SPEI no admite reembolso automatico; usa una dispersion manual.' },
      { status: 409 }
    );
  }
  return Response.json(await stripe.refunds.create({ payment_intent: paymentIntentId }));
}
`;

const REFUND_POLICY_TABLE = `export const REFUND_POLICY = [
  { payment_method: 'pix', refundable: false, alternative: 'payout' },
];

export function isRefundable(method: string) {
  return REFUND_POLICY.some((p) => p.payment_method === method && p.refundable);
}
`;

const SWITCH_ON_RAIL = `import { psp } from '@/lib/payments/psp';

export async function refundByRail(payment) {
  switch (payment.rail) {
    case 'pix':
      return psp.refunds.create({ payment_intent: payment.id });
    default:
      return psp.refunds.create({ payment_intent: payment.id });
  }
}
`;

const METHOD_ID_BEHIND_A_CONSTANT = `import { psp } from '@/lib/payments/psp';

const PIX = 'pix';

export async function undoCharge(payment) {
  if (payment.method === PIX) {
    return psp.refunds.create({ payment_intent: payment.id });
  }
}
`;

const RAW_FETCH_TO_REFUNDS_ENDPOINT = `export async function chargeSpei(order) {
  return fetch('https://api.psp.com/v1/charges', {
    method: 'POST',
    body: JSON.stringify({ payment_method: 'spei', amount: order.total }),
  });
}

export async function undoSpei(chargeId: string) {
  return fetch('https://api.psp.com/v1/refunds', {
    method: 'POST',
    body: JSON.stringify({ charge: chargeId }),
  });
}
`;

// --- Cases ----------------------------------------------------------------------------

module.exports = [
  {
    name: "Pix charge plus stripe.refunds.create() is denied",
    check,
    ctx: {
      filePath: '/proj/lib/payments/pix.ts',
      content: PIX_REFUND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: "SPEI charge plus createRefund() is denied",
    check,
    ctx: {
      filePath: '/proj/lib/payments/spei.js',
      content: SPEI_CREATE_REFUND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: "PSE method literal inside a /refund route path is denied",
    check,
    ctx: {
      filePath: '/proj/app/api/refund/route.ts',
      content: PSE_REFUND_ROUTE,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Card charge plus refunds.create() passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/card.ts',
      content: CARD_REFUND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'File mixing card, pix and boleto with a refund call warns',
    check,
    ctx: {
      filePath: '/proj/lib/payments/checkout.ts',
      content: MIXED_METHODS_REFUND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'warn',
  },
  {
    name: 'EDGE: outbound transfers.create()/payouts.create() on Pix passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/payouts.ts',
      content: PIX_PAYOUT_NOT_REFUND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'refunds.create() named only inside a comment passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/pix.ts',
      content: REFUND_MENTIONED_ONLY_IN_COMMENT,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore tag passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/pix.ts',
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: generic refund helper with no method literal passes',
    check,
    ctx: {
      filePath: '/proj/app/api/refund/route.ts',
      content: REFUND_WITH_NO_METHOD_LITERAL,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'Unrelated library file with a refund() function passes',
    check,
    ctx: {
      filePath: '/proj/src/lib/ring-buffer.ts',
      content: UNRELATED_LIBRARY_FILE,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: refund service that routes Pix to an outbound payout passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/refund.ts',
      content: PIX_ROUTED_TO_PAYOUT,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: refund route that rejects SPEI with a 409 passes',
    check,
    ctx: {
      filePath: '/proj/app/api/refunds/route.ts',
      content: SPEI_REJECTED_WITH_409,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: refund policy table under lib/refunds/ that creates no refund passes',
    check,
    ctx: {
      filePath: '/proj/lib/refunds/policy.ts',
      content: REFUND_POLICY_TABLE,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'BYPASS: switch (payment.rail) { case \'pix\': refunds.create() } is denied',
    check,
    ctx: {
      filePath: '/proj/lib/payments/refund-dispatch.ts',
      content: SWITCH_ON_RAIL,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: "BYPASS: rail hidden behind `const PIX = 'pix'` is denied",
    check,
    ctx: {
      filePath: '/proj/lib/payments/pix-refund.ts',
      content: METHOD_ID_BEHIND_A_CONSTANT,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'BYPASS: raw fetch POST to the PSP /v1/refunds endpoint on SPEI is denied',
    check,
    ctx: {
      filePath: '/proj/lib/payments/spei.ts',
      content: RAW_FETCH_TO_REFUNDS_ENDPOINT,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
];
