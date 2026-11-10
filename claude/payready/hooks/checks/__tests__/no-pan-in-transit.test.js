// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const mod = require('../no-pan-in-transit');

// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

// --- Fixtures -------------------------------------------------------------------------

const ROUTE_ACCEPTS_RAW_CARD = `import Stripe from 'stripe';
import { gateway } from '@/lib/payments/gateway';

export async function POST(request: Request) {
  const body = await request.json();
  const { card_number, cvv, exp_month, exp_year } = body;
  const charge = await gateway.charge({ card_number, cvv, amount: body.amount });
  return Response.json({ ok: true, id: charge.id });
}
`;

const CLIENT_FETCH_FORWARDS_CARD = `'use client';
import { useState } from 'react';

export function PayButton({ amount }) {
  const [cardNumber, setCardNumber] = useState('');
  const [cvc, setCvc] = useState('');

  const submit = async () => {
    await fetch('/api/charge', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ cardNumber, cvc, amount }),
    });
  };

  return <button onClick={submit}>Pagar</button>;
}
`;

const RAILS_MIGRATION_ADDS_CARD_COLUMNS = `class AddCardFieldsToOrders < ActiveRecord::Migration[7.1]
  def change
    add_column :orders, :card_number, :string
    add_column :orders, :cvv, :string
    add_column :orders, :exp_month, :integer
  end
end
`;

const DJANGO_MODEL_PERSISTS_CARD = `from django.db import models


class SavedCard(models.Model):
    user_id = models.BigIntegerField()
    card_number = models.CharField(max_length=19)
    cvv = models.CharField(max_length=4)
    exp_month = models.IntegerField()
    exp_year = models.IntegerField()
`;

const ROUTE_ACCEPTS_TOKEN_ONLY = `import Stripe from 'stripe';
import { randomUUID } from 'node:crypto';
import { stripe } from '@/lib/payments/stripe';

export async function POST(request: Request) {
  const { payment_method_id, amount_minor, currency } = await request.json();
  const intent = await stripe.paymentIntents.create(
    {
      amount: amount_minor,
      currency,
      payment_method: payment_method_id,
      confirm: true,
    },
    { idempotencyKey: randomUUID() }
  );
  return Response.json({ id: intent.id, status: intent.status });
}
`;

const READS_METADATA_OFF_TOKEN_RESPONSE = `import { stripe } from '@/lib/payments/stripe';
import { db } from '@/lib/db';

export async function saveCardSummary(userId: string, paymentMethodId: string) {
  const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);
  const { last4, brand, exp_month, exp_year } = paymentMethod.card;
  await db.cards.upsert({
    where: { userId },
    update: { last4, brand, expMonth: exp_month, expYear: exp_year },
  });
  return brand + ' ****' + last4 + ' ' + paymentMethod.card.exp_month + '/' + paymentMethod.card.exp_year;
}
`;

const PROVIDER_TYPE_IMPORT_ONLY = `import type { Stripe } from 'stripe';

export function summarise(pm: Stripe.PaymentMethod) {
  const { exp_month, exp_year } = pm.card;
  return exp_month + '/' + String(exp_year).slice(-2);
}
`;

const CANVAS_VIEWPORT_REDUCER = `export const DEFAULT_VIEWPORT = { zoom: 1, pan: { x: 0, y: 0 }, rotation: 0 };

export function viewportReducer(state, action) {
  switch (action.type) {
    case 'PAN':
      return { ...state, pan: action.pan };
    case 'ZOOM':
      return { ...state, zoom: action.zoom };
    default:
      return state;
  }
}
`;

const RULE_DESCRIBED_IN_COMMENT_AND_STRING = `/**
 * We never accept card_number or cvv on our own servers. The PAN is tokenised by Stripe
 * Elements in the browser and we only ever see a payment_method id.
 */
import { stripe } from '@/lib/payments/stripe';

const ERROR_COPY = 'Nunca nos envies tu card_number ni tu cvv por este formulario.';

export async function POST(request: Request) {
  const { payment_method_id } = await request.json();
  // cvv and card_number must not appear in the request schema
  if (!payment_method_id) return Response.json({ error: ERROR_COPY }, { status: 400 });
  return Response.json({ ok: true });
}
`;

const IGNORE_TAGGED = `import { gateway } from '@/lib/payments/gateway';
// pagokit-ignore: no-pan-in-transit -- PCI DSS SAQ D certified environment, audited 2026-02

export async function POST(request: Request) {
  const body = await request.json();
  const { card_number, cvv } = body;
  return Response.json({ ok: true });
}
`;

const PROVIDER_SDK_INTERNALS = `'use strict';
// Vendored provider SDK internals — this file legitimately models the card object.
module.exports.cardParams = {
  card_number: null,
  cvv: null,
  exp_month: null,
  exp_year: null,
};
`;

const SAVED_CARD_ROW = `type SavedCard = { id: string; brand: string; expMonth: number; expYear: number };

export function SavedCardRow({ card }: { card: SavedCard }) {
  const { expMonth, expYear } = card;
  return <span>{String(expMonth).padStart(2, '0')}/{String(expYear).slice(-2)}</span>;
}
`;

const ORDER_PICKUP_SECURITY_CODE = `import { db } from '@/lib/db';

export async function POST(req: Request) {
  const { order_id, security_code } = await req.json();
  const order = await db.orders.findUnique({ where: { id: order_id } });
  if (order.pickupCode !== security_code) {
    return Response.json({ error: 'codigo invalido' }, { status: 403 });
  }
  return Response.json({ ok: true });
}
`;

const CYPRESS_TEST_CARD = `describe('checkout', () => {
  it('pays with a test card', () => {
    cy.visit('/checkout');
    cy.getWithinIframe('input[name="cardnumber"]').type('4242424242424242');
    cy.getWithinIframe('input[name="cvc"]').type('123');
    cy.contains('Pagar').click();
    cy.contains('Gracias').should('be.visible');
  });
});
`;

const CAMEL_CASE_CARD_FIELDS = `import { gateway } from '@/lib/payments/gateway';

export async function POST(request: Request) {
  const body = await request.json();
  const creditCardNumber = body.creditCardNumber;
  const ccNumber = body.ccNumber;
  const charge = await gateway.charge({ creditCardNumber, amount: body.amount });
  return Response.json({ id: charge.id });
}
`;

const RAW_SQL_INSERT_AND_SHORTHAND = `import { pool } from '@/lib/db';

export async function storeCard(card_number: string, cvv: string, userId: string) {
  await pool.query(
    'INSERT INTO saved_cards (user_id, card_number, cvv) VALUES ($1, $2, $3)',
    [userId, card_number, cvv]
  );
  await mongo.collection('cards').insertOne({ card_number, cvv, userId });
}
`;

const ORM_ENTITY_ASSIGNMENT = `import { Payment } from '@/entities/Payment';

export async function chargeOrder(input, repo) {
  const payment = new Payment();
  payment.card_number = input.number;
  payment.cvv = input.code;
  await repo.save(payment);
  return payment;
}
`;

// --- Cases ----------------------------------------------------------------------------

module.exports = [
  {
    name: 'Route destructuring card_number and cvv off the request body is denied',
    check,
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: ROUTE_ACCEPTS_RAW_CARD,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Client fetch forwarding cardNumber + cvc in the JSON body is denied',
    check,
    ctx: {
      filePath: '/proj/src/components/PayButton.tsx',
      content: CLIENT_FETCH_FORWARDS_CARD,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Rails migration adding a card_number column is denied',
    check,
    ctx: {
      filePath: '/proj/db/migrate/20260215120000_add_card_fields_to_orders.rb',
      content: RAILS_MIGRATION_ADDS_CARD_COLUMNS,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Django model persisting card_number and cvv is denied',
    check,
    ctx: {
      filePath: '/proj/payments/models.py',
      content: DJANGO_MODEL_PERSISTS_CARD,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Route that accepts only payment_method_id passes',
    check,
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: ROUTE_ACCEPTS_TOKEN_ONLY,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: last4 / brand / exp_month read back off a PSP token response passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/card-summary.ts',
      content: READS_METADATA_OFF_TOKEN_RESPONSE,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: exp_month / exp_year destructured off a provider SDK type passes',
    check,
    ctx: {
      filePath: '/proj/lib/payments/summarise.ts',
      content: PROVIDER_TYPE_IMPORT_ONLY,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: canvas viewport reducer using a `pan` key passes',
    check,
    ctx: {
      filePath: '/proj/src/components/canvas/viewport.ts',
      content: CANVAS_VIEWPORT_REDUCER,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'card_number / cvv only in a doc comment and a user-facing string passes',
    check,
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: RULE_DESCRIBED_IN_COMMENT_AND_STRING,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore tag passes',
    check,
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'Provider SDK internals under node_modules pass',
    check,
    ctx: {
      filePath: '/proj/node_modules/stripe/lib/resources/Tokens.js',
      content: PROVIDER_SDK_INTERNALS,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: saved-card row rendering expMonth/expYear off a PSP card object passes',
    check,
    ctx: {
      filePath: '/proj/src/components/card/SavedCardRow.tsx',
      content: SAVED_CARD_ROW,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: order-pickup security_code (not a CVV) in a file with no card vocabulary passes',
    check,
    ctx: {
      filePath: '/proj/app/api/orders/pickup/route.ts',
      content: ORDER_PICKUP_SECURITY_CODE,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'FP: Cypress e2e typing a Stripe test card into a hosted field passes',
    check,
    ctx: {
      filePath: '/proj/cypress/e2e/checkout.cy.ts',
      content: CYPRESS_TEST_CARD,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'pass',
  },
  {
    name: 'BYPASS: creditCardNumber / ccNumber read off the request body is denied',
    check,
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: CAMEL_CASE_CARD_FIELDS,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'Raw SQL INSERT plus an object-shorthand insertOne of card_number/cvv is denied',
    check,
    ctx: {
      filePath: '/proj/lib/payments/store-card.ts',
      content: RAW_SQL_INSERT_AND_SHORTHAND,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
  {
    name: 'BYPASS: card_number assigned onto an ORM entity property is denied',
    check,
    ctx: {
      filePath: '/proj/lib/payments/charge.ts',
      content: ORM_ENTITY_ASSIGNMENT,
      toolName: 'Write',
      projectDir: '/proj',
    },
    expected: 'deny',
  },
];
