// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const check = require('../einvoice-obligation');

/**
 * PAGOKIT_STRICT is read from the environment, so the strict case wraps the same check
 * and restores the previous value. Keeps every other case deterministic.
 */
const strictCheck = {
  RULE_ID: check.RULE_ID,
  run(ctx) {
    const previous = process.env.PAGOKIT_STRICT;
    process.env.PAGOKIT_STRICT = '1';
    try {
      return check.run(ctx);
    } finally {
      if (previous === undefined) delete process.env.PAGOKIT_STRICT;
      else process.env.PAGOKIT_STRICT = previous;
    }
  },
};

/* ------------------------------------------------------------------ *
 * Throwaway project trees — the check scans the project for an invoicing
 * module and for PAGOKIT_TAX_TODO.md.
 * ------------------------------------------------------------------ */

const TEMP_ROOTS = [];

function makeProject(label, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `pagokit-einv-${label}-`));
  TEMP_ROOTS.push(root);
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body, 'utf8');
  }
  return root;
}

process.on('exit', () => {
  for (const root of TEMP_ROOTS) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

const PROJECT_PLAIN = makeProject('plain', {
  'package.json': '{"name":"tienda","dependencies":{"mercadopago":"^2.0.0"}}',
  'app/page.tsx': 'export default function Page() { return null; }',
});

const PROJECT_WITH_ISSUER = makeProject('issuer', {
  'package.json': '{"name":"tienda","dependencies":{"mercadopago":"^2.0.0"}}',
  'lib/cfdi/emitir.ts': 'export async function emitir(order) { return order; }',
});

const PROJECT_WITH_TODO = makeProject('todo', {
  'package.json': '{"name":"tienda","dependencies":{"mercadopago":"^2.0.0"}}',
  'PAGOKIT_TAX_TODO.md': '# Tax\n\nCFDI issuance handled by the ERP team in Q4.\n',
});

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

const MX_OXXO_CHARGE = `
import { MercadoPagoConfig, Payment } from 'mercadopago';

const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const mpPayment = new Payment(client);

export async function POST(req) {
  const { amount, email } = await req.json();
  const result = await mpPayment.create({
    body: {
      transaction_amount: amount,
      payment_method_id: 'oxxo',
      payer: { email },
    },
  });
  return Response.json({ id: result.id, status: result.status });
}
`;

const BR_PAID_ORDER = `
import { db } from '@/lib/db';

export async function POST(req) {
  const event = await req.json();
  const order = {
    id: event.data.id,
    status: 'paid',
    currency: 'BRL',
    total: event.data.amount,
  };
  await db.orders.upsert(order);
  return new Response('ok');
}
`;

const MX_WITH_ISSUER_IMPORT = `
import { MercadoPagoConfig, Payment } from 'mercadopago';
import Facturapi from 'facturapi';

const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const mpPayment = new Payment(client);
const facturapi = new Facturapi(process.env.FACTURAPI_KEY);

export async function POST(req) {
  const { amount, email, rfc } = await req.json();
  const result = await mpPayment.create({
    body: { transaction_amount: amount, payment_method_id: 'oxxo', payer: { email } },
  });
  await facturapi.invoices.create({ customer: { legal_name: rfc }, items: [] });
  return Response.json({ id: result.id });
}
`;

const USD_CHARGE_NO_JURISDICTION = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price_data: { currency: 'usd', unit_amount: amount }, quantity: 1 }],
    success_url: 'https://example.com/ok',
  });
  return Response.json({ url: session.url });
}
`;

const MOR_CHECKOUT_MXN = `
import { createCheckout } from '@lemonsqueezy/lemonsqueezy.js';

export async function POST(req) {
  const { variantId } = await req.json();
  const checkout = await createCheckout(STORE_ID, variantId, {
    checkoutData: { currency: 'MXN' },
  });
  return Response.json({ url: checkout.data.attributes.url });
}
`;

const COMMENT_AND_STRING_ONLY = `
// The MX flow charges with OXXO and the status comes back as 'approved'.
// mpPayment.create({ body: { payment_method_id: 'oxxo' } })
export const NOTE = 'status: "approved" with currency: "MXN"';

export function describeFlow() {
  return NOTE;
}
`;

const IGNORE_TAGGED = `
import { MercadoPagoConfig, Payment } from 'mercadopago';
// pagokit-ignore: einvoice-obligation -- the ERP issues the CFDI from the nightly export

const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const mpPayment = new Payment(client);

export async function POST(req) {
  const { amount, email } = await req.json();
  return mpPayment.create({
    body: { transaction_amount: amount, payment_method_id: 'oxxo', payer: { email } },
  });
}
`;

const UNRELATED_SHIPPING_FILE = `
const zones = [
  { country: 'MX', carrier: 'estafeta', days: 3 },
  { country: 'BR', carrier: 'correios', days: 5 },
];

export function quote(countryCode) {
  return zones.find((z) => z.country === countryCode) ?? null;
}
`;

/* 12 — Adversarial FP: a read-only admin report. It queries paid Mexican orders; it
        does not make one. */
const READ_ONLY_ORDER_REPORT = `
import { db } from '@/lib/db';

export async function paidOrdersForMexico() {
  return db.order.findMany({
    where: { status: 'paid', country: 'MX' },
    orderBy: { createdAt: 'desc' },
  });
}
`;

/* 13 — Adversarial FP: a refund. Money moves back; a refund produces a credit note,
        never a new CFDI obligation. */
const REFUND_IN_MXN = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { chargeId, amount } = await req.json();
  const refund = await stripe.refunds.create({ charge: chargeId, amount, currency: 'MXN' });
  return Response.json({ id: refund.id, status: refund.status });
}
`;

/* 14 — Adversarial FP: a shipping quote for Brazil. A status filter and a country code,
        but no sale anywhere in the file. */
const BR_SHIPPING_QUOTE = `
import { db } from '@/lib/db';

export async function quote(orderId) {
  const order = await db.order.findUnique({ where: { id: orderId } });
  const eligible = order.status === 'paid';
  const country = 'BR';
  const table = { BR: 24.9, AR: 31.5 };
  return { eligible, country, price: table[country], currency: 'BRL' };
}
`;

/* 15 — Adversarial bypass: an order's own receipt link. `invoiceUrl` is not a CFDI
        issuer, and treating it as one silenced the check on a real Mexican sale. */
const MX_CHARGE_WITH_INVOICE_URL = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount } = await req.json();
  const pi = await stripe.paymentIntents.create({ amount, currency: 'MXN' });
  return Response.json({ id: pi.id, invoiceUrl: '/orders/' + pi.id + '/receipt.pdf' });
}
`;

/* 16 — Adversarial bypass: the currency comes from config, so the only statement of
        jurisdiction left in the file is the locale. `es-MX` names one country. */
const MX_CHARGE_VIA_LOCALE = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount } = await req.json();
  return stripe.paymentIntents.create({
    amount,
    currency: process.env.STORE_CURRENCY,
    locale: 'es-MX',
  });
}
`;

/* 17 — Adversarial bypass: a project whose only "invoicing" is an order-receipt module
        called invoices/. It cannot emit an NF-e. */
const PROJECT_ORDER_RECEIPTS_ONLY = makeProject('receipts', {
  'package.json': '{"name":"loja","dependencies":{"stripe":"^17.0.0"}}',
  'lib/invoices/receipt.ts': 'export function renderReceipt(order) { return order.id; }',
});

const BR_BOLETO_CHARGE = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount } = await req.json();
  return stripe.paymentIntents.create({ amount, currency: 'BRL', payment_method_types: ['boleto'] });
}
`;

/* 18 — Adversarial FP: the only 'oxxo' in the file is an example value in a trailing
        comment on a code line. A comment is not a jurisdiction. */
const MP_CHARGE_WITH_METHOD_IN_A_COMMENT = `
import { mpPayment } from '@/lib/payments/mercadopago';

interface ChargeInput {
  productId: string;
  paymentMethodId: string; // e.g., 'master', 'visa', 'pix', 'oxxo'
  payerEmail: string;
}

export async function POST(request) {
  const input = await request.json();
  const payment = await mpPayment.create({
    body: {
      transaction_amount: input.amount,
      payment_method_id: input.paymentMethodId,
      payer: { email: input.payerEmail },
    },
  });
  return Response.json({ status: payment.status, payment_id: payment.id });
}
`;

/* 19 — Adversarial FP: an ambient declaration file. It declares the widget's shape;
        it cannot complete a sale. */
const WOMPI_AMBIENT_DECLARATIONS = `
declare global {
  interface WidgetCheckoutOptions {
    currency: 'COP';
    amountInCents: number;
    reference: string;
    publicKey: string;
  }
  class WidgetCheckout {
    constructor(options: WidgetCheckoutOptions);
    open(callback: (result: { transaction?: any }) => void): void;
  }
}
export {};
`;

module.exports = [
  {
    name: 'MX resolved from the OXXO method on a completed charge → warn',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MX_OXXO_CHARGE,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'warn',
  },
  {
    name: "BR resolved from currency 'BRL' on a status:'paid' order → warn",
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/webhooks/mercadopago/route.ts'),
      content: BR_PAID_ORDER,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'warn',
  },
  {
    name: 'PAGOKIT_STRICT=1 upgrades the same finding to deny',
    check: strictCheck,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MX_OXXO_CHARGE,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'deny',
  },
  {
    name: 'edge: USD charge — no single country owns the currency, so no mandate resolves → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: USD_CHARGE_NO_JURISDICTION,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'MX charge with a CFDI issuer imported in the same file → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MX_WITH_ISSUER_IMPORT,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'project already has an invoicing module (lib/cfdi/) → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_WITH_ISSUER, 'app/api/checkout/route.ts'),
      content: MX_OXXO_CHARGE,
      toolName: 'Write',
      projectDir: PROJECT_WITH_ISSUER,
    },
    expected: 'pass',
  },
  {
    name: 'PAGOKIT_TAX_TODO.md at the project root records the decision → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_WITH_TODO, 'app/api/checkout/route.ts'),
      content: MX_OXXO_CHARGE,
      toolName: 'Write',
      projectDir: PROJECT_WITH_TODO,
    },
    expected: 'pass',
  },
  {
    name: 'merchant of record owns the sale, so it owns the fiscal document → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MOR_CHECKOUT_MXN,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'charge, status and method mentioned only in comments and a string → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'lib/docs/flow-notes.ts'),
      content: COMMENT_AND_STRING_ONLY,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'unrelated shipping file with country literals but no sale → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'lib/shipping/zones.ts'),
      content: UNRELATED_SHIPPING_FILE,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: a read-only report of paid Mexican orders → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/admin/reports/orders.ts'),
      content: READ_ONLY_ORDER_REPORT,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: a refund in MXN is not a sale → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/refunds/route.ts'),
      content: REFUND_IN_MXN,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: a Brazilian shipping quote with a paid-status filter → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/shipping/quote.ts'),
      content: BR_SHIPPING_QUOTE,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: "adversarial: an order's own invoiceUrl is not a CFDI issuer → warn",
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MX_CHARGE_WITH_INVOICE_URL,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'warn',
  },
  {
    name: "adversarial: jurisdiction stated only by locale 'es-MX' → warn",
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/route.ts'),
      content: MX_CHARGE_VIA_LOCALE,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'warn',
  },
  {
    name: 'adversarial: an order-receipt invoices/ module cannot emit an NF-e → warn',
    check,
    ctx: {
      filePath: path.join(PROJECT_ORDER_RECEIPTS_ONLY, 'app/api/checkout/route.ts'),
      content: BR_BOLETO_CHARGE,
      toolName: 'Write',
      projectDir: PROJECT_ORDER_RECEIPTS_ONLY,
    },
    expected: 'warn',
  },
  {
    name: "adversarial: 'oxxo' appears only as an example in a trailing comment → pass",
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'app/api/checkout/charge/route.ts'),
      content: MP_CHARGE_WITH_METHOD_IN_A_COMMENT,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: an ambient .d.ts declaration file → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_PLAIN, 'types/wompi.d.ts'),
      content: WOMPI_AMBIENT_DECLARATIONS,
      toolName: 'Write',
      projectDir: PROJECT_PLAIN,
    },
    expected: 'pass',
  },
];
