// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const check = require('../network-txn-id-persistence');

/* ------------------------------------------------------------------ *
 * Throwaway project trees. This check reads the project's schema files,
 * so the fixtures have to exist on disk. Built with node built-ins only,
 * removed on exit.
 * ------------------------------------------------------------------ */

const TEMP_ROOTS = [];

function makeProject(label, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `pagokit-mit-${label}-`));
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

const PRISMA_WITHOUT_TLID = `
datasource db { provider = "postgresql", url = env("DATABASE_URL") }

model PaymentMethod {
  id             String   @id @default(cuid())
  userId         String
  providerRef    String
  brand          String
  last4          String
  createdAt      DateTime @default(now())
}
`;

const PRISMA_WITH_TLID = `
datasource db { provider = "postgresql", url = env("DATABASE_URL") }

model PaymentMethod {
  id                   String   @id @default(cuid())
  userId               String
  providerRef          String
  networkTransactionId String?  @map("network_transaction_id")
  createdAt            DateTime @default(now())
}
`;

const PROJECT_NO_COLUMN = makeProject('nocol', {
  'package.json': '{"name":"shop","dependencies":{"stripe":"^17.0.0"}}',
  'prisma/schema.prisma': PRISMA_WITHOUT_TLID,
});

const PROJECT_WITH_COLUMN = makeProject('withcol', {
  'package.json': '{"name":"shop","dependencies":{"stripe":"^17.0.0"}}',
  'prisma/schema.prisma': PRISMA_WITH_TLID,
});

const PROJECT_NO_SCHEMA = makeProject('noschema', {
  'package.json': '{"name":"shop","dependencies":{"stripe":"^17.0.0"}}',
  'app/page.tsx': 'export default function Page() { return null; }',
});

/* A project whose only file named `schema.ts` is a zod request validator. There is no
   database schema here at all, so there is nothing to conclude about a missing column. */
const PROJECT_ZOD_SCHEMA_ONLY = makeProject('zodschema', {
  'package.json': '{"name":"shop","dependencies":{"stripe":"^17.0.0","zod":"^3.23.0"}}',
  'src/lib/schema.ts': [
    "import { z } from 'zod';",
    "export const CheckoutInput = z.object({ email: z.string().email(), items: z.array(z.string()) });",
    'export type CheckoutInput = z.infer<typeof CheckoutInput>;',
  ].join('\n'),
});

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

const MIT_SETUP_INTENT = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function saveCardForSubscription(customerId) {
  const intent = await stripe.setupIntents.create({
    customer: customerId,
    usage: 'off_session',
    payment_method_types: ['card'],
  });
  return intent.client_secret;
}
`;

const MIT_SETUP_FUTURE_USAGE = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount, customerId } = await req.json();
  const pi = await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
    customer: customerId,
    setup_future_usage: 'off_session',
  });
  return Response.json({ clientSecret: pi.client_secret });
}
`;

const MIT_THAT_PERSISTS_THE_ID = `
import Stripe from 'stripe';
import { db } from '@/lib/db';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount, customerId } = await req.json();
  const pi = await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
    customer: customerId,
    setup_future_usage: 'off_session',
  });
  const charge = pi.latest_charge;
  await db.paymentMethod.update({
    where: { providerRef: pi.payment_method },
    data: { networkTransactionId: charge.payment_method_details.card.network_transaction_id },
  });
  return Response.json({ clientSecret: pi.client_secret });
}
`;

const ONE_TIME_PAYMENT_ONLY = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const { amount } = await req.json();
  const pi = await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
    automatic_payment_methods: { enabled: true },
  });
  return Response.json({ clientSecret: pi.client_secret });
}
`;

const COMMENT_AND_STRING_ONLY = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Someday we may pass setup_future_usage: 'off_session' here to support renewals.
const ROADMAP_NOTE = 'saved cards need setup_future_usage and a SetupIntent';

export async function POST(req) {
  const { amount } = await req.json();
  const pi = await stripe.paymentIntents.create({ amount, currency: 'usd' });
  return Response.json({ clientSecret: pi.client_secret });
}
`;

const IGNORE_TAGGED = `
import Stripe from 'stripe';
// pagokit-ignore: network-txn-id-persistence -- TLID is stored by the billing service, not this app
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function saveCard(customerId) {
  return stripe.setupIntents.create({ customer: customerId, usage: 'off_session' });
}
`;

const UNRELATED_SECRETS_FILE = `
import { readSecret } from '@/lib/hashicorp';

export async function getConfig() {
  const vaultToken = await readSecret('kv/data/app');
  return { vaultToken, region: 'us-east-1' };
}
`;

/* 11 — Adversarial FP: a payments file that reads its Stripe key out of HashiCorp Vault.
        `vault` on its own is not a card vault. */
const STRIPE_KEY_FROM_HASHICORP_VAULT = `
import Stripe from 'stripe';
import { vault } from '@/lib/secrets/vault';

let client;
export async function getStripe() {
  if (!client) {
    const secret = await vault.read('kv/data/prod/stripe');
    client = new Stripe(secret.data.secret_key);
  }
  return client;
}
`;

/* 12 — Adversarial FP: a read-only "your saved cards" listing. It stores nothing. */
const READ_ONLY_SAVED_CARD_LIST = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function GET(req) {
  const customerId = await requireCustomer(req);
  const methods = await stripe.paymentMethods.list({ customer: customerId, type: 'card' });
  return Response.json(methods.data.map((m) => ({ cardToken: m.id, brand: m.card.brand, last4: m.card.last4 })));
}
`;

/* 13 — Adversarial FP: a real SetupIntent, in a project whose only `schema.ts` is a zod
        validator. There is no schema to be missing a column from. */
const MIT_IN_ZOD_ONLY_PROJECT = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
  const si = await stripe.setupIntents.create({ customer: req.customerId, usage: 'off_session' });
  return Response.json({ clientSecret: si.client_secret });
}
`;

/* 14 — Adversarial bypass: a TODO comment naming the identifier silenced the whole rule. */
const TLID_MENTIONED_ONLY_IN_A_COMMENT = `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// TODO: someday persist network_transaction_id
export async function POST(req) {
  const si = await stripe.setupIntents.create({ customer: req.customerId, usage: 'off_session' });
  return Response.json({ clientSecret: si.client_secret });
}
`;

/* 15 — Adversarial bypass: the LATAM half of the catalog. A Mercado Pago pre-approval
        reuses a stored customer card on every renewal, in none of Stripe's vocabulary. */
const MERCADOPAGO_PREAPPROVAL = `
import { MercadoPagoConfig, PreApproval } from 'mercadopago';
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

export async function POST(req) {
  const { cardId, amount } = await req.json();
  const preapproval = new PreApproval(client);
  return preapproval.create({ body: {
    payer_email: req.email,
    card_token_id: cardId,
    auto_recurring: { frequency: 1, frequency_type: 'months', transaction_amount: amount, currency_id: 'ARS' },
  }});
}
`;

/* 16 — Adversarial bypass: a Wompi payment source charged with no cardholder present,
        reached through a local wrapper module rather than the SDK package. */
const WOMPI_RECURRING_PAYMENT_SOURCE = `
import { wompi } from '@/lib/wompi';

export async function POST(req) {
  const { paymentSourceId, amountInCents } = await req.json();
  return wompi.transactions.create({
    payment_source_id: paymentSourceId,
    amount_in_cents: amountInCents,
    currency: 'COP',
    recurrent: true,
  });
}
`;

module.exports = [
  {
    name: 'stop phase: SetupIntent for off-session use + schema without the column → deny',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'lib/billing/save-card.ts'),
      content: MIT_SETUP_INTENT,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'deny',
  },
  {
    name: 'mid-edit (post phase): setup_future_usage + schema without the column → warn',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/checkout/route.ts'),
      content: MIT_SETUP_FUTURE_USAGE,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'post',
    },
    expected: 'warn',
  },
  {
    name: 'schema already declares networkTransactionId → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_WITH_COLUMN, 'lib/billing/save-card.ts'),
      content: MIT_SETUP_INTENT,
      toolName: 'Write',
      projectDir: PROJECT_WITH_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'edge: project has no schema or migration file at all → pass (nothing to conclude)',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_SCHEMA, 'lib/billing/save-card.ts'),
      content: MIT_SETUP_INTENT,
      toolName: 'Write',
      projectDir: PROJECT_NO_SCHEMA,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'edge: the file itself persists the network transaction id → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/checkout/route.ts'),
      content: MIT_THAT_PERSISTS_THE_ID,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'one-time payment with no stored-card setup → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/checkout/route.ts'),
      content: ONE_TIME_PAYMENT_ONLY,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'setup_future_usage only in a comment and a string literal → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/checkout/route.ts'),
      content: COMMENT_AND_STRING_ONLY,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore bypass → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'lib/billing/save-card.ts'),
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'unrelated file: HashiCorp vault token, no payment SDK → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'lib/config/secrets.ts'),
      content: UNRELATED_SECRETS_FILE,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'no projectDir supplied → pass (cross-file half is unknowable)',
    check,
    ctx: {
      filePath: 'lib/billing/save-card.ts',
      content: MIT_SETUP_INTENT,
      toolName: 'Write',
      projectDir: '',
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: Stripe key read out of HashiCorp Vault → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'lib/payments/client.ts'),
      content: STRIPE_KEY_FROM_HASHICORP_VAULT,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: read-only saved-card listing → pass',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/cards/route.ts'),
      content: READ_ONLY_SAVED_CARD_LIST,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: "adversarial: the project's only schema.ts is a zod validator → pass",
    check,
    ctx: {
      filePath: path.join(PROJECT_ZOD_SCHEMA_ONLY, 'app/api/checkout/route.ts'),
      content: MIT_IN_ZOD_ONLY_PROJECT,
      toolName: 'Write',
      projectDir: PROJECT_ZOD_SCHEMA_ONLY,
      phase: 'stop',
    },
    expected: 'pass',
  },
  {
    name: 'adversarial: the identifier appears only in a TODO comment → deny',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/checkout/route.ts'),
      content: TLID_MENTIONED_ONLY_IN_A_COMMENT,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'deny',
  },
  {
    name: 'adversarial: Mercado Pago pre-approval reusing a stored card → deny',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/subscriptions/route.ts'),
      content: MERCADOPAGO_PREAPPROVAL,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'deny',
  },
  {
    name: 'adversarial: Wompi recurring charge on a stored payment source → deny',
    check,
    ctx: {
      filePath: path.join(PROJECT_NO_COLUMN, 'app/api/wompi/recurring/route.ts'),
      content: WOMPI_RECURRING_PAYMENT_SOURCE,
      toolName: 'Write',
      projectDir: PROJECT_NO_COLUMN,
      phase: 'stop',
    },
    expected: 'deny',
  },
];
