// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const check = require('../secret-in-client-bundle');

const PUBLIC_PREFIXED_SECRET = `
export const stripeConfig = {
  publishableKey: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY,
  secretKey: process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY,
};
`;

const SERVER_ROUTE_USING_SECRET = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export async function POST(req) {
  const session = await stripe.checkout.sessions.create({ mode: 'payment' });
  return Response.json({ id: session.id });
}
`;

// Publishable keys are meant to ship, and non-payment public tokens are not our business.
const CLIENT_WITH_PUBLIC_KEYS = `'use client';
import { useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function PayButton() {
  const [busy, setBusy] = useState(false);
  const map = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;
  const base = process.env.PUBLIC_URL;
  return <button onClick={() => setBusy(true)} disabled={busy}>{base}{map}</button>;
}
`;

const COMMENT_AND_STRING_ONLY = `
// Never introduce process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY — see SECURITY.md.
const LINT_MESSAGE = 'NEXT_PUBLIC_STRIPE_SECRET_KEY is banned';

export function describe() {
  /* VITE_MP_ACCESS_TOKEN was removed in v2 */
  return LINT_MESSAGE;
}
`;

const BYPASS_TAGGED = `
// pagokit-ignore: secret-in-client-bundle -- build-time only, stripped by the bundler define plugin
export const cfg = {
  secretKey: process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY,
};
`;

const UNRELATED_ANALYTICS = `
export const analytics = {
  id: process.env.NEXT_PUBLIC_ANALYTICS_ID,
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  db: process.env.DATABASE_URL,
};
`;

const USE_CLIENT_READS_SERVER_CREDENTIAL = `'use client';
import { useState } from 'react';

export default function DonateButton() {
  const [busy, setBusy] = useState(false);
  async function pay() {
    setBusy(true);
    await fetch('https://api.stripe.com/v1/payment_intents', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY },
    });
  }
  return <button onClick={pay} disabled={busy}>Donate</button>;
}
`;

// A server component that happens to live under components/ — legal, and very common.
const SERVER_COMPONENT_UNDER_COMPONENTS = `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

export default async function ProductGrid() {
  const products = await stripe.products.list({ limit: 10 });
  return (
    <ul>
      {products.data.map((p) => (<li key={p.id}>{p.name}</li>))}
    </ul>
  );
}
`;

// An app-router page is a server component by default: reading the secret here is correct.
const SERVER_PAGE_NO_CLIENT_MARKER = `
export default async function CheckoutPage() {
  const res = await fetch('https://api.stripe.com/v1/prices', {
    headers: { Authorization: 'Bearer ' + process.env.STRIPE_SECRET_KEY },
  });
  const prices = await res.json();
  return (
    <main>
      <h1>Checkout</h1>
      {prices.data.map((p) => (<Price key={p.id} price={p} />))}
    </main>
  );
}
`;

const VITE_ACCESS_TOKEN = `
export const mp = {
  accessToken: import.meta.env.VITE_MP_ACCESS_TOKEN,
  publicKey: import.meta.env.VITE_MP_PUBLIC_KEY,
};
`;

const ENV_EXAMPLE_WITH_PUBLIC_PRIVATE_KEY = `# Wompi
WOMPI_PUBLIC_KEY=pub_test_REPLACE_ME
NEXT_PUBLIC_WOMPI_PRIVATE_KEY=prv_test_REPLACE_ME
WOMPI_EVENTS_SECRET=REPLACE_ME
`;

const ENV_LOCAL_CLEAN = `# Do not add NEXT_PUBLIC_STRIPE_SECRET_KEY here, it would be bundled.
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_REPLACE_ME
STRIPE_SECRET_KEY=sk_test_REPLACE_ME
`;

// --- Adversarial-audit fixtures -------------------------------------------------------

// An async component can only be a React Server Component, and an RSC never reaches the
// browser — so reading the secret key in one is correct even under components/.
const ASYNC_SERVER_COMPONENT_UNDER_COMPONENTS = `
export default async function PricingTable() {
  const res = await fetch('https://api.stripe.com/v1/prices', {
    headers: { Authorization: \`Bearer \${process.env.STRIPE_SECRET_KEY}\` },
    next: { revalidate: 3600 },
  });
  const { data } = await res.json();
  return (
    <ul>
      {data.map((price) => (<li key={price.id}>{price.unit_amount}</li>))}
    </ul>
  );
}
`;

// STRIPE + WEBHOOK, but the name ends in DEBUG: a flag, not a credential.
const PUBLIC_DEBUG_FLAG = `'use client';
import { useState } from 'react';

const SHOW = process.env.NEXT_PUBLIC_STRIPE_WEBHOOK_DEBUG === 'true';

export function DebugPanel() {
  const [open, setOpen] = useState(SHOW);
  return <div onClick={() => setOpen(!open)} />;
}
`;

const SERVER_MODULE_READING_IMPORT_META = `
export const stripeKey = import.meta.env.STRIPE_SECRET_KEY;

export async function charge(amount) {
  return fetch('https://api.stripe.com/v1/charges', { headers: { Authorization: stripeKey } });
}
`;

const NEXT_CONFIG_SERVER_RUNTIME = `
module.exports = {
  reactStrictMode: true,
  serverRuntimeConfig: {
    stripeKey: process.env.STRIPE_SECRET_KEY,
  },
  env: {
    NEXT_PUBLIC_SITE_URL: process.env.SITE_URL,
  },
};
`;

// Vue CLI inlines every VUE_APP_* var into the bundle exactly like NEXT_PUBLIC_ does.
const VUE_APP_PREFIXED_SECRET = `
const key = process.env.VUE_APP_STRIPE_SECRET_KEY;
export default key;
`;

// The var name lives inside a string literal, which the shared stripper blanks.
const BRACKET_ENV_ACCESS = `'use client';
import { useState } from 'react';

export function Pay() {
  const [busy, setBusy] = useState(false);
  const key = process.env["STRIPE_SECRET_KEY"];
  return <button onClick={() => setBusy(true)}>{key ? 'go' : 'no'}</button>;
}
`;

// Vite only inlines import.meta.env into code it BUNDLES, so reading it is a client signal
// in its own right — no JSX, no hooks, no components/ directory needed.
const VITE_ENTRY_READING_SERVER_CREDENTIAL = `
import { createApp } from 'vue';

const key = import.meta.env.STRIPE_SECRET_KEY;
createApp({ data: () => ({ key }) }).mount('#app');
`;

// In the Pages Router the whole module ships, hooks or no hooks.
const PAGES_ROUTER_PAGE = `
export default function Checkout({ items }) {
  const key = process.env.STRIPE_SECRET_KEY;
  return (
    <div className="checkout">
      <span>{items.length}</span>
      <a href={'/pay?k=' + key}>Pay</a>
    </div>
  );
}
`;

const DESTRUCTURED_ENV_IN_CLIENT = `'use client';
import { useState } from 'react';

const { STRIPE_SECRET_KEY } = process.env;

export default function Donate() {
  const [busy, setBusy] = useState(false);
  return <button onClick={() => setBusy(!busy)}>{STRIPE_SECRET_KEY ? 'y' : 'n'}</button>;
}
`;

const NEXT_CONFIG_ENV_BLOCK = `
module.exports = {
  reactStrictMode: true,
  env: {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  },
};
`;

module.exports = [
  {
    name: 'NEXT_PUBLIC_STRIPE_SECRET_KEY denies',
    check,
    ctx: {
      filePath: 'src/lib/payments/config.ts',
      content: PUBLIC_PREFIXED_SECRET,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'server route reading STRIPE_SECRET_KEY passes',
    check,
    ctx: {
      filePath: 'app/api/checkout/route.ts',
      content: SERVER_ROUTE_USING_SECRET,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'client component with publishable key and non-payment public tokens passes',
    check,
    ctx: {
      filePath: 'components/PayButton.tsx',
      content: CLIENT_WITH_PUBLIC_KEYS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'occurrences only in comments and string literals pass',
    check,
    ctx: {
      filePath: 'src/lib/lint-messages.ts',
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
      filePath: 'src/lib/payments/config.ts',
      content: BYPASS_TAGGED,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'unrelated analytics config passes',
    check,
    ctx: {
      filePath: 'src/lib/analytics.ts',
      content: UNRELATED_ANALYTICS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: "'use client' component reading STRIPE_SECRET_KEY denies",
    check,
    ctx: {
      filePath: 'components/DonateButton.tsx',
      content: USE_CLIENT_READS_SERVER_CREDENTIAL,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: 'server component under components/ using the server SDK passes',
    check,
    ctx: {
      filePath: 'components/ProductGrid.tsx',
      content: SERVER_COMPONENT_UNDER_COMPONENTS,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'app-router page with JSX but no client marker passes',
    check,
    ctx: {
      filePath: 'app/checkout/page.tsx',
      content: SERVER_PAGE_NO_CLIENT_MARKER,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'VITE_MP_ACCESS_TOKEN denies while VITE_MP_PUBLIC_KEY would not',
    check,
    ctx: {
      filePath: 'src/lib/mp-client.ts',
      content: VITE_ACCESS_TOKEN,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: '.env.example declaring NEXT_PUBLIC_WOMPI_PRIVATE_KEY denies',
    check,
    ctx: {
      filePath: 'apps/web/.env.example',
      content: ENV_EXAMPLE_WITH_PUBLIC_PRIVATE_KEY,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'deny',
  },
  {
    name: '.env.local mentioning the bad name only in a # comment passes',
    check,
    ctx: {
      filePath: 'apps/web/.env.local',
      content: ENV_LOCAL_CLEAN,
      toolName: 'Write',
      projectDir: '/tmp/x',
    },
    expected: 'pass',
  },
  {
    name: 'async server component under components/ reading the secret key passes',
    check,
    ctx: { filePath: 'components/PricingTable.tsx', content: ASYNC_SERVER_COMPONENT_UNDER_COMPONENTS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'NEXT_PUBLIC_STRIPE_WEBHOOK_DEBUG passes (a flag, not a credential)',
    check,
    ctx: { filePath: 'components/DebugPanel.tsx', content: PUBLIC_DEBUG_FLAG, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'a server module reading import.meta.env passes',
    check,
    ctx: { filePath: 'src/lib/server/stripe.ts', content: SERVER_MODULE_READING_IMPORT_META, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'next.config serverRuntimeConfig holding the secret key passes',
    check,
    ctx: { filePath: 'next.config.js', content: NEXT_CONFIG_SERVER_RUNTIME, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'pass',
  },
  {
    name: 'VUE_APP_STRIPE_SECRET_KEY denies',
    check,
    ctx: { filePath: 'src/main.js', content: VUE_APP_PREFIXED_SECRET, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: "process.env[\"STRIPE_SECRET_KEY\"] in a client component denies",
    check,
    ctx: { filePath: 'components/Pay.tsx', content: BRACKET_ENV_ACCESS, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'a vite entry reading import.meta.env.STRIPE_SECRET_KEY denies',
    check,
    ctx: { filePath: 'src/main.js', content: VITE_ENTRY_READING_SERVER_CREDENTIAL, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'a pages-router page reading the secret key denies',
    check,
    ctx: { filePath: 'pages/checkout.jsx', content: PAGES_ROUTER_PAGE, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: 'const { STRIPE_SECRET_KEY } = process.env in a client component denies',
    check,
    ctx: { filePath: 'components/Donate.tsx', content: DESTRUCTURED_ENV_IN_CLIENT, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
  {
    name: "next.config's env block inlining STRIPE_SECRET_KEY denies",
    check,
    ctx: { filePath: 'next.config.js', content: NEXT_CONFIG_ENV_BLOCK, toolName: 'Write', projectDir: '/tmp/x' },
    expected: 'deny',
  },
];
