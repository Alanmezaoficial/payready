// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const mod = require('../pci-script-integrity');

// The repo runner resolves `check` by name (`${check}.js`); the group self-verify calls
// `check.run(ctx)` directly. This object satisfies both: it delegates through the prototype
// and stringifies back to the rule id.
const check = Object.assign(Object.create(mod), { toString: () => mod.RULE_ID });

// --- Real fixture project roots -------------------------------------------------------
// Condition (a) is a filesystem fact, so it needs real directories. The `.git` marker stops
// walkUpForFile from escaping into the machine's temp root, which keeps the tests deterministic.
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'pagokit-pci-'));
const NO_INVENTORY_DIR = path.join(TMP_ROOT, 'no-inventory');
const WITH_INVENTORY_DIR = path.join(TMP_ROOT, 'with-inventory');

fs.mkdirSync(NO_INVENTORY_DIR, { recursive: true });
fs.mkdirSync(WITH_INVENTORY_DIR, { recursive: true });
fs.writeFileSync(path.join(NO_INVENTORY_DIR, '.git'), 'gitdir: fixture\n');
fs.writeFileSync(path.join(WITH_INVENTORY_DIR, '.git'), 'gitdir: fixture\n');
fs.writeFileSync(
  path.join(WITH_INVENTORY_DIR, 'payment-page-scripts.json'),
  JSON.stringify(
    {
      scripts: [
        {
          src: 'https://js.stripe.com/v3',
          justification: 'PSP loader — tokenises the PAN inside a Stripe-owned iframe',
          authorised_by: 'payments@example.com',
          integrity: null,
        },
      ],
    },
    null,
    2
  )
);

// --- Fixtures -------------------------------------------------------------------------

const STRIPE_ELEMENTS_PAGE = `'use client';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <form>
        <PaymentElement />
        <button type="submit">Pagar</button>
      </form>
    </Elements>
  );
}
`;

const STRIPE_ELEMENTS_PAGE_WITH_LOADER = `'use client';
import Script from 'next/script';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  return (
    <>
      <Script src="https://js.stripe.com/v3" strategy="beforeInteractive" />
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <PaymentElement />
      </Elements>
    </>
  );
}
`;

const SERVER_ROUTE_RENDERING_LOADER = `import { NextResponse } from 'next/server';

export async function POST(request) {
  const html = '<!doctype html><script src="https://js.stripe.com/v3"></script>';
  return new NextResponse(html, { headers: { 'content-type': 'text/html' } });
}
`;

const DOCS_PAGE_MENTIONS_IN_COMMENT_AND_STRING = `export default function DocsPage() {
  // Example: loadStripe(pk) mounts <PaymentElement /> and calls stripe.elements() for you.
  const snippet = "const stripe = await loadStripe(key); stripe.elements(); // <CardElement />";
  return <pre>{snippet}</pre>;
}
`;

const IGNORE_TAGGED = `'use client';
// pagokit-ignore: pci-script-integrity -- script inventory is maintained in the compliance tracker
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <PaymentElement />
    </Elements>
  );
}
`;

const MARKETING_PAGE_UNPINNED_CDN = `export default function BlogPost() {
  return (
    <article>
      <h1>Como cobrar en LATAM</h1>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </article>
  );
}
`;

const PAYMENT_PAGE_THIRD_PARTY_NO_SRI = `'use client';
import Script from 'next/script';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  return (
    <>
      <Script src="https://js.stripe.com/v3" strategy="beforeInteractive" />
      <Script src="https://cdn.jsdelivr.net/npm/imask@7/dist/imask.min.js" />
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <PaymentElement />
      </Elements>
    </>
  );
}
`;

const PAYMENT_PAGE_THIRD_PARTY_WITH_SRI = `'use client';
import Script from 'next/script';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  return (
    <>
      <Script src="https://js.stripe.com/v3" strategy="beforeInteractive" />
      <Script
        src="https://cdn.jsdelivr.net/npm/imask@7.6.1/dist/imask.min.js"
        integrity="sha384-8B5vJcMH1nZ3zLUmB2Ff2b2mM0nB3bJt0mB5hQ1cQ0mP1nJ0sN2kL9dQ8vT1cJ4"
        crossorigin="anonymous"
      />
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <PaymentElement />
      </Elements>
    </>
  );
}
`;

const PAYMENT_PAGE_INLINE_GTAG = `'use client';
import { useEffect } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function CheckoutPage({ clientSecret }) {
  useEffect(() => {
    window.gtag('event', 'begin_checkout', { value: 49.9, currency: 'MXN' });
  }, []);
  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <PaymentElement />
    </Elements>
  );
}
`;

const WOMPI_WIDGET_BUTTON = `'use client';

export function WompiButton({ reference, amountInCents, signature }) {
  const open = () => {
    const checkout = new WidgetCheckout({
      currency: 'COP',
      amountInCents,
      reference,
      publicKey: process.env.NEXT_PUBLIC_WOMPI_PUBLIC_KEY,
      'signature:integrity': signature,
    });
    checkout.open((result) => console.log(result.transaction.id));
  };
  return <button onClick={open}>Pagar con Wompi</button>;
}
`;

// --- Adversarial-audit fixture roots --------------------------------------------------
// A monorepo whose inventory belongs to the app that owns the checkout, not to the repo root.
const MONOREPO_ROOT = path.join(TMP_ROOT, 'monorepo');
const MONOREPO_APP = path.join(MONOREPO_ROOT, 'apps', 'web');
fs.mkdirSync(path.join(MONOREPO_APP, 'app', 'checkout'), { recursive: true });
fs.writeFileSync(path.join(MONOREPO_ROOT, '.git'), 'gitdir: fixture\n');
fs.writeFileSync(
  path.join(MONOREPO_APP, 'payment-page-scripts.json'),
  JSON.stringify({ scripts: [{ src: 'https://js.stripe.com/v3', justification: 'PSP loader', integrity: null }] })
);

// A project whose inventory authorises the bot-protection script that cannot carry an SRI hash.
const TURNSTILE_DIR = path.join(TMP_ROOT, 'turnstile-inventoried');
fs.mkdirSync(TURNSTILE_DIR, { recursive: true });
fs.writeFileSync(path.join(TURNSTILE_DIR, '.git'), 'gitdir: fixture\n');
fs.writeFileSync(
  path.join(TURNSTILE_DIR, 'payment-page-scripts.json'),
  JSON.stringify({
    scripts: [
      { src: 'https://js.stripe.com/v3', justification: 'PSP loader', integrity: null },
      {
        src: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
        justification: 'bot protection on the payment page; generated per request, no SRI possible',
        authorised_by: 'payments@example.com',
        integrity: null,
      },
    ],
  })
);

const STORYBOOK_STORY = `import type { Meta } from '@storybook/react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe('pk_test_000');

export default { title: 'Checkout/Form' } satisfies Meta;
export const Default = () => (
  <Elements stripe={stripePromise}>
    <PaymentElement />
  </Elements>
);
`;

const CYPRESS_SPEC = `import { loadStripe } from '@stripe/stripe-js';

describe('checkout', () => {
  it('mounts the payment element', () => {
    cy.visit('/checkout');
    cy.wrap(loadStripe('pk_test_000')).should('exist');
  });
});
`;

const MONOREPO_CHECKOUT_PAGE = `'use client';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function Page({ clientSecret }) {
  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <PaymentElement />
    </Elements>
  );
}
`;

const CHECKOUT_BLOCKS_ANALYTICS = `'use client';
import { useEffect } from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

// PCI 6.4.3: nothing from these origins may execute while the payment element is mounted.
const BLOCKED_ON_CHECKOUT = [
  'https://www.googletagmanager.com',
  'https://connect.facebook.net',
];

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function Page({ clientSecret }) {
  useEffect(() => {
    blockOrigins(BLOCKED_ON_CHECKOUT);
  }, []);
  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <PaymentElement />
    </Elements>
  );
}
`;

const CHECKOUT_WITH_TURNSTILE = `'use client';
import Script from 'next/script';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function Page({ clientSecret }) {
  return (
    <>
      <Script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer />
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <PaymentElement />
      </Elements>
    </>
  );
}
`;

const SPLIT_ELEMENTS_WITH_GTM = `'use client';
import Script from 'next/script';
import { Elements, CardNumberElement, CardCvcElement } from '@stripe/react-stripe-js';
import { stripePromise } from '@/lib/stripe';

export default function Page() {
  return (
    <>
      <Script src="https://www.googletagmanager.com/gtm.js?id=GTM-XYZ" />
      <Elements stripe={stripePromise}>
        <CardNumberElement />
        <CardCvcElement />
      </Elements>
    </>
  );
}
`;

const MERCADOPAGO_BRICK_MOUNT = `'use client';
import { useEffect } from 'react';

export default function Pagar({ amount }) {
  useEffect(() => {
    const mp = new MercadoPago(process.env.NEXT_PUBLIC_MP_PUBLIC_KEY, { locale: 'es-MX' });
    const bricksBuilder = mp.bricks();
    bricksBuilder.create('cardPayment', 'brick_container', { initialization: { amount } });
  }, [amount]);
  return <div id="brick_container" />;
}
`;

const GTM_VIA_NEXT_THIRD_PARTIES = `'use client';
import { GoogleTagManager } from '@next/third-parties/google';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, PaymentElement } from '@stripe/react-stripe-js';

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function Page({ clientSecret }) {
  return (
    <>
      <GoogleTagManager gtmId="GTM-XYZ" />
      <Elements stripe={stripePromise} options={{ clientSecret }}>
        <PaymentElement />
      </Elements>
    </>
  );
}
`;

// --- Cases ----------------------------------------------------------------------------

module.exports = [
  {
    name: 'Stripe Elements page with no payment-page-scripts.json is denied',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: STRIPE_ELEMENTS_PAGE,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'Wompi WidgetCheckout mount with no inventory is denied',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'src/components/WompiButton.jsx'),
      content: WOMPI_WIDGET_BUTTON,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'Payment page with inventory and only the PSP loader passes',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: STRIPE_ELEMENTS_PAGE_WITH_LOADER,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: versionless js.stripe.com loader without integrity= is never demanded SRI',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/pagar/page.tsx'),
      content: STRIPE_ELEMENTS_PAGE_WITH_LOADER,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'EDGE: server route that renders the loader in an HTML string is not a payment page',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/api/checkout/route.ts'),
      content: SERVER_ROUTE_RENDERING_LOADER,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'Third-party CDN script without integrity/crossorigin on a payment page is denied',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: PAYMENT_PAGE_THIRD_PARTY_NO_SRI,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'Third-party script pinned with integrity + crossorigin passes',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: PAYMENT_PAGE_THIRD_PARTY_WITH_SRI,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'Inline gtag() on a payment page is denied',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: PAYMENT_PAGE_INLINE_GTAG,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'Payment element named only in a comment and a string literal passes',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/docs/page.tsx'),
      content: DOCS_PAGE_MENTIONS_IN_COMMENT_AND_STRING,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'pagokit-ignore tag passes',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: IGNORE_TAGGED,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'Unrelated marketing page with an unpinned CDN script passes',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/blog/page.tsx'),
      content: MARKETING_PAGE_UNPINNED_CDN,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'FP: Storybook story mounting Stripe Elements against a test key passes',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'src/components/CheckoutForm.stories.tsx'),
      content: STORYBOOK_STORY,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'FP: Cypress e2e spec that mounts the payment element passes',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'cypress/e2e/checkout.cy.ts'),
      content: CYPRESS_SPEC,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'FP: monorepo inventory next to the app (projectDir is the repo root) passes',
    check,
    ctx: {
      filePath: path.join(MONOREPO_APP, 'app/checkout/page.tsx'),
      content: MONOREPO_CHECKOUT_PAGE,
      toolName: 'Write',
      projectDir: MONOREPO_ROOT,
    },
    expected: 'pass',
  },
  {
    name: 'FP: checkout page that lists analytics origins in a consent BLOCKlist passes',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: CHECKOUT_BLOCKS_ANALYTICS,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'FP: Turnstile (SRI-incompatible) declared in the inventory passes',
    check,
    ctx: {
      filePath: path.join(TURNSTILE_DIR, 'app/checkout/page.tsx'),
      content: CHECKOUT_WITH_TURNSTILE,
      toolName: 'Write',
      projectDir: TURNSTILE_DIR,
    },
    expected: 'pass',
  },
  {
    name: 'Turnstile NOT declared in the inventory is denied (inventory it; do not hash it)',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: CHECKOUT_WITH_TURNSTILE,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'BYPASS: split Stripe Elements (<CardNumberElement>) is a mount too',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: SPLIT_ELEMENTS_WITH_GTM,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'BYPASS: Mercado Pago brick mounted through mp.bricks() is a mount too',
    check,
    ctx: {
      filePath: path.join(NO_INVENTORY_DIR, 'app/pagar/page.jsx'),
      content: MERCADOPAGO_BRICK_MOUNT,
      toolName: 'Write',
      projectDir: NO_INVENTORY_DIR,
    },
    expected: 'deny',
  },
  {
    name: 'BYPASS: GTM loaded through <GoogleTagManager> instead of a script tag is denied',
    check,
    ctx: {
      filePath: path.join(WITH_INVENTORY_DIR, 'app/checkout/page.tsx'),
      content: GTM_VIA_NEXT_THIRD_PARTIES,
      toolName: 'Write',
      projectDir: WITH_INVENTORY_DIR,
    },
    expected: 'deny',
  },
];
