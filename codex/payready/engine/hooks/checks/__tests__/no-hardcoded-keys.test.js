// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

// Build a synthetic value at runtime; this fixture has no provider credentials.
const fakeLiveKey = 'sk_live_' + 'NOTAREALKEYJUSTAFIXTURE001';

module.exports = [
  {
    name: 'allows test-key placeholder in .env.example',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/.env.example',
      content: 'STRIPE_SECRET_KEY=sk_test_REPLACE_ME\nMP_ACCESS_TOKEN=TEST-REPLACE_ME\n',
    },
    expected: 'pass',
  },
  {
    name: 'denies live Stripe key in .env.example',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/.env.example',
      content: `STRIPE_SECRET_KEY=${fakeLiveKey}\n`,
    },
    expected: 'deny',
  },
  {
    name: 'denies hardcoded Stripe live key in source',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: `import Stripe from 'stripe';\nconst stripe = new Stripe('${fakeLiveKey}');\n`,
    },
    expected: 'deny',
  },
  {
    name: 'allows reference to process.env (correct pattern)',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/app/api/checkout/route.ts',
      content: `import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\n`,
    },
    expected: 'pass',
  },
  {
    name: 'ignores keys inside line comments (documentation)',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/lib/payments/stripe.ts',
      content: `// Example: STRIPE_SECRET_KEY=${fakeLiveKey}\nconst k = process.env.STRIPE_SECRET_KEY;\n`,
    },
    expected: 'pass',
  },
  {
    name: 'respects pagokit-ignore tag',
    check: 'no-hardcoded-keys',
    ctx: {
      filePath: '/proj/app/api/test/route.ts',
      content: `// pagokit-ignore: no-hardcoded-keys -- test fixture for unit tests\nconst k = '${fakeLiveKey}';\n`,
    },
    expected: 'pass',
  },
];
