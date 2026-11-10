#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Advisor regression fixtures.
 *
 * Every case here is a wrong answer PagoKit could give, or did give, before this engine
 * existed. Locking them down is the point: a data edit that reintroduces one fails CI
 * instead of reaching a user.
 */
const { advise } = require('./lib/advisor');
const { loadAll } = require('./lib/catalog');

const catalog = loadAll();
let pass = 0, fail = 0;

function t(name, profile, assertions) {
  const r = advise(profile, catalog);
  for (const [what, fn] of Object.entries(assertions)) {
    let ok = false, detail = '';
    try { ok = fn(r); } catch (e) { detail = e.message; }
    if (ok) { pass++; console.log(`  [OK]   ${name} — ${what}`); }
    else {
      fail++;
      console.error(`  [FAIL] ${name} — ${what}${detail ? ` (${detail})` : ''}`);
      console.error(`         got recommendation: ${r.recommendation ? r.recommendation.id : 'none'}; refused: ${r.refused}; fallback: ${r.fallback_used}`);
    }
  }
}
const rec = (r) => (r.recommendation ? r.recommendation.id : null);
const rejectedFor = (r, id) => r.rejected.find((x) => x.id === id);
const discloses = (r, s) => r.disclosures.some((d) => d.toLowerCase().includes(s.toLowerCase()));

console.log('Advisor regression fixtures\n');

t('MX individual selling with OXXO',
  { seller_country: 'MX', billing_mode: 'one_time', required_methods: ['oxxo'], entity_type: 'individual', product_type: 'digital_goods', example_amount: 500, example_currency: 'MXN' },
  {
    'recommends Mercado Pago over Stripe': (r) => rec(r) === 'mercadopago',
    'rules out Lemon Squeezy on methods': (r) => rejectedFor(r, 'lemonsqueezy')?.filter === 'methods',
    'discloses the CFDI obligation': (r) => discloses(r, 'CFDI'),
    'computes a real fee': (r) => r.recommendation.fee.total > 0,
  });

t('US SaaS subscription',
  { seller_country: 'US', billing_mode: 'subscription', product_type: 'saas', entity_type: 'company', example_amount: 19, example_currency: 'USD' },
  {
    'recommends Stripe': (r) => rec(r) === 'stripe',
    'activates us_saas': (r) => r.active_modifiers.includes('us_saas'),
  });

t('Cross-border digital goods wanting tax handled',
  { seller_country: 'US', buyer_regions: ['US', 'DE', 'FR'], billing_mode: 'subscription', product_type: 'digital_goods', needs_tax_automation: true, example_amount: 20, example_currency: 'USD' },
  {
    'recommends the merchant of record': (r) => rec(r) === 'lemonsqueezy',
    'activates wants_no_fiscal_overhead': (r) => r.active_modifiers.includes('wants_no_fiscal_overhead'),
    'explains the MoR trade-off': (r) => r.recommendation.caveats.some((c) => /merchant of record/i.test(c)),
  });

t('Colombia one-time with PSE',
  { seller_country: 'CO', billing_mode: 'one_time', required_methods: ['pse'], entity_type: 'company', example_amount: 80000, example_currency: 'COP' },
  { 'recommends Wompi': (r) => rec(r) === 'wompi' });

t('Colombia SUBSCRIPTION must not get Wompi',
  { seller_country: 'CO', billing_mode: 'subscription', entity_type: 'company' },
  {
    'rules Wompi out on billing_mode': (r) => rejectedFor(r, 'wompi')?.filter === 'billing_mode',
    'still returns something usable': (r) => rec(r) !== null,
  });

t('Chile must not be answered with Stripe',
  { seller_country: 'CL', billing_mode: 'one_time', entity_type: 'individual', example_amount: 20000, example_currency: 'CLP' },
  {
    'does not recommend Stripe': (r) => rec(r) !== 'stripe',
    'rules Stripe out on region': (r) => rejectedFor(r, 'stripe')?.filter === 'region',
    'warns that CLP is zero-decimal': (r) => discloses(r, '0 decimal'),
  });

t('India must not be answered with Stripe as a domestic PSP',
  { seller_country: 'IN', billing_mode: 'one_time', entity_type: 'company', example_amount: 500, example_currency: 'INR' },
  {
    'does not recommend Stripe': (r) => rec(r) !== 'stripe',
    'discloses that a local acquirer is required': (r) => discloses(r, 'locally licensed'),
  });

t('Sanctioned market is refused, not ranked',
  { seller_country: 'CU', billing_mode: 'one_time' },
  {
    'refuses': (r) => r.refused === true,
    'gives no recommendation': (r) => r.recommendation === null,
    'states the reason': (r) => /sanctions/i.test(r.refusal_reason),
  });

t('Zero-decimal currency is called out',
  { seller_country: 'JP', billing_mode: 'one_time', entity_type: 'company', example_amount: 2000, example_currency: 'JPY' },
  { 'warns about the exponent': (r) => discloses(r, '0 decimal places') });

t('Three-decimal currency is called out',
  { seller_country: 'US', billing_mode: 'one_time', entity_type: 'company', example_amount: 20, example_currency: 'KWD' },
  { 'warns about the exponent': (r) => discloses(r, '3 decimal places') });

t('iOS digital goods activates the IAP penalty',
  { seller_country: 'US', platform: 'ios', product_type: 'digital_goods', billing_mode: 'subscription' },
  { 'activates ios_digital_goods': (r) => r.active_modifiers.includes('ios_digital_goods') });

t('A market with no local provider falls back and says so',
  { seller_country: 'BO', billing_mode: 'one_time', required_methods: ['pix'], entity_type: 'individual' },
  {
    'uses the cross-border fallback': (r) => r.fallback_used === true,
    'labels it as a fallback': (r) => r.recommendation.caveats.some((c) => /fallback/i.test(c)),
  });

t('Every recommendation states what PagoKit will actually build',
  { seller_country: 'US', billing_mode: 'one_time', product_type: 'saas', entity_type: 'company' },
  { 'carries an integration_level': (r) => ['build', 'generic', 'advise'].includes(r.recommendation.integration_level) });

t('Determinism: the same profile ranks identically twice',
  { seller_country: 'BR', billing_mode: 'one_time', required_methods: ['pix'], entity_type: 'individual', example_amount: 100, example_currency: 'BRL' },
  {
    'is stable': (r) => {
      const again = advise({ seller_country: 'BR', billing_mode: 'one_time', required_methods: ['pix'], entity_type: 'individual', example_amount: 100, example_currency: 'BRL' }, catalog);
      return JSON.stringify(r.candidates.map((c) => [c.id, c.score])) === JSON.stringify(again.candidates.map((c) => [c.id, c.score]));
    },
  });

t('An orchestrator is never offered as the provider',
  { seller_country: 'BO', billing_mode: 'one_time', entity_type: 'individual' },
  {
    'does not recommend a layer': (r) => !r.recommendation || !['orchestrator', 'billing_layer', 'entitlement_layer'].includes(
      (catalog.providers.providers.find((p) => p.id === rec(r)) || {}).role),
    'explains that a layer cannot acquire': (r) => r.rejected.some((x) => x.filter === 'role' && /cannot accept a payment on its own/.test(x.reason)),
  });

t('A layer IS offered when the use case asks for that role',
  { seller_country: 'US', billing_mode: 'subscription', required_layer: 'billing_layer' },
  { 'surfaces the billing layer': (r) => r.candidates.some((c) => c.role === 'billing_layer') });

t('India resolves to a locally licensed provider, not a cross-border one',
  { seller_country: 'IN', billing_mode: 'one_time', entity_type: 'company', example_amount: 500, example_currency: 'INR' },
  {
    'does not recommend Stripe': (r) => rec(r) !== 'stripe',
    'rules Stripe out on merchant domicile': (r) => rejectedFor(r, 'stripe')?.filter === 'merchant_domicile',
  });

t("Colombia keeps its curated local default",
  { seller_country: 'CO', billing_mode: 'one_time', required_methods: ['pse'], entity_type: 'company' },
  { 'ranks the curated local default first': (r) => rec(r) === 'wompi' });

t('Every advise-level recommendation says it will not write the code',
  { seller_country: 'CL', billing_mode: 'one_time', entity_type: 'company' },
  {
    'any advise-level candidate carries the disclosure': (r) =>
      r.candidates.filter((c) => c.integration_level === 'advise')
        .every((c) => c.caveats.some((x) => /will NOT write/i.test(x))),
  });

t('iOS digital goods routes to the store, not to a card processor',
  { seller_country: 'US', platform: 'ios', product_type: 'digital_goods', billing_mode: 'subscription', use_cases: ['mobile_digital_goods'] },
  {
    'recommends the entitlement layer': (r) => rec(r) === 'revenuecat',
    'blocks card processors outright': (r) => r.rejected.some((x) => x.id === 'stripe' && x.filter === 'use_case_block'),
    'blocks merchants of record too': (r) => r.rejected.some((x) => x.id === 'lemonsqueezy' && x.filter === 'use_case_block'),
  });

t('A banned vertical routes to a gateway with its own merchant account',
  { seller_country: 'US', product_type: 'physical', billing_mode: 'one_time', use_cases: ['high_risk_vertical'] },
  {
    'does not recommend an aggregator': (r) => !['stripe', 'square', 'paddle', 'lemonsqueezy'].includes(rec(r)),
    'explains the aggregator ban': (r) => r.rejected.some((x) => x.filter === 'use_case_block' && /terms prohibit|frozen/i.test(x.reason)),
  });

console.log('\n----');
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
