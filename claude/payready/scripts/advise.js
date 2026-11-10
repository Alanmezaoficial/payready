#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Deterministic provider recommendation. The advisor skill calls this instead of doing
 * the arithmetic itself, so the ranking is reproducible, testable and auditable.
 *
 *   node scripts/advise.js --country MX --billing one_time --methods oxxo --entity individual \
 *     --product digital_goods --amount 500 --currency MXN
 *   node scripts/advise.js --json '{"seller_country":"US","product_type":"saas",...}'
 *   node scripts/advise.js --country CL --explain      # human-readable, shows the maths
 */
const { advise } = require('./lib/advisor');

const argv = process.argv.slice(2);
const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
const flag = (n) => argv.includes(`--${n}`);
const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : []);

if (flag('help') || (!arg('country') && !arg('json'))) {
  console.log(`Usage:
  node scripts/advise.js --country <ISO2> [options]
  node scripts/advise.js --json '<profile JSON>'

Options:
  --country CODE          seller country (required)
  --buyers A,B,C          buyer regions (default: same as seller)
  --billing MODE          one_time | subscription
  --methods a,b           required payment method ids
  --entity TYPE           individual | solo | smb | company
  --product TYPE          saas | digital_goods | physical | service | donations | marketplace
  --platform P            web | ios | android | pos
  --use-cases a,b         detected use case ids
  --tax-automation        the seller wants the provider to handle tax
  --keys-within N         days available before keys are needed
  --amount N --currency C example transaction for the fee maths
  --explain               human-readable output instead of JSON`);
  process.exit(arg('country') || arg('json') ? 0 : 1);
}

const profile = arg('json') ? JSON.parse(arg('json')) : {
  seller_country: arg('country'),
  buyer_regions: list(arg('buyers')),
  billing_mode: arg('billing', 'one_time'),
  required_methods: list(arg('methods')),
  entity_type: arg('entity', 'company'),
  product_type: arg('product', 'unknown'),
  platform: arg('platform', 'web'),
  use_cases: list(arg('use-cases')),
  needs_tax_automation: flag('tax-automation'),
  needs_keys_within_days: arg('keys-within') ? Number(arg('keys-within')) : null,
  example_amount: arg('amount') ? Number(arg('amount')) : undefined,
  example_currency: arg('currency'),
};

const result = advise(profile);

if (!flag('explain')) { console.log(JSON.stringify(result, null, 2)); process.exit(0); }

if (result.refused) { console.log(`REFUSED: ${result.refusal_reason}`); process.exit(0); }
if (!result.recommendation) { console.log('No provider matched and no fallback is configured for this region.'); process.exit(0); }

const r = result.recommendation;
const LEVEL = {
  build: 'PagoKit will write the full integration.',
  generic: 'PagoKit will write a working scaffold from this provider\'s verification family.',
  advise: 'PagoKit will NOT write this integration — you get the recommendation and a checklist.',
};
console.log(`Recommendation: ${r.name}  [${r.integration_level}] — ${LEVEL[r.integration_level]}\n`);
console.log('Why:'); r.why.forEach((w) => console.log(`  • ${w}`));
if (r.fee) console.log(`\nCost on a typical charge:\n  ${r.fee.explanation}  →  you receive ${r.fee.net} ${r.fee.currency}`);
console.log(`\nScore: ${r.score}  (base ${r.base}${r.modifiers.map((m) => ` ${m.delta >= 0 ? '+' : ''}${m.delta} ${m.key}`).join('')}${r.integration_level === 'build' ? ' +0.5 build-level' : r.integration_level === 'generic' ? ' +0.25 generic-level' : ''})`);
if (r.caveats.length) { console.log('\nThings to know:'); r.caveats.forEach((c) => console.log(`  ! ${c}`)); }
if (result.rejected.length) {
  console.log('\nRuled out:');
  result.rejected.forEach((x) => console.log(`  × ${x.name} [${x.filter}] ${x.reason}`));
}
if (result.disclosures.length) { console.log('\nAlso true in this market:'); result.disclosures.forEach((d) => console.log(`  * ${d}`)); }
const others = result.candidates.slice(1, 3);
if (others.length) { console.log('\nAlternatives:'); others.forEach((c) => console.log(`  - ${c.name} (${c.score}) [${c.integration_level}]`)); }
console.log(`\nInformation verified on ${r.last_verified_at}.`);
