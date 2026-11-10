#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Builds the derived catalog artifacts from the per-provider source files.
 *
 *   SOURCE OF TRUTH : skills/payment-advisor/data/providers/<id>.json
 *   GENERATED       : skills/payment-advisor/data/providers.json        (full aggregate)
 *                     skills/payment-advisor/data/providers.index.json  (slim, advisor-facing)
 *
 * Why two outputs. The hooks and the doctor need every field (key patterns, detection
 * hints, env var names), so the aggregate stays. The advisor only needs enough to filter
 * and rank, and at 40+ providers loading the aggregate would cost ~50k tokens on every
 * single run - so it reads the index and pulls the full file only for the finalists.
 *
 * Run:   npm run build:catalog
 * Check: npm run check:catalog   (fails if the generated files drifted)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DATA = path.join(ROOT, 'skills/payment-advisor/data');
const SRC_DIR = path.join(DATA, 'providers');

function loadSources() {
  const files = fs.readdirSync(SRC_DIR).filter((f) => f.endsWith('.json')).sort();
  return files.map((f) => {
    const p = JSON.parse(fs.readFileSync(path.join(SRC_DIR, f), 'utf8'));
    const expected = `${p.id}.json`;
    if (f !== expected) {
      throw new Error(`providers/${f} declares id "${p.id}" - filename must be ${expected}`);
    }
    return p;
  });
}

function toIndexEntry(p) {
  const e = {
    id: p.id,
    name: p.name,
    status: p.status,
    integration_level: p.integration_level,
    role: p.role,
    wave: p.wave,
    merchant_domicile_regions: p.merchant_domicile_regions,
    method_coverage_regions: p.method_coverage_regions,
    currencies: p.currencies,
    methods: p.methods,
    notification_model: p.notification_model,
    verification_family: p.webhook && p.webhook.verification_family,
    webhook_confidence: p.webhook && p.webhook.evidence && p.webhook.evidence.confidence,
    onboarding_model: p.onboarding && p.onboarding.model,
    individual_allowed: !!(p.kyc && p.kyc.individual_allowed),
    supports: {
      one_time: p.supports.one_time,
      subscriptions: p.supports.subscriptions,
      marketplace_payouts: p.supports.marketplace_payouts,
      merchant_of_record: p.supports.merchant_of_record,
      save_card: !!p.supports.save_card,
      card_present: !!p.supports.card_present,
    },
    fees: p.fees ? {
      card_domestic_pct: p.fees.card_domestic_pct,
      card_domestic_fixed_usd: p.fees.card_domestic_fixed_usd,
    } : undefined,
    score_modifiers: p.score_modifiers || {},
    last_verified_at: p.last_verified_at,
    docs_url: p.docs_url,
  };
  if (p.layers_over) e.layers_over = p.layers_over;
  if (p.alternatives_to) e.alternatives_to = p.alternatives_to;
  if (p.deprioritized_reason) e.deprioritized_reason = p.deprioritized_reason;
  return e;
}

const BANNER =
  'GENERATED FILE - do not edit by hand. Source of truth: skills/payment-advisor/data/providers/<id>.json. Run `npm run build:catalog`.';

function build() {
  const providers = loadSources();
  const aggregate = {
    $schema: '../../../schemas/providers.schema.json',
    _generated: BANNER,
    providers,
  };
  const index = {
    _generated: BANNER,
    _comment:
      'Slim catalog index. The advisor loads THIS, filters and ranks, then reads providers/<id>.json only for the finalists.',
    count: providers.length,
    by_level: {
      build: providers.filter((p) => p.integration_level === 'build').map((p) => p.id),
      generic: providers.filter((p) => p.integration_level === 'generic').map((p) => p.id),
      advise: providers.filter((p) => p.integration_level === 'advise').map((p) => p.id),
    },
    providers: providers.map(toIndexEntry),
  };
  return {
    'providers.json': JSON.stringify(aggregate, null, 2) + '\n',
    'providers.index.json': JSON.stringify(index, null, 2) + '\n',
  };
}

function main() {
  const check = process.argv.includes('--check');
  const outputs = build();
  let drift = false;

  for (const [name, content] of Object.entries(outputs)) {
    const target = path.join(DATA, name);
    const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;
    if (check) {
      if (current !== content) {
        console.error(`[FAIL] ${name} is out of date. Run: npm run build:catalog`);
        drift = true;
      } else {
        console.log(`[OK]   ${name} is up to date`);
      }
    } else {
      fs.writeFileSync(target, content);
      console.log(`[OK]   wrote ${name}`);
    }
  }

  if (check && drift) process.exit(1);
  if (!check) {
    const n = JSON.parse(outputs['providers.json']).providers.length;
    console.log(`[DONE] catalog built from ${n} provider source files`);
  }
}

main();
