#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Renders docs/COVERAGE.md from the catalog. Single source of truth, no markdown drift.
 *
 * Two deliberate choices:
 *   - Country names come from Intl.DisplayNames, not a hardcoded table. Adding a country
 *     used to mean editing this file too; now it does not.
 *   - The header stamps the newest last_verified_at in the data, NOT today's date. Stamping
 *     today made every re-run dirty the file, which makes a drift check impossible.
 *
 * Run:   npm run generate:coverage
 * Check: npm run check:coverage
 */
const fs = require('fs');
const path = require('path');
const { loadAll, ROOT } = require('./lib/catalog');

const OUT_FILE = path.join(ROOT, 'docs', 'COVERAGE.md');

const LATAM_CODES = new Set([
  'MX','GT','BZ','SV','HN','NI','CR','PA','CU','DO','PR','HT','JM',
  'CO','VE','EC','PE','BO','BR','PY','UY','AR','CL',
]);

// Intl uses ISO-3166; the catalog uses a couple of legacy keys.
const NAME_OVERRIDES = { UK: 'United Kingdom' };
const display = new Intl.DisplayNames(['en'], { type: 'region' });
const countryName = (code) => {
  if (NAME_OVERRIDES[code]) return NAME_OVERRIDES[code];
  try { return display.of(code) || code; } catch { return code; }
};

const LEVEL_BADGE = { build: 'B', generic: 'G', advise: 'A' };

function renderProviders(ids, byId) {
  if (!ids || !ids.length) return '—';
  return ids
    .map((id) => {
      const p = byId[id];
      if (!p) return `${id} (?)`;
      const lvl = LEVEL_BADGE[p.integration_level] || '?';
      return `${p.name} (${lvl}${p.wave !== undefined ? p.wave : '?'})`;
    })
    .join(' · ');
}

function main() {
  const check = process.argv.includes('--check');
  const A = loadAll();
  const byId = Object.fromEntries(A.providers.providers.map((p) => [p.id, p]));
  const regions = A.regions.regions;

  const dataThrough = A.providers.providers
    .map((p) => p.last_verified_at).sort().pop();

  const latam = [], global = [], unsupported = [];
  for (const code of Object.keys(regions).sort()) {
    const r = regions[code];
    if (r.unsupported) unsupported.push([code, r]);
    else if (LATAM_CODES.has(code)) latam.push([code, r]);
    else global.push([code, r]);
  }

  const row = ([code, r]) => {
    const flags = [];
    if (r.requires_local_acquirer) flags.push('local acquirer required');
    if (r.instant_rail) flags.push(`rail: \`${r.instant_rail}\``);
    if (r.tax && r.tax.einvoice && r.tax.einvoice.mandate) flags.push(`e-invoice: ${r.tax.einvoice.mandate.toUpperCase()}`);
    return `| ${countryName(code)} | \`${code}\` | ${renderProviders(r.primary_providers, byId)} | ${renderProviders(r.fallback_cross_border_mor, byId)} | ${flags.join(' · ') || '—'} |`;
  };

  const table = (rows) =>
    ['| Country | Code | Primary providers | Fallback MoR | Notes |', '|---|---|---|---|---|', ...rows.map(row)].join('\n');

  const levelCounts = A.providers.providers.reduce((a, p) => {
    a[p.integration_level] = (a[p.integration_level] || 0) + 1; return a;
  }, {});

  const out = `# Country × Provider coverage

> Auto-generated from \`skills/payment-advisor/data/\`. Run \`npm run generate:coverage\` to regenerate.
> Reflects catalog data verified through **${dataThrough}**.

**Integration level** is what PagoKit will actually do for you:

| Badge | Level | What PagoKit does |
|---|---|---|
| \`B\` | build | Writes the full idiomatic integration from hand-written fragments |
| \`G\` | generic | Writes a working scaffold composed from the provider's verification family |
| \`A\` | advise | Recommends and explains, but **will not write the code** — you get docs and a checklist |

The digit after the badge is the delivery wave (\`0\` = already shipped).

**Totals:** ${latam.length + global.length} supported countries · ${unsupported.length} unsupported · ${A.providers.providers.length} providers (${Object.entries(levelCounts).map(([k, v]) => `${v} ${k}`).join(', ')}) · ${A.methods.methods.length} payment methods · ${A.currencies.currencies.length} currencies.

---

## LATAM (${latam.length} countries)

${table(latam)}

---

## Rest of world (${global.length} countries)

${table(global)}

---

## Unsupported (${unsupported.length} countries)

Sanctioned or otherwise blocked. The advisor refuses to recommend a provider here.

| Country | Code | Reason | Comment |
|---|---|---|---|
${unsupported.map(([code, r]) => `| ${countryName(code)} | \`${code}\` | \`${r.reason}\` | ${r.comment || ''} |`).join('\n')}
`;

  if (check) {
    const current = fs.existsSync(OUT_FILE) ? fs.readFileSync(OUT_FILE, 'utf8') : null;
    if (current !== out) {
      console.error('[FAIL] docs/COVERAGE.md is out of date. Run: npm run generate:coverage');
      process.exit(1);
    }
    console.log('[OK]   docs/COVERAGE.md is up to date');
    return;
  }
  fs.writeFileSync(OUT_FILE, out);
  console.log(`[OK] Wrote docs/COVERAGE.md (${latam.length} LATAM · ${global.length} global · ${unsupported.length} unsupported)`);
}

main();
