// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Shared catalog loading + the macro-region vocabulary.
 *
 * Macro regions exist because some providers genuinely operate at a bloc level and
 * enumerating 27 EU member states we have not individually verified would be inventing
 * data. A macro is explicit and checkable; a silently-unvalidated "EU" string is not.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const DATA = path.join(ROOT, 'skills/payment-advisor/data');

const MACRO_REGIONS = {
  GLOBAL: 'Anywhere the provider is not explicitly blocked.',
  EU: 'European Union member states.',
  EEA: 'European Economic Area.',
  LATAM: 'Latin America.',
  SEA: 'Southeast Asia.',
  MENA: 'Middle East and North Africa.',
  APAC: 'Asia-Pacific.',
  AFRICA: 'Sub-Saharan Africa.',
};

const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

function loadAll() {
  const providersDir = path.join(DATA, 'providers');
  const sources = fs.existsSync(providersDir)
    ? fs.readdirSync(providersDir).filter((f) => f.endsWith('.json')).sort()
        .map((f) => ({ file: `providers/${f}`, data: readJson(path.join(providersDir, f)) }))
    : [];
  return {
    DATA,
    ROOT,
    sources,
    providers: readJson(path.join(DATA, 'providers.json')),
    index: fs.existsSync(path.join(DATA, 'providers.index.json'))
      ? readJson(path.join(DATA, 'providers.index.json')) : null,
    regions: readJson(path.join(DATA, 'regions.json')),
    methods: readJson(path.join(DATA, 'methods.json')),
    use_cases: readJson(path.join(DATA, 'use_cases.json')),
    currencies: readJson(path.join(DATA, 'currencies.json')),
  };
}

/** Regions a provider covers, expanding macros against the known region set. */
function expandRegions(codes, knownRegionCodes) {
  const out = new Set();
  for (const c of codes || []) {
    if (c === 'GLOBAL') { knownRegionCodes.forEach((k) => out.add(k)); continue; }
    if (MACRO_REGIONS[c]) { out.add(c); continue; }
    out.add(c);
  }
  return out;
}

/** True when `code` is covered by `codes`, honouring macros. Conservative by design. */
function covers(codes, code) {
  if (!codes) return false;
  if (codes.includes(code)) return true;
  if (codes.includes('GLOBAL')) return true;
  const EU_MEMBERS = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE'];
  if ((codes.includes('EU') || codes.includes('EEA')) && EU_MEMBERS.includes(code)) return true;
  const LATAM = ['AR','BO','BR','CL','CO','CR','DO','EC','GT','HN','MX','NI','PA','PE','PR','PY','SV','UY','VE'];
  if (codes.includes('LATAM') && LATAM.includes(code)) return true;
  return false;
}

module.exports = { MACRO_REGIONS, loadAll, expandRegions, covers, readJson, DATA, ROOT };
