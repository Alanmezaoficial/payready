#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * PagoKit data validation.
 *
 * Two jobs:
 *   1. JSON Schema conformance for every data file.
 *   2. Cross-file integrity + the invariants that keep a 40-provider catalog honest.
 *
 * The invariants matter more than the schemas. A schema stops a typo; the invariants stop
 * PagoKit from generating a signature verifier for a scheme nobody actually verified.
 */
const fs = require('fs');
const path = require('path');
const Ajv = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const { loadAll, covers, MACRO_REGIONS, readJson } = require('./lib/catalog');

const ROOT = path.resolve(__dirname, '..');
const SCHEMAS = path.join(ROOT, 'schemas');
const DATA = path.join(ROOT, 'skills/payment-advisor/data');

const errors = [];
const warnings = [];
const fail = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);

// ---------------------------------------------------------------- schema pass
const PAIRS = [
  ['providers.json', 'providers.schema.json'],
  ['regions.json', 'regions.schema.json'],
  ['use_cases.json', 'use_cases.schema.json'],
  ['methods.json', 'methods.schema.json'],
  ['currencies.json', 'currencies.schema.json'],
];

// Ajv caches by $id, so each schema is compiled exactly once and reused below.
const compiled = {};
const compile = (schemaFile) => (compiled[schemaFile] ||= ajv.compile(readJson(path.join(SCHEMAS, schemaFile))));

for (const [dataFile, schemaFile] of PAIRS) {
  const dataPath = path.join(DATA, dataFile);
  if (!fs.existsSync(dataPath)) { fail(`${dataFile} is missing`); continue; }
  const validate = compile(schemaFile);
  if (validate(readJson(dataPath))) {
    console.log(`[OK]   ${dataFile} validates against ${schemaFile}`);
  } else {
    fail(`${dataFile} against ${schemaFile}`);
    for (const e of validate.errors) {
      fail(`    ${e.instancePath || '(root)'} ${e.message} ${JSON.stringify(e.params)}`);
    }
  }
}

// Each per-provider source file is validated on its own so the error points at the file
// you actually edit, not at a byte offset inside the generated aggregate.
const providerSchema = compile('providers.schema.json');
const srcDir = path.join(DATA, 'providers');
if (fs.existsSync(srcDir)) {
  for (const f of fs.readdirSync(srcDir).filter((x) => x.endsWith('.json')).sort()) {
    const one = { providers: [readJson(path.join(srcDir, f))] };
    if (!providerSchema(one)) {
      fail(`providers/${f} is invalid`);
      for (const e of providerSchema.errors) {
        fail(`    ${e.instancePath.replace('/providers/0', '')} ${e.message} ${JSON.stringify(e.params)}`);
      }
    }
  }
  console.log(`[OK]   ${fs.readdirSync(srcDir).filter((x) => x.endsWith('.json')).length} per-provider source files validate individually`);
}

// ------------------------------------------------------------- integrity pass
console.log('\nCross-file integrity checks:');
const A = loadAll();
const providers = A.providers.providers;
const regions = A.regions.regions;
const methods = A.methods.methods;
const currencies = A.currencies.currencies;
const useCases = A.use_cases.use_cases;

const providerIds = providers.map((p) => p.id);
const methodIds = methods.map((m) => m.id);
const currencyCodes = currencies.map((c) => c.code);
const regionCodes = Object.keys(regions);

const dupes = (arr, label) => {
  const seen = new Set(), dup = new Set();
  for (const x of arr) (seen.has(x) ? dup : seen).add(x);
  for (const d of dup) fail(`duplicate ${label} id: "${d}"`);
};
dupes(providerIds, 'provider');
dupes(methodIds, 'method');
dupes(currencyCodes, 'currency');

const providerSet = new Set(providerIds);
const methodSet = new Set(methodIds);
const currencySet = new Set(currencyCodes);
const regionSet = new Set(regionCodes);
const knownRegionToken = (c) => regionSet.has(c) || Object.hasOwn(MACRO_REGIONS, c);

// regions -> providers
for (const [code, r] of Object.entries(regions)) {
  for (const key of ['primary_providers', 'fallback_cross_border_mor']) {
    for (const id of r[key] || []) {
      if (!providerSet.has(id)) fail(`regions.${code}.${key} references unknown provider: "${id}"`);
    }
  }
  if (r.default_currency && !currencySet.has(r.default_currency)) {
    fail(`regions.${code}.default_currency "${r.default_currency}" is not declared in currencies.json`);
  }
  if (r.instant_rail && !methodSet.has(r.instant_rail)) {
    warn(`regions.${code}.instant_rail "${r.instant_rail}" is not declared in methods.json`);
  }
}

// use_cases -> providers
for (const [name, uc] of Object.entries(useCases)) {
  for (const key of ['recommended_providers_ranked', 'blocked_providers']) {
    for (const id of uc[key] || []) {
      if (!providerSet.has(id)) fail(`use_cases.${name}.${key} references unknown provider: "${id}"`);
    }
  }
}

// methods -> providers / methods
for (const m of methods) {
  for (const id of m.reachable_via || []) {
    if (!providerSet.has(id)) fail(`methods.${m.id}.reachable_via references unknown provider: "${id}"`);
  }
  if (m.succeeded_by && !methodSet.has(m.succeeded_by)) {
    fail(`methods.${m.id}.succeeded_by references unknown method: "${m.succeeded_by}"`);
  }
  for (const id of m.resolves_to || []) {
    if (!methodSet.has(id)) fail(`methods.${m.id}.resolves_to references unknown method: "${id}"`);
  }
}

// currencies: exponent and the boolean helpers must agree
for (const c of currencies) {
  if ((c.exponent === 0) !== !!c.zero_decimal) fail(`currencies.${c.code}: exponent ${c.exponent} disagrees with zero_decimal`);
  if ((c.exponent === 3) !== !!c.three_decimal) fail(`currencies.${c.code}: exponent ${c.exponent} disagrees with three_decimal`);
}

// providers -> everything
for (const p of providers) {
  const where = `providers.${p.id}`;

  // methods must be declared. This used to be a warning; at 40 providers a warning is a
  // green CI run over a broken catalog, so it is an error now.
  for (const id of p.methods) {
    if (!methodSet.has(id)) fail(`${where}.methods has "${id}" which is not declared in methods.json`);
  }
  for (const c of p.currencies) {
    if (!currencySet.has(c)) fail(`${where}.currencies has "${c}" which is not declared in currencies.json`);
  }
  for (const key of ['merchant_domicile_regions', 'method_coverage_regions']) {
    for (const c of p[key] || []) {
      if (!knownRegionToken(c)) fail(`${where}.${key} has "${c}" which is neither a regions.json key nor a macro region (${Object.keys(MACRO_REGIONS).join(', ')})`);
    }
  }
  for (const key of ['layers_over', 'alternatives_to']) {
    for (const id of p[key] || []) {
      if (!providerSet.has(id)) fail(`${where}.${key} references unknown provider: "${id}"`);
    }
  }

  // --- THE EVIDENCE RULE -------------------------------------------------
  // An LLM-written claim can never be marked as verified. This is the cheapest durable
  // defence against catalog rot, and it is exactly the failure the audits found.
  const ev = p.webhook && p.webhook.evidence;
  if (ev && ev.verified_by === 'llm-generated' && ev.confidence === 'high') {
    fail(`${where}.webhook.evidence: verified_by "llm-generated" cannot carry confidence "high". Verify against the provider's own docs first.`);
  }
  if (p.checkout_spec && p.checkout_spec.evidence
      && p.checkout_spec.evidence.verified_by === 'llm-generated'
      && p.checkout_spec.evidence.confidence === 'high') {
    fail(`${where}.checkout_spec.evidence: verified_by "llm-generated" cannot carry confidence "high".`);
  }

  // --- THE GENERATOR INVARIANT -------------------------------------------
  // If we cannot vouch for the signature scheme, we must not claim we can build it.
  if ((p.integration_level === 'build' || p.integration_level === 'generic')
      && p.notification_model === 'webhook'
      && p.webhook.verification_family !== 'none'
      && (!ev || ev.confidence !== 'high')) {
    fail(`${where}: integration_level "${p.integration_level}" requires webhook.evidence.confidence "high". Demote to "advise" or verify the scheme.`);
  }

  // --- shape coherence ----------------------------------------------------
  if (p.notification_model === 'return_url_commit' && !p.commit_required) {
    fail(`${where}: notification_model "return_url_commit" requires commit_required (an uncommitted transaction can auto-reverse).`);
  }
  if (p.webhook.payload_authoritative === false && !p.webhook.refetch_endpoint) {
    fail(`${where}.webhook: payload_authoritative false requires refetch_endpoint.`);
  }
  if (p.webhook.signature_covers_body === false && p.webhook.payload_authoritative !== false) {
    fail(`${where}.webhook: signature_covers_body false means a verified payload is still forgeable, so payload_authoritative must be false.`);
  }
  const loc = p.webhook.signature_location;
  if (loc && loc !== 'header' && loc !== 'none' && !p.webhook.signature_pointer) {
    fail(`${where}.webhook: signature_location "${loc}" requires signature_pointer.`);
  }
  const fam = p.webhook.verification_family;
  if (fam && fam.startsWith('hmac')) {
    for (const k of ['hash_algo', 'digest_encoding', 'signed_payload_template']) {
      if (!p.webhook[k]) fail(`${where}.webhook: verification_family "${fam}" requires ${k}.`);
    }
  }
  if (p.webhook.replay_mitigation_strategy
      && ['event-id-dedup', 'both'].includes(p.webhook.replay_mitigation_strategy)
      && !p.webhook.event_id_pointer) {
    fail(`${where}.webhook: replay strategy "${p.webhook.replay_mitigation_strategy}" requires event_id_pointer.`);
  }
  if (p.webhook.weak_crypto && !p.webhook.weak_crypto_reason) {
    fail(`${where}.webhook: weak_crypto requires weak_crypto_reason so the generator can warn instead of silently "upgrading" the hash.`);
  }
  if (!(p.credentials || []).some((c) => c.scope === 'server' || c.scope === 'both')) {
    fail(`${where}.credentials: at least one credential must have scope "server".`);
  }
  for (const c of p.credentials || []) {
    if (c.pattern) { try { new RegExp(c.pattern); } catch (e) { fail(`${where}.credentials.${c.id}.pattern is not a valid regex: ${e.message}`); } }
    if (c.live_pattern) { try { new RegExp(c.live_pattern); } catch (e) { fail(`${where}.credentials.${c.id}.live_pattern is not a valid regex: ${e.message}`); } }
    // A loose pattern would false-positive across the user's whole repo.
    if (c.pattern && !/^\^/.test(c.pattern)) {
      warn(`${where}.credentials.${c.id}.pattern is not anchored with ^ - it may match arbitrary user code.`);
    }
  }

  // build-level providers must actually have the fragments they claim
  if (p.integration_level === 'build') {
    const dir = path.join(ROOT, 'skills/integration-builder/templates', p.id);
    const alt = path.join(ROOT, 'skills/integration-builder/overrides', p.id);
    if (!fs.existsSync(dir) && !fs.existsSync(alt)) {
      fail(`${where}: integration_level "build" but neither templates/${p.id}/ nor overrides/${p.id}/ exists.`);
    }
  }
}

// --- reverse region consistency -------------------------------------------
// A country claiming a provider that does not claim the country is a coverage lie.
for (const [code, r] of Object.entries(regions)) {
  for (const id of r.primary_providers || []) {
    const p = providers.find((x) => x.id === id);
    if (!p) continue;
    if (!covers(p.method_coverage_regions, code)) {
      fail(`regions.${code} lists "${id}" as primary, but ${id}.method_coverage_regions does not cover ${code}.`);
    }
  }
  for (const id of r.fallback_cross_border_mor || []) {
    const p = providers.find((x) => x.id === id);
    if (!p) continue;
    if (!p.supports.merchant_of_record) {
      fail(`regions.${code}.fallback_cross_border_mor lists "${id}" which is not a merchant of record.`);
    }
  }
}

// --- summary ---------------------------------------------------------------
if (!errors.length) {
  console.log(`[OK]   ${providers.length} providers, ${methods.length} methods, ${regionCodes.length} regions, ${currencies.length} currencies cross-reference cleanly`);
  console.log('[OK]   evidence rule holds (no llm-generated claim marked high-confidence)');
  console.log('[OK]   generator invariant holds (no build/generic provider without a verified signature scheme)');
}
for (const w of warnings) console.warn(`[WARN] ${w}`);
if (errors.length) {
  console.error('');
  for (const e of errors) console.error(e.startsWith('    ') ? e : `[FAIL] ${e}`);
  console.error(`\n[FAIL] ${errors.filter((e) => !e.startsWith('    ')).length} problem(s) found.`);
  process.exit(1);
}
console.log(`\n[PASS] All data files valid and cross-referenced.${warnings.length ? ` (${warnings.length} warning(s))` : ''}`);
