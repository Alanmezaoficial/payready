#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Emit a validly-signed synthetic webhook event for any provider in the catalog.
 * This is what makes /pagokit:test work beyond Stripe.
 *
 *   node scripts/sign-event.js --provider stripe --secret whsec_x --url http://localhost:3000/api/webhook/stripe
 *   node scripts/sign-event.js --provider wompi --mode forged   # signature that must be rejected
 *   node scripts/sign-event.js --provider stripe --mode replay  # stale timestamp
 *   node scripts/sign-event.js --provider stripe --curl         # print a ready-to-run curl
 */
const { signEvent, UnsignableError } = require('./lib/webhook-sign');
const { loadAll } = require('./lib/catalog');
const SAMPLES = require('./fixtures/sample-events');

const argv = process.argv.slice(2);
const arg = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : argv[i + 1]; };
const flag = (n) => argv.includes(`--${n}`);

const id = arg('provider');
if (!id || flag('help')) {
  console.log('Usage: node scripts/sign-event.js --provider <id> [--secret S] [--url U] [--mode valid|forged|replay] [--event TYPE] [--curl]');
  const lvl = loadAll().providers.providers.map((p) => `  ${p.id.padEnd(16)} ${p.webhook.verification_family}`).join('\n');
  console.log(`\nProviders in the catalog:\n${lvl}`);
  process.exit(id ? 0 : 1);
}

const provider = loadAll().providers.providers.find((p) => p.id === id);
if (!provider) { console.error(`[FAIL] unknown provider "${id}"`); process.exit(1); }

const mode = arg('mode', 'valid');
const secret = arg('secret', 'sec_pagokit_test_1234567890abcdef');
const nowSec = Math.floor(Date.now() / 1000);
const tolerance = provider.webhook.recommended_tolerance_seconds || 300;
const timestamp = mode === 'replay' ? nowSec - tolerance - 600 : nowSec;

const sample = SAMPLES[provider.id];
if (!sample) { console.error(`[FAIL] no sample event for "${id}". Add one to scripts/fixtures/sample-events.js.`); process.exit(1); }

const payload = JSON.parse(JSON.stringify(sample.payload));
const evType = arg('event');
if (evType) {
  if (payload.type) payload.type = evType;
  else if (payload.event) payload.event = evType;
  else if (payload.meta && payload.meta.event_name) payload.meta.event_name = evType;
}

let signed;
try {
  signed = signEvent(provider, { payload, secret, timestamp, extraHeaders: sample.extraHeaders });
} catch (e) {
  if (e instanceof UnsignableError) {
    console.error(`[SKIP] ${e.message}`);
    console.error(`       Capture a real event from the ${provider.name} sandbox instead: ${provider.docs_url}`);
    process.exit(2);
  }
  throw e;
}

if (mode === 'forged') {
  // Flip the last character of the signature so the shape stays valid and only the
  // cryptographic check can catch it. That is exactly what we want to test.
  const hdr = (provider.webhook.signature_header || '').toLowerCase();
  if (provider.webhook.signature_location === 'body_field') {
    const b = JSON.parse(signed.body);
    const ptr = (provider.webhook.signature_pointer || '/signature/checksum').replace(/^\//, '').split('/');
    let node = b; for (let i = 0; i < ptr.length - 1; i++) node = node[ptr[i]];
    const cur = node[ptr[ptr.length - 1]];
    node[ptr[ptr.length - 1]] = cur.slice(0, -1) + (cur.slice(-1) === '0' ? '1' : '0');
    signed.body = JSON.stringify(b);
  } else if (signed.headers[hdr]) {
    const v = signed.headers[hdr];
    signed.headers[hdr] = v.slice(0, -1) + (v.slice(-1) === '0' ? '1' : '0');
  }
}

const url = arg('url', `http://localhost:3000/api/webhook/${provider.id}`);
if (flag('curl')) {
  const h = Object.entries(signed.headers).map(([k, v]) => `  -H '${k}: ${v}'`).join(' \\\n');
  console.log(`curl -i -X POST '${url}' \\\n${h} \\\n  --data '${signed.body.replace(/'/g, "'\\''")}'`);
} else {
  console.log(JSON.stringify({
    provider: provider.id,
    verification_family: provider.webhook.verification_family,
    mode,
    expected_result: mode === 'valid' ? '2xx' : '400 (must be rejected)',
    url, headers: signed.headers, body: signed.body,
  }, null, 2));
}
