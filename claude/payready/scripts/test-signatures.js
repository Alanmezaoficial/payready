#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Round-trip proof for every provider whose scheme PagoKit claims it can build.
 *
 * For each provider: sign a synthetic event, verify it, then confirm that verification
 * REJECTS a tampered body, a wrong secret, a missing signature, and a replayed timestamp.
 * If a provider is marked build/generic and cannot pass this, the catalog is lying.
 */
const { signEvent, verifyEvent, UnsignableError, SIGNABLE } = require('./lib/webhook-sign');
const { loadAll } = require('./lib/catalog');
const SAMPLES = require('./fixtures/sample-events');

const SECRET = 'sec_pagokit_test_1234567890abcdef';
const NOW = 1780000000;
let pass = 0, fail = 0;

const check = (name, cond, detail) => {
  if (cond) { pass++; console.log(`  [OK]   ${name}`); }
  else { fail++; console.error(`  [FAIL] ${name}${detail ? ` — ${detail}` : ''}`); }
};

const providers = loadAll().providers.providers;
console.log(`Signature round-trip: ${providers.length} providers\n`);

for (const p of providers) {
  console.log(`${p.name} (${p.webhook.verification_family})`);
  const claimsBuildable = p.integration_level === 'build' || p.integration_level === 'generic';

  if (!SIGNABLE.has(p.webhook.verification_family)) {
    // Not signable locally is fine — as long as the catalog does not claim otherwise.
    if (claimsBuildable && p.notification_model === 'webhook' && p.webhook.verification_family !== 'none') {
      check(`${p.id}: signable`, false, `family "${p.webhook.verification_family}" cannot be signed locally but integration_level is "${p.integration_level}"`);
    } else {
      console.log(`  [SKIP] ${p.webhook.verification_family} is not locally signable, and the catalog does not claim it is`);
    }
    console.log('');
    continue;
  }

  const sample = SAMPLES[p.id];
  if (!sample) { check(`${p.id}: has a sample event fixture`, false, 'add one to scripts/fixtures/sample-events.js'); console.log(''); continue; }

  let signed;
  try {
    signed = signEvent(p, { payload: sample.payload, secret: SECRET, timestamp: NOW, extraHeaders: sample.extraHeaders });
  } catch (e) {
    check(`${p.id}: sign`, false, e.message); console.log(''); continue;
  }

  check(`${p.id}: a signed event verifies`, verifyEvent(p, { headers: signed.headers, body: signed.body, secret: SECRET, now: NOW }).valid);

  const t = verifyEvent(p, { headers: signed.headers, body: sample.tamper(signed.body), secret: SECRET, now: NOW });
  check(`${p.id}: a tampered body is rejected`, !t.valid, t.valid ? 'tampering was ACCEPTED' : undefined);

  const w = verifyEvent(p, { headers: signed.headers, body: signed.body, secret: 'wrong_secret_value_here', now: NOW });
  check(`${p.id}: the wrong secret is rejected`, !w.valid, w.valid ? 'wrong secret was ACCEPTED' : undefined);

  const stripped = { ...signed.headers };
  delete stripped[(p.webhook.signature_header || '').toLowerCase()];
  if (p.webhook.signature_location !== 'body_field') {
    const m = verifyEvent(p, { headers: stripped, body: signed.body, secret: SECRET, now: NOW });
    check(`${p.id}: a missing signature is rejected`, !m.valid);
  }

  const tol = p.webhook.recommended_tolerance_seconds;
  if (tol && p.webhook.timestamp_source && p.webhook.timestamp_source !== 'none') {
    const r = verifyEvent(p, { headers: signed.headers, body: signed.body, secret: SECRET, now: NOW + tol + 60 });
    check(`${p.id}: a replayed event outside the ${tol}s window is rejected`, !r.valid, r.valid ? 'replay was ACCEPTED' : undefined);
  } else {
    // No timestamp to expire means dedup is the ONLY defence, so it must be declared.
    const dedups = ['event-id-dedup', 'both'].includes(p.webhook.replay_mitigation_strategy);
    check(`${p.id}: unsigned timestamp implies event-id dedup`, dedups && !!p.webhook.event_id_pointer,
      'without a signed timestamp, a captured event can be replayed forever unless the handler dedups by event id');
  }
  console.log('');
}

console.log('----');
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
