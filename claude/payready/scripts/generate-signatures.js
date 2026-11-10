#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Renders skills/webhook-verifier/signatures.md from the catalog.
 *
 * This file used to be hand-written prose that restated facts already living in
 * providers.json. A fact stated in two places is wrong in one of them eventually — and
 * for a webhook signature, "wrong" means a handler that silently accepts forged events.
 *
 * Run:   npm run generate:signatures
 * Check: npm run check:signatures
 */
const fs = require('fs');
const path = require('path');
const { loadAll, ROOT } = require('./lib/catalog');
const { SIGNABLE } = require('./lib/webhook-sign');

const OUT = path.join(ROOT, 'skills/webhook-verifier/signatures.md');

const FAMILY_BLURB = {
  hmac_raw_body: 'HMAC over the exact request bytes.',
  hmac_timestamp_body: 'HMAC over a timestamp concatenated with the raw body, so the signature itself expires.',
  hmac_field_concat: 'HMAC over a template of selected fields — the raw body is never hashed, so a raw-body verifier fails 100% of the time.',
  hmac_body_transform: 'HMAC over a TRANSFORM of the body (base64 of it, or a re-serialisation) rather than the received bytes.',
  standard_webhooks: 'The Standard Webhooks spec. Verify with the off-the-shelf `svix` package rather than hand-rolling crypto.',
  asymmetric_rsa: 'RSA signature verified with the provider public key. There is no shared secret.',
  asymmetric_jws: 'A JWS/JWT signature. Verify the algorithm explicitly; never trust the `alg` header.',
  body_embedded_sig: 'The signature travels INSIDE the body, not in a header. You must parse before you can verify — which is the one case where parsing first is correct.',
  shared_secret_header: 'No MAC at all: the header carries a static shared secret. That comparison is the entire security control, so it must be constant-time.',
  signed_headers: 'A canonical string built from method, URI and headers is signed.',
  mtls_or_ip: 'Authenticity comes from the transport (mutual TLS or an IP allowlist), not from a payload signature.',
  none_refetch: 'The callback is unsigned. Treat it purely as a ping and re-fetch the authoritative record.',
  sdk_verifier: "The provider's own SDK owns verification; there is no documented hand-rollable recipe.",
  unverified: 'The provider documents a scheme, but it has not yet been transcribed into typed catalog fields. PagoKit will not generate a verifier for it — see the note on each provider for what the docs say.',
  none: 'No verification mechanism is documented.',
};

function providerSection(p) {
  const w = p.webhook;
  const L = [];
  L.push(`## ${p.name}`);
  L.push('');
  L.push(`- **Verification family:** \`${w.verification_family}\` — ${FAMILY_BLURB[w.verification_family] || ''}`);
  if (w.signature_location === 'body_field') {
    L.push(`- **Signature location:** inside the body at \`${w.signature_pointer}\``);
  } else if (w.signature_header) {
    const fmt = w.header_format || { kind: 'raw' };
    const shape = fmt.kind === 'kv'
      ? ` (\`${fmt.timestamp_key ? `${fmt.timestamp_key}=<ts>${fmt.separator || ','}` : ''}${fmt.signature_key || 'v1'}=<sig>\`)`
      : fmt.kind === 'prefixed' ? ` (prefixed \`${fmt.prefix}\`)` : '';
    L.push(`- **Signature header:** \`${w.signature_header}\`${shape}`);
  }
  if (w.hash_algo) L.push(`- **Hash:** \`${w.hash_algo}\`${w.weak_crypto ? ' — **weak by modern standards.** ' + (w.weak_crypto_reason || '') + ' Implement it as documented and warn; never silently "upgrade" it, or verification breaks.' : ''}`);
  if (w.secret_encoding && w.secret_encoding !== 'raw') L.push(`- **Secret encoding:** \`${w.secret_encoding}\` — getting this wrong rejects every valid event.`);
  if (w.digest_encoding) L.push(`- **Digest encoding:** \`${w.digest_encoding}\``);
  if (w.signed_payload_template) L.push(`- **Signed string:** \`${w.signed_payload_template}\``);
  L.push(`- **Timestamp signed:** ${w.signature_includes_timestamp ? 'yes' : '**no**'}${w.recommended_tolerance_seconds ? ` (tolerance ${w.recommended_tolerance_seconds}s)` : ''}`);
  L.push(`- **Replay mitigation:** \`${w.replay_mitigation_strategy || 'none'}\`${w.event_id_pointer ? ` (dedup on \`${w.event_id_pointer}\`)` : ''}`);
  if (w.secret_env) L.push(`- **Webhook secret env var:** \`${w.secret_env}\`${p.env_vars && p.env_vars.secret && p.env_vars.secret !== w.secret_env ? ` — **different from \`${p.env_vars.secret}\`**. Verifying with the API key is a silent, permanent failure.` : ''}`);
  L.push(`- **Notification model:** \`${p.notification_model}\``);
  if (w.payload_authoritative === false) {
    L.push(`- **The payload is NOT authoritative.** Re-fetch before acting: \`${w.refetch_endpoint}\``);
  }
  if (w.signature_covers_body === false) {
    L.push('- **The signature does not cover the whole body.** Fields outside the signed set are attacker-controllable.');
  }
  if (w.ack_deadline_seconds) L.push(`- **Ack deadline:** ${w.ack_deadline_seconds}s${w.ack_body_literal ? ` and the body must be exactly \`${w.ack_body_literal}\`` : ''}`);
  L.push('');
  L.push('**Required events (must be routed):**');
  L.push('');
  for (const e of w.required_events_minimum) L.push(`- \`${e}\``);
  L.push('');
  L.push(`**Generate a signed test event:** \`node scripts/sign-event.js --provider ${p.id} --curl\``);
  L.push(`Forged and replayed variants: \`--mode forged\`, \`--mode replay\`. Both must be rejected with a 400.`);
  L.push('');
  if (p.anti_patterns && p.anti_patterns.length) {
    L.push(`**Anti-patterns specific to ${p.name}:**`);
    L.push('');
    for (const a of p.anti_patterns) L.push(`- ${a}`);
    L.push('');
  }
  const ev = w.evidence || {};
  L.push(`*Verified ${ev.verified_at || p.last_verified_at} · confidence \`${ev.confidence}\` · ${ev.verified_by}${ev.source_url ? ` · ${ev.source_url}` : ''}*`);
  L.push('');
  L.push('---');
  L.push('');
  return L.join('\n');
}

function main() {
  const check = process.argv.includes('--check');
  const A = loadAll();
  const providers = [...A.providers.providers].sort((a, b) => a.name.localeCompare(b.name));

  const families = {};
  for (const p of providers) (families[p.webhook.verification_family] ||= []).push(p.name);

  const out = `# Webhook Signatures — Per-Provider Reference

> **Generated from \`skills/payment-advisor/data/providers/\`.** Run \`npm run generate:signatures\`.
> Do not edit by hand: this file restates data, and a signature fact that disagrees with the
> catalog produces a handler that silently accepts forged events.

Every scheme below is one of ${Object.keys(FAMILY_BLURB).length} **verification families**. There are far fewer families than
providers, which is why PagoKit writes one fragment per family instead of one per provider.

| Family | Providers in the catalog | What it means |
|---|---|---|
${Object.entries(FAMILY_BLURB).map(([f, blurb]) => `| \`${f}\` | ${(families[f] || []).join(' · ') || '—'} | ${blurb} |`).join('\n')}

**Locally signable families** (PagoKit can generate a valid test event): ${[...SIGNABLE].map((f) => `\`${f}\``).join(', ')}.
For the rest, capture a real event from the provider sandbox.

---

${providers.map(providerSection).join('')}## Summary table

| Provider | Family | Location | Hash | Digest | Timestamp signed | Tolerance | Replay | Payload authoritative |
|---|---|---|---|---|---|---|---|---|
${providers.map((p) => {
    const w = p.webhook;
    return `| ${p.name} | \`${w.verification_family}\` | ${w.signature_location === 'body_field' ? `body \`${w.signature_pointer}\`` : `\`${w.signature_header}\``} | ${w.hash_algo || '—'} | ${w.digest_encoding || '—'} | ${w.signature_includes_timestamp ? 'yes' : '**no**'} | ${w.recommended_tolerance_seconds ? `${w.recommended_tolerance_seconds}s` : '—'} | \`${w.replay_mitigation_strategy || 'none'}\` | ${w.payload_authoritative === false ? '**no — re-fetch**' : 'yes'} |`;
  }).join('\n')}
`;

  if (check) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : null;
    if (current !== out) {
      console.error('[FAIL] skills/webhook-verifier/signatures.md is out of date. Run: npm run generate:signatures');
      process.exit(1);
    }
    console.log('[OK]   signatures.md is up to date');
    return;
  }
  fs.writeFileSync(OUT, out);
  console.log(`[OK] Wrote skills/webhook-verifier/signatures.md (${providers.length} providers, ${Object.keys(families).length} families in use)`);
}

main();
