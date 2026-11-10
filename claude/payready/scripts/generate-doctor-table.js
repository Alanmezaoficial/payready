#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Renders skills/doctor/PROVIDER_CHECKS.md from the catalog.
 *
 * The doctor skill used to hardcode env var names and key prefixes for four providers in
 * prose, which meant it silently audited nothing for any provider added afterwards.
 *
 * Run:   npm run generate:doctor
 * Check: npm run check:doctor
 */
const fs = require('fs');
const path = require('path');
const { loadAll, ROOT } = require('./lib/catalog');

const OUT = path.join(ROOT, 'skills/doctor/PROVIDER_CHECKS.md');

function main() {
  const check = process.argv.includes('--check');
  const providers = [...loadAll().providers.providers].sort((a, b) => a.name.localeCompare(b.name));

  const sections = providers.map((p) => {
    const creds = p.credentials || [];
    const rows = creds.map((c) => {
      const expect = c.test_prefix ? `must start with \`${c.test_prefix}\`` : c.pattern ? `must match \`${c.pattern}\`` : 'no format constraint';
      const sev = c.scope === 'client' ? '`[WARN]`' : '`[FAIL]`';
      return `| \`${c.env_var}\` | ${c.kind} | ${c.scope || 'server'} | ${expect} | ${c.live_prefix ? `\`${c.live_prefix}\` → \`[WARN]\` live key in setup` : '—'} | ${sev} if missing |`;
    });
    const w = p.webhook;
    const extras = [];
    if (w.secret_env) extras.push(`- The verifier must be passed \`${w.secret_env}\`${p.env_vars && p.env_vars.secret ? `, **not** \`${p.env_vars.secret}\`` : ''}. Passing the API key is a silent, permanent verification failure.`);
    if (w.payload_authoritative === false) extras.push(`- The payload is not authoritative: the handler must re-fetch via \`${w.refetch_endpoint}\` before acting. \`[FAIL]\` if absent.`);
    if (p.notification_model === 'return_url_commit') extras.push(`- This provider does not send webhooks. Confirm the commit call exists — an uncommitted transaction auto-reverses. \`[FAIL]\` if absent.`);
    if (['event-id-dedup', 'both'].includes(w.replay_mitigation_strategy)) extras.push(`- Replay strategy is \`${w.replay_mitigation_strategy}\`: confirm a \`webhook_events_processed\` lookup keyed on \`${w.event_id_pointer}\`. \`[FAIL]\` if absent.`);
    if (w.recommended_tolerance_seconds) extras.push(`- Confirm a timestamp tolerance of ~${w.recommended_tolerance_seconds}s. \`[WARN]\` if absent or wildly different.`);
    if (p.mor && p.mor.is_mor) extras.push(`- Merchant of record: flag any local tax calculation or ${(p.mor.disables_capabilities || []).join('/')} usage. \`[FAIL]\` — the provider rejects it.`);

    return `### ${p.name} \`${p.id}\`

| Env var | Kind | Scope | Expected in setup | Live prefix | Severity |
|---|---|---|---|---|---|
${rows.join('\n')}

**Webhook handler must contain:**

${extras.length ? extras.join('\n') : '- Signature verification for the `' + w.verification_family + '` family.'}

**Events that must be routed** (\`[WARN]\` per missing event):

${w.required_events_minimum.map((e) => `- \`${e}\``).join('\n')}
`;
  });

  const out = `# Doctor — per-provider audit checks

> **Generated from \`skills/payment-advisor/data/providers/\`.** Run \`npm run generate:doctor\`.
> Do not edit by hand. The doctor skill reads this file so it audits every provider in the
> catalog rather than the four that happened to be hardcoded in its prose.

Severity legend: \`[FAIL]\` blocks a production sign-off · \`[WARN]\` should be fixed · \`[OK]\` passes.

---

${sections.join('\n---\n\n')}
---

## Checks that apply to every provider

| Check | How | Severity |
|---|---|---|
| \`.gitignore\` covers \`.env\` | grep the nearest \`.gitignore\` | \`[FAIL]\` |
| \`.env\` is not committed | \`git ls-files .env\` returns nothing | \`[FAIL]\` |
| \`.env.example\` exists | file check | \`[WARN]\` |
| \`.env.example\` holds only test-mode values | compare against each credential's \`live_prefix\` | \`[FAIL]\` |
| Idempotency key is a real UUID | canonical generator present in the checkout path | \`[FAIL]\` |
| The five tables exist | \`payments\`, \`subscriptions\`, \`customers\`, \`idempotency_keys\`, \`webhook_events_processed\` | \`[WARN]\` per missing table |
| Amounts respect the currency exponent | zero-decimal and three-decimal currencies must not be multiplied by 100 | \`[FAIL]\` |
| \`PAGOKIT_PRODUCTION_CHECKLIST.md\` exists | file check | \`[WARN]\` |
`;

  if (check) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : null;
    if (current !== out) {
      console.error('[FAIL] skills/doctor/PROVIDER_CHECKS.md is out of date. Run: npm run generate:doctor');
      process.exit(1);
    }
    console.log('[OK]   PROVIDER_CHECKS.md is up to date');
    return;
  }
  fs.writeFileSync(OUT, out);
  console.log(`[OK] Wrote skills/doctor/PROVIDER_CHECKS.md (${providers.length} providers)`);
}
main();
