#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Renders hooks/ERROR_CODES.md by reading the checks themselves.
 *
 * v0.1 hand-maintained this file and it had already drifted: three codes the dispatcher
 * emits (ERR_CHECK_LOAD_FAILED, ERR_CHECK_RUNTIME, ERR_DISPATCHER_CRASHED) were undocumented.
 * A doc that describes code should be derived from that code.
 *
 * Run:   npm run generate:errors
 * Check: npm run check:errors
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHECKS = path.join(ROOT, 'hooks/checks');
const DISPATCHER = path.join(ROOT, 'hooks/pagokit-validate.js');
const OUT = path.join(ROOT, 'hooks/ERROR_CODES.md');

/** Pull the phases a rule runs in straight out of PHASE_CHECKS. */
function phaseMap() {
  const src = fs.readFileSync(DISPATCHER, 'utf8');
  const block = src.slice(src.indexOf('const PHASE_CHECKS'), src.indexOf('/** The prompt phase'));
  const map = {};
  for (const phase of ['pre', 'post', 'stop', 'prompt']) {
    const m = new RegExp(`\\b${phase}:\\s*\\[([\\s\\S]*?)\\]`).exec(block);
    if (!m) continue;
    for (const q of m[1].matchAll(/'([a-z0-9-]+)'/g)) (map[q[1]] ||= []).push(phase);
  }
  return map;
}

function extract(file) {
  const src = fs.readFileSync(path.join(CHECKS, file), 'utf8');
  const ruleId = (/const RULE_ID = '([^']+)'/.exec(src) || [])[1] || file.replace(/\.js$/, '');
  // The doc comment at the top of every check is its own description.
  const doc = (/\/\*\*([\s\S]*?)\*\//.exec(src) || [])[1] || '';
  const lines = doc.split('\n').map((l) => l.replace(/^\s*\*ы?\s?/, '').replace(/^\s*\*\s?/, '').trim()).filter(Boolean);
  const rule = (lines.find((l) => /^SECURITY_RULES Rule/.test(l)) || '').replace(/^SECURITY_RULES /, '').replace(/\s*—.*$/, '').trim();
  const summary = lines.filter((l) => !/^SECURITY_RULES/.test(l) && !/^Bypass:/.test(l))
    .join(' ').replace(/\s+/g, ' ').trim();

  // Find every emitted code and the level(s) it can carry. A level may be a literal or a
  // ternary (`strict ? 'deny' : 'warn'`), and one code can be emitted at both levels from
  // different branches - so collect the set rather than the first match.
  const byCode = new Map();
  for (const m of src.matchAll(/code:\s*'([A-Z_]+)'/g)) {
    const code = m[1];
    const from = Math.max(0, m.index - 400);
    const window = src.slice(from, m.index + 400);
    const levels = new Set();
    for (const lm of window.matchAll(/level:\s*(?:[^,\n]*?\?\s*)?'(deny|warn)'(?:\s*:\s*'(deny|warn)')?/g)) {
      levels.add(lm[1]);
      if (lm[2]) levels.add(lm[2]);
    }
    if (!levels.size) {
      // Shorthand form (`level,` from a variable). Fall back to level assignments anywhere
      // in the file - a check that computes its level still has to write it down somewhere.
      for (const am of src.matchAll(/\blevel\s*=\s*(?:[^;\n]*?\?\s*)?'(deny|warn)'(?:\s*:\s*'(deny|warn)')?/g)) {
        levels.add(am[1]);
        if (am[2]) levels.add(am[2]);
      }
      for (const am of src.matchAll(/level:\s*'(deny|warn)'/g)) levels.add(am[1]);
      // Or the level arrives as a call argument: finding('deny', line, kind).
      for (const am of src.matchAll(/\(\s*'(deny|warn)'\s*,/g)) levels.add(am[1]);
    }
    if (!levels.size) continue;
    const prev = byCode.get(code) || new Set();
    for (const l of levels) prev.add(l);
    byCode.set(code, prev);
  }
  const codes = [...byCode.entries()].map(([code, levels]) => ({
    code,
    level: [...levels].sort().reverse().join(' / '), // deny first when both apply
  }));
  return { ruleId, rule, summary, codes };
}

function main() {
  const check = process.argv.includes('--check');
  const phases = phaseMap();
  const files = fs.readdirSync(CHECKS).filter((f) => f.endsWith('.js')).sort();
  const entries = files.map(extract).filter((e) => e.codes.length);

  const rows = entries.flatMap((e) =>
    e.codes.map(({ code, level }) =>
      `| \`${code}\` | \`${e.ruleId}\` | **${level}** | ${(phases[e.ruleId] || ['—']).join(', ')} | ${e.rule || '—'} |`)
  );

  const details = entries.map((e) => {
    const codes = e.codes.map((c) => `\`${c.code}\` (${c.level})`).join(' · ');
    return `### \`${e.ruleId}\`\n\n${codes}${e.rule ? ` · ${e.rule}` : ''}${(phases[e.ruleId] || []).length ? ` · runs at: ${(phases[e.ruleId]).join(', ')}` : ''}\n\n${e.summary || ''}\n\nBypass: \`// pagokit-ignore: ${e.ruleId} -- <reason>\`\n`;
  }).join('\n');

  const out = `# PagoKit error codes

> **Generated from \`hooks/checks/*.js\` and the PHASE_CHECKS map.** Run \`npm run generate:errors\`.
> Do not edit by hand — a document describing code should be derived from that code.

## The stderr contract

Each finding is one JSON object per line on **stderr**:

\`\`\`json
{"tool":"pagokit-validate","file":"app/api/webhook/route.ts","rule":"webhook-has-signature","level":"deny","code":"ERR_WEBHOOK_NO_SIG","message_en":"...","message_es":"...","suggested_fix":"..."}
\`\`\`

| Exit code | Meaning |
|---|---|
| \`0\` | Pass, or warnings only. The write proceeds. |
| \`2\` | At least one **deny**. The write is blocked and the finding is appended to \`.pagokit/audit.log\`. |

A \`deny\` is not a bug report. It means the write would have introduced a failure that does not
throw — an unsigned webhook, a wrong currency exponent, a secret compared with \`===\`. Read the
\`suggested_fix\` and change the code.

If a rule is genuinely wrong for your case, use the escape hatch. It is logged, which makes it a
decision on the record rather than a silent hole:

\`\`\`ts
// pagokit-ignore: <rule-id> -- <why this is safe here>
\`\`\`

## All codes

| Code | Rule | Level | Phase | Security rule |
|---|---|---|---|---|
${rows.join('\n')}

## Internal codes

These come from the dispatcher, never from a check, and **never block**. A validator that
crashes fails open by design — a broken check must not stop a developer working.

| Code | Meaning |
|---|---|
| \`ERR_CHECK_LOAD_FAILED\` | A check file could not be \`require\`d. |
| \`ERR_CHECK_RUNTIME\` | A check threw while running. |
| \`ERR_DISPATCHER_CRASHED\` | The dispatcher itself failed. |

## Per-rule detail

${details}`;

  if (check) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : null;
    if (current !== out) { console.error('[FAIL] hooks/ERROR_CODES.md is out of date. Run: npm run generate:errors'); process.exit(1); }
    console.log('[OK]   ERROR_CODES.md is up to date');
    return;
  }
  fs.writeFileSync(OUT, out);
  console.log(`[OK] Wrote hooks/ERROR_CODES.md (${entries.length} rules, ${rows.length} codes)`);
}
main();
