#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SessionStart hook.
 *
 * PagoKit's entire differentiator is a set of rules the model must not forget. Compaction
 * drops them: after a long session the model no longer remembers that a refund on Pix is
 * fiction, or that JPY has no minor unit. This re-injects the non-negotiable subset on
 * startup, resume, clear, compact and fork.
 *
 * Deliberately short. A wall of text gets skimmed; twelve lines that each prevent a specific
 * money-losing bug do not. The full rules stay one Read away.
 *
 * stdin:  { session_id, reason: 'startup'|'resume'|'clear'|'compact'|'fork', ... }
 * stdout: { hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: '...' } }
 */

const fs = require('node:fs');
const path = require('node:path');

const PLUGIN_ROOT = path.resolve(__dirname, '..');
const DATA = path.join(PLUGIN_ROOT, 'skills', 'payment-advisor', 'data');

function readStdin(timeoutMs = 1500) {
  return new Promise((resolve) => {
    let buf = '';
    const done = (v) => { clearTimeout(timer); resolve(v); };
    const timer = setTimeout(() => done(''), timeoutMs);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', () => done(buf));
    process.stdin.on('error', () => done(''));
  });
}

function catalogSummary() {
  try {
    const idx = JSON.parse(fs.readFileSync(path.join(DATA, 'providers.index.json'), 'utf8'));
    const methods = JSON.parse(fs.readFileSync(path.join(DATA, 'methods.json'), 'utf8'));
    const currencies = JSON.parse(fs.readFileSync(path.join(DATA, 'currencies.json'), 'utf8'));
    const zero = currencies.currencies.filter((c) => c.exponent === 0).map((c) => c.code);
    const three = currencies.currencies.filter((c) => c.exponent === 3).map((c) => c.code);
    const irreversible = methods.methods
      .filter((m) => m.reversibility === 'irreversible_no_refund')
      .map((m) => m.id);
    return {
      count: idx.count,
      levels: idx.by_level,
      verified: idx.providers.filter((p) => p.webhook_confidence === 'high').length,
      zero, three, irreversible,
    };
  } catch {
    return null;
  }
}

async function main() {
  const raw = await readStdin();
  let reason = 'startup';
  try { reason = (JSON.parse(raw || '{}').reason) || 'startup'; } catch { /* keep default */ }

  const c = catalogSummary();
  if (!c) { process.exit(0); } // no catalog, nothing useful to say

  const lines = [
    'PagoKit is loaded. Non-negotiable rules for any payment code in this session:',
    '',
    '1. A webhook handler MUST verify the signature before parsing, over the RAW body. No exceptions.',
    '2. Signature verification alone does not stop replay. Use the timestamp window when the scheme signs a timestamp, and event-id dedup when it does not.',
    '3. Idempotency keys come from crypto.randomUUID() or the language equivalent. Never Math.random() or Date.now().',
    '4. Never hardcode a live key. Never write .env before .gitignore covers it.',
    '5. Never accept or store a PAN, CVV or track data on the merchant server. That is PCI SAQ D.',
    `6. Amounts follow the CURRENCY's ISO 4217 exponent, not a reflexive x100. Zero-decimal: ${c.zero.join(' ')}. Three-decimal: ${c.three.join(' ')}.`,
    `7. "Refund the charge" does not exist on irreversible rails (${c.irreversible.slice(0, 8).join(', ')}${c.irreversible.length > 8 ? ', …' : ''}). Emit a payout instead, and say so.`,
    '8. Log event.id, event.type and event.created. Never the payload.',
    '9. Verify with the WEBHOOK SECRET, not the API key. They are different values and mixing them fails silently.',
    '10. Compare signatures with timingSafeEqual / compare_digest, never ===.',
    '',
    `Catalog: ${c.count} providers (${(c.levels.build || []).length} build, ${(c.levels.generic || []).length} generic, ${(c.levels.advise || []).length} advise), ${c.verified} with a high-confidence webhook scheme.`,
    'Always tell the user which integration_level applies. If a scheme is not high-confidence, do NOT emit a signature verifier — emit re-fetch, dedup and a TODO.',
    '',
    'The validators run as hooks and will block a write that breaks rules 1-5. That is expected behaviour, not a bug: read the error and fix the code.',
  ];

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext: lines.join('\n'),
    },
    systemMessage: reason === 'compact'
      ? 'PagoKit security rules re-injected after compaction.'
      : undefined,
  }));
  process.exit(0);
}

main().catch(() => process.exit(0)); // never break the session
