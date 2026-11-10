#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Verifies that every provider a fragment NAMES actually exists in the catalog.
 *
 * Fragments are prose about data, which is the same drift hazard the generated docs solve.
 * An audit of the first draft found six invented members across four fragments — Komoju,
 * HitPay, Nuvei, PayU, Fawry and Ozow were named as belonging to a verification family while
 * being in no catalog entry at all. Worse, one fragment attributed the wrong SCHEME to a real
 * provider, teaching a JSON re-serialisation that does not happen.
 *
 * A reader trusts "providers in this family" as a fact. This makes it one.
 *
 * Run: npm run check:fragments
 */
const fs = require('fs');
const path = require('path');
const { loadAll, ROOT } = require('./lib/catalog');

const FRAGMENTS = path.join(ROOT, 'skills/integration-builder/fragments');

// Real companies a fragment may legitimately name as context without PagoKit supporting them
// (a scheme's origin, a cautionary example, a spec author). Each needs a reason to be here.
const ALLOWED_NON_CATALOG = new Map([
  ['svix', 'authors the Standard Webhooks spec; named as the library to use, not as a provider'],
  ['standard webhooks', 'the specification itself'],
  ['braintree', 'the canonical sdk_verifier case — named as the reason the family exists'],
  ['apple', 'store billing, named in the IAP context'],
  ['google', 'store billing, named in the IAP context'],
  ['visa', 'card network'],
  ['mastercard', 'card network'],
  ['bacen', 'the Brazilian central bank, named for the Pix MED process'],
]);

const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}

function main() {
  const providers = loadAll().providers.providers;
  // Match on the id, the full name, and the name with any parenthetical stripped, so
  // "Paddle" resolves to "Paddle (Paddle Billing)".
  const known = new Set();
  for (const p of providers) {
    known.add(norm(p.id));
    known.add(norm(p.name));
    known.add(norm(p.name.replace(/\(.*?\)/g, '')));
    for (const w of p.name.replace(/\(.*?\)/g, '').split(/[\s/·—-]+/)) {
      if (w.length >= 4) known.add(norm(w));
    }
  }

  const problems = [];
  let claims = 0;

  for (const file of walk(FRAGMENTS)) {
    const md = fs.readFileSync(file, 'utf8');
    for (const line of md.split('\n')) {
      if (!/^\*\*Providers in this family:\*\*/.test(line)) continue;
      for (const m of line.matchAll(/\*\*([^*]+)\*\*/g)) {
        const raw = m[1].replace(/^Providers in this family:?$/i, '').trim();
        if (!raw || /^providers in this family/i.test(raw)) continue;

        // Bold is also used for emphasis in these lines ("**not**", "**SHA-512**",
        // "**milliseconds**"), so only a token that reads like a company name is treated as
        // a claim: one to three capitalised words, no code spans, no algorithm identifiers.
        if (raw.includes('`')) continue;
        if (!/^[A-Z][A-Za-z0-9.&'’+-]*(?: [A-Z][A-Za-z0-9.&'’+-]*){0,2}(?:['’]s)?$/.test(raw.split(/\s+—|\s+\(|,/)[0].trim())) continue;
        if (/^(SHA|HMAC|RSA|ECDSA|EC|JWS|JWT|AES|MD5|SAQ|PCI|API|SDK|UUID|HTTP|TLS|URL|ISO)[-\d]/i.test(raw)) continue;

        claims++;
        // Take the leading proper-noun run: "Mollie's next-generation webhooks" -> "Mollie"
        const head = raw.split(/[’']s\b|\s+—|\s+\(|,/)[0].trim();
        const n = norm(head);
        if (!n) continue;
        if (known.has(n)) continue;
        if ([...known].some((k) => k.length >= 4 && (n.startsWith(k) || k.startsWith(n)))) continue;
        if (ALLOWED_NON_CATALOG.has(head.toLowerCase())) continue;
        if ([...ALLOWED_NON_CATALOG.keys()].some((k) => n.includes(norm(k)))) continue;
        problems.push({ file: path.relative(ROOT, file), claim: head });
      }
    }
  }

  console.log(`Fragment provider claims: ${claims} checked across ${walk(FRAGMENTS).length} fragments`);
  if (!problems.length) {
    console.log('[OK]   every provider named in a "Providers in this family" line exists in the catalog');
    return;
  }
  for (const p of problems) {
    console.error(`[FAIL] ${p.file}: names "${p.claim}", which is not in the catalog and is not an allowed reference`);
  }
  console.error(`\n[FAIL] ${problems.length} unsupported provider claim(s). Either add the provider to the catalog, remove the claim, or add it to ALLOWED_NON_CATALOG with a reason.`);
  process.exit(1);
}
main();
