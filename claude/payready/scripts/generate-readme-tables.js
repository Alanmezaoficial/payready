#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Injects catalog-derived tables into README.md and docs/README.es.md between markers.
 *
 * The README used to restate the provider list, the method list and the roadmap in prose.
 * That prose drifted: at v0.1.0 the README and the advisor skill listed DIFFERENT Phase 2
 * provider sets. Generated blocks cannot drift, and CI proves it.
 *
 *   <!-- pagokit:providers:start --> ... <!-- pagokit:providers:end -->
 *
 * Run:   npm run generate:readme
 * Check: npm run check:readme
 */
const fs = require('fs');
const path = require('path');
const { loadAll, ROOT } = require('./lib/catalog');

const LEVEL_LABEL = {
  en: { build: 'full build', generic: 'scaffold', advise: 'advice only' },
  es: { build: 'build completo', generic: 'scaffold', advise: 'solo asesoría' },
};

function blocks(lang) {
  const A = loadAll();
  const providers = [...A.providers.providers].sort((a, b) => (a.wave - b.wave) || a.name.localeCompare(b.name));
  const methods = A.methods.methods;
  const regions = A.regions.regions;
  const byId = Object.fromEntries(methods.map((m) => [m.id, m]));

  const supported = Object.values(regions).filter((r) => !r.unsupported).length;
  const withLocal = Object.values(regions).filter((r) => !r.unsupported && r.primary_providers.length).length;
  const catCount = methods.reduce((a, m) => { a[m.category] = (a[m.category] || 0) + 1; return a; }, {});

  // --- providers table
  const head = lang === 'es'
    ? '| Proveedor | Nivel | Rol | Cobertura de compradores | Suscripciones | MoR | Alta |'
    : '| Provider | Level | Role | Buyer coverage | Subscriptions | MoR | Onboarding |';
  // A 42-row table buries the thing the reader actually needs to know: which of these will
  // PagoKit write for me. Build and generic get the table; the advisory catalog gets a
  // compact list, grouped by the wave that will promote it.
  const buildable = providers.filter((p) => p.integration_level !== 'advise');
  const advisory = providers.filter((p) => p.integration_level === 'advise');

  const row = (p) => {
    const cov = p.method_coverage_regions.includes('GLOBAL') ? 'Global'
      : p.method_coverage_regions.slice(0, 8).join(' · ') + (p.method_coverage_regions.length > 8 ? ' · …' : '');
    return `| **${p.name}** | ${LEVEL_LABEL[lang][p.integration_level]} | ${p.role} | ${cov} | ${p.supports.subscriptions ? '✓' : '—'} | ${p.supports.merchant_of_record ? '✓' : '—'} | ${(p.onboarding || {}).model || '?'} |`;
  };
  const sep = head.replace(/[^|]+/g, '---').replace(/---\|---/g, '---|---');

  const byWave = {};
  for (const p of advisory) (byWave[p.wave ?? 9] ||= []).push(p.name);
  const waveLines = Object.keys(byWave).sort().map((w) =>
    `- **${lang === 'es' ? 'Ola' : 'Wave'} ${w}** — ${byWave[w].sort().join(' · ')}`);

  const T = lang === 'es' ? {
    build: '### Lo que PagoKit escribe por ti',
    adv: '### Lo que PagoKit conoce y recomienda, pero no escribe',
    advNote: `Otros ${advisory.length} proveedores con datos verificados: el advisor los compara, calcula sus comisiones y explica sus condiciones — y te dice claramente que el código lo escribes tú. Suben a nivel \`build\` cuando su esquema de firma queda verificado y transcrito.`,
  } : {
    build: '### What PagoKit writes for you',
    adv: "### What PagoKit knows and recommends, but doesn't write",
    advNote: `Another ${advisory.length} providers with verified catalog data: the advisor compares them, computes their fees and explains their constraints — and tells you plainly that the code is yours to write. They move up to \`build\` once their signature scheme is verified and transcribed.`,
  };

  const providersBlock = [
    T.build, '', head, sep, ...buildable.map(row), '',
    T.adv, '', T.advNote, '', ...waveLines,
  ].join('\n');

  // --- methods summary
  const order = ['card', 'wallet', 'bank_transfer', 'qr', 'cash_voucher', 'direct_debit', 'mobile_money', 'bnpl', 'crypto', 'open_banking', 'card_present', 'benefits', 'other'];
  const catName = {
    en: { card: 'Cards', wallet: 'Wallets', bank_transfer: 'Bank transfer', qr: 'QR / instant', cash_voucher: 'Cash vouchers', direct_debit: 'Direct debit', mobile_money: 'Mobile money', bnpl: 'BNPL', crypto: 'Crypto', open_banking: 'Open banking', card_present: 'Card present', benefits: 'Benefits (EBT/HSA)', other: 'Store billing' },
    es: { card: 'Tarjetas', wallet: 'Wallets', bank_transfer: 'Transferencia bancaria', qr: 'QR / instantáneo', cash_voucher: 'Vouchers en efectivo', direct_debit: 'Débito directo', mobile_money: 'Dinero móvil', bnpl: 'BNPL', crypto: 'Cripto', open_banking: 'Open banking', card_present: 'Presencial', benefits: 'Beneficios (EBT/HSA)', other: 'Facturación de tienda' },
  }[lang];
  const mHead = lang === 'es' ? '| Categoría | Métodos | Ejemplos |' : '| Category | Methods | Examples |';
  const mRows = order.filter((c) => catCount[c]).map((c) => {
    const ex = methods.filter((m) => m.category === c && !m.deny_list).slice(0, 5).map((m) => m.label).join(' · ');
    return `| ${catName[c]} | ${catCount[c]} | ${ex} |`;
  });
  const methodsBlock = [mHead, '|---|---|---|', ...mRows].join('\n');

  // --- stats line
  const statsBlock = lang === 'es'
    ? `**${providers.length} proveedores** · **${methods.length} métodos de pago** · **${supported} países** (${withLocal} con proveedor local) · **${A.currencies.currencies.length} monedas** con su exponente ISO 4217 · **${new Set(providers.map((p) => p.webhook.verification_family)).size} familias de verificación de webhook** en uso.`
    : `**${providers.length} providers** · **${methods.length} payment methods** · **${supported} countries** (${withLocal} with a local provider) · **${A.currencies.currencies.length} currencies** with their ISO 4217 exponent · **${new Set(providers.map((p) => p.webhook.verification_family)).size} webhook verification families** in use.`;

  // --- rails highlight
  const railRows = Object.entries(regions)
    .filter(([, r]) => r.instant_rail)
    .map(([code, r]) => ({ code, rail: r.instant_rail, label: byId[r.instant_rail] ? byId[r.instant_rail].label : r.instant_rail }))
    .sort((a, b) => a.code.localeCompare(b.code));
  const railsBlock = (lang === 'es'
    ? '| País | Rail instantáneo dominante |\n|---|---|\n'
    : '| Country | Dominant instant rail |\n|---|---|\n')
    + railRows.map((r) => `| \`${r.code}\` | ${r.label} |`).join('\n');

  return { providers: providersBlock, methods: methodsBlock, stats: statsBlock, rails: railsBlock };
}

function inject(file, lang) {
  const b = blocks(lang);
  let src = fs.readFileSync(file, 'utf8');
  let changed = 0;
  for (const [key, content] of Object.entries(b)) {
    const re = new RegExp(`(<!-- pagokit:${key}:start -->)[\\s\\S]*?(<!-- pagokit:${key}:end -->)`, 'g');
    if (!re.test(src)) continue;
    re.lastIndex = 0;
    src = src.replace(re, `$1\n${content}\n$2`);
    changed++;
  }
  return { src, changed };
}

function main() {
  const check = process.argv.includes('--check');
  const targets = [
    [path.join(ROOT, 'README.md'), 'en'],
    [path.join(ROOT, 'docs/README.es.md'), 'es'],
  ];
  let drift = false;
  for (const [file, lang] of targets) {
    if (!fs.existsSync(file)) continue;
    const { src, changed } = inject(file, lang);
    const current = fs.readFileSync(file, 'utf8');
    if (check) {
      if (src !== current) { console.error(`[FAIL] ${path.basename(file)} tables are out of date. Run: npm run generate:readme`); drift = true; }
      else console.log(`[OK]   ${path.basename(file)} tables are up to date (${changed} blocks)`);
    } else {
      fs.writeFileSync(file, src);
      console.log(`[OK]   ${path.basename(file)}: ${changed} generated block(s)`);
    }
  }
  if (check && drift) process.exit(1);
}
main();
