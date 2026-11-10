// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 20 — Merchant-of-record capability conflict.
 *
 * When a merchant-of-record (MoR) provider owns the sale, the MoR is the seller: it
 * settles, it invoices, it remits the tax, it eats the chargeback. Code in the same
 * integration that ALSO tries to act as the merchant — creating connected accounts,
 * splitting payouts, building its own card form, issuing its own invoices, or computing
 * a VAT/IVA rate the MoR already remits — compiles cleanly, fails at runtime (or worse,
 * silently double-taxes the buyer), and the developer blames the payment plugin.
 *
 * Gating: the file's PRIMARY provider must resolve to a catalog provider with
 * `mor.is_mor === true`. Primary is the provider named by a path segment
 * (app/api/lemonsqueezy/...), or — when no path segment names one — the single provider
 * whose SDK the file imports. A file that imports two providers and lives in no
 * provider-named directory is ambiguous and is never denied.
 *
 * Bypass: `// pagokit-ignore: mor-capability-conflict -- <reason>`.
 */

const path = require('node:path');
const {
  hasIgnoreTag,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  loadProviders,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'mor-capability-conflict';

/* ------------------------------------------------------------------ *
 * Provider resolution (catalog-driven, no hardcoded provider list)
 * ------------------------------------------------------------------ */

/** Every path/module slug that can name this provider: id + normalised display name. */
function providerSlugs(provider) {
  const slugs = new Set();
  const id = String(provider.id || '').toLowerCase();
  if (id) slugs.add(id);
  const name = String(provider.name || '').toLowerCase().trim();
  if (name) {
    slugs.add(name.replace(/[^a-z0-9]+/g, ''));
    slugs.add(name.replace(/[^a-z0-9]+/g, '-'));
    slugs.add(name.replace(/[^a-z0-9]+/g, '_'));
  }
  slugs.delete('');
  return slugs;
}

/** Provider named by a directory or basename segment of the path, or null. */
function providerFromPath(filePath, providers) {
  if (!filePath) return null;
  const norm = String(filePath).replace(/\\/g, '/').toLowerCase();
  const segments = norm.split('/').filter(Boolean);
  if (!segments.length) return null;
  const last = segments[segments.length - 1];
  segments[segments.length - 1] = last.replace(/\.[a-z0-9]+$/, '');

  const hits = [];
  for (const provider of providers) {
    const slugs = providerSlugs(provider);
    for (const seg of segments) {
      const collapsed = seg.replace(/[^a-z0-9]+/g, '');
      if (slugs.has(seg) || slugs.has(collapsed)) {
        hits.push(provider);
        break;
      }
    }
  }
  // Two provider names in one path is not a resolution, it is a routing table.
  return hits.length === 1 ? hits[0] : null;
}

/** Module specifiers imported by the file (JS/TS + Python forms). */
function importedModules(content) {
  const mods = [];
  const jsRe = /(?:from\s*|require\s*\(\s*|import\s*\(\s*)['"]([^'"\n]+)['"]/g;
  let m;
  while ((m = jsRe.exec(content))) mods.push(m[1].toLowerCase());
  const pyRe = /^\s*(?:from\s+([A-Za-z0-9_.]+)\s+import\b|import\s+([A-Za-z0-9_.]+))/gm;
  while ((m = pyRe.exec(content))) mods.push(String(m[1] || m[2]).toLowerCase());
  return mods;
}

/** Providers whose SDK (or a local module named after them) this file imports. */
function providersFromImports(content, providers) {
  const mods = importedModules(content);
  if (!mods.length) return [];
  const out = [];
  for (const provider of providers) {
    const slugs = providerSlugs(provider);
    let hit = false;
    for (const mod of mods) {
      const parts = mod.split(/[^a-z0-9]+/).filter(Boolean);
      const collapsed = mod.replace(/[^a-z0-9]+/g, '');
      if (parts.some((p) => slugs.has(p)) || slugs.has(collapsed)) {
        hit = true;
        break;
      }
    }
    if (hit) out.push(provider);
  }
  return out;
}

/**
 * The provider this file belongs to. Path segment wins (an
 * app/api/webhooks/<provider>/ directory is an explicit statement of ownership);
 * otherwise a single SDK import decides. Ambiguity resolves to null.
 */
function resolvePrimaryProvider(filePath, content, providers) {
  const byPath = providerFromPath(filePath, providers);
  if (byPath) return byPath;
  const byImport = providersFromImports(content, providers);
  return byImport.length === 1 ? byImport[0] : null;
}

/* ------------------------------------------------------------------ *
 * Merchant-acting signals
 * ------------------------------------------------------------------ */

/**
 * A connected account is a PSP object, not a row in your users table. Requiring one of
 * the fields the PSP demands is what separates `stripe.accounts.create({ type: 'express' })`
 * from `accounts.create({ email, plan })` against the app's own auth store.
 */
const CONNECT_QUALIFIER_RE =
  /\bcapabilities\b|\btos_acceptance\b|\bbusiness_type\b|\bcontroller\b|\baccount_token\b|\btype\s*:\s*['"](?:express|standard|custom)['"]/;
/** A Stripe invoice item needs a customer (or an invoice) and a price. */
const INVOICE_ITEM_QUALIFIER_RE =
  /\bcustomer\s*:|\binvoice\s*:|\bunit_amount\b|\bprice_data\b|\bprice\s*:|\bamount\s*:/;

const SIGNALS = [
  {
    re: /\baccounts\.create\s*\(/,
    qualifier: CONNECT_QUALIFIER_RE,
    capability: 'marketplace_payouts',
    what_en: 'connected-account creation (accounts.create)',
    what_es: 'creación de cuentas conectadas (accounts.create)',
  },
  {
    re: /\btransfer_data\b/,
    capability: 'marketplace_payouts',
    what_en: 'split settlement (transfer_data)',
    what_es: 'reparto de la liquidación (transfer_data)',
  },
  {
    re: /\bon_behalf_of\b/,
    capability: 'marketplace_payouts',
    what_en: 'settling on behalf of another merchant (on_behalf_of)',
    what_es: 'liquidar por cuenta de otro comercio (on_behalf_of)',
  },
  {
    re: /\bstripe\.elements\s*\(/,
    capability: 'deep_checkout_branding',
    what_en: 'a self-hosted card form (stripe.elements())',
    what_es: 'un formulario de tarjeta propio (stripe.elements())',
  },
  {
    re: /\binvoiceItems\.create\s*\(/,
    qualifier: INVOICE_ITEM_QUALIFIER_RE,
    capability: 'invoicing',
    what_en: 'issuing your own invoice lines (invoiceItems.create)',
    what_es: 'emitir tus propias líneas de factura (invoiceItems.create)',
  },
  {
    re: /\btaxRates\.create\s*\(/,
    capability: 'custom_tax_engine',
    what_en: 'defining merchant tax rates (taxRates.create)',
    what_es: 'definir tasas de impuesto propias (taxRates.create)',
  },
  {
    re: /\bstripe\.tax\./,
    capability: 'custom_tax_engine',
    what_en: 'a tax engine call (stripe.tax.*)',
    what_es: 'una llamada al motor de impuestos (stripe.tax.*)',
  },
];

const TAX_ENGINE_WORDS = 'avalara|avatax|taxjar|anrok|quaderno';
// An import of a third-party tax engine. Read from the RAW source on purpose: module
// specifiers are string literals, so the stripped copy no longer contains them. The
// `from`/`require`/`import` prefix is what proves it is code and not prose.
const TAX_ENGINE_IMPORT_RE = new RegExp(
  "(?:from\\s*|require\\s*\\(\\s*|import\\s*\\(\\s*)['\"][^'\"\\n]*(?:" + TAX_ENGINE_WORDS + ")[^'\"\\n]*['\"]",
  'i'
);
// Usage of a tax-engine identifier in real code (comments and strings already blanked).
const TAX_ENGINE_IDENT_RE = new RegExp('\\b(?:' + TAX_ENGINE_WORDS + ')\\b', 'i');
// The engine called over raw HTTP, with no SDK to import. Read from the RAW line (the URL
// is a string literal); the caller still requires that line to be code, not a comment.
const TAX_ENGINE_ENDPOINT_RE = new RegExp(
  "['\"`][^'\"`\\n]*https?://[^'\"`\\s]*(?:" + TAX_ENGINE_WORDS + ")",
  'i'
);
// AVATAX_KEY / TAXJAR_API_TOKEN: the `_` blocks the \\b in TAX_ENGINE_IDENT_RE, and an env
// var named after the engine is as good a declaration of intent as an import.
const TAX_ENGINE_ENVVAR_RE = new RegExp(
  '\\b(?:' + TAX_ENGINE_WORDS + ')_[A-Z0-9_]{2,}\\b',
  'i'
);

/**
 * Words that turn a vat/iva identifier into something that is NOT a rate table.
 * `vatNumberLength = { ES: 9, DE: 9, FR: 11 }` validates VAT *registration numbers*;
 * the values sit in the same 1..30 range as VAT percentages, so only the name tells
 * them apart, and denying a legitimate validator is worse than missing a rate table.
 */
const NON_RATE_WORDS = new Set([
  'number', 'numbers', 'num', 'length', 'len', 'digits', 'digit', 'id', 'ids', 'uuid',
  'format', 'formats', 'pattern', 'patterns', 'regex', 'regexp', 'prefix', 'prefixes',
  'threshold', 'thresholds', 'registration', 'reg', 'validator', 'validators', 'valid',
  'validation', 'mask', 'masks', 'label', 'labels', 'name', 'names', 'exempt', 'exempt',
]);
/** Words that, next to `tax`, name a per-country rate table. */
const RATE_TABLE_WORDS = new Set([
  'rate', 'rates', 'by', 'per', 'country', 'countries', 'region', 'regions', 'table',
  'tables', 'map', 'pais', 'paises', 'jurisdiction', 'jurisdictions', 'percent',
  'percentage', 'tasa', 'tasas',
]);

function identWords(ident) {
  return ident
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/** Identifier subwords that mark a rate table as a VAT/IVA/tax-rate table. */
function looksLikeTaxIdentifier(line) {
  const idents = line.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || [];
  for (const ident of idents) {
    const flat = ident.toLowerCase().replace(/[^a-z0-9]/g, '');
    const words = identWords(ident);
    if (words.some((w) => NON_RATE_WORDS.has(w))) continue;
    if (flat.includes('taxrate')) return true;
    if (words.includes('vat') || words.includes('iva') || words.includes('impuesto')) return true;
    // `taxByCountry` is the most obvious name a developer gives this table, and it
    // carries neither `vat`, `iva` nor `taxRate`.
    if (words.includes('tax') && words.some((w) => RATE_TABLE_WORDS.has(w))) return true;
  }
  return false;
}

/** Known region codes, so `{ MX: 0.16, BR: 0.17 }` is a tax table and `{ ID: 2 }` is not. */
function regionCodeSet() {
  const set = new Set();
  try {
    const raw = require('node:fs').readFileSync(
      path.join(utils.PLUGIN_ROOT, 'skills', 'payment-advisor', 'data', 'regions.json'),
      'utf8'
    );
    for (const code of Object.keys(JSON.parse(raw).regions || {})) set.add(code.toUpperCase());
  } catch {
    /* no catalog → no table detection, which is the safe direction */
  }
  return set;
}

/**
 * A local country→rate map near a vat/iva/taxRate identifier.
 *
 * The identifier and the opening brace are read from the STRIPPED source (so a comment
 * can never seed a match); the entries are read from the raw window because the country
 * keys are usually quoted string literals. Two distinct catalog region codes are
 * required — a single `{ MX: 0.16 }` is not enough to block a developer's write.
 */
function findLocalTaxTable(rawLines, strippedLines, regionCodes) {
  if (!regionCodes.size) return null;
  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    if (!looksLikeTaxIdentifier(line)) continue;
    const opener = strippedLines.slice(i, Math.min(strippedLines.length, i + 3)).join('\n');
    if (!/[[{]/.test(opener)) continue;
    const window = rawLines.slice(i, Math.min(rawLines.length, i + 15)).join('\n');
    // Country keys are written both `'MX'` and `mx`; the identifier gate above is what
    // keeps `{ id: 2, in: 3 }` out, so casing can be permissive here.
    const entryRe = /['"]?\b([A-Za-z]{2})\b['"]?\s*:\s*(?:0?\.\d+|\d{1,2}(?:\.\d+)?)\s*(?=[,}\]\r\n])/g;
    const found = new Set();
    let m;
    while ((m = entryRe.exec(window))) {
      const code = m[1].toUpperCase();
      if (regionCodes.has(code)) found.add(code);
    }
    if (found.size >= 2) {
      return { line: i + 1, codes: Array.from(found).slice(0, 4) };
    }
  }
  return null;
}

function firstLineOf(strippedLines, re) {
  for (let i = 0; i < strippedLines.length; i++) {
    if (re.test(strippedLines[i])) return i + 1;
  }
  return null;
}

/**
 * First line where `signal.re` matches the stripped source AND — when the signal carries
 * a qualifier — the RAW ±3-line window also matches it. The qualifier reads raw text
 * because the fields that prove the call is the PSP's (`type: 'express'`) are string
 * literals the stripper blanks out.
 */
function firstSignalLine(signal, strippedLines, rawLines) {
  for (let i = 0; i < strippedLines.length; i++) {
    if (!signal.re.test(strippedLines[i])) continue;
    if (!signal.qualifier) return i + 1;
    const window = rawLines
      .slice(Math.max(0, i - 3), Math.min(rawLines.length, i + 4))
      .join('\n');
    if (signal.qualifier.test(window)) return i + 1;
  }
  return null;
}

/** First line that is real code AND whose raw text matches `re`. */
function firstRawCodeLine(rawLines, strippedLines, re) {
  for (let i = 0; i < rawLines.length; i++) {
    if (!/\S/.test(strippedLines[i] || '')) continue;
    if (re.test(rawLines[i])) return i + 1;
  }
  return null;
}

/* ------------------------------------------------------------------ */

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const providers = (loadProviders().providers || []).filter((p) => p && p.id);
  if (!providers.length) return null;

  const provider = resolvePrimaryProvider(filePath, content, providers);
  if (!provider) return null;                       // not resolvable → never fire
  const mor = provider.mor || {};
  if (mor.is_mor !== true) return null;             // not an MoR → never fire

  const stripped = stripCommentsAndStrings(content);
  const strippedLines = stripped.split('\n');
  const rawLines = String(content).split('\n');

  let hit = null;
  for (const signal of SIGNALS) {
    const line = firstSignalLine(signal, strippedLines, rawLines);
    if (line) {
      hit = { capability: signal.capability, what_en: signal.what_en, what_es: signal.what_es, line };
      break;
    }
  }

  const endpointLine = firstRawCodeLine(rawLines, strippedLines, TAX_ENGINE_ENDPOINT_RE);
  if (
    !hit &&
    (TAX_ENGINE_IMPORT_RE.test(content) ||
      TAX_ENGINE_IDENT_RE.test(stripped) ||
      TAX_ENGINE_ENVVAR_RE.test(stripped) ||
      endpointLine)
  ) {
    const line =
      firstLineOf(strippedLines, TAX_ENGINE_IDENT_RE) ||
      firstLineOf(strippedLines, TAX_ENGINE_ENVVAR_RE) ||
      endpointLine ||
      firstLineOf(rawLines, TAX_ENGINE_IMPORT_RE) ||
      1;
    hit = {
      capability: 'custom_tax_engine',
      what_en: 'a third-party tax engine (Avalara / TaxJar / Anrok / Quaderno)',
      what_es: 'un motor de impuestos externo (Avalara / TaxJar / Anrok / Quaderno)',
      line,
    };
  }

  if (!hit) {
    const table = findLocalTaxTable(rawLines, strippedLines, regionCodeSet());
    if (table) {
      hit = {
        capability: 'custom_tax_engine',
        what_en: `a local VAT/IVA rate table (${table.codes.join(', ')})`,
        what_es: `una tabla local de tasas de IVA (${table.codes.join(', ')})`,
        line: table.line,
      };
    }
  }

  if (!hit) return null;

  const label = provider.name || provider.id;
  const handles = (mor.handles || []).join(', ');
  const disabled = (mor.disables_capabilities || []).includes(hit.capability);

  const handlesEn = handles
    ? ` ${label} already handles: ${handles}.`
    : ` ${label} is the seller of record for this sale.`;
  const handlesEs = handles
    ? ` ${label} ya se encarga de: ${handles}.`
    : ` ${label} es el vendedor de registro de esta venta.`;
  const conflictEn = disabled
    ? `${label} explicitly disables "${hit.capability}" for merchants on its platform`
    : `that duplicates the "${hit.capability}" capability ${label} owns as merchant of record`;
  const conflictEs = disabled
    ? `${label} deshabilita explícitamente "${hit.capability}" para los comercios de su plataforma`
    : `eso duplica la capacidad "${hit.capability}" que ${label} tiene como merchant of record`;

  const isTax = hit.capability === 'custom_tax_engine' || hit.capability === 'invoicing';
  const consequenceEn = isTax
    ? 'Charging tax the MoR already remits bills the buyer twice and leaves you with tax you never owed.'
    : 'The MoR settles the funds, so this call has no money to act on: it fails at runtime, in production.';
  const consequenceEs = isTax
    ? 'Cobrar un impuesto que el MoR ya remite le cobra dos veces al comprador y te deja cargando un impuesto que nunca te tocó.'
    : 'El MoR liquida el dinero, así que esta llamada no tiene fondos sobre los cuales actuar: falla en runtime, en producción.';

  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_MOR_CONFLICT',
    message_en:
      `Line ${hit.line} uses ${hit.what_en}, but ${conflictEn} (Rule 20).` +
      handlesEn +
      ` ${consequenceEn}`,
    message_es:
      `La línea ${hit.line} usa ${hit.what_es}, pero ${conflictEs} (Regla 20).` +
      handlesEs +
      ` ${consequenceEs}`,
    suggested_fix:
      `Delete the "${hit.capability}" logic and read the value back from ${label} instead ` +
      `(its order/checkout payload carries the tax, the invoice and the settlement breakdown). ` +
      `If you genuinely need this capability, you need a direct acquirer next to ${label}, not inside its flow — ` +
      `run /pagokit-advisor to pick one.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
