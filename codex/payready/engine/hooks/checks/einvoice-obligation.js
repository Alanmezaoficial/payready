// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 22 — a completed sale in a country where the fiscal document is
 * part of the sale, with nothing in the project that can issue it.
 *
 * In Mexico and Brazil (and Chile, Peru, Colombia, Ecuador, Italy) issuing the fiscal
 * document is a legal obligation attached to the sale, not an accounting chore that can
 * follow later. An integration that charges the card but cannot emit the CFDI or the NF-e
 * is not "missing a feature": it is not shippable. That is a business fact, not a code
 * defect, which is exactly why this check warns instead of blocking — a validator that
 * blocks a legitimate write is a validator that gets uninstalled. Set PAGOKIT_STRICT=1
 * to make it a hard stop in CI.
 *
 * Bypass: `// pagokit-ignore: einvoice-obligation -- <reason>`, or a PAGOKIT_TAX_TODO.md
 * at the project root that records the decision.
 */

const fs = require('node:fs');
const path = require('node:path');
const {
  hasIgnoreTag,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  catalogSdkCallRegex,
  loadProviders,
  hasPaymentSdkImport,
  isWebhookFilePath,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'einvoice-obligation';

/* ------------------------------------------------------------------ *
 * Catalog lookups
 * ------------------------------------------------------------------ */

function loadJson(...segments) {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(utils.PLUGIN_ROOT, 'skills', 'payment-advisor', 'data', ...segments), 'utf8')
    );
  } catch {
    return null;
  }
}

let _cache = null;
function catalog() {
  if (_cache) return _cache;
  const regions = (loadJson('regions.json') || {}).regions || {};
  const methods = (loadJson('methods.json') || {}).methods || [];

  const mandateRegions = {};          // 'MX' -> { mandate, note }
  const currencyOwners = {};          // 'MXN' -> ['MX']
  for (const [code, region] of Object.entries(regions)) {
    const einvoice = region && region.tax && region.tax.einvoice;
    if (einvoice && einvoice.mandate) {
      mandateRegions[code] = einvoice;
    }
    const cur = region && region.default_currency;
    if (cur) {
      (currencyOwners[cur.toUpperCase()] = currencyOwners[cur.toUpperCase()] || []).push(code);
    }
  }

  // A currency only identifies a country when exactly one country in the catalog uses it.
  // USD and EUR name half a dozen countries each and must never resolve a jurisdiction.
  const currencyToRegion = {};
  for (const [cur, owners] of Object.entries(currencyOwners)) {
    if (owners.length === 1) currencyToRegion[cur] = owners[0];
  }

  // Only single-region methods anchored to a real catalog region carry a jurisdiction.
  const methodToRegion = {};
  for (const method of methods) {
    const regionList = method.regions || [];
    if (regionList.length !== 1) continue;
    const only = regionList[0];
    if (!regions[only]) continue;     // GLOBAL / EU / APAC are not jurisdictions
    methodToRegion[String(method.id).toLowerCase()] = { region: only, label: method.label || method.id };
  }

  _cache = { regions, mandateRegions, currencyToRegion, methodToRegion };
  return _cache;
}

const MANDATE_LABELS = {
  cfdi: 'CFDI 4.0',
  nfe: 'NF-e',
  dte: 'DTE',
  sunat: 'SUNAT (comprobante electrónico)',
  dian: 'DIAN (facturación electrónica)',
  sri: 'SRI (Ecuador)',
  sdi: 'SdI / FatturaPA',
  zatca: 'ZATCA (Fatoora)',
};

const REGION_NAMES = {
  MX: 'Mexico', BR: 'Brazil', CO: 'Colombia', CL: 'Chile', PE: 'Peru',
  EC: 'Ecuador', IT: 'Italy', SA: 'Saudi Arabia',
};
const REGION_NAMES_ES = {
  MX: 'México', BR: 'Brasil', CO: 'Colombia', CL: 'Chile', PE: 'Perú',
  EC: 'Ecuador', IT: 'Italia', SA: 'Arabia Saudita',
};

/* ------------------------------------------------------------------ *
 * Signals
 * ------------------------------------------------------------------ */

const COMPLETED_STATUS_RE = /\bstatus\s*[:=]\s*['"](succeeded|approved|paid|APPROVED|SUCCEEDED|PAID)['"]/;
const CURRENCY_LITERAL_RE = /\b(?:currency|currency_id|moneda|currencyCode)\s*[:=]\s*['"]([A-Za-z]{3})['"]/g;
const COUNTRY_LITERAL_RE =
  /\b(?:country|country_code|countryCode|pais|país|market|jurisdiction)\s*[:=]\s*['"]([A-Za-z]{2})['"]/g;
// A line that is real code carries an assignment or a key; a comment line strips to blanks.
const CODE_LINE_RE = /[A-Za-z_$][\w$]*\s*[:=]|[[({]/;

/**
 * A module — a file, a directory, or an import — that can emit the fiscal document.
 *
 * The bare English word `invoic` is deliberately NOT here. Every order object in the
 * world carries an `invoiceUrl`, and every shop has an `invoices/` folder for its own
 * receipts; treating either as "this project can already emit a CFDI" silences the check
 * on exactly the integrations it exists for. A fiscal document has a name, and every
 * order object in the world carries an `invoiceUrl` or an `invoice_id`; treating that as
 * "this project can already emit a CFDI" silences the check on exactly the integrations
 * name it goes by is in this list.
 */
const INVOICING_CODE_RE =
  /\bcfdi\b|\bnfe\b|\bnf_e\b|\bnota_fiscal\b|\bnotafiscal\b|factura|\bzatca\b|\bsunat\b|\bdian\b|\bsri_ec\b|\bdte\b|\btimbrad|facturama|facturapi|focusnfe|enotas|contaazul|\balegra\b|\bsiigo\b|e-?invoic|\bfiscal_?document\b/i;

/** A reversal is not a sale. A refund creates a credit note, never a new obligation. */
const REVERSAL_RE = /\brefund|\breversal|\bvoid\b|\bcancel|\bchargeback|\bdispute|\breverse\b/i;

/** `locale: 'es-MX'` / `lang: 'pt-BR'` — an unambiguous statement of jurisdiction. */
const LOCALE_LITERAL_RE =
  /\b(?:locale|lang|language|culture)\s*[:=]\s*['"][a-z]{2}[-_]([A-Za-z]{2})['"]/g;

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', '.svelte-kit', 'dist', 'build', 'out',
  'coverage', 'vendor', '__pycache__', '.venv', 'venv', 'target', '.turbo', '.cache',
]);

/** Does the project contain a file or directory that can issue the fiscal document? */
function projectHasInvoicing(projectDir) {
  if (!projectDir) return false;
  let budget = 300;
  const queue = [{ dir: projectDir, depth: 0 }];
  while (queue.length && budget > 0) {
    const { dir, depth } = queue.shift();
    budget--;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        if (INVOICING_CODE_RE.test(entry.name)) return true;
        if (depth < 4) queue.push({ dir: path.join(dir, entry.name), depth: depth + 1 });
        continue;
      }
      if (INVOICING_CODE_RE.test(entry.name)) return true;
    }
  }
  return false;
}

/** Is this file owned by a merchant-of-record provider? The MoR issues the document. */
function fileBelongsToMor(filePath, content) {
  const providers = (loadProviders().providers || []).filter((p) => p && p.mor && p.mor.is_mor);
  if (!providers.length) return false;
  const norm = String(filePath || '').replace(/\\/g, '/').toLowerCase();
  for (const provider of providers) {
    const slugs = [String(provider.id).toLowerCase()];
    const name = String(provider.name || '').toLowerCase();
    if (name) slugs.push(name.replace(/[^a-z0-9]+/g, ''), name.replace(/[^a-z0-9]+/g, '-'));
    for (const slug of slugs) {
      if (!slug) continue;
      if (norm.split(/[/.]/).includes(slug)) return true;
      const importRe = new RegExp(
        "(?:from\\s*|require\\s*\\(\\s*)['\"][^'\"\\n]*" + slug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
        'i'
      );
      if (importRe.test(content)) return true;
    }
  }
  return false;
}

/**
 * Comments out, string literals in — offsets and line numbers preserved.
 *
 * Every literal this check resolves a jurisdiction from (`'MXN'`, `'oxxo'`, `'es-MX'`)
 * is a string, so it cannot read the fully stripped copy. But reading the raw line means
 * `paymentMethodId: string; // e.g. 'visa', 'oxxo'` resolves Mexico from a comment, and
 * "a comment is not code" is the one promise every check in this suite makes.
 */
function stripCommentsKeepStrings(code) {
  const out = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    const next = code[i + 1];
    if (c === '/' && next === '/') {
      out.push('  ');
      i += 2;
      while (i < n && code[i] !== '\n') { out.push(' '); i++; }
      continue;
    }
    if (c === '/' && next === '*') {
      out.push('  ');
      i += 2;
      while (i < n - 1 && !(code[i] === '*' && code[i + 1] === '/')) {
        out.push(code[i] === '\n' ? '\n' : ' ');
        i++;
      }
      out.push('  ');
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      out.push(c);
      i++;
      while (i < n && code[i] !== quote) {
        if (code[i] === '\\' && i + 1 < n) { out.push(code[i], code[i + 1]); i += 2; continue; }
        out.push(code[i]);
        i++;
      }
      if (i < n) out.push(quote);
      i++;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

/** An ambient declaration file declares shapes. It cannot complete a sale. */
function isDeclarationFile(filePath) {
  return /\.d\.[cm]?ts$/i.test(String(filePath || ''));
}

/* ------------------------------------------------------------------ */

function resolveRegion(rawLines, strippedLines) {
  const { mandateRegions, currencyToRegion, methodToRegion } = catalog();

  // 1. Country literal — the most direct statement of jurisdiction.
  for (let i = 0; i < rawLines.length; i++) {
    if (!CODE_LINE_RE.test(strippedLines[i] || '')) continue;
    COUNTRY_LITERAL_RE.lastIndex = 0;
    let m;
    while ((m = COUNTRY_LITERAL_RE.exec(rawLines[i]))) {
      const code = m[1].toUpperCase();
      if (mandateRegions[code]) {
        return { region: code, via_en: `country: '${code}'`, via_es: `el literal country: '${code}'`, line: i + 1 };
      }
    }
  }

  // 2. Currency literal — only when the currency belongs to exactly one country.
  for (let i = 0; i < rawLines.length; i++) {
    if (!CODE_LINE_RE.test(strippedLines[i] || '')) continue;
    CURRENCY_LITERAL_RE.lastIndex = 0;
    let m;
    while ((m = CURRENCY_LITERAL_RE.exec(rawLines[i]))) {
      const cur = m[1].toUpperCase();
      const region = currencyToRegion[cur];
      if (region && mandateRegions[region]) {
        return { region, via_en: `currency '${cur}'`, via_es: `la moneda '${cur}'`, line: i + 1 };
      }
    }
  }

  // 3. A locale literal — `es-MX` names a country and nothing else.
  for (let i = 0; i < rawLines.length; i++) {
    if (!CODE_LINE_RE.test(strippedLines[i] || '')) continue;
    LOCALE_LITERAL_RE.lastIndex = 0;
    let m;
    while ((m = LOCALE_LITERAL_RE.exec(rawLines[i]))) {
      const code = m[1].toUpperCase();
      if (mandateRegions[code]) {
        return {
          region: code,
          via_en: `the locale '${m[0].split(/['"]/)[1]}'`,
          via_es: `el locale '${m[0].split(/['"]/)[1]}'`,
          line: i + 1,
        };
      }
    }
  }

  // 4. A single-country payment method literal (oxxo → MX, boleto → BR, pse → CO).
  for (let i = 0; i < rawLines.length; i++) {
    if (!CODE_LINE_RE.test(strippedLines[i] || '')) continue;
    for (const [id, info] of Object.entries(methodToRegion)) {
      if (!mandateRegions[info.region]) continue;
      const re = new RegExp("['\"]" + id + "['\"]", 'i');
      if (re.test(rawLines[i])) {
        return {
          region: info.region,
          via_en: `the ${info.label} payment method`,
          via_es: `el método de pago ${info.label}`,
          line: i + 1,
        };
      }
    }
  }

  return null;
}

function run(ctx) {
  const { filePath, content, projectDir } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;
  if (isDeclarationFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  const strippedLines = stripped.split('\n');
  // Comments removed, string literals kept: the jurisdiction literals live in strings.
  const rawLines = stripCommentsKeepStrings(String(content)).split('\n');

  // (a) Does this file complete a sale?
  const sdkCall = catalogSdkCallRegex();
  const CREATION_RE = /\.create\s*\(|createCheckout\s*\(|WidgetCheckout/;
  // A reversal moves money back. `stripe.refunds.create` is in the catalog's call
  // patterns, and reading it as "a sale in Mexico" is both wrong and unactionable —
  // a refund produces a credit note, not a CFDI.
  const isReversal = (i) =>
    REVERSAL_RE.test(strippedLines[i] || '') ||
    REVERSAL_RE.test(strippedLines[Math.max(0, i - 1)] || '');
  let chargeLine = null;
  if (sdkCall) {
    let firstSdkLine = null;
    for (let i = 0; i < strippedLines.length; i++) {
      if (!sdkCall.test(strippedLines[i])) continue;
      if (isReversal(i)) continue;
      if (firstSdkLine === null) firstSdkLine = i + 1;
      if (CREATION_RE.test(strippedLines[i])) { chargeLine = i + 1; break; }
    }
    if (!chargeLine) chargeLine = firstSdkLine;
  }
  if (!chargeLine) {
    // A bare `status: 'paid'` is a query filter as often as it is a settled sale. It
    // only speaks for a completed sale inside code that is demonstrably payments code.
    const isPaymentsFile =
      hasPaymentSdkImport(content) ||
      (sdkCall ? sdkCall.test(stripped) : false) ||
      isWebhookFilePath(filePath);
    if (isPaymentsFile) {
      for (let i = 0; i < rawLines.length; i++) {
        // The status value is a string literal, so it is read from the raw line; the
        // stripped copy of the same line proves the line is code and not a comment.
        if (COMPLETED_STATUS_RE.test(rawLines[i]) && /\bstatus\s*[:=]/.test(strippedLines[i] || '')) {
          if (isReversal(i)) continue;
          chargeLine = i + 1;
          break;
        }
      }
    }
  }
  if (!chargeLine) return null;

  // (b) A merchant of record already owns the fiscal document for this sale.
  if (fileBelongsToMor(filePath, content)) return null;

  // (c) Which jurisdiction? Unresolvable → silent, always.
  const resolved = resolveRegion(rawLines, strippedLines);
  if (!resolved) return null;

  // (d) Is there already something that can invoice?
  if (INVOICING_CODE_RE.test(content)) return null;
  if (projectDir) {
    try {
      if (fs.existsSync(path.join(projectDir, 'PAGOKIT_TAX_TODO.md'))) return null;
    } catch { /* ignore */ }
    if (projectHasInvoicing(projectDir)) return null;
  }

  const { mandateRegions } = catalog();
  const einvoice = mandateRegions[resolved.region] || {};
  const mandateKey = String(einvoice.mandate || '').toLowerCase();
  const mandate = MANDATE_LABELS[mandateKey] || (einvoice.mandate || 'e-invoice').toUpperCase();
  const countryEn = REGION_NAMES[resolved.region] || resolved.region;
  const countryEs = REGION_NAMES_ES[resolved.region] || resolved.region;
  const strict = process.env.PAGOKIT_STRICT === '1';

  return {
    rule: RULE_ID,
    level: strict ? 'deny' : 'warn',
    code: 'ERR_EINVOICE_MISSING',
    message_en:
      `This file completes a sale (line ${chargeLine}) in ${countryEn} — indicated by ${resolved.via_en} at ` +
      `line ${resolved.line} — and nothing in the project can issue the ${mandate} fiscal document. ` +
      `In ${countryEn} issuing it is a legal obligation attached to the sale, not a later accounting step, ` +
      `so the integration is not shippable as written. A merchant of record (it becomes the seller) removes ` +
      `the obligation from you entirely.`,
    message_es:
      `Este archivo completa una venta (línea ${chargeLine}) en ${countryEs} — lo indica ${resolved.via_es} en ` +
      `la línea ${resolved.line} — y no hay nada en el proyecto que pueda emitir el comprobante fiscal ` +
      `${mandate}. En ${countryEs} emitirlo es una obligación legal que nace con la venta, no un trámite ` +
      `contable posterior, así que la integración no se puede lanzar tal como está. Un merchant of record ` +
      `(se vuelve el vendedor) te quita la obligación por completo.`,
    suggested_fix:
      `Pick one of three, then move on: (1) wire a ${mandate} issuer (Facturama / Facturapi for CFDI, ` +
      `Focus NFe / eNotas for NF-e, Alegra or Siigo for DIAN) into the same handler that marks the sale paid; ` +
      `(2) sell through a merchant of record, which issues the document as the seller; or ` +
      `(3) record the decision in PAGOKIT_TAX_TODO.md at the project root and this check goes quiet.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
