// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 28 — Hardcoded currency the chosen provider does not support.
 *
 * A `currency: 'USD'` inside a Wompi integration is not a typo the compiler catches: it fails
 * at the API, in production, on the first real checkout. This check resolves which provider a
 * file belongs to (path segment or SDK import, matched against the catalog) and compares every
 * hardcoded currency literal against that provider's verified currency list.
 *
 * Always 'warn', never 'deny': the catalog records the currencies verified for the provider,
 * and an individual merchant account can have more enabled. This is advice, not a defect.
 *
 * Bypass: `// pagokit-ignore: currency-mismatch -- <reason>`.
 */

const {
  hasIgnoreTag,
  isSourceCodeFile,
  stripCommentsAndStrings,
  loadProviders,
  loadCurrencies,
} = require('../lib/utils');

const RULE_ID = 'currency-mismatch';

// `currency: 'COP'`, `"currency": "COP"`, `currency="COP"`, `currency_id: 'ARS'`,
// `const CURRENCY = 'USD'`, `currency: \`USD\``. Case-insensitive: a screaming-case constant
// is the same hardcoded currency as a lowercase key.
const CURRENCY_LITERAL =
  /\b(currency|currency_id|currencyId|currencyCode|currency_code|moneda)\b['"`]?\s*(?::|=>|=)\s*['"`]([A-Za-z]{3})['"`]/gi;

// Number formatting is presentation, not a charge: `Intl.NumberFormat('en-US', { currency:
// 'USD' })` inside a Wompi module is how you show a converted price, and warning on it sends
// the developer to change working display code.
const DISPLAY_CALL = /\bIntl\s*\.\s*NumberFormat\s*\(|\.\s*toLocaleString\s*\(|\bformatToParts\s*\(/g;

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/** Blank comments, keep string bodies, preserve offsets (the currency lives in a string). */
function blankComments(code, filePath) {
  const hash = /\.(py|rb|sh|pl)$/i.test(filePath || '');
  const out = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    const d = code[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && code[i] !== '\n') { out.push(' '); i++; }
      continue;
    }
    if (c === '#' && hash) {
      while (i < n && code[i] !== '\n') { out.push(' '); i++; }
      continue;
    }
    if (c === '/' && d === '*') {
      out.push(' ', ' ');
      i += 2;
      while (i < n && !(code[i] === '*' && code[i + 1] === '/')) {
        out.push(code[i] === '\n' ? '\n' : ' ');
        i++;
      }
      if (i < n) { out.push(' ', ' '); i += 2; }
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const q = c;
      out.push(c);
      i++;
      while (i < n && code[i] !== q) {
        if (code[i] === '\\' && i + 1 < n) { out.push(code[i], code[i + 1]); i += 2; continue; }
        out.push(code[i]);
        i++;
      }
      if (i < n) { out.push(code[i]); i++; }
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

// Newline offsets, cached per text: a hook runs on every write, and slicing the whole file
// once per match turns a big file into quadratic work.
const _lineCache = [];
function newlineOffsets(text) {
  for (const entry of _lineCache) if (entry.text === text) return entry.offsets;
  const offsets = [];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) offsets.push(i);
  _lineCache.unshift({ text, offsets });
  if (_lineCache.length > 2) _lineCache.pop();
  return offsets;
}

function lineNumberAt(text, index) {
  const offsets = newlineOffsets(text);
  let lo = 0;
  let hi = offsets.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (offsets[mid] < index) lo = mid + 1;
    else hi = mid;
  }
  return lo + 1;
}

/** Balanced argument region of the first `(` at or after `from`. */
function callArgRange(text, from) {
  const open = text.indexOf('(', from);
  if (open === -1) return null;
  let depth = 0;
  const max = Math.min(text.length, open + 2000);
  for (let i = open; i < max; i++) {
    const ch = text[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return [open + 1, i];
    }
  }
  return [open + 1, max];
}

/**
 * Is the key at `index` real code, or text inside a string?
 *
 * The currency code itself lives in a string, so the file cannot simply match against
 * stripCommentsAndStrings output -- but the KEY must be code. `stripped` blanks string bodies
 * while preserving offsets, so a blank there means the key is prose. The one exception is a
 * quoted key, `"currency": "USD"`, which is real code with quotes around it.
 */
function keyIsCode(commentFree, stripped, index, keyLen) {
  if (stripped[index] && stripped[index] !== ' ') return true;
  const q = commentFree[index - 1];
  if (q !== '"' && q !== "'" && q !== '`') return false;
  if (commentFree[index + keyLen] !== q) return false;
  let i = index + keyLen + 1;
  while (i < commentFree.length && /[ \t]/.test(commentFree[i])) i++;
  return commentFree[i] === ':';
}

/** Argument regions of display-formatting calls, whose currency option is not a charge. */
function displayRegions(code) {
  const out = [];
  DISPLAY_CALL.lastIndex = 0;
  let m;
  while ((m = DISPLAY_CALL.exec(code)) !== null) {
    const range = callArgRange(code, m.index + m[0].length - 1);
    if (range) out.push(range);
  }
  return out;
}

/** Provider ids named by a path segment: /api/webhook/wompi/, lib/payments/lemon-squeezy.ts */
function providersFromPath(filePath, providers) {
  const hits = new Set();
  const norm = String(filePath || '').replace(/\\/g, '/').toLowerCase();
  const tokens = new Set();
  for (const seg of norm.split('/')) {
    const base = seg.replace(/\.[a-z0-9]+$/, '');
    if (base) tokens.add(slug(base));
    for (const t of base.split(/[^a-z0-9]+/)) if (t) tokens.add(t);
  }
  for (const p of providers) {
    const names = new Set([slug(p.id), slug(p.name)].filter(Boolean));
    for (const t of tokens) if (names.has(t)) hits.add(p.id);
  }
  return hits;
}

/**
 * Provider ids named by an import/require specifier. Takes comment-free code: an import that
 * only survives in a commented-out line is not a provider this file uses.
 */
function providersFromImport(content, providers) {
  const specs = new Set();
  const patterns = [
    /(?:from\s*|require\s*\(\s*|import\s*\(\s*)['"]([^'"\n]+)['"]/g,
    /^\s*(?:import|from)\s+([A-Za-z0-9_@./-]+)/gm,
    /^\s*use\s+([A-Za-z0-9_\\]+)/gm,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) specs.add(m[1]);
  }

  const hits = new Set();
  for (const p of providers) {
    const pats = new Set((p.detection && p.detection.sdk_import_patterns) || []);
    for (const langs of Object.values(p.sdks || {})) {
      if (langs && langs.pkg) pats.add(langs.pkg);
    }
    for (const spec of specs) {
      const low = spec.toLowerCase();
      for (const pat of pats) {
        const lp = String(pat).toLowerCase();
        if (low === lp || low.startsWith(lp)) { hits.add(p.id); break; }
      }
      // Internal wrappers: '@/lib/payments/wompi'
      const last = low.split(/[/\\]/).pop() || '';
      if (slug(last) === slug(p.id)) hits.add(p.id);
    }
  }
  return hits;
}

/* ------------------------------------------------------------------ *
 * Rule
 * ------------------------------------------------------------------ */

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (filePath && !isSourceCodeFile(filePath)) return null;

  const providers = loadProviders().providers || [];
  if (!providers.length) return null;

  const code = blankComments(content, filePath);

  const hits = new Set([
    ...providersFromPath(filePath, providers),
    ...providersFromImport(code, providers),
  ]);
  // Undetermined or ambiguous — say nothing rather than guess the provider.
  if (hits.size !== 1) return null;

  const provider = providers.find((p) => p.id === [...hits][0]);
  const supported = (provider && provider.currencies) || [];
  if (!supported.length) return null;
  const supportedSet = new Set(supported.map((c) => String(c).toUpperCase()));

  const known = new Set((loadCurrencies().currencies || []).map((c) => String(c.code).toUpperCase()));

  const display = displayRegions(code);
  const stripped = stripCommentsAndStrings(content);

  CURRENCY_LITERAL.lastIndex = 0;
  let m;
  while ((m = CURRENCY_LITERAL.exec(code)) !== null) {
    const cur = m[2].toUpperCase();
    if (!known.has(cur)) continue;          // not an ISO code — a different bug, not this rule
    if (supportedSet.has(cur)) continue;
    if (!keyIsCode(code, stripped, m.index, m[1].length)) continue;
    if (display.some(([a, b]) => m.index >= a && m.index <= b)) continue;

    const line = lineNumberAt(code, m.index);
    // Render the literal in one normalized shape: the raw match can start mid-quote
    // (`currency": "USD"`) or nest backticks, both of which read as noise in the message.
    const op = /=>/.test(m[0]) ? ' =>' : m[0].slice(m[1].length).includes(':') ? ':' : ' =';
    const literal = `${m[1]}${op} '${m[2]}'`;
    const shown = supported.slice(0, 8).join(', ');
    const more = supported.length > 8 ? `, +${supported.length - 8} more` : '';
    const name = (provider && provider.name) || provider.id;

    return {
      rule: RULE_ID,
      level: 'warn',
      code: 'ERR_CURRENCY_UNSUPPORTED',
      message_en:
        `Line ${line} hardcodes \`${literal}\`, but ${cur} is not in the currency list verified for ${name} (${shown}${more}). Unless your account has ${cur} enabled, the API rejects the charge at runtime.`,
      message_es:
        `La línea ${line} fija \`${literal}\`, pero ${cur} no está en la lista de monedas verificada para ${name} (${shown}${more}). Salvo que tu cuenta tenga ${cur} habilitada, la API va a rechazar el cobro en producción.`,
      suggested_fix:
        `Charge one of ${name}'s verified currencies (${shown}${more}), or confirm in the ${name} dashboard that ${cur} is enabled for this account.\n` +
        `If the merchant genuinely sells in ${cur}, route that flow to a provider that settles it — /pagokit:advisor compares them.\n` +
        `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
    };
  }

  return null;
}

module.exports = { run, RULE_ID };
