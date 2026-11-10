// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 13 — Minor-unit conversion must match the currency's ISO 4217 exponent.
 *
 * A reflexive `Math.round(amount * 100)` is only correct for two-decimal currencies.
 * In a zero-decimal currency (JPY, CLP, KRW, PYG, VND...) the amount is already in its
 * smallest unit, so the ×100 charges the customer 100x. In a three-decimal currency
 * (KWD, BHD, OMR, JOD, TND...) the smallest unit is 1/1000, so ×100 is off by 10x — and
 * for the providers that hash the amount at its ISO exponent it also breaks the signature,
 * which sends the developer debugging HMAC instead of the exponent.
 *
 * Deny needs three independent signals: an amount-shaped ×100 (or ÷100), a zero/three-decimal
 * currency literal in the same file, and the file looking payments-related. When the only
 * currency signal is an SDK call the finding drops to 'warn', because ×100 is also how
 * percentages are computed.
 *
 * Bypass: `// pagokit-ignore: minor-units -- <reason>`.
 */

const {
  hasIgnoreTag,
  isSourceCodeFile,
  stripCommentsAndStrings,
  hasPaymentSdkImport,
  catalogSdkCallRegex,
  nonStandardExponentCurrencies,
  loadCurrencies,
} = require('../lib/utils');

const RULE_ID = 'minor-units';

/* ------------------------------------------------------------------ *
 * Identifier vocabulary
 * ------------------------------------------------------------------ */

// Words that make an identifier a money amount.
const AMOUNT_TOKENS = new Set([
  'amount', 'amounts', 'amt', 'total', 'totals', 'subtotal', 'subtotals',
  'price', 'prices', 'precio', 'precios', 'monto', 'montos',
  'importe', 'importes', 'valor', 'valores', 'grandtotal',
]);

// Words that mean "this multiplication is not money" — percentages, UI geometry, ratios.
// Checked against the identifier AND the whole line.
const NOT_AMOUNT_TOKENS = new Set([
  'pct', 'percent', 'percentage', 'percentages', 'porcentaje', 'ratio', 'ratios',
  'rate', 'rates', 'tasa', 'share', 'progress', 'opacity', 'scale', 'zoom',
  'width', 'height', 'fraction', 'proportion', 'coverage', 'score', 'probability',
  'confidence', 'alpha', 'volume', 'apr', 'growth', 'delta', 'variance', 'weight',
]);

// Counts and units of measure. Checked against the identifier only: a line may legitimately
// read `amount: Math.round(price * 100) * quantity`, and that x100 is still the bug.
const NOT_AMOUNT_IDENTIFIER = new Set([
  'length', 'count', 'size', 'index', 'idx', 'offset', 'limit', 'page', 'quantity', 'qty',
  'seconds', 'minutes', 'hours', 'days', 'months', 'years', 'ms', 'px', 'bytes', 'kb', 'mb',
  'degrees', 'latitude', 'longitude', 'version', 'level', 'rows', 'items',
  // Units of measure: `totalMeters * 100` is centimetres, not cents.
  'meters', 'metres', 'metros', 'cm', 'mm', 'km', 'inches', 'feet', 'grams', 'kg',
  'distance', 'girth', 'area', 'duration', 'calories', 'steps', 'pixels',
]);

// Vocabulary that only ever means "this file converts between major and minor units".
// Its presence anywhere is enough: the maths below it is deliberate. Never fire.
const EXPONENT_AWARE_STRICT =
  /zero[_-]?decimal|three[_-]?decimal|minor[_-]?unit|major[_-]?unit|smallest[_-]?unit|currency[_-]?exponent|toMinorUnits|fromMinorUnits|iso4217/i;

// Words that mean "minor units" only in a currency context. A `const decimalPlaces = 2` for a
// chart axis, or a `2 ** n` backoff whose helper is called an exponent, must not switch the
// whole rule off for the file -- that is a one-identifier bypass. These exempt the file only
// when the same line also talks about currency.
const EXPONENT_AWARE_LOOSE = /\bexponents?\b|decimal[_-]?places|decimalplaces/i;
const CURRENCY_WORD = /currenc|moneda|divisa|iso\s*4217/i;

/** True when the file demonstrably reasons about ISO exponents already. */
function isExponentAware(commentFree) {
  if (EXPONENT_AWARE_STRICT.test(commentFree)) return true;
  for (const line of commentFree.split('\n')) {
    if (EXPONENT_AWARE_LOOSE.test(line) && CURRENCY_WORD.test(line)) return true;
  }
  return false;
}

// A conditional that mentions currency near the maths = the file already branches per currency.
const CONDITIONAL = /\?|\bif\b|\belif\b|\bcase\b|\bswitch\b|\bmatch\b|\.includes\s*\(|\.has\s*\(|===|!==|==|\bin\b/;

const PAYMENTS_PATH =
  /checkout|payment|refund|billing|charge|cobro|pago/i;

// Bounded repetition, not `*`: an unbounded member chain makes the scan quadratic on a
// minified or generated line, and a hook that stalls is a hook that gets uninstalled.
const CHAIN = "[A-Za-z_$][\\w$]*(?:\\s*(?:\\.|->|::)\\s*[A-Za-z_$][\\w$]*){0,6}";

// `100`, `100.0`, `100.00` -- Python and PHP write the float form and it is the same bug.
const HUNDRED = "(?<![\\w$.])100(?:\\.0+)?(?![\\d.])";

// Object keys / kwargs that make the value they hold the money of a charge. Used to catch a
// x100 whose identifier is not money-named (`amount: Math.round(cost * 100)`).
const MONEY_KEYS = [
  'amount_in_cents', 'amountInCents', 'transaction_amount', 'transactionAmount',
  'gross_amount', 'grossAmount', 'unit_amount', 'unitAmount', 'amount_cents', 'amountCents',
  'unit_price', 'unitPrice', 'monto_menor', 'amount', 'monto', 'importe', 'precio',
  'price', 'total', 'subtotal', 'valor',
];
const MONEY_KEY_RE = new RegExp(
  '(?:^|[\\s{,(])["\']?(' +
    MONEY_KEYS.slice().sort((a, b) => b.length - a.length).join('|') +
    ')["\']?\\s*[:=](?![=>])\\s*',
  'g'
);

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

/**
 * Blank comments but KEEP string bodies, preserving every offset.
 * stripCommentsAndStrings() blanks strings too, which is right for code patterns but
 * would erase the currency literal this rule depends on.
 */
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

/** camelCase + snake_case + dotted chain -> lowercase word tokens. */
function tokenize(s) {
  return String(s)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .map((t) => t.toLowerCase())
    .filter(Boolean);
}

function hasAny(tokens, set) {
  return tokens.some((t) => set.has(t));
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

/** Prefer well-known codes when naming examples, without hardcoding the list itself. */
function sampleCodes(list, preferred, n) {
  const seen = new Set();
  const out = [];
  for (const code of preferred) {
    if (list.includes(code) && !seen.has(code)) { out.push(code); seen.add(code); }
  }
  for (const code of list) {
    if (out.length >= n) break;
    if (!seen.has(code)) { out.push(code); seen.add(code); }
  }
  return out.slice(0, n).join(', ');
}

function currencyByCode() {
  const map = new Map();
  for (const c of loadCurrencies().currencies || []) {
    map.set(String(c.code).toUpperCase(), c);
  }
  return map;
}

/**
 * Find currency-code literals in comment-free source. Returns every hit with its offset so
 * the message can name a line, plus whether a plain two-decimal currency was pinned.
 */
function scanCurrencyLiterals(code, zeroSet, threeSet, known) {
  const found = [];
  const perLine = new Map();

  const patterns = [
    /['"`]\s*([A-Za-z]{3})\s*['"`]/g,
    /\bcurrenc(?:y|y_id|ycode|y_code)\b['"`]?\s*(?::|=>|=)\s*['"`]?([A-Za-z]{3})\b/gi,
  ];

  const seen = new Set();
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code)) !== null) {
      const upper = m[1].toUpperCase();
      if (!known.has(upper)) continue;
      const key = upper + '@' + m.index;
      if (seen.has(key)) continue;
      seen.add(key);
      const kind = zeroSet.has(upper) ? 'zero' : threeSet.has(upper) ? 'three' : 'two';
      const line = lineNumberAt(code, m.index);
      found.push({ code: upper, kind, index: m.index, line });
      if (!perLine.has(line)) perLine.set(line, new Set());
      perLine.get(line).add(upper);
    }
  }

  // Two or more distinct non-standard codes on one line is a lookup table / locale map, not a
  // charge. Drop that line's literals -- but only that line's. Bailing on the whole file made
  // a stray `{ 'JPY': 'ja-JP', 'KRW': 'ko-KR' }` switch the rule off for the charge below it.
  const tableLines = new Set();
  for (const [line, codes] of perLine) {
    let nonStandard = 0;
    for (const c of codes) if (zeroSet.has(c) || threeSet.has(c)) nonStandard++;
    if (nonStandard >= 2) tableLines.add(line);
  }

  const kept = found.filter((c) => !tableLines.has(c.line));
  const nonStandard = kept.filter((c) => c.kind !== 'two').sort((a, b) => a.index - b.index);
  const standard = kept.filter((c) => c.kind === 'two').sort((a, b) => a.index - b.index);
  return { nonStandard, standard, standardPinned: standard.length > 0 };
}

/** Money-shaped key/kwarg value regions, and the plain identifiers they hold. */
function moneyContext(stripped) {
  const ranges = [];
  const names = new Set();
  MONEY_KEY_RE.lastIndex = 0;
  let m;
  while ((m = MONEY_KEY_RE.exec(stripped)) !== null) {
    const start = m.index + m[0].length;
    let depth = 0;
    let i = start;
    const max = Math.min(stripped.length, start + 200);
    while (i < max) {
      const ch = stripped[i];
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth--; }
      else if ((ch === ',' || ch === ';' || ch === '\n') && depth === 0) break;
      i++;
    }
    ranges.push([start, i]);
    const bare = stripped.slice(start, i).trim();
    if (/^[A-Za-z_$][\w$]*$/.test(bare)) names.add(bare);
  }
  return { ranges, names };
}

/**
 * Find `<amount-ish chain> <op> 100` (either operand order) in stripped code.
 * Skips percentage/geometry identifiers, ratios, the round-to-2-decimals idiom, and any line
 * whose neighbourhood already branches on the currency.
 */
function findAmountScaling(stripped, commentFree, op, money) {
  const opEsc = op === '*' ? '\\*' : '\\/';
  const forward = new RegExp('(' + CHAIN + ')\\s*' + opEsc + '\\s*' + HUNDRED, 'g');
  const backward = op === '*'
    ? new RegExp('(?<![\\w$.])100(?:\\.0+)?(?![\\d.])\\s*\\*\\s*(' + CHAIN + ')', 'g')
    : null;

  const strippedLines = stripped.split('\n');
  const codeLines = commentFree.split('\n');

  const consider = (chain, matchStart, matchEnd) => {
    const chainTokens = tokenize(chain);
    if (hasAny(chainTokens, NOT_AMOUNT_TOKENS)) return null;
    if (hasAny(chainTokens, NOT_AMOUNT_IDENTIFIER)) return null;

    const line = lineNumberAt(stripped, matchStart);
    const lineText = strippedLines[line - 1] || '';
    if (hasAny(tokenize(lineText), NOT_AMOUNT_TOKENS)) return null;

    // `paid / totalCarts * 100` is a percentage of a total, not a total in cents. The chain
    // being the divisor is the tell, whatever the identifier is called.
    let back = matchStart - 1;
    while (back >= 0 && /\s/.test(stripped[back])) back--;
    if (back >= 0 && stripped[back] === '/') return null;

    // `Math.round(gross * 100) / 100` is rounding to two decimals and converts nothing.
    if (/^\s*\)*\s*\/\s*100(?![\d.])/.test(stripped.slice(matchEnd, matchEnd + 12))) return null;

    // Money by name, or money by position: `amount: Math.round(cost * 100)` and
    // `const minor = Math.round(yen * 100); ... { amount: minor }` are both the bug.
    if (!hasAny(chainTokens, AMOUNT_TOKENS)) {
      const inMoneySlot = money.ranges.some(([a, b]) => matchStart < b && matchEnd > a);
      const assigned = lineText.match(/(?:^|[;{(])\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=(?![=>])/);
      const feedsMoney = assigned ? money.names.has(assigned[1]) : false;
      if (!inMoneySlot && !feedsMoney) return null;
    }

    // Currency-aware branch nearby -> the developer already handles exponents.
    const from = Math.max(0, line - 3);
    const to = Math.min(codeLines.length, line + 2);
    const windowText = codeLines.slice(from, to).join('\n');
    if (/currenc|moneda|divisa/i.test(windowText) && CONDITIONAL.test(windowText)) return null;

    return { chain: chain.replace(/\s+/g, ''), line };
  };

  for (const re of [forward, backward]) {
    if (!re) continue;
    let m;
    while ((m = re.exec(stripped)) !== null) {
      const chainIndex = re === forward ? m.index : m.index + m[0].indexOf(m[1], 3);
      const hit = consider(m[1], chainIndex, m.index + m[0].length);
      if (hit) return hit;
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Rule
 * ------------------------------------------------------------------ */

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (filePath && !isSourceCodeFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  const commentFree = blankComments(content, filePath);

  // (c) Is this file payments-related at all?
  const pathPayments = PAYMENTS_PATH.test(String(filePath || '').replace(/\\/g, '/'));
  const sdkImport = hasPaymentSdkImport(content);
  if (!pathPayments && !sdkImport) return null;

  // The file already reasons about minor units — its maths is deliberate.
  if (isExponentAware(commentFree)) return null;

  const { zero, three } = nonStandardExponentCurrencies();
  const zeroSet = new Set(zero);
  const threeSet = new Set(three);
  const known = currencyByCode();

  const { nonStandard, standard, standardPinned } = scanCurrencyLiterals(
    commentFree, zeroSet, threeSet, known
  );

  const sdkCallRe = catalogSdkCallRegex();
  const sdkSignal = sdkImport || (sdkCallRe ? sdkCallRe.test(stripped) : false);

  // (b) Needs a non-standard currency literal, or at least an SDK signal.
  if (!nonStandard.length) {
    if (standardPinned) return null; // a two-decimal currency is pinned: x100 is correct
    if (!sdkSignal) return null;
  }

  const money = moneyContext(stripped);
  const mul = findAmountScaling(stripped, commentFree, '*', money);
  const zeroHit = nonStandard.find((c) => c.kind === 'zero');
  const div = zeroHit ? findAmountScaling(stripped, commentFree, '/', money) : null;

  if (!mul && !div) return null;

  // Whichever currency literal sits closest to the maths is the one that governs it. A file
  // whose charge pins `currency: 'usd'` on the next line is correct even if a JPY appears in
  // a locale map further up -- denying that write would be denying working code.
  const nearest = (list, line) =>
    list.reduce((best, c) => (best === null || Math.abs(c.line - line) < Math.abs(best.line - line) ? c : best), null);
  const mathsLine = (mul || div).line;
  const nearNonStandard = nearest(nonStandard, mathsLine);
  const nearStandard = nearest(standard, mathsLine);
  if (
    nearStandard &&
    (!nearNonStandard || Math.abs(nearStandard.line - mathsLine) < Math.abs(nearNonStandard.line - mathsLine))
  ) {
    return null;
  }

  /* --- deny: a real zero/three-decimal currency is named in this file --- */
  if (nonStandard.length) {
    const cur = mul
      ? (nearNonStandard || nonStandard[0])
      : (nearNonStandard && nearNonStandard.kind === 'zero' ? nearNonStandard : zeroHit);
    const meta = known.get(cur.code) || {};
    const name = meta.name || cur.code;
    const exponent = typeof meta.exponent === 'number' ? meta.exponent : (cur.kind === 'zero' ? 0 : 3);

    if (mul) {
      const enWhy = cur.kind === 'zero'
        ? `${cur.code} has no minor unit, so the amount is already final and the x100 charges the customer 100x too much`
        : `${cur.code} is a three-decimal currency (1 ${cur.code} = 1000 minor units), so multiplying by 100 instead of 1000 leaves the charge off by 10x`;
      const esWhy = cur.kind === 'zero'
        ? `${cur.code} no tiene unidad menor: el monto ya es final, así que multiplicar por 100 le cobra al cliente 100 veces de más`
        : `${cur.code} es una moneda de tres decimales (1 ${cur.code} = 1000 unidades menores), así que multiplicar por 100 en vez de por 1000 deja el cobro 10 veces por debajo`;

      return {
        rule: RULE_ID,
        level: 'deny',
        code: 'ERR_MINOR_UNITS',
        message_en:
          `Line ${mul.line}: \`${mul.chain} * 100\` assumes a two-decimal currency, but this file charges in ${cur.code} (${name}, ISO 4217 exponent ${exponent}, named on line ${cur.line}). ${enWhy}.`,
        message_es:
          `Línea ${mul.line}: \`${mul.chain} * 100\` asume una moneda de dos decimales, pero este archivo cobra en ${cur.code} (${name}, exponente ISO 4217 ${exponent}, declarado en la línea ${cur.line}). ${esWhy}.`,
        suggested_fix:
          `Scale by the currency's ISO 4217 exponent instead of a literal 100:\n` +
          `  const EXPONENT = { ${cur.code}: ${exponent} };  // 0 = zero-decimal, 3 = three-decimal, default 2\n` +
          `  const minor = Math.round(${mul.chain} * 10 ** (EXPONENT[currency] ?? 2));\n` +
          `For ${cur.code} that means ${exponent === 0 ? 'passing the amount unchanged' : 'multiplying by 1000'}.\n` +
          `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
      };
    }

    return {
      rule: RULE_ID,
      level: 'deny',
      code: 'ERR_MINOR_UNITS',
      message_en:
        `Line ${div.line}: \`${div.chain} / 100\` converts back from minor units, but this file uses ${cur.code} (${name}, ISO 4217 exponent 0, named on line ${cur.line}). ${cur.code} amounts are already whole units — dividing by 100 shrinks the amount 100x.`,
      message_es:
        `Línea ${div.line}: \`${div.chain} / 100\` convierte desde unidades menores, pero este archivo usa ${cur.code} (${name}, exponente ISO 4217 0, declarado en la línea ${cur.line}). En ${cur.code} los montos ya vienen en unidades enteras: dividir entre 100 los reduce 100 veces.`,
      suggested_fix:
        `Do not divide ${cur.code} amounts by 100 — use the amount as-is, or divide by 10 ** exponent with the exponent read per currency.\n` +
        `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
    };
  }

  /* --- warn: payments SDK present, currency unknown at write time --- */
  const zeroSample = sampleCodes(zero, ['JPY', 'KRW', 'CLP'], 3);
  const threeSample = sampleCodes(three, ['KWD', 'BHD'], 2);
  return {
    rule: RULE_ID,
    level: 'warn',
    code: 'ERR_MINOR_UNITS',
    message_en:
      `Line ${mul.line}: \`${mul.chain} * 100\` hardcodes a two-decimal minor unit in a file that calls a payments SDK, and no currency literal is visible to confirm it. ${zero.length} zero-decimal currencies (${zeroSample}...) would be charged 100x and ${three.length} three-decimal ones (${threeSample}...) would be off by 10x.`,
    message_es:
      `Línea ${mul.line}: \`${mul.chain} * 100\` fija una unidad menor de dos decimales en un archivo que llama a un SDK de pagos, y no hay ningún literal de moneda a la vista que lo confirme. Las ${zero.length} monedas sin decimales (${zeroSample}...) se cobrarían 100 veces de más, y las ${three.length} de tres decimales (${threeSample}...) quedarían 10 veces por debajo.`,
    suggested_fix:
      `Derive the multiplier from the currency instead of assuming 2 decimals:\n` +
      `  const minor = Math.round(${mul.chain} * 10 ** exponentFor(currency));  // 0 | 2 | 3\n` +
      `If this codepath is pinned to a two-decimal currency, say so with an explicit \`currency: 'USD'\` literal.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
