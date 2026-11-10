// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 24 — raw PAN / CVV must never cross the merchant's own server.
 *
 * Promotes SECURITY_RULES Rule 12 from prose to enforcement. The moment a card number or a
 * CVV is accepted by your route handler, read out of your request body, stored in a column,
 * or forwarded in a fetch body, the merchant leaves SAQ A (about 20 questions, self-assessed)
 * and lands in SAQ D (about 300 questions, plus quarterly ASV scans and, above the volume
 * thresholds, an on-site QSA). It is the most expensive mistake available in this space, and
 * it is invisible until an auditor arrives.
 *
 * Gating, because this check blocks a write:
 *   - Only "strong" tokens (card_number / creditCardNumber / ccNumber, cvv, cvc, track1/2,
 *     numero_tarjeta) can deny on their own, and only from an accept/forward position — an
 *     object key, a destructured name, a property assignment, a form field name, a DB column,
 *     or a request-body read.
 *   - `security_code` is strong only when the file carries card vocabulary at all: on its own
 *     it is an order pickup code or a 2FA code at least as often as it is a CVV.
 *   - "Weak" tokens (pan, exp_month, exp_year, expiry_date) are ambiguous in ordinary code
 *     (`pan` is map/zoom vocabulary, and exp_month is legitimate token metadata), so two
 *     distinct weak tokens in accept positions are required before they say anything.
 *   - Anything destructured out of a provider token response (paymentMethod.card, charge.source,
 *     token.card) is skipped: last4 / brand / exp_month read back from the PSP is not PAN.
 *   - Stories, Cypress/Playwright specs and other harness files are skipped outright: an E2E
 *     suite types a Stripe test PAN into a hosted field on purpose.
 *
 * Bypass: `// pagokit-ignore: no-pan-in-transit -- <reason>`.
 */

const path = require('node:path');
const {
  hasIgnoreTag,
  isWebhookFilePath,
  isAllowlistedTestFile,
  stripCommentsAndStrings,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'no-pan-in-transit';

// Case-insensitive: `card_?number` also covers cardNumber, CardNumber and CARD_NUMBER.
// The `credit`/`debit`/`cc` prefixes matter: the token is captured whole and then anchored
// against STRONG_RE, so `creditCardNumber` only resolves if the alternation spells it out.
const STRONG_SRC = [
  '(?:credit|debit)_?card_?(?:number|num|no)',
  'card_?(?:number|num|no)',
  'cc_?(?:number|num)',
  'numero_?(?:de_?)?tarjeta',
  'cvv2', 'cvv', 'card_?cvc', 'cvc', 'security_?code', 'track_?[12]',
].join('|');
const WEAK_SRC = 'pan|exp_?month|exp_?year|expir(?:y|ation)_?date';
const ANY_SRC = `${STRONG_SRC}|${WEAK_SRC}`;

const STRONG_RE = new RegExp(`^(?:${STRONG_SRC})$`, 'i');

/**
 * `security_code` is the one "strong" token that is routinely something else — an order
 * pickup code, a voucher code, a 2FA code. It only counts as cardholder data when the file
 * is actually about a card; otherwise it is demoted to the weak tier.
 */
const CONDITIONAL_STRONG_RE = /^security_?code$/i;
const CARD_VOCAB_RE =
  /\b(?:card|cards|tarjeta|tarjetas|cvv|cvc|pan|cardholder|titular|credit_?card|debit_?card|visa|mastercard|amex)\b/i;

/** Receivers that mean "this value came from the caller", not from the PSP. */
const BODY_ROOT = 'req|request|body|payload|params|query|form|form_data|formData|data|input|dto|fields|attrs|\\$_POST|\\$_GET|\\$_REQUEST';

/** Receivers that mean "this value came back from the provider" — legitimate metadata. */
const TOKEN_SOURCE_RE =
  /\b(?:payment_?method|paymentmethod|charges?|token|source|setup_?intent|payment_?intent|intent|customer|subscription|pm|card_?token)\b/i;

/** Fields that only exist AFTER tokenisation — their presence means this is PSP metadata. */
const TOKEN_METADATA_RE = /\b(?:last_?4|brand|fingerprint|funding|card_?id|payment_?method_?id)\b/i;

function reAll(src, flags) {
  return new RegExp(src, flags);
}

/** Blank comment bodies while preserving byte offsets. Strings survive, unlike stripCommentsAndStrings. */
function maskComments(src, ext) {
  const blank = (m) => m.replace(/[^\n]/g, ' ');
  let out = src.replace(/<!--[\s\S]*?-->/g, blank).replace(/\/\*[\s\S]*?\*\//g, blank);
  const hashComments = ['.py', '.rb', '.sh', '.yml', '.yaml'].includes(ext);
  out = out
    .split('\n')
    .map((line) => {
      for (let i = 0; i < line.length - 1; i++) {
        if (line[i] === '/' && line[i + 1] === '/' && line[i - 1] !== ':' && line[i - 1] !== '/') {
          return line.slice(0, i) + ' '.repeat(line.length - i);
        }
      }
      if (hashComments) {
        const h = line.indexOf('#');
        if (h >= 0) return line.slice(0, h) + ' '.repeat(line.length - h);
      }
      return line;
    })
    .join('\n');
  return out;
}

function lineAt(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') n++;
  return n;
}

/**
 * Detectors. Each is applied to one of two views:
 *   'code'   — comments AND string bodies blanked (identifiers, keys, member access)
 *   'masked' — comments blanked, strings intact (form names, bracket access, SQL DDL)
 *
 * Every pattern captures the field token in group 1 so strong/weak can be resolved per hit.
 */
const DETECTORS = [
  // --- code view ---------------------------------------------------------------------
  {
    view: 'code',
    kind: 'object key / typed property',
    re: reAll(`(?:^|[{,(;]|\\s)(${ANY_SRC})\\s*\\??\\s*:`, 'gim'),
  },
  {
    view: 'code',
    kind: 'destructured from the request',
    re: reAll(`\\{[^{}]*?\\b(${ANY_SRC})\\b[^{}]*\\}\\s*=\\s*([\\w.$\\[\\]()]+)`, 'gim'),
    rhsGroup: 2,
  },
  {
    view: 'code',
    kind: 'read off the request body',
    re: reAll(`\\b(?:${BODY_ROOT})(?:\\.\\w+)*\\.(${ANY_SRC})\\b`, 'gi'),
  },
  {
    view: 'code',
    kind: 'assigned onto a record',
    // `payment.card_number = input.number` never passes through an object literal or a
    // destructure, so without this every ORM entity hydration walked straight past.
    re: reAll(`\\b\\w+(?:\\.\\w+)*\\.(${ANY_SRC})\\s*=(?!=)`, 'gi'),
  },
  {
    view: 'code',
    kind: 'forwarded in an outbound request body',
    re: reAll(`(?:JSON\\.stringify\\s*\\(\\s*\\{|body\\s*:\\s*\\{)[^{}]*?\\b(${ANY_SRC})\\b`, 'gi'),
  },
  // --- masked view -------------------------------------------------------------------
  {
    view: 'masked',
    kind: 'form field name',
    re: reAll(`\\bname\\s*=\\s*["'\`]\\s*(${ANY_SRC})\\s*["'\`]`, 'gi'),
  },
  {
    view: 'masked',
    kind: 'read off the request body',
    re: reAll(
      `\\b(?:${BODY_ROOT})(?:\\.\\w+)*(?:\\[\\s*["'\`](${ANY_SRC})["'\`]\\s*\\]|\\.get\\s*\\(\\s*["'\`](${ANY_SRC})["'\`])`,
      'gi'
    ),
    altGroup: 2,
  },
  {
    view: 'masked',
    kind: 'database column',
    re: reAll(
      `(?:add_column\\s+:\\w+\\s*,\\s*:|t\\.\\w+\\s+:|table\\.\\w+\\s*\\(\\s*["'\`]|addColumn\\s*\\(\\s*["'\`][^"'\`]*["'\`]\\s*,\\s*["'\`]|ADD\\s+(?:COLUMN\\s+)?["'\`]?)(${ANY_SRC})\\b`,
      'gi'
    ),
  },
  {
    view: 'masked',
    kind: 'database column',
    re: reAll(`\\b(${ANY_SRC})\\s+(?:VARCHAR|NVARCHAR|CHAR|TEXT|STRING|BIGINT|NUMERIC)\\b`, 'gi'),
  },
  {
    view: 'masked',
    kind: 'database column',
    re: reAll(`\\b(${ANY_SRC})\\s*=\\s*models\\.\\w*Field\\s*\\(`, 'gi'),
  },
];

/** Stories, Cypress/Playwright specs and other harness files. Test PANs live here by design. */
function looksLikeHarnessFile(norm) {
  if (/\.(?:stories|story)\.[a-z]+$/.test(norm)) return true;
  if (/\.cy\.[a-z]+$/.test(norm)) return true;
  if (/\.e2e(?:-spec)?\.[a-z]+$/.test(norm)) return true;
  const parts = norm.split('/');
  return parts.some((p) => ['cypress', 'playwright', 'e2e', '.storybook', 'stories', '__mocks__'].includes(p));
}

/** Is this file plausibly about payments at all? One of several required signals. */
function hasPaymentsContext(filePath, content, code, masked) {
  if (utils.hasPaymentSdkImport(content)) return true;
  const sdkRe = utils.catalogSdkCallRegex();
  if (sdkRe && sdkRe.test(code)) return true;
  if (isWebhookFilePath(filePath)) return true;

  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  if (/(?:checkout|payment|pagos?|billing|charge|refund|tarjeta|cobro|card|order|subscription|migrat|schema)/.test(norm)) {
    return true;
  }
  return /\b(?:checkout|payment|payments|paymentintent|billing|charge|charges|pay|pagar|tarjeta|pago|pagos|cobro|stripe|mercadopago|wompi|lemonsqueezy|conekta|openpay|culqi|dlocal|ebanx)\b/i.test(masked);
}

/** Extensions this rule refuses to reason about — prose and lockfiles are not code. */
const SKIP_EXTENSIONS = new Set([
  '.md', '.mdx', '.txt', '.rst', '.json', '.lock', '.csv', '.svg', '.png', '.jpg', '.gif', '.ico',
]);

function collectHits(code, masked, cardVocab) {
  const hits = [];
  for (const d of DETECTORS) {
    const text = d.view === 'code' ? code : masked;
    const re = new RegExp(d.re.source, d.re.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const field = m[1] || (d.altGroup ? m[d.altGroup] : null);
      if (!field) continue;

      // Reading card metadata back off a provider token response is legitimate.
      if (d.rhsGroup && TOKEN_SOURCE_RE.test(m[d.rhsGroup] || '')) continue;
      if (TOKEN_SOURCE_RE.test(m[0]) && !/\b(?:req|request|body|payload|params|form|input)\b/i.test(m[0])) continue;

      // An import/export statement naming a provider type is not a PAN in transit.
      const lineStart = text.lastIndexOf('\n', m.index) + 1;
      let lineEnd = text.indexOf('\n', m.index);
      if (lineEnd === -1) lineEnd = text.length;
      const line = text.slice(lineStart, lineEnd);
      if (/^\s*(?:import|export)\b/.test(line) && /\bfrom\s*["'`]/.test(line)) continue;
      if (/^\s*(?:import|from)\b/.test(line) && /\bimport\b/.test(line)) continue;

      hits.push({
        field,                       // as written, for the message
        key: field.toLowerCase(),    // normalised, for de-duplication
        strong: STRONG_RE.test(field) && !(CONDITIONAL_STRONG_RE.test(field) && !cardVocab),
        kind: d.kind,
        line: lineAt(text, m.index),
        snippet: line.trim().slice(0, 120),
      });
    }
  }
  hits.sort((a, b) => a.line - b.line);
  return hits;
}

/** Spanish labels for the accept positions, so message_es is not half-English. */
const KIND_ES = {
  'object key / typed property': 'clave de objeto / propiedad tipada',
  'destructured from the request': 'desestructurado desde la petición',
  'read off the request body': 'leído del body de la petición',
  'forwarded in an outbound request body': 'reenviado en el body de una petición saliente',
  'form field name': 'atributo name de un campo de formulario',
  'database column': 'columna de base de datos',
};

function finding(hit, extra) {
  const kindEs = KIND_ES[hit.kind] || hit.kind;
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_PAN_IN_TRANSIT',
    message_en:
      `Line ${hit.line} moves raw cardholder data through your own infrastructure ` +
      `(\`${hit.field}\` — ${hit.kind})${extra}. Once a PAN or CVV touches your server, storage, or ` +
      `logs you are out of SAQ A and into SAQ D: ~300 controls, quarterly ASV scans, and the CVV may ` +
      `never be stored at all (PCI DSS 3.2).`,
    message_es:
      `La línea ${hit.line} hace pasar datos de tarjeta en crudo por tu propia infraestructura ` +
      `(\`${hit.field}\` — ${kindEs})${extraEs(extra)}. En cuanto un PAN o un CVV toca tu servidor, tu ` +
      `base de datos o tus logs te sales del SAQ A y caes en el SAQ D: ~300 controles, escaneos ASV ` +
      `trimestrales, y el CVV no se puede almacenar nunca (PCI DSS 3.2).`,
    suggested_fix:
      `Never let the card number reach your code. Collect it inside the PSP's hosted fields — Stripe ` +
      `Elements / Payment Element, a Mercado Pago Brick, the Wompi widget — and send your server only the ` +
      `resulting token or payment_method id.\n` +
      `Server side, accept \`payment_method_id\` (or \`token\`) and nothing else; drop the ` +
      `\`${hit.field}\` field from the request schema, the form, and any migration that persists it.\n` +
      `Reading last4 / brand / exp_month back off a PSP token response is fine — accepting them from a ` +
      `user is not.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

function extraEs(extra) {
  return extra ? extra.replace(' alongside ', ' junto con ') : '';
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;

  // Defensive: the dispatcher already filters these, but this check must never fire on a
  // provider SDK's own source or on a fixture that deliberately contains a test PAN.
  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  if (!norm) return null;
  if (norm.includes('/node_modules/') || norm.includes('/vendor/') || norm.includes('/.venv/')) return null;
  if (norm.includes('/site-packages/') || norm.includes('/dist/') || norm.includes('/build/')) return null;
  if (isAllowlistedTestFile(filePath)) return null;
  // isAllowlistedTestFile misses the two conventions that matter most here: an E2E suite
  // types a Stripe test PAN into a hosted field on purpose, and denying that write blocks
  // the very test that proves the integration works.
  if (looksLikeHarnessFile(norm)) return null;

  const ext = path.extname(norm);
  if (SKIP_EXTENSIONS.has(ext)) return null;

  const code = stripCommentsAndStrings(content);
  const masked = maskComments(content, ext);

  const hits = collectHits(code, masked, CARD_VOCAB_RE.test(masked));
  if (!hits.length) return null;

  const strongHits = hits.filter((h) => h.strong);
  const weakHits = hits.filter((h) => !h.strong);
  const distinctStrong = new Set(strongHits.map((h) => h.key)).size;

  const context = hasPaymentsContext(filePath, content, code, masked);

  if (strongHits.length && (context || distinctStrong >= 2)) {
    const others = new Set(hits.map((h) => h.field));
    others.delete(strongHits[0].field);
    const extra = others.size
      ? ` alongside ${[...others].slice(0, 4).map((f) => '`' + f + '`').join(', ')}`
      : '';
    return finding(strongHits[0], extra);
  }

  // `pan` and `exp_month` are too ordinary to deny on their own. Two of them together, in a
  // payments file, from an unambiguous accept position (a form field, a column, a body read)
  // is a card form. A plain object key is NOT enough — `expMonth: exp_month` is how everyone
  // writes back the metadata a PSP token already gave them.
  const eligibleWeak = weakHits.filter(
    (h) => h.kind !== 'object key / typed property' && !TOKEN_METADATA_RE.test(h.snippet)
  );
  const distinctEligibleWeak = new Set(eligibleWeak.map((h) => h.key)).size;
  if (context && distinctEligibleWeak >= 2) {
    const others = new Set(eligibleWeak.map((h) => h.field));
    others.delete(eligibleWeak[0].field);
    const extra = ` alongside ${[...others].slice(0, 4).map((f) => '`' + f + '`').join(', ')}`;
    return finding(eligibleWeak[0], extra);
  }

  return null;
}

module.exports = { run, RULE_ID };
