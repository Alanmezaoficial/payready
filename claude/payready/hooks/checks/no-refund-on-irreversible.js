// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 17 — do not call "refund" on a rail that has no refund.
 *
 * On account-to-account rails — Pix, SPEI, PSE, Yape, Nequi, Bre-B, UPI, PayNow — a completed
 * transfer is final. There is no refund endpoint and no chargeback: the only way to return
 * money is to originate a NEW payout to the payer's account, which needs their bank details,
 * a separate payout balance, and its own reconciliation. Code written against `refunds.create`
 * compiles, ships, passes review, and then fails the first time a customer asks for money
 * back — in exactly the rails growing fastest in LATAM.
 *
 * The reversibility of every method comes from the catalog (`methods[].reversibility`), not
 * from a list in this file, so a method added to the catalog is enforced without a code change.
 * A method id counts only from a payment-method position: a *_method_types array, the value of
 * a method-ish key, a `case` label under `switch (payment.rail)`, or an UPPER_SNAKE constant
 * that names the rail.
 *
 * Deliberate non-rule: an outbound payout or transfer on an irreversible rail is correct — it
 * is the actual fix — so `transfers.create` / `payouts.create` are never flagged. The same goes
 * for the guard clause itself: when the branch a rail sits in already originates a payout or
 * refuses the rail with a 4xx, that rail is dropped. Denying `if (m === 'pix') return payout()`
 * would be denying the fix this rule exists to ask for.
 *
 * Bypass: `// pagokit-ignore: no-refund-on-irreversible -- <reason>`.
 */

const path = require('node:path');
const { hasIgnoreTag, stripCommentsAndStrings } = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'no-refund-on-irreversible';

/** Refund call sites. Deliberately excludes transfers.create / payouts.create. */
const REFUND_CALLS = [
  { re: /\brefunds\s*\.\s*create\s*\(/i, label: 'refunds.create()' },
  { re: /\bRefund\s*\.\s*create\s*\(/, label: 'Refund.create()' },
  { re: /\bcreateRefund\s*\(/, label: 'createRefund()' },
  { re: /\bcreate_refund\s*\(/, label: 'create_refund()' },
  { re: /\.\s*refund\s*\(/, label: '.refund()' },
  { re: /\brefundPayment\s*\(/i, label: 'refundPayment()' },
];

/** A route whose own path is a refund endpoint. */
const REFUND_ROUTE_RE =
  /(?:app|router|api)\s*\.\s*(?:post|put|patch|delete)\s*\(\s*["'`][^"'`]*\brefunds?\b/i;

/**
 * A refund created by hitting the PSP's REST endpoint directly. Anchored on http:// or an
 * /api//v1/ prefix so that `import { x } from '@/lib/payments/refunds'` is not a refund call.
 */
const REFUND_URL_RE =
  /["'`](?:https?:\/\/[^"'`\n]+|[^"'`\n]*\/(?:api|v\d+))\/[^"'`\n]*\b(?:refunds?|reembolsos?|devolucoes|devolucao)\b/i;

/** `export async function refundPayment(...)` declares the helper; it does not call one. */
const DECLARATION_RE = /(?:function|def|fun|sub|const|let|var|class)\s+$/i;

/** Originating money outbound — the correct fix on an irreversible rail, never the bug. */
const PAYOUT_RE =
  /\b(?:transfers?|payouts?|disbursements?|dispersiones?|transferencias?|devolucoes)\s*\.\s*create\s*\(|\b(?:createTransfer|createPayout|create_payout|create_transfer|sendPayout|originate\w*(?:Payout|Transfer|Refund)|refundViaPayout|payoutTo\w*)\s*\(/i;

/** Refusing the rail outright: a 4xx, a throw, or an explicit "not supported". */
const REFUSAL_RE =
  /\bthrow\b|\braise\b|\bstatus\s*[:(]\s*[45]\d\d|\.\s*status\s*\(\s*[45]\d\d|\bunsupported\b|\bnot[_\s]supported\b|\bno\s+(?:admite|soporta|permite|hay)\b|\bnot\s+(?:allowed|available|refundable)\b|\bunsupported\w*\b|\berror\b/i;

/** A file that actually serves an HTTP request, as opposed to a policy/constants module. */
const HANDLER_RE =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\s*\(|\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*[:=]|\b(?:app|router)\s*\.\s*(?:post|put|patch|delete)\s*\(|\bexport\s+default\s+(?:async\s+)?(?:function|\w+\s*=>)|\bmodule\.exports\s*=|\bdef\s+(?:post|put|patch|delete|handler)\b|\bclass\s+\w*Controller\b/i;

/**
 * Method literals, read from the catalog. Generic single words ('card', 'link', 'pan') are far
 * too common to match anywhere in a file, so a literal only counts when it sits in a
 * payment-method position: inside a *_method_types array, or as the value of a method-ish key.
 */
const METHOD_ARRAY_RE =
  /(?:payment_method_types|paymentMethodTypes|payment_methods|paymentMethods|allowed_payment_methods|excluded_payment_methods|payment_method_options|metodos_de_pago|rails)\s*[:=]\s*\[([^\]]*)\]/gi;

/** The discriminant of a `switch` that is switching on the rail. */
const METHOD_KEY_SRC =
  'payment_method|paymentMethod|payment_method_id|payment_type|paymentType|method_type|methodType|method|metodo|metodo_pago|metodo_de_pago|rail|transfer_method|tipo_pago';

const SWITCH_RE = new RegExp(`switch\\s*\\(([^)]{0,200})\\)\\s*\\{`, 'gi');
const METHOD_KEY_RE = new RegExp(`\\b(?:${METHOD_KEY_SRC})\\b`, 'i');
const CASE_RE = /case\s*["'`]([a-z0-9_]+)["'`]\s*:/gi;

/**
 * `const PIX = 'pix'` then `payment.method === PIX`. Only an UPPER_SNAKE name counts, and
 * only when the name itself is the rail or is method-ish — that is what keeps this from
 * matching every string constant in the file.
 */
const METHOD_CONST_RE =
  /(?:^|[\n;{,]|\b(?:const|let|var|final|readonly|static)\s+)\s*([A-Z][A-Z0-9_]*)\s*(?::\s*\w+\s*)?=\s*["'`]([a-z0-9_]+)["'`]/g;

// `[:=]{1,3}` so both `payment_method: 'pse'` and `tx.payment_method === 'pse'` resolve.
const METHOD_VALUE_RE =
  /\b(?:payment_method|paymentMethod|payment_method_id|payment_type|paymentType|method_type|methodType|method|metodo|metodo_pago|metodo_de_pago|rail|transfer_method|tipo_pago)\s*[:=]{1,3}\s*["'`]([a-z0-9_]+)["'`]/gi;

/** Blank comment bodies while preserving byte offsets. Strings survive — method ids live in them. */
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

function lineOf(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

/** The `{ ... }` that opens at or after `from`, brace-matched. */
function blockFrom(text, from) {
  const open = text.indexOf('{', from);
  if (open === -1 || open - from > 200) return null;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return text.slice(open);
}

/**
 * The branch a method literal sits in, if it sits in one at all.
 *
 * This is the difference between "refunds Pix" and "checks for Pix so it does not refund it".
 * Without it the check denies the exact guard clause it is asking the developer to write.
 */
function branchBodyFor(text, index) {
  const line = lineOf(text, index);
  if (/\bcase\s*["'`]/.test(line)) {
    const rest = text.slice(index);
    const stop = rest.search(/\n\s*(?:case\b|default\s*:|\})/);
    return stop === -1 ? rest : rest.slice(0, stop);
  }
  if (/\b(?:if|elif|elsif|unless|when)\b/.test(line) || /\?/.test(line)) {
    const block = blockFrom(text, index);
    if (block) return block;
    // Braceless guard (`if (m === 'pix') return payout(...)`, or Python): take the tail of
    // this line plus the two that follow it.
    const start = text.indexOf('\n', index);
    const head = line.slice(line.indexOf('\n') + 1);
    return head + '\n' + text.slice(start + 1, start + 200).split('\n').slice(0, 2).join('\n');
  }
  return null;
}

/**
 * True when the branch this rail sits in already does the right thing: originates an
 * outbound payout, or refuses the rail. A branch that still calls a refund is not handled.
 */
function branchHandlesRail(text, index) {
  const body = branchBodyFor(text, index);
  if (!body) return false;
  for (const c of REFUND_CALLS) if (c.re.test(body)) return false;
  if (REFUND_URL_RE.test(body)) return false;
  return PAYOUT_RE.test(body) || REFUSAL_RE.test(body);
}

let _methodIndex = null;
/** id -> { reversibility, label } for every method in the catalog. */
function methodIndex() {
  if (_methodIndex) return _methodIndex;
  _methodIndex = new Map();
  let methods = [];
  try {
    methods = require(
      path.join(utils.PLUGIN_ROOT, 'skills', 'payment-advisor', 'data', 'methods.json')
    ).methods || [];
  } catch {
    methods = [];
  }
  for (const m of methods) {
    if (!m || !m.id) continue;
    _methodIndex.set(String(m.id).toLowerCase(), {
      reversibility: m.reversibility || 'unknown',
      label: m.label || m.id,
    });
  }
  return _methodIndex;
}

/** Every catalog method id sitting in a payment-method position, with its line. */
function findMethodLiterals(masked) {
  const index = methodIndex();
  const found = new Map(); // id -> { id, line, reversibility, label }

  const record = (rawId, absIndex) => {
    const id = String(rawId).toLowerCase();
    const entry = index.get(id);
    if (!entry) return;
    if (found.has(id)) return;
    found.set(id, { id, index: absIndex, line: lineAt(masked, absIndex), ...entry });
  };

  let m;
  const arrRe = new RegExp(METHOD_ARRAY_RE.source, METHOD_ARRAY_RE.flags);
  while ((m = arrRe.exec(masked)) !== null) {
    const inner = m[1] || '';
    const base = m.index + m[0].indexOf(inner);
    const strRe = /["'`]([a-z0-9_]+)["'`]/gi;
    let s;
    while ((s = strRe.exec(inner)) !== null) record(s[1], base + s.index);
  }

  const valRe = new RegExp(METHOD_VALUE_RE.source, METHOD_VALUE_RE.flags);
  while ((m = valRe.exec(masked)) !== null) record(m[1], m.index);

  // `switch (payment.rail) { case 'pix': ... }` — a case label is a method position only
  // when the thing being switched on is the method.
  const swRe = new RegExp(SWITCH_RE.source, SWITCH_RE.flags);
  while ((m = swRe.exec(masked)) !== null) {
    if (!METHOD_KEY_RE.test(m[1] || '')) continue;
    const body = blockFrom(masked, m.index + m[0].length - 1);
    if (!body) continue;
    const base = masked.indexOf(body, m.index);
    const caseRe = new RegExp(CASE_RE.source, CASE_RE.flags);
    let cm;
    while ((cm = caseRe.exec(body)) !== null) record(cm[1], base + cm.index);
  }

  // `const PIX = 'pix'` — one indirection is all it takes to hide the rail otherwise.
  const constRe = new RegExp(METHOD_CONST_RE.source, METHOD_CONST_RE.flags);
  while ((m = constRe.exec(masked)) !== null) {
    const name = m[1].toLowerCase().replace(/[^a-z0-9]/g, '');
    const id = m[2].toLowerCase();
    const flat = id.replace(/[^a-z0-9]/g, '');
    if (name.includes(flat) || /(method|rail|metodo|pago|payment)/.test(name)) {
      record(id, m.index);
    }
  }

  return [...found.values()];
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;

  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  const ext = path.extname(norm);
  const code = stripCommentsAndStrings(content);
  const masked = maskComments(content, ext);

  // --- Signal 1: is a refund actually being created here? -------------------------------
  let refund = null;
  for (const c of REFUND_CALLS) {
    const re = new RegExp(c.re.source, c.re.flags.includes('g') ? c.re.flags : c.re.flags + 'g');
    let m;
    while ((m = re.exec(code)) !== null) {
      // `export async function refundPayment(payment)` declares the helper — reporting it as
      // "line 3 calls refundPayment()" points the developer at the wrong line entirely.
      if (DECLARATION_RE.test(code.slice(Math.max(0, m.index - 24), m.index))) continue;
      if (refund === null || m.index < refund.index) {
        refund = { label: c.label, index: m.index, line: lineAt(code, m.index) };
      }
      break;
    }
  }
  if (!refund) {
    const rm = REFUND_ROUTE_RE.exec(masked);
    if (rm) {
      refund = {
        label: 'a /refund route',
        labelEs: 'una ruta /refund',
        verbEn: 'exposes',
        verbEs: 'expone',
        index: rm.index,
        line: lineAt(masked, rm.index),
      };
    }
  }
  if (!refund) {
    // A raw POST to the PSP's refunds endpoint is still creating a refund.
    const um = REFUND_URL_RE.exec(masked);
    if (um) {
      refund = {
        label: "the PSP's refunds endpoint directly",
        labelEs: 'directamente al endpoint de reembolsos del PSP',
        verbEs: 'llama',
        index: um.index,
        line: lineAt(masked, um.index),
      };
    }
  }
  if (!refund) {
    // The route path itself can be the refund signal: app/api/refund/route.ts,
    // lib/payments/create-refund.ts. Still requires a method literal below to say anything.
    const segments = norm.split('/');
    const base = path.basename(norm, ext);
    const pathSaysRefund = segments.some((p) => /^refunds?$/.test(p)) || /\brefunds?\b/.test(base);
    // A path is not a refund on its own: lib/refunds/policy.ts is a lookup table, and denying
    // a constants module because of the directory it lives in is pure noise.
    if (pathSaysRefund && HANDLER_RE.test(code)) {
      refund = { label: 'a refund endpoint', index: 0, line: 1, fromPath: true };
    }
  }
  if (!refund) return null;

  // --- Signal 2: which rail does this code path settle on? ------------------------------
  const methods = findMethodLiterals(masked);
  if (!methods.length) return null;

  // Drop every rail whose own branch already originates a payout or refuses the rail: that
  // branch is the fix this rule exists to ask for.
  const methodsInPlay = methods.filter((x) => !branchHandlesRail(masked, x.index));
  if (!methodsInPlay.length) return null;

  const irreversible = methodsInPlay.filter((x) => x.reversibility === 'irreversible_no_refund');
  if (!irreversible.length) return null;
  const reversible = methodsInPlay.filter((x) => x.reversibility !== 'irreversible_no_refund');

  const names = (list) => list.map((x) => `${x.label} ('${x.id}')`).join(', ');
  const bypass = `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`;

  // The refund signal is either a call site (with a line) or the file's own path.
  // Labels that are not code identifiers need a Spanish form of their own, or message_es ends
  // up reading "llama a the PSP's refunds endpoint directly".
  const lead = refund.fromPath
    ? 'This file is a refund endpoint (its path contains /refund)'
    : `Line ${refund.line} ${refund.verbEn || 'calls'} ${refund.label}`;
  const leadEs = refund.fromPath
    ? 'Este archivo es un endpoint de reembolso (su ruta contiene /refund)'
    : `La línea ${refund.line} ${refund.verbEs || 'llama a'} ${refund.labelEs || refund.label}`;

  // Mixed, or several irreversible rails at once: which branch the refund belongs to is not
  // decidable from the file, so warn rather than block.
  if (reversible.length || irreversible.length > 1) {
    const reason = reversible.length
      ? `this file mixes reversible methods (${names(reversible)}) with irreversible ones (${names(irreversible)})`
      : `this file names several irreversible methods (${names(irreversible)})`;
    const reasonEs = reversible.length
      ? `este archivo mezcla métodos reversibles (${names(reversible)}) con irreversibles (${names(irreversible)})`
      : `este archivo nombra varios métodos irreversibles (${names(irreversible)})`;
    return {
      rule: RULE_ID,
      level: 'warn',
      code: 'ERR_REFUND_IRREVERSIBLE',
      message_en:
        `${lead}, and ${reason}. On the irreversible rails a refund ` +
        `endpoint does not exist, so that branch will fail at runtime. Warning, not a block — which ` +
        `branch the refund belongs to cannot be decided from this file alone.`,
      message_es:
        `${leadEs} y ${reasonEs}. En los rieles irreversibles no ` +
        `existe un endpoint de reembolso, así que esa rama va a fallar en producción. Es un aviso, no un ` +
        `bloqueo: desde este archivo no se puede saber a qué rama pertenece el reembolso.`,
      suggested_fix:
        `Branch explicitly on the method before refunding:\n` +
        `  if (IRREVERSIBLE_METHODS.has(payment.method)) return originateRefundPayout(payment);\n` +
        `  return psp.refunds.create({ payment_intent: payment.id });\n` +
        `For ${names(irreversible)}, "refund" means originating a new outbound transfer to the payer's ` +
        `account — collect and store their key/CLABE/account at payment time, or you will not be able ` +
        `to return the money at all.\n` +
        bypass,
    };
  }

  const only = irreversible[0];
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_REFUND_IRREVERSIBLE',
    message_en:
      `${lead} for a ${only.label} ('${only.id}') payment (method literal on line ${only.line}). ` +
      `${only.label} is an irreversible rail: there is no refund ` +
      `API and no chargeback, so the refund fails the first time a customer asks for their money back.`,
    message_es:
      `${leadEs} para un pago con ${only.label} ('${only.id}') (el literal del método está en la ` +
      `línea ${only.line}). ${only.label} es un riel irreversible: no ` +
      `hay API de reembolso ni contracargo, así que el reembolso revienta la primera vez que un cliente ` +
      `pida su dinero de vuelta.`,
    suggested_fix:
      `Replace the refund with an outbound payout to the payer:\n` +
      `  await psp.transfers.create({ amount, currency, destination: payer.accountKey, ` +
      `idempotencyKey: crypto.randomUUID() });\n` +
      `That means you must capture and store the payer's account key (Pix key, CLABE, PSE bank + ` +
      `document) at payment time — after the fact you may not be able to reach them.\n` +
      `Also surface this in the UI: "${only.label} no admite reembolso automático" beats a failed ` +
      `refund button.\n` +
      bypass,
  };
}

module.exports = { run, RULE_ID };
