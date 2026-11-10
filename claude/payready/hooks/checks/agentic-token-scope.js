// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 16 — agentic commerce: unscoped, persisted, or V1-shaped payment tokens.
 *
 * A shared payment token is a single-use credential the buyer's agent hands the merchant
 * with a ceiling attached: a maximum amount, an expiry, and a currency. Redeeming it
 * without checking all three is how an agent gets charged 400 USD for a 40 USD cart, and
 * how an expired token turns into a chargeback with no cardholder to argue with. Storing
 * or logging it defeats the point of a scoped credential entirely.
 *
 * The third failure is a training artefact: x402 V1 sent the payment in an `X-PAYMENT`
 * header and advertised requirements in a `PAYMENT-REQUIRED` header. The current shape
 * uses `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` and carries the requirements in the 402
 * response BODY. Emitting the V1 header produces a 402 loop that logs nothing and fails
 * silently — the single most likely thing a 2025-trained model writes here.
 *
 * Bypass: `// pagokit-ignore: agentic-token-scope -- <reason>`.
 */

const {
  hasIgnoreTag,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  hasPaymentSdkImport,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'agentic-token-scope';

/** The token itself. Matched against STRIPPED source only: a mention is not a use. */
const TOKEN_RE =
  /shared_payment_token|shared_payment_granted_token|sharedPaymentToken|sharedPaymentGrantedToken|\bspt_|delegated_payment|delegatedPayment|agent_payment_token|agentPaymentToken/;

const AMOUNT_LIMIT_RE =
  /usage_limits|usageLimits|max_amount|maxAmount|spending_limit|spendingLimit|amount_limit|amountLimit/;
const EXPIRY_RE = /expires_at|expiresAt|expires_in|expiresIn|\bexpiry\b|\bexpiration\b|\bnot_after\b/;
const CURRENCY_RE = /\bcurrenc(?:y|ies)\b|\bcurrencyCode\b|\bcurrency_code\b/;
const COMPARISON_RE = /[<>]=?|[=!]==?|\.gte?\b|\.lte?\b|\bassert\b|\bthrow\b|\bmatch(?:es)?\b/;
/**
 * A scope check must REJECT. Clamping the cart to the ceiling
 * (`amount = total > max ? max : total`) compares and then charges anyway.
 */
const REJECT_RE =
  /\bthrow\b|\breturn\b|\breject\b|\babort\b|\bassert\b|\bError\s*\(|\bstatus\s*[:(]\s*4\d\d/i;
/** An expiry is only checked when it is compared against a clock. */
const TIME_SOURCE_RE =
  /\bDate\.now\s*\(|\bDate\.parse\s*\(|\bnew\s+Date\b|\bnow\s*\(|\bcurrentTime\b|\btimestamp\b|\bunix\w*\b|\btime\.time\s*\(|\bdatetime\.(?:now|utcnow)\b|\bTime\.now\b|\bisExpired\b|\bexpired\b/i;

const LOG_CALL_RE =
  /\b(?:console\.(?:log|info|warn|error|debug|table)|logger\.(?:log|info|warn|error|debug|trace)|log\.(?:info|warn|error|debug)|print|println|puts|fmt\.Print(?:f|ln)?)\s*\(/;
const STORAGE_WRITE_RE =
  /\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(|\b(?:redis|kv|cache|store|memcached|client)\s*\.\s*(?:set|setex|setEx|psetex|hset|hSet|put)\s*\(/;
const DB_WRITE_RE =
  /\b(?:insert|insertInto|insertOne|insertMany|createMany|upsert|bulkCreate|persist|writeItem|putItem|updateOne|findOneAndUpdate)\s*\(|\.\s*save\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|\.\s*create\s*\(\s*\{[\s\S]{0,40}\bdata\b/i;

/**
 * A property assignment whose LEFT-hand side names the token —
 * `order.sharedPaymentToken = t;` — the ORM shape of persisting it.
 */
const TOKEN_FIELD_ASSIGN_RE =
  /^\s*[\w$]+(?:\.[\w$]+)+\s*=[^=]/;

/**
 * Evidence that this file actually REDEEMS the token rather than merely describing it.
 * A .d.ts-style type file or an interface declaration names every field of the token and
 * checks none of them, and denying that is denying a type.
 */
const REDEEM_RE =
  /\b(?:charge|capture|redeem|purchase|settle|authori[sz]e|checkout|pay)[\w$]*\s*\(|\.\s*create\s*\(|\bfetch\s*\(|\baxios\s*[.(]|\brequests\s*\.\s*(?:post|put)\s*\(/i;

/* --- x402 header shape (read from RAW source: header names are string literals) --- */
const V1_HEADER_RE = /['"]\s*X-PAYMENT(?:-RESPONSE)?\s*['"]/i;
const V1_REQUIREMENTS_HEADER_RE = /['"]\s*(?:X-)?PAYMENT-REQUIRED\s*['"]/i;
const HEADER_CONTEXT_RE =
  /\bheaders?\b|\bsetHeader\b|\bappend\b|\bHeaders\b|\.set\s*\(|\bres\b|\bresponse\b|\bfetch\b|\breq\b/i;

/** Lines whose stripped form still holds code — a comment strips to whitespace. */
function isCodeLine(strippedLine) {
  return /\S/.test(strippedLine || '');
}

function windowText(lines, index, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(lines.length, index + radius + 1);
  return lines.slice(start, end).join('\n');
}

/**
 * Find a line where `re` matches AND a comparison happens within ±1 line.
 *
 * The radius is 1, not 3: at radius 3 any neighbouring `if (a !== b)` satisfies every
 * other field's "check", so destructuring `expires_at` two lines above an unrelated
 * comparison read as an expiry check. `extra`, when given, must match the same window —
 * that is how the expiry check is forced to compare against a clock.
 */
function checkedNear(lines, re, extra) {
  for (let i = 0; i < lines.length; i++) {
    if (!re.test(lines[i])) continue;
    const win = windowText(lines, i, 1);
    if (!COMPARISON_RE.test(win)) continue;
    if (extra && !extra.test(win)) continue;
    return true;
  }
  return false;
}

function firstLine(lines, re) {
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) return i + 1;
  }
  return null;
}

function finding(level, line, kind) {
  const MESSAGES = {
    persisted: {
      en:
        `Line ${line} stores or logs a shared payment token. That token is a single-use credential ` +
        `scoped to one cart: persisting it in a database, a log line, or localStorage turns a bounded ` +
        `authorisation into a standing one, and puts a live payment credential in a place that is ` +
        `backed up, shipped to a log aggregator, and readable by anyone with the device.`,
      es:
        `La línea ${line} guarda o loguea un shared payment token. Ese token es una credencial de un solo ` +
        `uso, ligada a un carrito: persistirlo en una base de datos, en un log o en localStorage convierte una ` +
        `autorización acotada en una permanente, y deja una credencial de pago viva en un lugar que se ` +
        `respalda, se manda al agregador de logs y lo lee cualquiera con el dispositivo.`,
      fix:
        `Redeem the token and drop it. Persist the resulting charge id (and the merchant's own order id), ` +
        `never the token. Strip it before logging: log a hash or the last four characters if you need to ` +
        `correlate.`,
    },
    x402_v1: {
      en:
        `Line ${line} uses the retired x402 V1 header shape (X-PAYMENT / PAYMENT-REQUIRED). The current ` +
        `protocol signs with PAYMENT-SIGNATURE, answers with PAYMENT-RESPONSE, and carries the payment ` +
        `requirements in the BODY of the 402 response, not in a header. A V1 client and a current server ` +
        `never agree, and the failure is a silent 402 loop: no error, no charge, no log.`,
      es:
        `La línea ${line} usa el esquema de cabeceras de x402 V1 (X-PAYMENT / PAYMENT-REQUIRED), ya ` +
        `retirado. El protocolo actual firma con PAYMENT-SIGNATURE, responde con PAYMENT-RESPONSE y lleva ` +
        `los requisitos de pago en el CUERPO de la respuesta 402, no en una cabecera. Un cliente V1 y un ` +
        `servidor actual nunca se ponen de acuerdo, y la falla es un bucle 402 silencioso: sin error, sin ` +
        `cobro, sin log.`,
      fix:
        `Send the signed payload in PAYMENT-SIGNATURE and read the server's answer from PAYMENT-RESPONSE. ` +
        `On the server, return 402 with the requirements as JSON in the response body — do not set a ` +
        `PAYMENT-REQUIRED header, no current client reads one.`,
    },
    unscoped: {
      en:
        `Line ${line} redeems a shared payment token without enforcing its full scope. All three checks ` +
        `are mandatory before you charge: the cart total against usage_limits.max_amount, the current ` +
        `time against expires_at, and the cart currency against the token's currency. A missing amount ` +
        `check is an overcharge, a missing expiry check is an unwinnable dispute, and a missing currency ` +
        `check charges the wrong money at the wrong rate.`,
      es:
        `La línea ${line} usa un shared payment token sin verificar todo su alcance. Las tres ` +
        `comprobaciones son obligatorias antes de cobrar: el total del carrito contra ` +
        `usage_limits.max_amount, la hora actual contra expires_at, y la moneda del carrito contra la del ` +
        `token. Sin la de monto hay sobrecobro, sin la de expiración hay una disputa imposible de ganar, y ` +
        `sin la de moneda se cobra en otra divisa y a otro tipo de cambio.`,
      fix:
        `Before charging: (1) compare the cart total to token.usage_limits.max_amount and reject when it ` +
        `is greater; (2) reject when Date.now() is past token.expires_at; (3) reject when ` +
        `cart.currency !== token.currency. Reject means a 4xx to the agent, not a clamped amount.`,
    },
  };
  const m = MESSAGES[kind];
  return {
    rule: RULE_ID,
    level,
    code: 'ERR_SPT_UNSCOPED',
    message_en: `${m.en.replace(/\.$/, '')} (Rule 16).`,
    message_es: `${m.es.replace(/\.$/, '')} (Regla 16).`,
    suggested_fix: `${m.fix}\nTo bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  const lines = stripped.split('\n');
  const rawLines = String(content).split('\n');

  const usesToken = TOKEN_RE.test(stripped);

  /* ---- 1. Persisted or logged. A scoped credential must not outlive the request. ---- */
  if (usesToken) {
    // Log / cache / storage sinks: the token must be on the sink's OWN line.
    for (let i = 0; i < lines.length; i++) {
      if (!TOKEN_RE.test(lines[i])) continue;
      if (LOG_CALL_RE.test(lines[i]) || STORAGE_WRITE_RE.test(lines[i])) {
        return finding('deny', i + 1, 'persisted');
      }
    }
    // Database writes: the token must be inside the write's OWN argument, or assigned
    // onto the record just above it. "Redeem the token, then insert the order row" is
    // the shape this rule PRESCRIBES — a proximity window alone denies the correct code.
    for (let i = 0; i < lines.length; i++) {
      if (!DB_WRITE_RE.test(lines[i])) continue;
      const args = lines.slice(i, Math.min(lines.length, i + 9)).join('\n');
      if (TOKEN_RE.test(args)) return finding('deny', i + 1, 'persisted');
      for (let j = Math.max(0, i - 3); j < i; j++) {
        const lhs = lines[j].split('=')[0];
        if (TOKEN_FIELD_ASSIGN_RE.test(lines[j]) && TOKEN_RE.test(lhs)) {
          return finding('deny', j + 1, 'persisted');
        }
      }
    }
  }

  /* ---- 2. x402 V1 header shape. Header names are strings, so read the raw line and
            require a header context nearby to prove it is not prose. ---- */
  const x402Relevant =
    usesToken || /\bx402\b/i.test(stripped) || /\b402\b/.test(stripped) || hasPaymentSdkImport(content);
  if (x402Relevant) {
    for (let i = 0; i < rawLines.length; i++) {
      if (!V1_HEADER_RE.test(rawLines[i]) && !V1_REQUIREMENTS_HEADER_RE.test(rawLines[i])) continue;
      if (!isCodeLine(lines[i])) continue;                       // comment → not code
      if (!HEADER_CONTEXT_RE.test(windowText(lines, i, 2))) continue; // prose in a string → skip
      return finding('deny', i + 1, 'x402_v1');
    }
  }

  /* ---- 3. Redeemed without the full scope check. ---- */
  if (!usesToken) return null;
  // A type declaration names every field of the token and enforces none of them, which is
  // correct for a type. The finding says "redeems", so require evidence of a redemption.
  if (!REDEEM_RE.test(stripped) && !hasPaymentSdkImport(content)) return null;
  const hasAmountCheck = checkedNear(lines, AMOUNT_LIMIT_RE, REJECT_RE);
  // Naming `expires_at` in a destructure is not checking it — the comparison is the check.
  const hasExpiryCheck = checkedNear(lines, EXPIRY_RE, TIME_SOURCE_RE);
  const hasCurrencyCheck = checkedNear(lines, CURRENCY_RE);
  if (hasAmountCheck && hasExpiryCheck && hasCurrencyCheck) return null;

  return finding('deny', firstLine(lines, TOKEN_RE) || 1, 'unscoped');
}

module.exports = { run, RULE_ID };
