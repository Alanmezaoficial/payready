// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 19 — no-plaintext-secret-compare.
 *
 * Detects a non-constant-time comparison of a signature, token or secret inside a
 * payments-relevant file. `sig !== expected` leaks the position of the first differing
 * byte through timing, which is enough to forge a signature byte by byte.
 *
 * For the `shared_secret_header` verification family the comparison IS the whole
 * security control — there is no HMAC behind it — so the finding is reported as such.
 *
 * Gating. Naming a secret is NOT enough: `savedTokens.filter((t) => t !== token)`,
 * `cached.digest !== bodyDigest` and `order.verified !== event.verified` all mention a
 * secret and none of them is a verification. So a comparison fires only when it has the
 * SHAPE of a verification:
 *
 *   1. the file is source code AND payments-relevant (webhook path, payment SDK import,
 *      catalog verifier/SDK call, or a catalog credential env var);
 *   2. both operands are real expressions in comment-and-string stripped code — a literal
 *      on either side (`type === 'signature'`, `sig === null`, `x.length !== 64`) dies here;
 *   3. neither operand ends in a descriptor segment (`.length`, `.type`, `.id`, `.status`),
 *      so length guards and event-type switches never fire;
 *   4. at least one operand carries a secret word; and
 *   5. the two sides are cast in opposing roles — one of them is qualified as the
 *      expected/computed/received/header value, or the two sides name DIFFERENT secrets
 *      (a token compared against a secret), or one side reads a credential out of the
 *      environment. Two mentions of the same secret with no role qualifier is a lookup,
 *      not a verification, and passes;
 *   6. the comparison does not already use a constant-time primitive.
 *
 * Operands are read from the RAW line (offsets survive stripping), so the secret word
 * inside an accessor — `req.headers.get('stripe-signature')`, `req.headers['x-signature']`
 * — is seen. The stripped line still decides whether an operand is an expression at all,
 * so a bare string literal can never supply the secret word.
 *
 * Bypass: `// pagokit-ignore: no-plaintext-secret-compare -- <reason>`.
 */

const path = require('node:path');
const {
  hasIgnoreTag,
  isWebhookFilePath,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  hasPaymentSdkImport,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'no-plaintext-secret-compare';

/**
 * Words that make an identifier a secret-bearing value, mapped to the SECRET THEY NAME.
 * The canonical form is what decides whether two operands name the same secret or two
 * different ones, so `sig`/`signature`/`firma` collapse to one entry and `hmac`/`digest`/
 * `checksum`/`hash` to another. Spanish spellings are first-class: this plugin's users
 * write `firmaEsperada`, not `expectedSignature`.
 */
const SECRET_WORDS = new Map([
  ['signature', 'signature'], ['signatures', 'signature'], ['sig', 'signature'],
  ['sigs', 'signature'], ['signed', 'signature'],
  ['firma', 'signature'], ['firmas', 'signature'], ['firmado', 'signature'],
  ['token', 'token'], ['tokens', 'token'],
  ['secret', 'secret'], ['secrets', 'secret'], ['secreto', 'secret'], ['secretos', 'secret'],
  ['hmac', 'digest'], ['digest', 'digest'], ['digests', 'digest'],
  ['checksum', 'digest'], ['checksums', 'digest'], ['hash', 'digest'], ['hashes', 'digest'],
  ['verify', 'verify'], ['verified', 'verify'], ['verification', 'verify'], ['verifier', 'verify'],
]);

/**
 * Words that cast one side of a comparison as a party to a verification: the value we
 * computed versus the value they sent. Their presence is what separates
 * `firmaEsperada !== firmaRecibida` (a verification) from `a.token === b.token` (a lookup).
 */
const ROLE_WORDS = new Set([
  'expected', 'computed', 'calculated', 'derived', 'generated', 'ours', 'our', 'own',
  'provided', 'received', 'incoming', 'given', 'actual', 'supplied', 'submitted',
  'claimed', 'presented', 'candidate', 'remote', 'theirs', 'their', 'header', 'headers',
  'esperada', 'esperado', 'calculada', 'calculado', 'recibida', 'recibido',
  'generada', 'generado', 'enviada', 'enviado', 'entrante', 'propia', 'propio',
  'nuestra', 'nuestro', 'cabecera', 'encabezado',
]);

/**
 * If the LAST word of an identifier is one of these, the identifier names a descriptor
 * about the secret, not the secret itself (`verification_status`, `tokenType`, `sigId`).
 * Comparing those is ordinary application logic.
 */
const DESCRIPTOR_TAIL = new Set([
  'status', 'state', 'type', 'kind', 'name', 'count', 'length', 'size',
  'index', 'id', 'ids', 'error', 'mode', 'version', 'enabled', 'exists',
  'present', 'missing', 'required', 'at', 'ms', 'seconds',
]);

/** Operands that are literals, not values worth a constant-time compare. */
const LITERAL_OPERANDS = new Set([
  'null', 'undefined', 'true', 'false', 'NaN', 'Infinity',
  'None', 'nil', 'NULL', 'True', 'False', 'void',
]);

/** Constant-time primitives. Their presence on the line means the code is already right. */
const CONSTANT_TIME_RE =
  /timingSafeEqual|timing_safe_equal|compare_digest|hash_equals|secure_compare|secureCompare|constantTime|constant_time|MessageDigest\s*\.\s*isEqual|sodium_memcmp|crypto_verify|subtle\s*\.\s*verify/i;

/** Loose (non-constant-time) comparison helpers that are not operators. */
const LOOSE_COMPARE_RE =
  /\.equals\s*\(|\.equalsIgnoreCase\s*\(|\bstrcmp\s*\(|\bstrcasecmp\s*\(|\bstrcmpi\s*\(|\bisEqual\s*\(|\bdeepEqual\s*\(/;

/** Reading a credential out of the environment, in any of the six supported languages. */
const ENV_READ_RE =
  /process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env|os\s*\.\s*environ|os\s*\.\s*getenv|System\s*\.\s*getenv|Deno\s*\.\s*env|\bgetenv\s*\(|\bENV\s*\[|\$_ENV\b|\$_SERVER\b/;

const OPERATOR_RE = /!==|===|!=|==/g;
const OPERATOR_LINE_END_RE = /(?:!==|===|!=|==)\s*$/;
const OPERATOR_LINE_START_RE = /^\s*(?:!==|===|!=|==)/;

/** Split `expectedSignature` / `MP_WEBHOOK_SECRET` / `$sig_header` into lowercase words. */
function words(identifier) {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+|\s+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

/**
 * Every identifier-ish token in a raw operand, INCLUDING the ones inside an accessor's
 * string argument — `req.headers.get('stripe-signature')` has to yield `signature`, or
 * the most common vulnerable form in the wild goes unseen.
 */
function operandTokens(rawExpr) {
  return String(rawExpr || '').split(/[^A-Za-z0-9_$]+/).filter(Boolean);
}

/** Computations whose RESULT is a secret however the variable holding it is named. */
const DIGEST_COMPUTATION_RE =
  /createHmac|create_hmac|hash_hmac|hmac\s*\.\s*new|HMAC\s*\.\s*new|OpenSSL::HMAC|hexdigest|MessageDigest|\bhash\s*\(|\bdigest\s*\(/;

/** Assignment shapes across the six supported languages: `const x =`, `$x =`, `x :=`. */
const ASSIGNMENT_RE =
  /(?:^|[;{)]|\b(?:const|let|var|final|my)\s+)\s*\$?([A-Za-z_][A-Za-z0-9_$]*)\s*(?::[^=\n]*)?:?=(?!=)/g;

/**
 * Variables that hold a secret because of what they were ASSIGNED, not what they are
 * called. `$esperado = hash_hmac(...)` and `$recibido = $evento['signature']['checksum']`
 * are both secrets, and neither name contains a secret word — which is ordinary in
 * Spanish-language code, the majority of this plugin's users.
 *
 * One hop only, and only when the right-hand side already resolves to a secret.
 */
function secretVariables(strippedLines, rawLines) {
  const aliases = new Map();
  for (let i = 0; i < strippedLines.length; i++) {
    const line = strippedLines[i];
    if (!line.trim()) continue;              // blank in the stripped view = comment or string
    ASSIGNMENT_RE.lastIndex = 0;
    let m;
    while ((m = ASSIGNMENT_RE.exec(line)) !== null) {
      const name = m[1];
      if (!name || SECRET_WORDS.has(name.toLowerCase())) continue;
      const rhs = rawLines[i].slice(m.index + m[0].length);
      const found = secretsIn(rhs, null);
      if (DIGEST_COMPUTATION_RE.test(rhs)) found.add('digest');
      if (!found.size) continue;
      const prior = aliases.get(name);
      if (prior) for (const s of found) prior.add(s);
      else aliases.set(name, found);
    }
  }
  return aliases;
}

/** The canonical secrets an operand names, skipping tokens that are mere descriptors. */
function secretsIn(rawExpr, aliases) {
  const found = new Set();
  for (const token of operandTokens(rawExpr)) {
    const parts = words(token);
    if (!parts.length) continue;
    if (DESCRIPTOR_TAIL.has(parts[parts.length - 1])) continue;
    for (const w of parts) {
      const canon = SECRET_WORDS.get(w);
      if (canon) found.add(canon);
    }
    // `$esperado` in PHP is the variable `esperado` — the sigil is not part of the name.
    const bare = token.replace(/^\$+/, '');
    const inherited = aliases && (aliases.get(token) || aliases.get(bare));
    if (inherited) for (const s of inherited) found.add(s);
  }
  return found;
}

/** Does an operand cast itself as the expected / received / header side? */
function hasRoleWord(rawExpr) {
  for (const token of operandTokens(rawExpr)) {
    for (const w of words(token)) if (ROLE_WORDS.has(w)) return true;
  }
  return false;
}

/**
 * Walk backwards from `end` over one expression: identifier chars, dots and balanced
 * ()/[] groups. Returns the START index of that expression (=== end when there is none).
 */
function exprStart(text, end) {
  let i = end - 1;
  while (i >= 0 && /\s/.test(text[i])) i--;
  let guard = 0;
  while (i >= 0 && guard++ < 400) {
    const c = text[i];
    if (/[A-Za-z0-9_$.]/.test(c)) { i--; continue; }
    if (c === ')' || c === ']') {
      const open = c === ')' ? '(' : '[';
      let depth = 0;
      let j = i;
      for (; j >= 0; j--) {
        if (text[j] === c) depth++;
        else if (text[j] === open) {
          depth--;
          if (depth === 0) break;
        }
      }
      if (j < 0) break; // unbalanced — stop rather than guess
      i = j - 1;
      continue;
    }
    break;
  }
  return i + 1;
}

/** Walk forwards from `from` over one expression. Returns its END index. */
function exprEnd(text, from) {
  let i = from;
  while (i < text.length && /\s/.test(text[i])) i++;
  let guard = 0;
  while (i < text.length && guard++ < 400) {
    const c = text[i];
    if (/[A-Za-z0-9_$.]/.test(c)) { i++; continue; }
    if (c === '(' || c === '[') {
      const close = c === '(' ? ')' : ']';
      let depth = 0;
      let j = i;
      for (; j < text.length; j++) {
        if (text[j] === c) depth++;
        else if (text[j] === close) {
          depth--;
          if (depth === 0) break;
        }
      }
      if (j >= text.length) break;
      i = j + 1;
      continue;
    }
    break;
  }
  return i;
}

/**
 * The last identifier segment of an expression, with trailing call and index groups
 * peeled first, so the segment is the callee rather than the argument:
 * `stripe.webhooks.sig` -> 'sig'; `hmac.digest('hex')` -> 'digest';
 * `req.headers.get(...)` -> 'get'; blank (a stripped string literal) -> null.
 */
function terminalSegment(expr, depth = 0) {
  let t = String(expr || '').replace(/\s+$/, '').replace(/^\s+/, '');
  // `(await computeExpected(raw))` — unwrap the grouping parens and read what is inside.
  if (depth < 3 && t.startsWith('(') && t.endsWith(')')) {
    let d = 0;
    let wrapsAll = true;
    for (let i = 0; i < t.length; i++) {
      if (t[i] === '(') d++;
      else if (t[i] === ')') {
        d--;
        if (d === 0 && i !== t.length - 1) { wrapsAll = false; break; }
      }
    }
    if (wrapsAll) return terminalSegment(t.slice(1, -1), depth + 1);
  }
  let guard = 0;
  while (t && guard++ < 8 && (t.endsWith(')') || t.endsWith(']'))) {
    const close = t[t.length - 1];
    const open = close === ')' ? '(' : '[';
    let depth = 0;
    let i = t.length - 1;
    for (; i >= 0; i--) {
      if (t[i] === close) depth++;
      else if (t[i] === open) {
        depth--;
        if (depth === 0) break;
      }
    }
    if (i < 0) return null; // unbalanced — give up rather than guess
    t = t.slice(0, i).replace(/\s+$/, '');
  }
  if (!t) return null;
  const m = t.match(/([A-Za-z_$][A-Za-z0-9_$]*)\s*$/);
  return m ? m[1] : null;
}

/** Is this segment a descriptor about a value rather than the value? */
function isDescriptorSegment(segment) {
  const parts = words(segment || '');
  if (!parts.length) return false;
  return DESCRIPTOR_TAIL.has(parts[parts.length - 1]);
}

/**
 * The verification test. `left`/`right` are the RAW operand sources; `terminals` are the
 * segments from the stripped view. Returns true when this comparison is a verification.
 */
function isVerificationCompare(left, right, aliases) {
  const leftSecrets = secretsIn(left, aliases);
  const rightSecrets = secretsIn(right, aliases);
  if (!leftSecrets.size && !rightSecrets.size) return false;

  // One side is cast as the expected / received / header value.
  if (hasRoleWord(left) || hasRoleWord(right)) return true;

  // Two different secrets face each other: a token checked against a secret.
  if (leftSecrets.size && rightSecrets.size) {
    const union = new Set([...leftSecrets, ...rightSecrets]);
    if (union.size > 1) return true;
  }

  // A secret-bearing side is read straight out of the environment.
  if (leftSecrets.size && ENV_READ_RE.test(left)) return true;
  if (rightSecrets.size && ENV_READ_RE.test(right)) return true;

  return false;
}

/** Blank `#` comments for languages that use them; offsets are preserved. */
function stripHashComments(code) {
  return code.replace(/#[^\n]*/g, (m) => ' '.repeat(m.length));
}

function preparedSource(filePath, content) {
  const ext = path.extname(filePath || '').toLowerCase();
  let stripped = stripCommentsAndStrings(content);
  if (['.py', '.rb', '.php', '.sh'].includes(ext)) stripped = stripHashComments(stripped);
  return stripped;
}

/**
 * Physical lines joined into the logical lines a comparison actually lives on, so a
 * prettier-wrapped `signature !==\n  expectedSignature` is still one comparison. Raw and
 * stripped are joined identically, keeping their offsets aligned.
 */
function logicalLines(strippedLines, rawLines) {
  const units = [];
  let i = 0;
  while (i < strippedLines.length) {
    let stripped = strippedLines[i];
    let raw = rawLines[i];
    const start = i;
    let joins = 0;
    while (
      joins < 2 &&
      i + 1 < strippedLines.length &&
      (OPERATOR_LINE_END_RE.test(stripped) || OPERATOR_LINE_START_RE.test(strippedLines[i + 1]))
    ) {
      stripped = stripped + ' ' + strippedLines[i + 1];
      raw = raw + ' ' + rawLines[i + 1];
      i++;
      joins++;
    }
    units.push({ stripped, raw, lineNo: start + 1 });
    i++;
  }
  return units;
}

/** Is this file about payments at all? Nothing fires outside this gate. */
function isPaymentsRelevant(filePath, content, stripped) {
  if (isWebhookFilePath(filePath)) return true;
  if (hasPaymentSdkImport(content)) return true;
  const verifier = utils.catalogVerifierRegex();
  if (verifier && verifier.test(stripped)) return true;
  const sdkCall = utils.catalogSdkCallRegex();
  if (sdkCall && sdkCall.test(stripped)) return true;
  for (const cred of utils.catalogCredentials()) {
    if (cred.env_var && stripped.includes(cred.env_var)) return true;
  }
  return false;
}

/**
 * Best-effort provider resolution, used only to sharpen the message. Returns null when
 * the evidence is absent or ambiguous.
 */
function resolveProvider(filePath, content, stripped) {
  const lowerPath = (filePath || '').toLowerCase();
  const scored = [];
  for (const provider of utils.loadProviders().providers || []) {
    let score = 0;
    for (const name of (provider.detection && provider.detection.verifier_names) || []) {
      if (stripped.includes(name)) score += 3;
    }
    for (const value of Object.values(provider.env_vars || {})) {
      const list = Array.isArray(value) ? value : [value];
      for (const envVar of list) {
        if (envVar && content.includes(envVar)) score += 3;
      }
    }
    for (const pkg of Object.values(provider.sdks || {})) {
      if (pkg && pkg.pkg && content.includes(pkg.pkg)) score += 2;
    }
    if (provider.id && lowerPath.includes(provider.id)) score += 2;
    if (score > 0) scored.push({ provider, score });
  }
  if (!scored.length) return null;
  scored.sort((a, b) => b.score - a.score);
  if (scored.length > 1 && scored[0].score === scored[1].score) return null;
  return scored[0].provider;
}

function finding(lineNo, snippet, provider) {
  const family = provider && provider.webhook && provider.webhook.verification_family;
  const sharedSecret = family === 'shared_secret_header';

  const enExtra = sharedSecret
    ? ` ${provider.name} uses the shared_secret_header scheme: this comparison is the entire signature check, so a timing leak here is the whole vulnerability, not a hardening detail.`
    : '';
  const esExtra = sharedSecret
    ? ` ${provider.name} usa el esquema shared_secret_header: esta comparación es toda la verificación, así que una fuga por tiempos acá es la vulnerabilidad completa y no un detalle de endurecimiento.`
    : '';

  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_TIMING_UNSAFE',
    message_en:
      `Line ${lineNo} compares a signature/token/secret with a short-circuiting comparison (\`${snippet}\`). ` +
      `That leaks how many leading bytes matched, which is enough to forge a valid value byte by byte (Rule 19).${enExtra}`,
    message_es:
      `La línea ${lineNo} compara una firma/token/secreto con una comparación que corta en el primer byte distinto (\`${snippet}\`). ` +
      `Eso revela cuántos bytes coincidieron, y con eso alcanza para falsificar un valor válido byte por byte (Regla 19).${esExtra}`,
    suggested_fix:
      `Use a constant-time comparison:\n` +
      `  Node:   crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))  // guard equal length first\n` +
      `  Python: hmac.compare_digest(a, b)\n` +
      `  PHP:    hash_equals($expected, $received)\n` +
      `  Ruby:   OpenSSL.secure_compare(a, b)\n` +
      `  Go:     subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

/** Trim a snippet to something readable inside a one-line message. */
function snip(text, max = 60) {
  const flat = String(text || '').replace(/\s+/g, ' ').trim();
  return flat.length > max ? flat.slice(0, max - 1) + '…' : flat;
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = preparedSource(filePath, content);
  if (!isPaymentsRelevant(filePath, content, stripped)) return null;

  const strippedLines = stripped.split('\n');
  const rawLines = content.split('\n');
  const aliases = secretVariables(strippedLines, rawLines);
  const units = logicalLines(strippedLines, rawLines);

  for (const unit of units) {
    const line = unit.stripped;
    const raw = unit.raw;
    if (!line.trim()) continue;
    if (CONSTANT_TIME_RE.test(line)) continue;

    // 1. Operator comparisons: === / == / !== / != (JS, TS, PHP, Python, Ruby, Go, Java).
    OPERATOR_RE.lastIndex = 0;
    let match;
    while ((match = OPERATOR_RE.exec(line)) !== null) {
      const op = match[0];
      const leftEnd = match.index;
      const rightFrom = match.index + op.length;
      const leftFrom = exprStart(line, leftEnd);
      const rightTo = exprEnd(line, rightFrom);

      const leftStripped = line.slice(leftFrom, leftEnd);
      const rightStripped = line.slice(rightFrom, rightTo);
      const leftTerm = terminalSegment(leftStripped);
      const rightTerm = terminalSegment(rightStripped);
      if (!leftTerm || !rightTerm) continue;                       // a literal / blanked string
      if (LITERAL_OPERANDS.has(leftTerm) || LITERAL_OPERANDS.has(rightTerm)) continue;
      // A length / type / id / status guard is not a constant-time site.
      if (isDescriptorSegment(leftTerm) || isDescriptorSegment(rightTerm)) continue;

      const leftRaw = raw.slice(leftFrom, leftEnd);
      const rightRaw = raw.slice(rightFrom, rightTo);
      if (!isVerificationCompare(leftRaw, rightRaw, aliases)) continue;

      return finding(
        unit.lineNo,
        `${snip(leftRaw, 28)} ${op} ${snip(rightRaw, 28)}`,
        resolveProvider(filePath, content, stripped)
      );
    }

    // 2. Helper comparisons: .equals( / strcmp( — check only the receiver and the args.
    const loose = line.match(LOOSE_COMPARE_RE);
    if (loose) {
      const idx = line.indexOf(loose[0]);
      const openParen = line.indexOf('(', idx);
      const receiver = raw.slice(exprStart(line, idx), idx);
      let args = '';
      if (openParen !== -1) {
        let depth = 0;
        for (let j = openParen; j < line.length; j++) {
          if (line[j] === '(') depth++;
          else if (line[j] === ')') {
            depth--;
            if (depth === 0) { args = raw.slice(openParen + 1, j); break; }
          }
        }
        if (!args && depth > 0) args = raw.slice(openParen + 1);
      }
      if (isVerificationCompare(receiver, args, aliases)) {
        return finding(
          unit.lineNo,
          loose[0].trim(),
          resolveProvider(filePath, content, stripped)
        );
      }
    }
  }

  return null;
}

module.exports = { run, RULE_ID };
