// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 27 — webhook-secret-not-api-key.
 *
 * Detects signature verification performed with the API key instead of the webhook
 * signing secret. The two credentials live next to each other in every dashboard, so the
 * mix-up is common — and silent: every signature fails to verify, and the developer
 * spends the afternoon blaming the HMAC algorithm, the raw body, or the encoding.
 *
 * Resolution is catalog-driven: the provider is resolved from the file, then
 * `credentials[].kind` / `env_vars` say which var is the api_key and which is the
 * webhook_secret. Credentials of any other kind (Wompi's integrity signing_salt, for
 * example) are deliberately not api keys, so signing with them never fires.
 *
 * Gating (all must hold before denying):
 *   1. the file is webhook-related source code;
 *   2. exactly one provider resolves from the file, and its two roles are distinct vars;
 *   3. the file never READS the webhook-secret var — if the developer reads it at all, the
 *      value passed here is probably derived from it. Merely naming it in a string
 *      (`throw new Error('STRIPE_WEBHOOK_SECRET is required')`) does not count, or the
 *      check would disarm itself on the most common error message in the file;
 *   4. the api-key var — or a local const it was assigned to, since most codebases lift
 *      env vars to the top of the file — appears inside the ARGUMENT LIST of the
 *      verification call (paren-balanced), not merely somewhere nearby, so an adjacent
 *      `new Stripe(process.env.STRIPE_SECRET_KEY)` cannot trigger it. `new Sdk(...)`
 *      sub-expressions are blanked inside that list too: handing the verifier a client
 *      built from the api key is correct, passing the api key itself is the bug.
 *
 * Bypass: `// pagokit-ignore: webhook-secret-not-api-key -- <reason>`.
 */

const path = require('node:path');
const {
  hasIgnoreTag,
  isWebhookFilePath,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'webhook-secret-not-api-key';

const HASH_COMMENT_EXTS = ['.py', '.rb', '.php', '.sh'];
const MAX_CALL_LINES = 6;   // paren balance is the real gate; this only stops a runaway scan
const MAX_CALL_CHARS = 2000;

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Verification entry points, catalog-declared plus the language-level HMAC primitives. */
const GENERIC_VERIFY_CALLS = [
  'constructEvent', 'construct_event',
  'createHmac', 'create_hmac', 'hash_hmac',
  'hmac.new', 'HMAC.new', 'OpenSSL::HMAC.hexdigest', 'OpenSSL::HMAC.digest',
  'verifySignature', 'verify_signature',
  'verifyWebhookSignature', 'verify_webhook_signature',
  'verifyWebhook', 'verify_webhook',
  'verifyHeader', 'verify_header',
];

/** Env-read shapes across the six supported languages, for one named variable. */
function envReadPattern(name) {
  const n = escapeRe(name);
  return '(?:process\\s*\\.\\s*env|import\\s*\\.\\s*meta\\s*\\.\\s*env|os\\s*\\.\\s*environ|' +
    'os\\s*\\.\\s*[Gg]etenv|System\\s*\\.\\s*getenv|Deno\\s*\\.\\s*env\\s*\\.\\s*get|\\bgetenv|\\bENV|' +
    '\\$_ENV|\\$_SERVER)\\s*[.\\[(]\\s*[\'"]?' + n + '[\'"]?';
}

/**
 * Does the file actually READ this variable, as opposed to merely naming it in a string?
 * `throw new Error('STRIPE_WEBHOOK_SECRET is required')` names it and does not use it, and
 * treating that as "the developer wired it up" would disarm the check for free.
 */
function referencesVar(stripped, codeKeepStrings, name) {
  if (new RegExp('\\b' + escapeRe(name) + '\\b').test(stripped)) return true;
  return new RegExp(envReadPattern(name)).test(codeKeepStrings);
}

/**
 * Variables the api key was assigned to. Most codebases lift env vars into a const at the
 * top of the file, so the literal var name never appears at the call site.
 */
function apiKeyAliases(codeKeepStrings, apiKeys) {
  const aliases = new Set();
  for (const key of apiKeys) {
    // The right-hand side must BE the env read: `new Stripe(process.env.KEY)` binds an SDK
    // client, not the credential, and must not alias.
    const re = new RegExp(
      '(?:const|let|var|final|my)?\\s*\\$?([A-Za-z_][A-Za-z0-9_$]*)\\s*(?::[^=\\n]*)?:?=\\s*' + envReadPattern(key),
      'g'
    );
    let m;
    while ((m = re.exec(codeKeepStrings)) !== null) if (m[1]) aliases.add(m[1]);
  }
  return aliases;
}

/**
 * Blank `new Stripe(...)` / `new MercadoPagoConfig(...)` sub-expressions inside an argument
 * list. Handing the verifier an SDK client that was built with the api key is correct; it
 * is passing the api key ITSELF as the signing secret that is the bug.
 */
function blankSdkConstructions(text) {
  const out = text.split('');
  const re = /\bnew\s+[A-Za-z_$][A-Za-z0-9_$.]*\s*\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    let depth = 0;
    for (let i = m.index + m[0].length - 1; i < text.length; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') {
        depth--;
        if (depth === 0) {
          for (let j = m.index; j <= i; j++) if (out[j] !== '\n') out[j] = ' ';
          break;
        }
      }
    }
  }
  return out.join('');
}

let _verifyRe = null;
function verifyCallRegex() {
  if (_verifyRe) return _verifyRe;
  const names = GENERIC_VERIFY_CALLS.concat(utils.catalogVerifierNames());
  const alts = [...new Set(names)].sort((a, b) => b.length - a.length).map(escapeRe);
  _verifyRe = new RegExp('(?:' + alts.join('|') + ')\\s*\\(', 'g');
  return _verifyRe;
}

/**
 * Blank comments but KEEP string bodies, preserving every offset. Needed because most
 * languages name an env var inside a string (`os.environ["X"]`, `getenv('X')`), which
 * stripCommentsAndStrings blanks. Call sites are still located in the fully stripped
 * view, so a commented-out or quoted call never counts as code.
 */
function stripCommentsPreserveStrings(code, hashComments) {
  const out = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    const next = code[i + 1];
    if (c === '/' && next === '/') {
      while (i < n && code[i] !== '\n') { out.push(' '); i++; }
      continue;
    }
    if (c === '/' && next === '*') {
      out.push(' ', ' ');
      i += 2;
      while (i < n && !(code[i] === '*' && code[i + 1] === '/')) {
        out.push(code[i] === '\n' ? '\n' : ' ');
        i++;
      }
      if (i < n) { out.push(' ', ' '); i += 2; }
      continue;
    }
    if (hashComments && c === '#') {
      while (i < n && code[i] !== '\n') { out.push(' '); i++; }
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
      if (i < n) { out.push(code[i]); i++; }
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

/** The api-key vars and the webhook-secret vars this provider declares. */
function credentialRoles(provider) {
  const apiKeys = new Set();
  const webhookSecrets = new Set();
  for (const cred of provider.credentials || []) {
    if (!cred.env_var) continue;
    if (cred.kind === 'api_key') apiKeys.add(cred.env_var);
    else if (cred.kind === 'webhook_secret') webhookSecrets.add(cred.env_var);
  }
  const env = provider.env_vars || {};
  if (env.secret) apiKeys.add(env.secret);
  if (env.webhook_secret) webhookSecrets.add(env.webhook_secret);
  if (provider.webhook && provider.webhook.secret_env) webhookSecrets.add(provider.webhook.secret_env);
  return { apiKeys: [...apiKeys], webhookSecrets: [...webhookSecrets] };
}

/** Resolve exactly one provider, or null when the evidence is absent or ambiguous. */
function resolveProvider(filePath, content, stripped) {
  const lowerPath = (filePath || '').toLowerCase();
  const scored = [];
  for (const provider of utils.loadProviders().providers || []) {
    let score = 0;
    for (const name of (provider.detection && provider.detection.verifier_names) || []) {
      if (stripped.includes(name)) score += 3;
    }
    for (const value of Object.values(provider.env_vars || {})) {
      for (const envVar of Array.isArray(value) ? value : [value]) {
        if (envVar && content.includes(envVar)) score += 3;
      }
    }
    for (const lang of Object.values(provider.sdks || {})) {
      if (lang && lang.pkg && content.includes(lang.pkg)) score += 2;
    }
    if (provider.id && lowerPath.includes(provider.id)) score += 2;
    if (score > 0) scored.push({ provider, score });
  }
  if (!scored.length) return null;
  scored.sort((a, b) => b.score - a.score);
  if (scored.length > 1 && scored[0].score === scored[1].score) return null;
  if (scored[0].score < 2) return null;
  return scored[0].provider;
}

/**
 * The paren-balanced argument list of the call whose '(' sits at `argStart`, capped at
 * MAX_CALL_LINES beyond the call's own line. Returns [start, end) into the same string.
 */
function argumentRange(stripped, argStart) {
  let depth = 1;
  let newlines = 0;
  const limit = Math.min(stripped.length, argStart + MAX_CALL_CHARS);
  for (let i = argStart; i < limit; i++) {
    const c = stripped[i];
    if (c === '\n') {
      newlines++;
      if (newlines > MAX_CALL_LINES) return [argStart, i];
    } else if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return [argStart, i];
    }
  }
  return [argStart, limit];
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const ext = path.extname(filePath || '').toLowerCase();
  const hashComments = HASH_COMMENT_EXTS.includes(ext);

  let stripped = stripCommentsAndStrings(content);
  if (hashComments) stripped = stripped.replace(/#[^\n]*/g, (m) => ' '.repeat(m.length));
  const code = stripCommentsPreserveStrings(content, hashComments);

  // Only webhook verification code is in scope.
  if (!isWebhookFilePath(filePath) && !/webhook|signature|checksum/i.test(code)) return null;

  const provider = resolveProvider(filePath, content, stripped);
  if (!provider) return null;

  const { apiKeys, webhookSecrets } = credentialRoles(provider);
  if (!apiKeys.length || !webhookSecrets.length) return null;
  // The catalog gives one var both roles for this provider: nothing to distinguish.
  if (apiKeys.some((k) => webhookSecrets.includes(k))) return null;
  // The developer reads the signing secret somewhere — assume they wired it through.
  for (const secret of webhookSecrets) {
    if (referencesVar(stripped, code, secret)) return null;
  }

  const wanted = [...new Set([...apiKeys, ...apiKeyAliases(code, apiKeys)])];

  const re = verifyCallRegex();
  re.lastIndex = 0;
  let call;
  while ((call = re.exec(stripped)) !== null) {
    const argStart = call.index + call[0].length;
    const [start, end] = argumentRange(stripped, argStart);
    const args = blankSdkConstructions(code.slice(start, end));
    for (const apiKey of wanted) {
      if (!new RegExp('\\b' + escapeRe(apiKey) + '\\b').test(args)) continue;
      const lineNo = stripped.slice(0, call.index).split('\n').length;
      const callName = call[0].replace(/\s*\($/, '');
      const secret = webhookSecrets[0];
      const direct = apiKeys.includes(apiKey);
      const namedEn = direct ? `${apiKey},` : `${apiKey}, which holds ${apiKeys[0]},`;
      const namedEs = direct ? `${apiKey},` : `${apiKey}, que guarda ${apiKeys[0]},`;
      return {
        rule: RULE_ID,
        level: 'deny',
        code: 'ERR_WRONG_WEBHOOK_SECRET',
        message_en:
          `Line ${lineNo}: \`${callName}()\` is verifying the ${provider.name} signature with ${namedEn} ` +
          `which is the API key, not the webhook signing secret. Every signature will fail to verify and the ` +
          `error will look like an algorithm bug. Use ${secret} (Rule 27).`,
        message_es:
          `Línea ${lineNo}: \`${callName}()\` verifica la firma de ${provider.name} con ${namedEs} ` +
          `que es la clave de API, no el secreto de firma del webhook. Ninguna firma va a pasar la verificación ` +
          `y el error va a parecer un problema del algoritmo. Usá ${secret} (Regla 27).`,
        suggested_fix:
          `Pass process.env.${secret} to ${callName}() instead of process.env.${apiKey}.\n` +
          `${secret} comes from the webhook endpoint's own settings in the ${provider.name} dashboard — it is a ` +
          `different value from ${apiKey}, and it is per-endpoint, so staging and production each have their own.\n` +
          `Add ${secret} to .env.example so the next environment does not repeat this.\n` +
          `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
      };
    }
  }

  return null;
}

module.exports = { run, RULE_ID };
