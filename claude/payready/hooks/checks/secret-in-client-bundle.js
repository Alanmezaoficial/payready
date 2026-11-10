// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 26 — secret-in-client-bundle.
 *
 * Detects a server-only credential that is reachable from client-side code. Two shapes:
 *
 *   (a) a public-prefixed env var (NEXT_PUBLIC_*, VITE_*, PUBLIC_*, REACT_APP_*, …) whose
 *       name is a catalog server credential, or contains SECRET / PRIVATE, or contains
 *       API_KEY / TOKEN / WEBHOOK together with a catalog provider name. The bundler
 *       inlines these into JavaScript that every visitor downloads.
 *
 *   (b) a client-side file reading `process.env.X` / `import.meta.env.X` where X is a
 *       catalog credential whose scope is 'server'.
 *
 * This is a credential disclosure, not a style issue: a leaked secret key lets anyone
 * charge, refund and read the merchant's account, so the level is 'deny'.
 *
 * Gating (a leaked-secret check that cries wolf gets uninstalled, so):
 *   - a credential the catalog scopes to 'client' (publishable / public keys) never fires;
 *   - broad words (API_KEY, TOKEN, WEBHOOK) only fire when the var name also names a
 *     catalog provider, so NEXT_PUBLIC_MAPBOX_TOKEN and NEXT_PUBLIC_ALGOLIA_API_KEY pass;
 *   - shape (b) needs a real client signal ('use client', or JSX plus interactivity) and
 *     backs off entirely when the file imports a SERVER payment SDK, because that is a
 *     server component and reading the secret there is correct.
 *
 * Bypass: `// pagokit-ignore: secret-in-client-bundle -- <reason>`.
 */

const path = require('node:path');
const { hasIgnoreTag, stripCommentsAndStrings, isSourceCodeFile } = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'secret-in-client-bundle';

// Longest first: the alternation must not match PUBLIC_ inside NEXT_PUBLIC_.
// Vue CLI's VUE_APP_ and Plasmo's PLASMO_PUBLIC_ inline into the bundle exactly like
// NEXT_PUBLIC_ does; leaving them out means a whole framework's leaks go unseen.
const PUBLIC_ENV_RE =
  /\b(NEXT_PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|PLASMO_PUBLIC_|REACT_APP_|GATSBY_|VUE_APP_|PUBLIC_|VITE_)([A-Z0-9_]+)/g;

const ENV_ACCESS_RE = /(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;

/** `const { STRIPE_SECRET_KEY } = process.env;` — the read with no dot in it. */
const DESTRUCTURE_ENV_RE =
  /\{([^{}]*)\}\s*=\s*(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env)\b/g;

/** The same prefixes, anchored, for testing one var name on its own. */
const PUBLIC_PREFIX_RE =
  /^(NEXT_PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|PLASMO_PUBLIC_|REACT_APP_|GATSBY_|VUE_APP_|PUBLIC_|VITE_)([A-Z0-9_]+)$/;

/**
 * `process.env['STRIPE_SECRET_KEY']` — the name lives inside a string literal, which the
 * shared stripper blanks. Read those from a comments-blanked, strings-KEPT view instead,
 * but only in this bracket-access shape: a var name merely quoted in prose (a lint
 * message, an error string) must stay a pass.
 */
const BRACKET_ENV_RE =
  /(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env|os\s*\.\s*environ|os\s*\.\s*getenv|Deno\s*\.\s*env\s*\.\s*get|System\s*\.\s*getenv|getenv|ENV|\$_ENV|\$_SERVER)\s*[[(]\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g;

/** Blank comments, keep string bodies, preserve every offset. */
function stripCommentsKeepStrings(code) {
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
    if (c === '#') {
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

/** Words that are never legitimately shipped to a browser, whatever the vendor. */
const ALWAYS_SERVER_WORDS = /(^|_)(SECRET|PRIVATE|SIGNING)(_|$)/;

/**
 * Words that are risky only when the var also names a payment provider — and only as the
 * TAIL of the name. `NEXT_PUBLIC_STRIPE_WEBHOOK_DEBUG` and `..._TOKEN_REFRESH_URL` are
 * flags and endpoints, not credentials; a credential's name ends in what it is.
 */
const PROVIDER_SCOPED_WORDS = /(^|_)(API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN|TOKEN)$/;

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Catalog credentials split by scope, plus every env_vars entry that is server-only. */
function credentialSets() {
  const server = new Map(); // env var -> provider id
  const client = new Set();
  for (const cred of utils.catalogCredentials()) {
    if (!cred.env_var) continue;
    if (cred.scope === 'client') client.add(cred.env_var);
    else if (cred.scope === 'server') server.set(cred.env_var, cred.provider);
  }
  for (const provider of utils.loadProviders().providers || []) {
    const env = provider.env_vars || {};
    for (const key of ['secret', 'webhook_secret']) {
      if (env[key]) server.set(env[key], provider.id);
    }
    for (const extra of env.extra || []) server.set(extra, provider.id);
    if (env.publishable) client.add(env.publishable);
  }
  // A var the catalog also scopes to the client wins: publishable keys are meant to ship.
  for (const name of client) server.delete(name);
  return { server, client };
}

/** The catalog's display name for a provider id, for prose that reads like prose. */
function providerName(id) {
  for (const provider of utils.loadProviders().providers || []) {
    if (provider.id === id) return provider.name || id;
  }
  return id;
}

/** Uppercase tokens that identify a payment provider inside an env var name. */
function providerHints() {
  const hints = new Map(); // token -> provider id
  for (const provider of utils.loadProviders().providers || []) {
    if (provider.id) hints.set(provider.id.toUpperCase(), provider.id);
    if (provider.name) hints.set(provider.name.replace(/\s+/g, '').toUpperCase(), provider.id);
    const envValues = Object.values(provider.env_vars || {}).flat().filter(Boolean);
    for (const cred of provider.credentials || []) if (cred.env_var) envValues.push(cred.env_var);
    for (const envVar of envValues) {
      const prefix = String(envVar).split('_')[0];
      if (prefix && prefix.length >= 2) hints.set(prefix, provider.id);
    }
  }
  return hints;
}

function matchesKnown(name, collection) {
  if (collection instanceof Map) {
    if (collection.has(name)) return collection.get(name);
    for (const [known, providerId] of collection) {
      if (name.endsWith('_' + known) || name === known) return providerId;
    }
    return null;
  }
  if (collection.has(name)) return true;
  for (const known of collection) {
    if (name.endsWith('_' + known) || name === known) return true;
  }
  return false;
}

/** Does the file import a SERVER payment SDK? Then it is server code, not a bundle leak. */
function importsServerPaymentSdk(content) {
  const pkgs = new Set();
  for (const provider of utils.loadProviders().providers || []) {
    for (const lang of Object.values(provider.sdks || {})) {
      if (lang && lang.pkg) pkgs.add(lang.pkg);
    }
  }
  for (const pkg of pkgs) {
    const e = escapeRe(pkg);
    if (new RegExp("from\\s+['\"]" + e + "['\"]").test(content)) return true;
    if (new RegExp("require\\s*\\(\\s*['\"]" + e + "['\"]").test(content)) return true;
    if (new RegExp('^\\s*import\\s+' + e + '\\b', 'm').test(content)) return true;
  }
  return /\bnew\s+Stripe\s*\(/.test(content) || /\bMercadoPagoConfig\s*\(/.test(content);
}

function hasUseClientDirective(content) {
  const head = content.split('\n').slice(0, 12);
  return head.some((l) => /^\s*['"]use client['"]\s*;?\s*$/.test(l));
}

function hasServerMarker(filePath, content) {
  const norm = (filePath || '').toLowerCase().replace(/\\/g, '/');
  if (/(^|\/)(api|server)\//.test(norm)) return true;
  if (/(^|\/)route\.[jt]sx?$/.test(norm)) return true;
  if (/(^|\/)middleware\.[jt]s$/.test(norm)) return true;
  if (/\.server\.[jt]sx?$/.test(norm)) return true;
  if (/^\s*['"]use server['"]\s*;?\s*$/m.test(content)) return true;
  if (/\b(getServerSideProps|getStaticProps|getStaticPaths)\b/.test(content)) return true;
  if (/export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS)\b/.test(content)) return true;
  // Only a React Server Component may be an async component, and an RSC never ships to
  // the browser — so reading the secret key in one is correct, wherever the file lives.
  if (/export\s+default\s+async\s+function\b/.test(content)) return true;
  if (/export\s+default\s+async\s*\(/.test(content)) return true;
  if (/export\s+const\s+(?:runtime|dynamic|revalidate)\b/.test(content)) return true;
  return false;
}

/** Is this file client-side? Returns the bilingual signal name, or null. */
function clientSignal(filePath, content, stripped) {
  if (hasUseClientDirective(content)) {
    return { en: "the 'use client' directive", es: "la directiva 'use client'" };
  }
  if (hasServerMarker(filePath, content)) return null;
  if (importsServerPaymentSdk(content)) return null; // server component / server module

  // Vite and Astro only inline import.meta.env into code they BUNDLE. A file reading it
  // is client code by construction, whatever it is called and wherever it sits.
  if (/import\s*\.\s*meta\s*\.\s*env\s*[.[]/.test(stripped) ||
      /import\s*\.\s*meta\s*\.\s*env\s*[.[]/.test(content)) {
    return { en: 'a bundler-inlined import.meta.env read', es: 'una lectura de import.meta.env que el bundler incrusta' };
  }

  const norm = (filePath || '').toLowerCase().replace(/\\/g, '/');
  const ext = path.extname(norm);
  const underComponents = /(^|\/)components?\//.test(norm);
  // In the Pages Router every module under pages/ (except pages/api/) is compiled into
  // the client bundle, hooks or no hooks.
  const underPages = /(^|\/)pages\//.test(norm) && !/(^|\/)pages\/api\//.test(norm);
  const jsxExt = ext === '.jsx' || ext === '.tsx';
  const hasJsx = /<[A-Za-z][\w.]*[\s/>]/.test(content) && /return\s*\(?\s*</.test(content);
  const interactive =
    /\buse(?:State|Effect|Ref|Reducer|Context|Memo|Callback|Router)\s*\(/.test(stripped) ||
    /\bon(?:Click|Change|Submit|Input|Blur|Focus)\s*=/.test(content) ||
    /\b(?:window|document|localStorage|sessionStorage)\s*\./.test(stripped) ||
    /import\s*\.\s*meta\s*\.\s*env\b/.test(stripped);

  if (underPages && (hasJsx || interactive)) {
    return {
      en: 'its location under pages/, where the bundler ships every module whole',
      es: 'su ubicación dentro de pages/, de donde el bundler empaqueta todo lo que encuentra',
    };
  }
  if (underComponents && (hasJsx || interactive)) {
    return { en: 'its location under components/', es: 'su ubicación dentro de components/' };
  }
  if (jsxExt && hasJsx && interactive) {
    return { en: 'browser-only React APIs in a JSX file', es: 'APIs de React que solo corren en el navegador' };
  }
  return null;
}

/**
 * The span of next.config's `env` block, or null. Next copies every key in that block
 * into the client bundle verbatim, which makes it a client file for those keys only —
 * `serverRuntimeConfig` right above it stays server-side and must not fire.
 */
function nextConfigEnvRange(filePath, stripped) {
  const base = path.basename((filePath || '').toLowerCase());
  if (!/^next\.config\.(js|cjs|mjs|ts)$/.test(base)) return null;
  const m = /\benv\s*:\s*\{/.exec(stripped);
  if (!m) return null;
  let depth = 0;
  for (let i = m.index + m[0].length - 1; i < stripped.length; i++) {
    if (stripped[i] === '{') depth++;
    else if (stripped[i] === '}') {
      depth--;
      if (depth === 0) return [m.index, i];
    }
  }
  return [m.index, stripped.length];
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function deny(varName, lineNo, reasonEn, reasonEs, fixEn) {
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_SECRET_CLIENT_BUNDLE',
    message_en:
      `Line ${lineNo}: \`${varName}\` puts a server-only payment credential in the client bundle — ${reasonEn}. ` +
      `Anyone who opens devtools can read it and use it against your account (Rule 26).`,
    message_es:
      `Línea ${lineNo}: \`${varName}\` deja una credencial de servidor en el bundle del cliente — ${reasonEs}. ` +
      `Cualquiera que abra las devtools la lee y la usa contra tu cuenta (Regla 26).`,
    suggested_fix:
      `${fixEn}\n` +
      `Rotate the credential in the provider dashboard: once it has been built into a bundle, assume it is public.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;

  const base = path.basename(filePath || '');
  const isEnvFile = /^\.env(\.|$)/.test(base);
  if (!isSourceCodeFile(filePath) && !isEnvFile) return null;

  // Comments and string literals are blanked so documentation and prose never fire.
  const stripped = isEnvFile
    ? content.replace(/#[^\n]*/g, (m) => ' '.repeat(m.length))
    : stripCommentsAndStrings(content);

  // A second view where comments are gone but strings survive, so `process.env['X']`
  // is read while a var name merely quoted in prose stays invisible.
  const keepStrings = isEnvFile ? stripped : stripCommentsKeepStrings(content);

  const { server, client } = credentialSets();
  const hints = providerHints();

  let m;
  const bracketRefs = [];
  BRACKET_ENV_RE.lastIndex = 0;
  while ((m = BRACKET_ENV_RE.exec(keepStrings)) !== null) {
    bracketRefs.push({ name: m[1], index: m.index });
  }

  const accessRefs = [];
  ENV_ACCESS_RE.lastIndex = 0;
  while ((m = ENV_ACCESS_RE.exec(stripped)) !== null) {
    accessRefs.push({ name: m[1], index: m.index });
  }
  DESTRUCTURE_ENV_RE.lastIndex = 0;
  while ((m = DESTRUCTURE_ENV_RE.exec(stripped)) !== null) {
    for (const part of m[1].split(',')) {
      const name = part.split(':')[0].trim();
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        accessRefs.push({ name, index: m.index + m[0].indexOf(name) });
      }
    }
  }
  accessRefs.push(...bracketRefs);

  // ---- (a) a public-prefixed env var that carries a server credential -------------
  const publicRefs = [];
  PUBLIC_ENV_RE.lastIndex = 0;
  while ((m = PUBLIC_ENV_RE.exec(stripped)) !== null) {
    publicRefs.push({ full: m[0], rest: m[2], index: m.index });
  }
  for (const ref of bracketRefs) {
    const parsed = PUBLIC_PREFIX_RE.exec(ref.name);
    if (parsed) publicRefs.push({ full: parsed[0], rest: parsed[2], index: ref.index });
  }

  for (const { full, rest, index } of publicRefs) {
    const lineNo = lineOf(content, index);

    // Publishable / public keys are meant to be in the bundle.
    if (matchesKnown(rest, client) || matchesKnown(full, client)) continue;
    if (/(PUBLISHABLE|PUBLIC)_KEY$/.test(rest)) continue;

    const catalogProvider = matchesKnown(rest, server) || matchesKnown(full, server);
    if (catalogProvider) {
      return deny(
        full,
        lineNo,
        `it is ${providerName(catalogProvider)}'s server credential ${rest} behind a public prefix`,
        `es ${rest}, la credencial de servidor de ${providerName(catalogProvider)}, detrás de un prefijo público`,
        `Drop the public prefix and read it only on the server (route handler, server action, or API route): process.env.${rest}. ` +
          `If the browser needs something, use the publishable key instead.`
      );
    }

    if (ALWAYS_SERVER_WORDS.test(rest)) {
      return deny(
        full,
        lineNo,
        `a variable named "${rest}" is a secret and a public prefix ships it to the browser`,
        `una variable llamada "${rest}" es un secreto y el prefijo público la manda al navegador`,
        `Rename it without the public prefix and read it server-side only: process.env.${rest}.`
      );
    }

    const hintProvider = (() => {
      for (const token of rest.split('_')) {
        if (hints.has(token)) return hints.get(token);
      }
      return null;
    })();
    if (hintProvider && PROVIDER_SCOPED_WORDS.test(rest)) {
      return deny(
        full,
        lineNo,
        `it exposes a ${providerName(hintProvider)} credential ("${rest}") through a public prefix`,
        `expone una credencial de ${providerName(hintProvider)} ("${rest}") con un prefijo público`,
        `Read it server-side as process.env.${rest}. Only the publishable/public key belongs in client code.`
      );
    }
  }

  // ---- (b) client-side code reading a server-scoped catalog credential -------------
  if (isEnvFile) return null;

  // next.config's env block is a client bundle in disguise, for the keys inside it.
  const envRange = nextConfigEnvRange(filePath, stripped);
  if (envRange) {
    for (const { name, index } of accessRefs) {
      if (index < envRange[0] || index > envRange[1]) continue;
      const providerId = server.get(name);
      if (!providerId) continue;
      return deny(
        name,
        lineOf(content, index),
        "it sits in next.config's `env` block, which Next inlines into every client bundle, " +
          `and it is ${providerName(providerId)}'s server credential`,
        'está en el bloque `env` de next.config, que Next incrusta en todos los bundles del cliente, ' +
          `y es la credencial de servidor de ${providerName(providerId)}`,
        `Remove ${name} from the \`env\` block. Server code reads process.env.${name} directly and does not ` +
          `need it declared there. If a value really has to reach the browser, move it to a NEXT_PUBLIC_ variable ` +
          `and make sure it is not a secret.`
      );
    }
  }

  const signal = clientSignal(filePath, content, stripped);
  if (!signal) return null;

  for (const { name, index } of accessRefs) {
    if (client.has(name) || PUBLIC_PREFIX_RE.test(name)) continue;
    const providerId = server.get(name);
    if (!providerId) continue;
    return deny(
      name,
      lineOf(content, index),
      `this file is client-side (${signal.en}) and reads ${providerName(providerId)}'s server credential`,
      `este archivo corre en el cliente (${signal.es}) y lee la credencial de servidor de ${providerName(providerId)}`,
      `Move the call that needs ${name} into a route handler, server action or API route, and have the component fetch that endpoint. ` +
        `The browser only ever needs the publishable key.`
    );
  }

  return null;
}

module.exports = { run, RULE_ID };
