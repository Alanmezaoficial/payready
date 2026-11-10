// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 23 — A hand-rolled verifier must match the provider's
 * declared encodings.
 *
 * This is the number one cause of "the secret is right and verification always
 * fails": the secret is decoded with the wrong encoding, the digest is emitted
 * as base64 where the provider sends hex, or the HMAC uses a different hash
 * than the provider signs with. Every expected value is catalog data
 * (`webhook.secret_encoding`, `webhook.digest_encoding`, `webhook.hash_algo`),
 * so the mismatch is mechanically checkable — no heuristics involved.
 *
 * Fires only when the provider resolves from the path or the SDK import, the
 * file is webhook context, and the file actually hand-rolls createHmac /
 * createHash. Calling the provider SDK's own verifier always passes.
 *
 * Bypass: `// pagokit-ignore: webhook-secret-encoding -- <reason>`.
 */

const {
  hasIgnoreTag,
  isWebhookFilePath,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  loadProviders,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'webhook-secret-encoding';

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// ---------------------------------------------------------------------------
// Provider resolution
// ---------------------------------------------------------------------------

function resolveProvider(filePath, content) {
  const { providers } = loadProviders();
  const list = providers || [];
  const flat = String(filePath || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const p of list) {
    if (p.id && flat.includes(String(p.id).toLowerCase())) return p;
  }
  if (!content) return null;
  for (const p of list) {
    for (const pat of (p.detection && p.detection.sdk_import_patterns) || []) {
      const e = escapeRe(pat);
      if (new RegExp("(?:from|require\\s*\\()\\s*['\"]" + e).test(content)) return p;
      if (new RegExp('^\\s*(?:import|use)\\s+' + e + '\\b', 'm').test(content)) return p;
    }
  }
  for (const p of list) {
    for (const n of (p.detection && p.detection.verifier_names) || []) {
      if (n && content.includes(n)) return p;
    }
  }
  return null;
}

/** Env vars that hold this provider's webhook secret, straight from the catalog. */
function webhookSecretEnvVars(p) {
  const out = new Set();
  if (p.webhook && p.webhook.secret_env) out.add(p.webhook.secret_env);
  if (p.env_vars && p.env_vars.webhook_secret) out.add(p.env_vars.webhook_secret);
  for (const c of p.credentials || []) {
    if (c.env_var && (c.kind === 'webhook_secret' || c.kind === 'signing_salt')) out.add(c.env_var);
  }
  return Array.from(out);
}

/**
 * The provider SDK's own verifier — a namespaced call such as
 * stripe.webhooks.constructEvent. Bare helper names from the catalog
 * (verifyMpSignature, verifyWompiChecksum) are user-land functions that live in
 * exactly the files this rule inspects, so they are NOT an exemption.
 */
function usesSdkVerifier(strippedCode) {
  const dotted = [];
  for (const p of loadProviders().providers || []) {
    for (const n of (p.detection && p.detection.verifier_names) || []) {
      if (n && n.includes('.')) dotted.push(escapeRe(n));
    }
  }
  dotted.push('constructEvent', 'construct_event');
  return new RegExp('(?:' + dotted.join('|') + ')\\s*\\(').test(strippedCode);
}

// ---------------------------------------------------------------------------
// Tiny source readers
// ---------------------------------------------------------------------------

function lineOf(content, idx) {
  return content.slice(0, Math.max(0, idx)).split('\n').length;
}

/**
 * True when `idx` in the raw content is real code, not a comment or the inside
 * of a string. stripCommentsAndStrings preserves offsets, so a blanked position
 * no longer matches the original character.
 */
function isLive(content, stripped, idx) {
  return stripped[idx] === content[idx];
}

/** Index just past the `)` closing the `(` at openIdx, or the end of src. */
function closeOf(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return src.length;
}

/** Top-level arguments of the call whose `(` sits at openIdx. */
function readArgs(src, openIdx) {
  const args = [];
  let depth = 0;
  let cur = '';
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '(' || c === '[' || c === '{') {
      depth++;
      if (depth === 1) continue;
    } else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) {
        args.push(cur);
        return args.map((a) => a.trim());
      }
    } else if (c === ',' && depth === 1) {
      args.push(cur);
      cur = '';
      continue;
    }
    if (depth >= 1) cur += c;
  }
  return args.map((a) => a.trim());
}

const STRING_LITERAL = /^(['"])([^'"]*)\1$/;
function literalOf(arg) {
  const m = STRING_LITERAL.exec(String(arg || '').trim());
  return m ? m[2] : null;
}

/**
 * Every live call site of `name(` — returns { index, args }. The name may be a
 * method (`hmac.digest`) or a namespaced call (`crypto.createHmac`), so a `.`
 * is allowed in front; a word character is not, which keeps `mydigest(` out.
 */
function callSites(content, stripped, name) {
  const re = new RegExp('(?:^|[^\\w$])(' + escapeRe(name) + ')\\s*\\(', 'g');
  const out = [];
  let m;
  while ((m = re.exec(content)) !== null) {
    const nameIdx = m.index + m[0].indexOf(m[1]);
    if (!isLive(content, stripped, nameIdx)) continue;
    const open = content.indexOf('(', nameIdx + m[1].length);
    if (open === -1) continue;
    out.push({ index: nameIdx, open, end: closeOf(content, open), args: readArgs(content, open) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Which expressions actually hold the webhook secret
// ---------------------------------------------------------------------------

/** Names that read as a digest/signature rather than as the key. */
const NOT_A_SECRET_NAME = /^(?:expected|computed|digest|signature|sig|sign|checksum|header|hash|hmac|received|provided)/i;

/** RHS shapes that produce a digest, not the key. */
const DERIVES_A_DIGEST = /create(?:Hmac|Hash)|\.\s*digest\s*\(|\.\s*update\s*\(|timingSafeEqual/;

/**
 * Local identifiers that hold the webhook secret.
 *
 * `const eventsKey = process.env.WOMPI_EVENTS_SECRET` renames the secret to
 * something with no "secret" in it; without this, every later check that asks
 * "is this argument the secret?" answers no and the rule goes silent on exactly
 * the file it exists for. Two passes so `const a = SECRET; const b = a;` resolves.
 */
function collectSecretAliases(content, secretEnvs) {
  const aliases = new Set();
  const assign = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*([^;\n]+)/g;
  for (let pass = 0; pass < 2; pass++) {
    assign.lastIndex = 0;
    let m;
    while ((m = assign.exec(content)) !== null) {
      const name = m[1];
      const rhs = m[2];
      if (aliases.has(name)) continue;
      if (NOT_A_SECRET_NAME.test(name)) continue;
      if (DERIVES_A_DIGEST.test(rhs)) continue;
      const known =
        secretEnvs.some((e) => rhs.includes(e)) ||
        /secret|signing[_-]?key/i.test(rhs) ||
        Array.from(aliases).some((a) => new RegExp('\\b' + escapeRe(a) + '\\b').test(rhs));
      if (known) aliases.add(name);
    }
  }
  return Array.from(aliases);
}

function makeIsSecretish(secretEnvs, aliases) {
  const aliasRes = aliases.map((a) => new RegExp('\\b' + escapeRe(a) + '\\b'));
  return function isSecretish(text) {
    const t = String(text || '');
    if (!t) return false;
    if (secretEnvs.some((e) => t.includes(e))) return true;
    if (/secret|signing[_-]?key/i.test(t)) return true;
    return aliasRes.some((re) => re.test(t));
  };
}

// ---------------------------------------------------------------------------
// Signature chains: createHmac/createHash ... .digest(...)
// ---------------------------------------------------------------------------

/**
 * A file hashes more than one thing — a cache key, a dedupe id, an ETag. Judging
 * the algorithm and the digest encoding file-wide reads those as if they were the
 * verifier, which both denies correct code (an md5 cache key in a webhook route)
 * and lets a broken verifier hide behind an unrelated correct-looking digest.
 *
 * So group each create(Hmac|Hash) with the `.digest(...)` that terminates it, and
 * only judge the chains that actually touch the webhook secret.
 */
function signatureChains(content, stripped, isSecretish) {
  const creates = [];
  for (const fn of ['createHmac', 'createHash']) {
    for (const call of callSites(content, stripped, fn)) creates.push({ ...call, fn });
  }
  creates.sort((a, b) => a.index - b.index);
  const digests = callSites(content, stripped, 'digest').sort((a, b) => a.index - b.index);

  const chains = [];
  for (let i = 0; i < creates.length; i++) {
    const c = creates[i];
    const nextCreate = i + 1 < creates.length ? creates[i + 1].index : Infinity;
    const d = digests.find((x) => x.index > c.index && x.index < nextCreate && x.index - c.index < 800);
    const chainText = content.slice(c.index, d ? d.end : Math.min(content.length, c.index + 400));
    chains.push({
      fn: c.fn,
      index: c.index,
      algoLit: literalOf(c.args[0]),
      keyArg: c.args[1] || '',
      digestIndex: d ? d.index : null,
      digestLit: d ? literalOf(d.args[0]) : null,
      hasDigest: Boolean(d),
      relevant: isSecretish(c.args[1] || '') || isSecretish(chainText),
    });
  }
  return chains;
}

// ---------------------------------------------------------------------------
// Encoding normalisation
// ---------------------------------------------------------------------------

function normSecretEncoding(v) {
  const s = String(v || '').toLowerCase();
  if (!s || s === 'raw' || s === 'utf8' || s === 'utf-8' || s === 'none' || s === 'plain') return 'raw';
  if (s.startsWith('base64url')) return 'base64url';
  if (s.startsWith('base64')) return 'base64';
  if (s.startsWith('hex')) return 'hex';
  return s;
}

function normBufferEncoding(v) {
  const s = String(v || '').toLowerCase().replace(/-/g, '');
  if (s === 'utf8' || s === 'ascii' || s === 'binary' || s === 'latin1' || s === '') return 'raw';
  if (s === 'base64url') return 'base64url';
  if (s === 'base64') return 'base64';
  if (s === 'hex') return 'hex';
  return s;
}

function normAlgo(v) {
  return String(v || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function finding(line, en, es, fix) {
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_ENCODING_MISMATCH',
    message_en: `${en} (Rule 23)`,
    message_es: `${es} (Regla 23)`,
    suggested_fix: `${fix}\nTo bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);

  // Hand-rolled crypto is the whole subject of this rule.
  if (!/\bcreate(?:Hmac|Hash)\s*\(/.test(stripped)) return null;
  if (usesSdkVerifier(stripped)) return null;

  const provider = resolveProvider(filePath, content);
  if (!provider || !provider.webhook) return null;

  const secretEnvs = webhookSecretEnvVars(provider);
  const referencesSecretEnv = secretEnvs.some((e) => content.includes(e));
  const namesCatalogVerifier = ((provider.detection && provider.detection.verifier_names) || [])
    .some((n) => n && content.includes(n));
  if (!isWebhookFilePath(filePath) && !referencesSecretEnv && !namesCatalogVerifier) return null;

  const wh = provider.webhook;
  const name = provider.name || provider.id;

  const aliases = collectSecretAliases(content, secretEnvs);
  const isSecretish = makeIsSecretish(secretEnvs, aliases);
  const chains = signatureChains(content, stripped, isSecretish).filter((c) => c.relevant);

  // ---- 1. Secret encoding -------------------------------------------------
  // Only when the catalog actually declares one. Most entries do not yet, and
  // reading a missing field as "raw" denies every Standard Webhooks verifier —
  // whose secret genuinely is base64 behind the whsec_ prefix.
  const expectedSecret = wh.secret_encoding ? normSecretEncoding(wh.secret_encoding) : null;
  const bufferCalls = expectedSecret ? callSites(content, stripped, 'Buffer.from') : [];
  const secretBuffers = [];
  for (const call of bufferCalls) {
    const arg0 = call.args[0] || '';
    if (!isSecretish(arg0)) continue;
    // `Buffer.from(env, 'base64').toString('utf8')` unwraps a base64-stored env
    // value and hands createHmac the raw string — the buffer is never the key.
    if (/^\s*\.\s*toString\s*\(/.test(content.slice(call.end, call.end + 24))) continue;
    secretBuffers.push({ index: call.index, encoding: normBufferEncoding(literalOf(call.args[1])) });
  }
  if (secretBuffers.length) {
    const correct = secretBuffers.find((b) => b.encoding === expectedSecret);
    if (!correct) {
      const bad = secretBuffers[0];
      const line = lineOf(content, bad.index);
      const shown = bad.encoding === 'raw' ? 'no encoding argument (utf-8)' : `'${bad.encoding}'`;
      return finding(
        line,
        `${name} declares secret_encoding "${wh.secret_encoding}", but line ${line} builds the secret buffer with ${shown}. The HMAC key ends up being different bytes than the provider signed with, so every signature comparison fails no matter how correct the secret is.`,
        `${name} declara secret_encoding "${wh.secret_encoding}", pero la línea ${line} arma el buffer del secreto con ${shown}. La llave del HMAC queda con bytes distintos a los que firmó el proveedor, así que la comparación de la firma siempre falla por más que el secreto esté bien.`,
        expectedSecret === 'raw'
          ? `Use the secret as-is:\n  const key = process.env.${secretEnvs[0] || 'WEBHOOK_SECRET'};\n  crypto.createHmac('${wh.hash_algo || 'sha256'}', key)`
          : `Decode the secret first:\n  const key = Buffer.from(process.env.${secretEnvs[0] || 'WEBHOOK_SECRET'}, '${expectedSecret}');\n  crypto.createHmac('${wh.hash_algo || 'sha256'}', key)`
      );
    }
  }

  if (!chains.length) return null; // no hashing touches the secret — nothing to judge

  // ---- 2. Digest encoding -------------------------------------------------
  const expectedDigestRaw = String(wh.digest_encoding || '').toLowerCase();
  const expectedDigest = expectedDigestRaw.startsWith('hex') ? 'hex' : normBufferEncoding(expectedDigestRaw);
  // `.digest()` with no argument returns a Buffer for timingSafeEqual — valid,
  // and it means this chain says nothing about the encoding either way.
  const rawDigestChain = chains.some((c) => c.hasDigest && c.digestLit === null);
  const digests = chains
    .filter((c) => c.digestLit !== null)
    .map((c) => ({ index: c.digestIndex, encoding: normBufferEncoding(c.digestLit), raw: c.digestLit }));
  if (expectedDigestRaw && digests.length) {
    const correct = digests.find((d) => d.encoding === expectedDigest);
    if (!correct && !rawDigestChain) {
      const bad = digests[0];
      const line = lineOf(content, bad.index);
      return finding(
        line,
        `${name} sends its signature ${expectedDigestRaw === 'hex_upper' ? 'as UPPERCASE hex' : `as ${expectedDigestRaw}`}, but line ${line} computes .digest('${bad.raw}'). The two strings can never be equal, so verification rejects every legitimate delivery.`,
        `${name} manda la firma ${expectedDigestRaw === 'hex_upper' ? 'en hex MAYÚSCULAS' : `en ${expectedDigestRaw}`}, pero la línea ${line} calcula .digest('${bad.raw}'). Esas dos cadenas nunca van a coincidir, así que la verificación rechaza todas las entregas legítimas.`,
        `Emit the digest in the encoding the provider uses:\n  .digest('${expectedDigest}')${expectedDigestRaw === 'hex_upper' ? '.toUpperCase()' : ''}\nCompare with crypto.timingSafeEqual over equal-length buffers.`
      );
    }
    if (correct && expectedDigestRaw === 'hex_upper' && !/\.\s*toUpperCase\s*\(/.test(stripped)) {
      const line = lineOf(content, correct.index);
      return finding(
        line,
        `${name} sends its signature as UPPERCASE hex, but line ${line} compares the lowercase output of .digest('hex') with no .toUpperCase(). A case-sensitive comparison rejects every legitimate delivery.`,
        `${name} manda la firma en hex MAYÚSCULAS, pero la línea ${line} compara la salida en minúsculas de .digest('hex') sin .toUpperCase(). Una comparación sensible a mayúsculas rechaza todas las entregas legítimas.`,
        `Normalise the case before comparing:\n  const expected = hmac.digest('hex').toUpperCase();`
      );
    }
  }

  // ---- 3. Hash algorithm --------------------------------------------------
  const expectedAlgo = normAlgo(wh.hash_algo);
  if (expectedAlgo) {
    const algos = chains
      .filter((c) => c.algoLit !== null)
      .map((c) => ({ index: c.index, algo: normAlgo(c.algoLit), raw: c.algoLit, fn: c.fn }));
    if (algos.length) {
      const correct = algos.find((a) => a.algo === expectedAlgo);
      if (!correct) {
        const bad = algos[0];
        const line = lineOf(content, bad.index);
        return finding(
          line,
          `${name} signs its webhooks with ${wh.hash_algo}, but line ${line} calls ${bad.fn}('${bad.raw}') over the webhook secret. A digest from a different hash never matches the header, so verification rejects every legitimate delivery.`,
          `${name} firma sus webhooks con ${wh.hash_algo}, pero la línea ${line} llama a ${bad.fn}('${bad.raw}') sobre el secreto del webhook. Un digest de otro hash nunca coincide con el header, así que la verificación rechaza todas las entregas legítimas.`,
          `Use the algorithm the provider signs with:\n  crypto.${bad.fn}('${wh.hash_algo}', key)`
        );
      }
    }
  }

  return null;
}

module.exports = { run, RULE_ID };
