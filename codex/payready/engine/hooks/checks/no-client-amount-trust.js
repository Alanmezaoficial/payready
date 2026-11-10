// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 25 — The charge amount must never come from the request body.
 *
 * If a server endpoint reads `amount` / `price` / `monto` from what the browser posted and
 * hands that value to the payment provider, anyone can re-post the request with amount = 1
 * and buy the cart for a cent. The amount has to be looked up server-side (catalog, cart,
 * order row) and only then charged.
 *
 * Deny needs the full chain, not a keyword: a server-shaped, payments-relevant file, an
 * amount-named value bound from the request, and that exact value reaching a provider SDK
 * call or an `amount`-shaped key of the charge payload. A refund endpoint that also loads
 * the original payment is exempt — partial refunds legitimately take an amount.
 *
 * Bypass: `// pagokit-ignore: no-client-amount-trust -- <reason>`.
 */

const {
  hasIgnoreTag,
  isSourceCodeFile,
  isWebhookFilePath,
  stripCommentsAndStrings,
  hasPaymentSdkImport,
  catalogSdkCallRegex,
  catalogVerifierRegex,
  loadProviders,
} = require('../lib/utils');

const RULE_ID = 'no-client-amount-trust';

/* ------------------------------------------------------------------ *
 * Vocabulary
 * ------------------------------------------------------------------ */

// Property names that mean "this is the money", read off the request.
const AMOUNT_PROPS = [
  'amount_in_cents', 'amountincents', 'transaction_amount', 'transactionamount',
  'gross_amount', 'grossamount', 'unit_amount', 'unitamount', 'amount_cents',
  'amountcents', 'unit_price', 'unitprice', 'subtotal', 'importe', 'precio',
  'amount', 'price', 'total', 'monto', 'valor', 'amt',
];

// Object keys that are the money slot of a charge payload.
const SINK_KEYS = [
  'amount_in_cents', 'amountInCents', 'transaction_amount', 'transactionAmount',
  'gross_amount', 'grossAmount', 'unit_amount', 'unitAmount', 'amount_cents',
  'amountCents', 'amount', 'value',
];

// Where client-controlled data enters a server handler.
const REQ_SOURCE =
  /\b(?:req|request|ctx|c|event|context)\s*\.\s*(?:req\s*\.\s*)?(?:json|body|formData|form|text|parseBody|query|get_json|POST|GET|data)\b/;

// A server-side lookup of previously stored state.
const SERVER_LOOKUP =
  /\.(?:retrieve|find|findUnique|findFirst|findOne|findById|findMany|query|select|fetchOne|first)\s*\(|\bprisma\s*\.|\bsupabase\s*\.\s*from\s*\(|\bSELECT\s+|\bknex\s*\(|\bMongo|\bfindOneBy\b/i;

const SERVER_PATH =
  /(?:\/api\/|(?:^|\/)route\.[jt]sx?$|\/routes?\/|\/controllers?\/|\/handlers?\/|\/endpoints?\/|\/server\/|\/pages\/api\/|\/functions?\/)/;

const CLIENT_PATH = /\/(?:components?|client|ui|views?|hooks|widgets?)\//;

const PAYMENTS_PATH =
  /checkout|payments?|charges?|billing|subscri|refunds?|pagos?|cobros?|invoice/i;

// Where the payload is going: an HTTP call out to the provider.
const OUTBOUND =
  /\bfetch\s*\(|\baxios\s*\.|\brequests\s*\.\s*(?:post|put)\s*\(|\bHttpClient\b|\bcurl_setopt\b|\bhttpx\s*\./;

// A row being written, not a charge being made. The verb is what makes it a write: matching a
// bare `db.` also matched `db.order.findUnique(...)`, so any lookup before the payload made
// the sink invisible.
const DB_CALLEE =
  /\b(?:prisma|db|database|knex|supabase|mongoose|sequelize|repo|repository|collection|entityManager)\b[\w$.]*\.\s*(?:create|createMany|insert|insertOne|insertMany|update|updateOne|updateMany|upsert|save|set|add|put)\s*\(|\.(?:insertOne|insertMany|upsert|bulkWrite)\s*\(/gi;

const OUTBOUND_CALLEE = /\bfetch\s*\(|\baxios\s*\.|\brequests\s*\.|\bhttpx\s*\./gi;

// Calls that open an outbound HTTP request, for locating the payload they carry.
const OUTBOUND_CALL =
  /\bfetch\s*\(|\baxios\s*(?:\.\s*\w+\s*)?\(|\brequests\s*\.\s*\w+\s*\(|\bhttpx\s*\.\s*\w+\s*\(/g;

// Telemetry. Recording what the browser claimed is not the same defect as charging it.
const LOG_CALL =
  /\b(?:logger|log|console|Sentry|analytics|tracker|metrics|datadog|posthog|segment)\s*\.\s*\w+\s*\(|\bcaptureMessage\s*\(|\bcaptureException\s*\(/g;

// Serializing a reply to the browser. Echoing the number the browser sent is not charging it.
const RESPONSE_CALL =
  /\b(?:Response|NextResponse)\s*\.\s*json\s*\(|\bres\s*\.\s*(?:json|send|status)\s*\(|\bjsonify\s*\(|\bJsonResponse\s*\(|\bResponse\s*\(/g;

// Numeric transforms. A client number that has been rounded, coerced or multiplied is still
// the client's number; a value that came back from a lookup is not.
const NUMERIC_HELPERS = new Set([
  'number', 'parseint', 'parsefloat', 'tofixed', 'tonumber', 'toint', 'int', 'float',
  'round', 'floor', 'ceil', 'abs', 'trunc', 'min', 'max', 'pow', 'big', 'bigint',
  'decimal', 'tostring', 'string', 'valueof', 'sum',
]);

const POST_HANDLER =
  /export\s+(?:async\s+)?function\s+(?:POST|PUT)\b|\b(?:app|router|server)\s*\.\s*(?:post|put)\s*\(|@(?:Post|Put)\s*\(|@\w+\.(?:post|put)\s*\(|\bdef\s+(?:post|create)\b/;

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Longest-first so `amount_in_cents` is not swallowed by `amount`.
const byLengthDesc = (a, b) => b.length - a.length;
const AMOUNT_ALT = AMOUNT_PROPS.slice().sort(byLengthDesc).map(esc).join('|');
const AMOUNT_SET = new Set(AMOUNT_PROPS.map((s) => s.toLowerCase()));
const SINK_ALT = SINK_KEYS.slice().sort(byLengthDesc).map(esc).join('|');

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

/** Value expression that follows a key, stopping at the enclosing separator. */
function valueRange(text, start) {
  let depth = 0;
  let i = start;
  const max = Math.min(text.length, start + 240);
  while (i < max) {
    const ch = text[i];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) break;
      depth--;
    } else if ((ch === ',' || ch === ';' || ch === '\n') && depth === 0) break;
    i++;
  }
  return [start, i];
}

/** Balanced argument region of the first `(` at or after `from`. */
function callArgRange(text, from) {
  const open = text.indexOf('(', from);
  if (open === -1) return null;
  let depth = 0;
  const max = Math.min(text.length, open + 4000);
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
 * Blank comments but KEEP string bodies, preserving every offset. Import specifiers live in
 * strings, so stripCommentsAndStrings (which blanks those too) cannot be used to decide which
 * provider a file imports -- but a commented-out import must not count either.
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

/* ------------------------------------------------------------------ *
 * Taint
 * ------------------------------------------------------------------ */

/** Every `name = <expr>` binding in real code, with the offsets of its right-hand side. */
function collectBindings(stripped) {
  const out = [];
  const re = /(?:^|[;{}()\n,])[ \t]*(?:const|let|var)?[ \t]*([A-Za-z_$][\w$]*)[ \t]*=(?![=>])[ \t]*([^;\n]{1,200})/g;
  let m;
  while ((m = re.exec(stripped)) !== null) {
    const rhs = m[2];
    const rhsStart = m.index + m[0].length - rhs.length;
    out.push({ name: m[1], rhs, start: rhsStart, end: rhsStart + rhs.length, line: lineNumberAt(stripped, rhsStart) });
  }
  return out;
}

/** `const { a, amount: amt } = <req source>` */
function collectDestructured(stripped, rootRe) {
  const out = [];
  const re = /(?:const|let|var)?\s*\{([^{}]{0,400})\}\s*=\s*([^;\n]{1,200})/g;
  let m;
  while ((m = re.exec(stripped)) !== null) {
    const rhs = m[2];
    if (!REQ_SOURCE.test(rhs) && !(rootRe && rootRe.test(rhs))) continue;
    const line = lineNumberAt(stripped, m.index);
    for (const part of m[1].split(',')) {
      const bits = part.split(':');
      const key = (bits[0] || '').trim().replace(/^\.\.\./, '');
      const alias = (bits[1] || bits[0] || '').trim().split('=')[0].trim();
      if (!key || !alias || !/^[A-Za-z_$][\w$]*$/.test(alias)) continue;
      if (!AMOUNT_SET.has(key.toLowerCase())) continue;
      out.push({ name: alias, line });
    }
  }
  return out;
}

/**
 * Offsets where a request-rooted amount is read: `body.amount`, `req.body.price`,
 * `data['amount']`, `form.get('monto')`. Bracket / get() forms read their argument from
 * the original text, which shares offsets with the stripped copy.
 */
function collectTaintedSites(stripped, content, roots) {
  const sites = [];
  const rootAlt = [...roots].map(esc)
    .concat(['req\\s*\\.\\s*body', 'request\\s*\\.\\s*body', 'req\\s*\\.\\s*query', 'request\\s*\\.\\s*query'])
    .join('|');

  const dotted = new RegExp('(?:' + rootAlt + ')\\s*\\.\\s*(?:' + AMOUNT_ALT + ')\\b', 'gi');
  let m;
  while ((m = dotted.exec(stripped)) !== null) {
    sites.push({ start: m.index, end: m.index + m[0].length, text: m[0].replace(/\s+/g, '') });
  }

  const indexed = new RegExp('(?:' + rootAlt + ')\\s*(?:\\.\\s*get\\s*\\(|\\[)', 'gi');
  while ((m = indexed.exec(stripped)) !== null) {
    const tail = content.slice(m.index, m.index + m[0].length + 60);
    const arg = tail.match(/(?:get\s*\(|\[)\s*['"]([\w.-]+)['"]/);
    if (arg && AMOUNT_SET.has(arg[1].toLowerCase())) {
      const end = m.index + m[0].length + arg.index + arg[0].length;
      sites.push({ start: m.index, end, text: content.slice(m.index, end).replace(/\s+/g, '') });
    }
  }
  return sites;
}

function overlappingSite(range, sites) {
  for (const site of sites) {
    if (site.start < range[1] && site.end > range[0]) return site;
  }
  return null;
}

/** Does this slice use a tainted value (not merely name a key)? */
function taintIn(stripped, range, taintedVars, sites, spreadRe) {
  const site = overlappingSite(range, sites);
  if (site) return { how: '`' + site.text + '`', line: lineNumberAt(stripped, site.start) };
  const slice = stripped.slice(range[0], range[1]);
  // `{ ...body }` hands over every field the browser sent, amount included.
  if (spreadRe) {
    const sp = slice.match(spreadRe);
    if (sp) return { how: '`...' + sp[1] + '`', line: lineNumberAt(stripped, range[0]) };
  }
  for (const [name, info] of taintedVars) {
    if (new RegExp('\\b' + esc(name) + '\\b(?!\\s*[:=])').test(slice)) {
      return { how: '`' + name + '`', line: info.line, origin: info.origin };
    }
  }
  return null;
}

/**
 * Regions whose contents are demonstrably not a charge: a reply being serialized back to the
 * browser, and an outbound request whose URL literal names no provider in the catalog (an
 * analytics beacon, an internal service). Only a URL we can actually read excludes anything —
 * an env-var URL stays suspect.
 */
function nonChargeRegions(stripped, content, providerSlugs) {
  const regions = [];
  const add = (re, foreignOnly) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(stripped)) !== null) {
      const range = callArgRange(stripped, m.index + m[0].length - 1);
      if (!range) continue;
      if (foreignOnly) {
        const url = content.slice(range[0], Math.min(range[1], range[0] + 300)).match(/['"`]([^'"`\n]{6,200})['"`]/);
        if (!url) continue;                       // no literal URL: cannot rule it out
        const low = url[1].toLowerCase();
        if (!/^https?:|^\/\//.test(low)) continue; // not an absolute URL: cannot rule it out
        if (providerSlugs.some((slug) => low.includes(slug))) continue;
      }
      regions.push(range);
    }
  };
  add(RESPONSE_CALL, false);
  add(LOG_CALL, false);
  add(OUTBOUND_CALL, true);
  return regions;
}

function inRegions(index, regions) {
  for (const [a, b] of regions) if (index >= a && index <= b) return true;
  return false;
}

/** Provider name fragments a URL would carry: 'stripe', 'wompi', 'mercadopago'... */
function providerSlugList() {
  const out = new Set();
  for (const p of loadProviders().providers || []) {
    const id = String(p.id).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (id.length >= 4) out.add(id);
    const name = String(p.name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (name.length >= 4) out.add(name);
  }
  return [...out];
}

/** Callees used in an expression, by their last segment. */
function calleesOf(expr) {
  const out = [];
  const re = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g;
  let m;
  while ((m = re.exec(expr)) !== null) {
    const parts = m[1].split('.').map((x) => x.trim().toLowerCase());
    out.push(parts[parts.length - 1]);
  }
  return out;
}

/**
 * True when `rhs` only reshapes a value arithmetically. `Math.round(amount * 100)` keeps the
 * client's number; `await db.cart.find(...)` replaces it with one of record.
 */
function isNumericHop(rhs) {
  if (/\bawait\b/.test(rhs)) return false;
  if (SERVER_LOOKUP.test(rhs)) return false;
  return calleesOf(rhs).every((c) => NUMERIC_HELPERS.has(c));
}

/**
 * Does this file import a provider SDK *or* a local wrapper named after one
 * ('@/lib/payments/mercadopago')? hasPaymentSdkImport only sees the bare package, and most
 * real routes import the wrapper.
 */
function importsProviderModule(content) {
  const specs = new Set();
  for (const re of [
    /(?:from\s*|require\s*\(\s*|import\s*\(\s*)['"]([^'"\n]+)['"]/g,
    /^\s*(?:import|from)\s+([A-Za-z0-9_@./-]+)/gm,
  ]) {
    let m;
    while ((m = re.exec(content)) !== null) specs.add(m[1].toLowerCase());
  }
  if (!specs.size) return false;
  for (const p of loadProviders().providers || []) {
    const id = String(p.id).toLowerCase().replace(/[^a-z0-9]/g, '');
    const pats = [...((p.detection && p.detection.sdk_import_patterns) || [])].map((x) => String(x).toLowerCase());
    for (const spec of specs) {
      if (pats.some((pat) => spec === pat || spec.startsWith(pat))) return true;
      for (const seg of spec.split(/[/\\]/)) {
        if (seg.replace(/[^a-z0-9]/g, '') === id) return true;
      }
    }
  }
  return false;
}

/** Last index in `slice` matched by a global regex, or -1. */
function lastIndexOf(re, slice) {
  re.lastIndex = 0;
  let last = -1;
  let m;
  while ((m = re.exec(slice)) !== null) last = m.index;
  return last;
}

/**
 * True when the key sits in an object being written to a datastore rather than sent to a
 * provider. Persisting what the client claimed is not the same defect as charging it.
 */
function looksLikeDbWrite(stripped, keyIndex) {
  const slice = stripped.slice(Math.max(0, keyIndex - 300), keyIndex);
  const db = lastIndexOf(DB_CALLEE, slice);
  if (db === -1) return false;
  return db > lastIndexOf(OUTBOUND_CALLEE, slice);
}

/* ------------------------------------------------------------------ *
 * Rule
 * ------------------------------------------------------------------ */

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (filePath && !isSourceCodeFile(filePath)) return null;

  const p = String(filePath || '').replace(/\\/g, '/');
  const isPython = /\.py$/i.test(p);

  // Client-side code cannot be the place the amount is decided; nothing to enforce.
  if (/^\s*['"]use client['"]/m.test(content)) return null;
  if (CLIENT_PATH.test(p)) return null;

  // A webhook receiver reads amounts off a signed provider event, not off a browser.
  if (isWebhookFilePath(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  const commentFree = blankComments(content, filePath);

  // Server shape.
  const sdkImport = hasPaymentSdkImport(commentFree);
  const isServer = SERVER_PATH.test(p) || (POST_HANDLER.test(stripped) && sdkImport);
  if (!isServer) return null;

  // Payments relevance.
  const sdkCallRe = catalogSdkCallRegex();
  const sdkCall = sdkCallRe ? sdkCallRe.test(stripped) : false;
  if (!sdkImport && !sdkCall && !PAYMENTS_PATH.test(p)) return null;

  // A refund that loads the original payment may legitimately take a partial amount.
  const refundish = /refund|reembolso|devoluc/i.test(p) || /refunds?\s*\.\s*create|createRefund/i.test(stripped);
  if (refundish && SERVER_LOOKUP.test(stripped)) return null;

  /* --- 1. what is bound from the request --- */
  const bindings = collectBindings(stripped);

  // A value that came out of a signature verifier is provider-signed, not browser input, so
  // `event.data.object.amount` off a verified event is trusted. Only that root is trusted:
  // a stray `constructEvent()` elsewhere in the file used to switch the whole rule off.
  const verifierRe = catalogVerifierRegex();
  const verified = new Set();
  if (verifierRe) {
    const anywhere = new RegExp(verifierRe.source, 'g');
    for (const b of bindings) {
      anywhere.lastIndex = 0;
      if (anywhere.test(b.rhs)) verified.add(b.name);
    }
  }
  const requestRoot = (rhs) => {
    const m = rhs.match(REQ_SOURCE);
    return m ? (m[0].match(/^[A-Za-z_$][\w$]*/) || [''])[0] : '';
  };
  const fromClient = (rhs) => {
    const root = requestRoot(rhs);
    return root !== '' && !verified.has(root);
  };

  const roots = new Set();
  const amountAccessRe = new RegExp('\\.\\s*(?:' + AMOUNT_ALT + ')\\b', 'i');
  for (const b of bindings) {
    if (!fromClient(b.rhs)) continue;
    if (!amountAccessRe.test(b.rhs) && !/\[|\.\s*get\s*\(/.test(b.rhs)) roots.add(b.name);
  }

  const sites = collectTaintedSites(stripped, content, roots).filter(
    (site) => !verified.has((site.text.match(/^[A-Za-z_$][\w$]*/) || [''])[0])
  );

  const taintedVars = new Map();
  for (const b of bindings) {
    const fromRequest = fromClient(b.rhs) && amountAccessRe.test(b.rhs);
    const fromRoot = overlappingSite([b.start, b.end], sites) !== null;
    if (fromRequest || fromRoot) taintedVars.set(b.name, { line: b.line, origin: b.name });
  }
  const rootRe = roots.size ? new RegExp('\\b(?:' + [...roots].map(esc).join('|') + ')\\b') : null;
  for (const d of collectDestructured(stripped, rootRe)) {
    if (!taintedVars.has(d.name)) taintedVars.set(d.name, { line: d.line, origin: d.name });
  }

  // Arithmetic does not launder the value: `const cents = Math.round(amount * 100)` is still
  // the amount the browser chose. Propagate to a fixed point over numeric hops only.
  for (let pass = 0; pass < 4; pass++) {
    let grew = false;
    for (const b of bindings) {
      if (taintedVars.has(b.name) || verified.has(b.name)) continue;
      if (!isNumericHop(b.rhs)) continue;
      for (const [name, info] of taintedVars) {
        if (new RegExp('\\b' + esc(name) + '\\b(?!\\s*[:=])').test(b.rhs)) {
          taintedVars.set(b.name, { line: info.line, origin: info.origin });
          grew = true;
          break;
        }
      }
    }
    if (!grew) break;
  }

  // `create({ ...body })` forwards the amount without ever naming it.
  const spreadRe = roots.size
    ? new RegExp('\\.\\.\\.\\s*(' + [...roots].map(esc).join('|') + ')\\b')
    : null;

  if (!taintedVars.size && !sites.length && !spreadRe) return null;

  /* --- 2. does it reach the charge? --- */

  // 2a. Inside the arguments of a catalog SDK call.
  if (sdkCallRe) {
    const global = new RegExp(sdkCallRe.source, 'g');
    let m;
    while ((m = global.exec(stripped)) !== null) {
      const region = callArgRange(stripped, m.index);
      if (!region) continue;
      const hit = taintIn(stripped, region, taintedVars, sites, spreadRe);
      if (hit) {
        const callee = m[0].replace(/\($/, '') + '()';
        return finding(hit, lineNumberAt(stripped, m.index), { en: callee, es: callee }, refundish);
      }
    }
  }

  // 2b. As the value of an amount-shaped key in a payload leaving for the provider.
  if (!sdkImport && !sdkCall && !OUTBOUND.test(stripped) && !importsProviderModule(commentFree)) return null;
  const skipRegions = nonChargeRegions(stripped, content, providerSlugList());
  const keyPatterns = [new RegExp('(?:^|[\\s{,(])["\']?(' + SINK_ALT + ')["\']?\\s*:\\s*', 'g')];
  if (isPython) {
    keyPatterns.push(new RegExp('[,(]\\s*(' + SINK_ALT + ')\\s*=\\s*', 'g'));
  }
  for (const re of keyPatterns) {
    let m;
    while ((m = re.exec(stripped)) !== null) {
      if (inRegions(m.index, skipRegions)) continue;
      if (looksLikeDbWrite(stripped, m.index)) continue;
      const start = m.index + m[0].length;
      const hit = taintIn(stripped, valueRange(stripped, start), taintedVars, sites, spreadRe);
      if (hit) {
        return finding(hit, lineNumberAt(stripped, m.index), {
          en: 'the `' + m[1] + '` key of the charge payload',
          es: 'la clave `' + m[1] + '` del payload del cobro',
        }, refundish);
      }
    }
  }

  return null;
}

function finding(hit, sinkLine, sinkLabel, refundish) {
  // When the value was carried through an intermediate, say so: the line we can point at is
  // where the client value entered, not where the intermediate is named.
  const derivedEn = hit.origin && '`' + hit.origin + '`' !== hit.how
    ? ` (derived from \`${hit.origin}\`)` : '';
  const derivedEs = hit.origin && '`' + hit.origin + '`' !== hit.how
    ? ` (derivado de \`${hit.origin}\`)` : '';
  const consequenceEn = refundish
    ? 'Anyone can repost that request with a larger amount and pull back more than they paid.'
    : 'Anyone can repost that request with amount = 1 and buy the order for a cent.';
  const consequenceEs = refundish
    ? 'Cualquiera puede reenviar ese request con un monto mayor y recuperar más de lo que pagó.'
    : 'Cualquiera puede reenviar ese request con amount = 1 y llevarse la orden por un centavo.';
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_CLIENT_AMOUNT',
    message_en:
      `The charge amount comes from the request: ${hit.how}${derivedEn} is read from the client payload at line ${hit.line} and reaches ${sinkLabel.en} at line ${sinkLine}. ${consequenceEn}`,
    message_es:
      `El monto del cobro viene del request: ${hit.how}${derivedEs} se lee del payload del cliente en la línea ${hit.line} y llega a ${sinkLabel.es} en la línea ${sinkLine}. ${consequenceEs}`,
    suggested_fix:
      `Take only identifiers from the body (productId, cartId, quantity) and compute the amount server-side:\n` +
      `  const { cartId } = await request.json();\n` +
      `  const cart = await db.cart.findUnique({ where: { id: cartId } });   // price of record\n` +
      `  const amount = cart.items.reduce((n, i) => n + i.unitAmount * i.quantity, 0);\n` +
      `Then charge \`amount\`. If the client value is only a cross-check, compare it and reject on mismatch instead of charging it.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
