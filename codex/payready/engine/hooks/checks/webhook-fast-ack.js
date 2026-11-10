// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 18 — Ack the webhook first, do the slow work after.
 *
 * Providers that declare an ack deadline retry the delivery when the handler
 * does not answer in time. Blocking the response on a third-party HTTP call, an
 * email send, a PDF/image render or a sleep is the classic way to blow the
 * deadline: the provider retries, the handler runs again, and the order is
 * fulfilled twice.
 *
 * Warn-only by design. Whether a given call is "slow" cannot be decided from
 * source, so this rule never blocks a write — it names the deadline and the
 * consequence and leaves the judgement to the developer.
 *
 * Bypass: `// pagokit-ignore: webhook-fast-ack -- <reason>`.
 */

const {
  hasIgnoreTag,
  isWebhookFilePath,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  loadProviders,
  catalogVerifierRegex,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'webhook-fast-ack';

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// ---------------------------------------------------------------------------
// Provider resolution — the deadline is catalog data, not a constant here.
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
    const envs = [];
    for (const v of Object.values(p.env_vars || {})) {
      if (Array.isArray(v)) envs.push(...v);
      else if (v) envs.push(v);
    }
    for (const e of envs) if (e && content.includes(e)) return p;
  }
  return null;
}

/** Hosts that belong to the provider itself — re-fetching from them is the fix, not the bug. */
function providerHosts(p) {
  const hosts = new Set();
  const urls = [];
  if (p.docs_url) urls.push(p.docs_url);
  if (p.webhook && p.webhook.refetch_endpoint) urls.push(p.webhook.refetch_endpoint);
  if (p.webhook && p.webhook.evidence && p.webhook.evidence.source_url) {
    urls.push(p.webhook.evidence.source_url);
  }
  for (const u of urls) {
    const m = /https?:\/\/([^/\s]+)/i.exec(String(u));
    if (m) hosts.add(m[1].toLowerCase());
  }
  return Array.from(hosts);
}

function isInternalOrProviderHost(host, provider) {
  const h = String(host || '').toLowerCase();
  if (!h) return true;
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?$/.test(h)) return true;
  if (/\.(local|internal|test|localhost)(:\d+)?$/.test(h)) return true;
  // A single-label host is a container/service name on a private network
  // (`http://ledger:8080`), never a third party on the public internet.
  if (!h.replace(/:\d+$/, '').includes('.')) return true;
  // RFC1918 and link-local.
  if (/^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) return true;
  if (provider && provider.id && h.includes(String(provider.id).toLowerCase())) return true;
  for (const ph of providerHosts(provider || {})) {
    const reg = ph.split('.').slice(-2).join('.');
    if (h === ph || h === reg || h.endsWith('.' + reg)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Where the handler acks
// ---------------------------------------------------------------------------

const ACK_PATTERNS = [
  /\bres\s*\.\s*status\s*\(\s*20\d/,
  /\bres\s*\.\s*(?:send|json|sendStatus|end)\s*\(/,
  /\breply\s*\.\s*(?:code|send|status)\s*\(/,
  /\breturn\s+new\s+Response\s*\(/,
  /\breturn\s+(?:Next)?Response\s*\.\s*\w+\s*\(/,
  /\breturn\s+c\s*\.\s*(?:json|text|body|newResponse)\s*\(/,
  /\breturn\s+JSONResponse\s*\(/,
  /\breturn\s+HttpResponse\s*\(/,
  /\breturn\s+jsonify\s*\(/,
  /\breturn\s+\{\s*statusCode/,
];

/** A 4xx/5xx in the same breath as the response — a rejection, not an ack. */
const ERROR_STATUS = /\b(?:status|statusCode|code)\s*[:(=]\s*['"]?[45]\d\d/;

/**
 * Where the handler answers the provider with a success.
 *
 * Taking the first response of any kind gets this backwards: almost every real
 * handler rejects a missing or invalid signature with a 400 near the top, and
 * treating that as the ack marks the entire body of the handler as post-ack
 * work — the rule then never fires on the code it exists for.
 */
function ackIndex(stripped, content) {
  let best = Infinity;
  for (const re of ACK_PATTERNS) {
    const g = new RegExp(re.source, 'g');
    let m;
    while ((m = g.exec(stripped)) !== null) {
      const window = content.slice(Math.max(0, m.index - 100), m.index + 160);
      if (ERROR_STATUS.test(window)) continue;
      if (m.index < best) best = m.index;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// The correct pattern: hand the work to something else
// ---------------------------------------------------------------------------

const ENQUEUE_PATTERNS = [
  /\bqueue\s*\.\s*add\s*\(/i,
  /\binngest\s*\.\s*send\s*\(/,
  /\b\w*(?:queue|topic|pubsub|pub_?sub|bus|broker|channel|producer|kafka|redis|nats|rabbit|sns|amqp|stream)\w*\s*\.\s*publish\s*\(/i,
  /\bwaitUntil\s*\(/,
  /\.\s*enqueue\s*\(/,
  /\bboss\s*\.\s*send\s*\(/,
  /\bsqs\s*\.\s*send/i,
  /\b\w*(?:sqs|queue|producer|topic|channel|broker)\w*\s*\.\s*sendMessage\s*\(/i,
  /\btrigger\s*\.\s*dev\b/,
  /\btasks?\s*\.\s*trigger\s*\(/,
  /\b(?:unstable_)?after\s*\(\s*(?:async|\(\s*\)|function)/,
  /\bdispatch\s*\(\s*new\s+\w+/, // Laravel: dispatch(new FulfilOrder(...))
  /\.\s*delay\s*\(/, // Celery
  /\bperform_later\s*\(/, // ActiveJob
];

function enqueuesWork(stripped) {
  return ENQUEUE_PATTERNS.some((re) => re.test(stripped));
}

// ---------------------------------------------------------------------------
// Known-slow blocking work
// ---------------------------------------------------------------------------

const HTTP_PATTERNS = [
  { re: /await\s+fetch\s*\(/g, label: 'fetch()', labelEs: 'fetch()' },
  { re: /await\s+axios(?:\s*\.\s*\w+)?\s*\(/g, label: 'axios', labelEs: 'axios' },
  { re: /await\s+got\s*(?:\.\s*\w+\s*)?\(/g, label: 'got()', labelEs: 'got()' },
  { re: /await\s+(?:httpx|requests)\s*\.\s*\w+\s*\(/g, label: 'an HTTP client', labelEs: 'un cliente HTTP' },
];

const BLOCKING_PATTERNS = [
  { re: /\bsendMail\s*\(/, label: 'an email send (sendMail)', labelEs: 'un envío de correo (sendMail)', kind: 'email' },
  { re: /\.\s*emails\s*\.\s*send\s*\(/, label: 'an email send (resend.emails.send)', labelEs: 'un envío de correo (resend.emails.send)', kind: 'email' },
  { re: /\bsgMail\s*\.\s*send\s*\(/, label: 'an email send (sgMail.send)', labelEs: 'un envío de correo (sgMail.send)', kind: 'email' },
  // Call sites only. `import puppeteer from 'puppeteer'` at the top of a file
  // says nothing about whether the render sits on the webhook's request path.
  { re: /\b(?:puppeteer|chromium|playwright)\s*\.\s*launch\s*\(/, label: 'a headless-browser render (puppeteer.launch)', labelEs: 'un render en navegador headless (puppeteer.launch)', kind: 'render' },
  { re: /\bnew\s+PDFDocument\s*\(/, label: 'PDF generation (new PDFDocument)', labelEs: 'la generación de un PDF (new PDFDocument)', kind: 'render' },
  { re: /\bsharp\s*\(/, label: 'image processing (sharp)', labelEs: 'procesamiento de imágenes (sharp)', kind: 'render' },
  { re: /\brenderToBuffer\s*\(/, label: 'document rendering (renderToBuffer)', labelEs: 'el render de un documento (renderToBuffer)', kind: 'render' },
  { re: /await\s+new\s+Promise\s*\([\s\S]{0,120}?setTimeout\s*\(/, label: 'an explicit sleep (setTimeout)', labelEs: 'una espera explícita (setTimeout)', kind: 'sleep' },
  { re: /\btime\s*\.\s*sleep\s*\(/, label: 'an explicit sleep (time.sleep)', labelEs: 'una espera explícita (time.sleep)', kind: 'sleep' },
  { re: /await\s+sleep\s*\(/, label: 'an explicit sleep (await sleep)', labelEs: 'una espera explícita (await sleep)', kind: 'sleep' },
];

function lineOf(content, idx) {
  return content.slice(0, Math.max(0, idx)).split('\n').length;
}

function isWebhookFile(filePath, stripped) {
  if (isWebhookFilePath(filePath)) return true;
  const verifier = catalogVerifierRegex();
  if (verifier && verifier.test(stripped)) return true;
  return /stripe\.webhooks\.constructEvent|constructEvent\s*\(/.test(stripped);
}

/** The text between the `(` at openIdx and its matching `)`. */
function argText(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
    if (i - openIdx > 2000) break;
  }
  return src.slice(openIdx + 1, Math.min(src.length, openIdx + 400));
}

/**
 * An HTTP call only counts when a literal absolute URL to a third party sits in
 * the call's own argument list. A relative path, an env-var URL or the
 * provider's own API does not fire — guessing there would be a false positive.
 *
 * The URL has to come out of the arguments, not out of a character window: a
 * fixed window picks up the docs link in the comment on the next line and
 * reports an internal call as a third-party one.
 */
function findExternalHttpCall(stripped, content, ack, provider) {
  for (const { re, label, labelEs } of HTTP_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(stripped)) !== null) {
      if (m.index >= ack) continue;
      const open = content.indexOf('(', m.index + m[0].length - 1);
      if (open === -1) continue;
      const args = argText(content, open);
      const u = /https?:\/\/([^/'"`\s),]+)/i.exec(args);
      if (!u) continue;
      if (isInternalOrProviderHost(u[1], provider)) continue;
      return { index: m.index, label: `${label} to ${u[1]}`, labelEs: `${labelEs} a ${u[1]}` };
    }
  }
  return null;
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  if (!isWebhookFile(filePath, stripped)) return null;

  const provider = resolveProvider(filePath, content);
  const deadline = provider && provider.webhook && provider.webhook.ack_deadline_seconds;
  if (!deadline && deadline !== 0) return null; // no declared deadline — nothing to measure against

  if (enqueuesWork(stripped)) return null; // already handing the work off

  const ack = ackIndex(stripped, content);

  let hit = findExternalHttpCall(stripped, content, ack, provider);
  if (!hit) {
    for (const { re, label, labelEs } of BLOCKING_PATTERNS) {
      const m = re.exec(stripped);
      if (m && m.index < ack) {
        hit = { index: m.index, label, labelEs };
        break;
      }
    }
  }
  if (!hit) return null;

  const line = lineOf(content, hit.index);
  const name = provider.name || provider.id;

  return {
    rule: RULE_ID,
    level: 'warn',
    code: 'ERR_ACK_TOO_SLOW',
    message_en:
      `Line ${line} blocks the webhook response on ${hit.label}. ${name} expects an ack within ${deadline}s; ` +
      `past that it treats the delivery as failed and retries it, so the same event runs twice and the order can be fulfilled twice (Rule 18).`,
    message_es:
      `La línea ${line} bloquea la respuesta del webhook con ${hit.labelEs || hit.label}. ${name} espera el ack en ${deadline}s; ` +
      `pasado ese tiempo da la entrega por fallida y la reintenta, así que el mismo evento se procesa dos veces y el pedido puede quedar cumplido dos veces (Regla 18).`,
    suggested_fix:
      `Ack first, then do the work off the request path:\n` +
      `  await queue.add('fulfil-order', { eventId: event.id });\n` +
      `  return new Response(null, { status: 200 });\n` +
      `Vercel: wrap it in waitUntil(). Inngest/Trigger.dev: inngest.send(). Laravel: dispatch(new Job(...)). Celery: task.delay().\n` +
      `If the call is genuinely fast (a warm internal service), bypass with "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
