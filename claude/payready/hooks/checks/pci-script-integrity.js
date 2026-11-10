// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 15 — PCI DSS 4.0.1 script authorisation and integrity on payment pages.
 *
 * PCI DSS 4.0.1 requirements 6.4.3 and 11.6.1 became mandatory on 31 March 2025: every
 * script that executes on a payment page must be authorised, inventoried, and integrity
 * checked. Almost nobody generates that inventory, and the scripts that break SAQ A
 * eligibility (a tag manager, a session recorder) are exactly the ones a developer drops
 * onto a checkout page without thinking.
 *
 * This check only speaks when the file actually MOUNTS a payment element (Stripe Elements,
 * a Mercado Pago Brick, a Wompi widget, a Lemon Squeezy overlay, or a PSP loader script).
 * A page that merely has a `<script>` tag is not a payment page, and a server file never is.
 *
 * Deliberate non-rule: PSP loader scripts (js.stripe.com/v3, sdk.mercadopago.com, ...) are
 * versionless by design and rotate their bundles. Demanding SRI on them would break a live
 * checkout, so hosts listed in a provider's `pci.loader_exempt_from_sri` are never asked for
 * an integrity attribute. That exemption is read from the catalog, not hardcoded.
 *
 * Same shape, different reason: Turnstile / reCAPTCHA / hCaptcha are generated per request and
 * cannot carry a stable hash at all, so for those the ask is req. 6.4.3 (name it in the
 * inventory) rather than req. 11.6.1 (hash it) — advice a developer can actually follow.
 *
 * Bypass: `// pagokit-ignore: pci-script-integrity -- <reason>`.
 */

const fs = require('node:fs');
const path = require('node:path');
const {
  hasIgnoreTag,
  isAllowlistedTestFile,
  stripCommentsAndStrings,
  walkUpForFile,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'pci-script-integrity';

const INVENTORY_FILENAME = 'payment-page-scripts.json';

/** Extensions that can render a payment page. Anything else is out of scope. */
const PAGE_EXTENSIONS = new Set([
  '.html', '.htm', '.tsx', '.jsx', '.js', '.mjs', '.ts', '.vue', '.svelte', '.astro',
]);

/**
 * A payment element being mounted. A bare `<script>` tag is deliberately NOT in this list —
 * every marketing page has script tags, and firing on those would make the plugin unusable.
 */
const MOUNT_PATTERNS = [
  { re: /\bstripe\s*\.\s*elements\s*\(/, label: 'stripe.elements()' },
  { re: /<CardElement\b/, label: '<CardElement>' },
  { re: /<PaymentElement\b/, label: '<PaymentElement>' },
  // Split Stripe Elements: the same PAN iframe, mounted field by field. Omitting these let a
  // real card form through the front door.
  { re: /<CardNumberElement\b/, label: '<CardNumberElement>' },
  { re: /<CardExpiryElement\b/, label: '<CardExpiryElement>' },
  { re: /<CardCvcElement\b/, label: '<CardCvcElement>' },
  { re: /<ExpressCheckoutElement\b/, label: '<ExpressCheckoutElement>' },
  { re: /\belements\s*\.\s*create\s*\(/, label: "elements.create()" },
  { re: /\bloadStripe\s*\(/, label: 'loadStripe()' },
  // `mp.bricks()` is how the Mercado Pago docs actually spell it — the receiver is almost
  // never the literal `mercadopago`.
  { re: /\.\s*bricks\s*\(\s*\)/, label: '.bricks()' },
  { re: /\bbricksBuilder\s*\.\s*create\s*\(/, label: 'bricksBuilder.create()' },
  { re: /\bnew\s+MercadoPago\s*\(/, label: 'new MercadoPago()' },
  { re: /\bnew\s+WidgetCheckout\s*\(/, label: 'new WidgetCheckout()' },
  { re: /\bLemonSqueezy\s*\.\s*Setup\s*\(/, label: 'LemonSqueezy.Setup()' },
];

/** Third-party analytics / tag managers, as URL hosts. */
const ANALYTICS_HOSTS = [
  { re: /https?:\/\/[^\s"'`<>]*googletagmanager\.com/i, label: 'Google Tag Manager' },
  { re: /https?:\/\/[^\s"'`<>]*google-analytics\.com/i, label: 'Google Analytics' },
  { re: /https?:\/\/[^\s"'`<>]*connect\.facebook\.net/i, label: 'Meta Pixel' },
  { re: /https?:\/\/[^\s"'`<>]*hotjar\.com/i, label: 'Hotjar' },
  { re: /https?:\/\/[^\s"'`<>]*clarity\.ms/i, label: 'Microsoft Clarity' },
  { re: /https?:\/\/[^\s"'`<>]*segment\.(?:com|io)/i, label: 'Segment' },
];

/**
 * Analytics initialised from inline code, a wrapper component, or a wrapper package rather
 * than a raw tag. `<GoogleTagManager />` from @next/third-parties loads the exact same
 * container as a `<script src="googletagmanager.com">` and must not be a way around this.
 */
const ANALYTICS_CALLS = [
  { re: /<GoogleTagManager\b/, label: '<GoogleTagManager> (@next/third-parties)' },
  { re: /<GoogleAnalytics\b/, label: '<GoogleAnalytics> (@next/third-parties)' },
  { re: /\bTagManager\s*\.\s*initialize\s*\(/, label: 'TagManager.initialize() (react-gtm-module)' },
  { re: /\bReactPixel\s*\.\s*init\s*\(/, label: 'ReactPixel.init() (Meta Pixel)' },
  { re: /\bhotjar\s*\.\s*initialize\s*\(/, label: 'hotjar.initialize()' },
  { re: /\bgtag\s*\(/, label: 'gtag()' },
  { re: /\bfbq\s*\(/, label: 'fbq()' },
  { re: /\bdataLayer\s*\.\s*push\s*\(/, label: 'dataLayer.push()' },
  { re: /\bhj\s*\(/, label: 'hj() (Hotjar)' },
  { re: /\bclarity\s*\(/, label: 'clarity()' },
  { re: /\banalytics\s*\.\s*load\s*\(/, label: 'analytics.load() (Segment)' },
];

/**
 * Blank out comment bodies while preserving every byte offset and newline.
 *
 * stripCommentsAndStrings() also blanks string literals, which destroys the `src="https://..."`
 * we need to read. So markup scanning uses this weaker mask, and code scanning uses the strong
 * one. A `//` preceded by `:` is a URL scheme separator, never a comment.
 */
function maskComments(src) {
  const blank = (m) => m.replace(/[^\n]/g, ' ');
  let out = src.replace(/<!--[\s\S]*?-->/g, blank).replace(/\/\*[\s\S]*?\*\//g, blank);
  out = out
    .split('\n')
    .map((line) => {
      for (let i = 0; i < line.length - 1; i++) {
        if (line[i] === '/' && line[i + 1] === '/' && line[i - 1] !== ':' && line[i - 1] !== '/') {
          return line.slice(0, i) + ' '.repeat(line.length - i);
        }
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

/** Hosts every provider in the catalog declares as legitimately un-SRI-able. */
function exemptHosts() {
  const out = [];
  for (const p of utils.loadProviders().providers || []) {
    for (const h of (p.pci && p.pci.loader_exempt_from_sri) || []) out.push(String(h).toLowerCase());
  }
  return out;
}

/**
 * Scripts that are generated per-request and therefore CANNOT carry a stable SRI hash.
 * Cloudflare Turnstile, reCAPTCHA and hCaptcha all document this. Demanding `integrity=`
 * on them is advice a developer physically cannot follow, so 11.6.1 is satisfied the other
 * way round: the script has to be named in the authorised inventory (req. 6.4.3).
 */
const SRI_INCOMPATIBLE_SRC = [
  /challenges\.cloudflare\.com\/turnstile\//i,
  /google\.com\/recaptcha\//i,
  /gstatic\.com\/recaptcha\//i,
  /\bhcaptcha\.com\//i,
];

function isSriIncompatible(src) {
  return SRI_INCOMPATIBLE_SRC.some((re) => re.test(String(src || '')));
}

/**
 * A line that LOADS a script, as opposed to one that merely names a host — a CSP directive,
 * a consent blocklist, a comment in a config array. Blocking a checkout page *because* it
 * lists the origins it refuses to run would be precisely backwards.
 */
const LOAD_SIGNAL_RE =
  /<script\b|\bsrc\s*[:=]|\b\w*(?:src|url|script|tag)\w*\s*[:=]|\bimport\s*\(|\bappendChild\b|\bdocument\s*\.\s*write\b|\bloadScript\b|\binjectScript\b/i;

const BLOCKLIST_RE = /\b(?:block|deny|ban|banned|forbid|forbidden|disallow|reject|exclude|excluded|blacklist|blocklist|denylist)/i;

function lineOf(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

function hostOf(url) {
  const m = /^(?:https?:)?\/\/([^/?#:]+)/i.exec(String(url).trim());
  return m ? m[1].toLowerCase() : null;
}

function isExemptHost(host, exempt) {
  if (!host) return false;
  return exempt.some((e) => host === e || host.endsWith('.' + e));
}

/** Every `<script ...>` / `<Script ...>` open tag outside a comment. */
function scriptTags(masked) {
  const tags = [];
  const re = /<script\b([^>]*)>/gi;
  let m;
  while ((m = re.exec(masked)) !== null) {
    const attrs = m[1] || '';
    const srcM =
      /\bsrc\s*=\s*["'`]([^"'`]+)["'`]/i.exec(attrs) ||
      /\bsrc\s*=\s*\{\s*["'`]([^"'`]+)["'`]\s*\}/i.exec(attrs);
    tags.push({
      attrs,
      src: srcM ? srcM[1] : null,
      line: lineAt(masked, m.index),
    });
  }
  return tags;
}

/**
 * Stories, Cypress/Playwright specs and other harness files mount a payment element on
 * purpose, against test keys, and never render to a real cardholder. `isAllowlistedTestFile`
 * misses the two directory conventions that matter here (`cypress/`, `e2e/`) and stories
 * entirely, so they are added on top of it.
 */
function looksLikeHarnessFile(filePath) {
  if (isAllowlistedTestFile(filePath)) return true;
  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  if (/\.(?:stories|story)\.[a-z]+$/.test(norm)) return true;
  if (/\.cy\.[a-z]+$/.test(norm)) return true;
  if (/\.e2e(?:-spec)?\.[a-z]+$/.test(norm)) return true;
  const parts = norm.split('/');
  return parts.some((p) => ['cypress', 'playwright', 'e2e', '.storybook', 'stories', '__mocks__'].includes(p));
}

/**
 * Server files never mount a payment element in the browser. Denying a route handler because
 * it happens to mention loadStripe would be the fastest way to get the plugin uninstalled.
 */
function looksLikeServerFile(filePath, code) {
  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  const parts = norm.split('/');
  const SERVER_DIRS = ['api', 'server', 'routes', 'controllers', 'handlers', 'functions', 'actions', 'middleware'];
  if (parts.some((p) => SERVER_DIRS.includes(p))) return true;
  if (/\.server\.[a-z]+$/.test(norm)) return true;
  if (/^\s*['"]use server['"]/m.test(code)) return true;
  if (/\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s*\(/.test(code)) return true;
  if (/\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*[:=]/.test(code)) return true;
  if (/\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use)\s*\(/.test(code)) return true;
  if (/\bexport\s+default\s+(?:async\s+)?function\s+handler\s*\(/.test(code)) return true;
  return false;
}

/** Read the inventory and count how many scripts it actually declares. */
function readInventory(invPath) {
  let raw;
  try {
    raw = fs.readFileSync(invPath, 'utf8');
  } catch {
    return { ok: false, reason: 'unreadable', count: 0 };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: 'malformed', count: 0 };
  }
  if (Array.isArray(parsed)) return { ok: parsed.length > 0, reason: 'empty', count: parsed.length };
  if (parsed && typeof parsed === 'object') {
    for (const [k, v] of Object.entries(parsed)) {
      if (k === '$schema') continue;
      if (Array.isArray(v)) return { ok: v.length > 0, reason: 'empty', count: v.length };
    }
    const keys = Object.keys(parsed).filter((k) => k !== '$schema');
    return { ok: keys.length > 0, reason: 'empty', count: keys.length };
  }
  return { ok: false, reason: 'empty', count: 0 };
}

/** Does the inventory actually name this script? Substring match on the raw file is enough. */
function inventoryDeclares(invPath, src, host) {
  let raw;
  try {
    raw = fs.readFileSync(invPath, 'utf8').toLowerCase();
  } catch {
    return false;
  }
  if (src && raw.includes(String(src).toLowerCase())) return true;
  return !!host && raw.includes(String(host).toLowerCase());
}

function run(ctx) {
  const { filePath, content, projectDir } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;

  const ext = path.extname(String(filePath || '')).toLowerCase();
  if (!PAGE_EXTENSIONS.has(ext)) return null;
  if (looksLikeHarnessFile(filePath)) return null;

  const code = stripCommentsAndStrings(content);
  const masked = maskComments(content);
  const exempt = exemptHosts();
  const tags = scriptTags(masked);

  // --- Gate 1: is a payment element actually mounted here? -----------------------------
  let mount = null;
  for (const p of MOUNT_PATTERNS) {
    const m = p.re.exec(code);
    if (m && (mount === null || m.index < mount.index)) {
      mount = { label: p.label, index: m.index, line: lineAt(code, m.index) };
    }
  }
  if (!mount) {
    for (const t of tags) {
      const h = hostOf(t.src || '');
      if (isExemptHost(h, exempt)) {
        mount = {
          label: `PSP loader <script src="${t.src}">`,
          labelEs: `loader del PSP <script src="${t.src}">`,
          line: t.line,
        };
        break;
      }
    }
  }
  if (!mount) return null;

  // --- Gate 2: never fire on a server file ---------------------------------------------
  if (looksLikeServerFile(filePath, code)) return null;

  const where = `line ${mount.line} (${mount.label})`;
  // Built separately rather than by string-replacing `where`: the label itself needs
  // translating when it is prose, not a code identifier.
  const whereEs = `línea ${mount.line} (${mount.labelEs || mount.label})`;

  // --- (a) the script inventory must exist ---------------------------------------------
  // Look from the file outwards first: in a monorepo the inventory belongs to the app that
  // owns the payment page (apps/web/), not to the repo root that projectDir points at.
  const fileDir = filePath ? path.dirname(String(filePath)) : null;
  const invPath =
    (fileDir ? walkUpForFile(fileDir, INVENTORY_FILENAME) : null) ||
    (projectDir ? walkUpForFile(projectDir, INVENTORY_FILENAME) : null);
  if (!invPath) {
    return {
      rule: RULE_ID,
      level: 'deny',
      code: 'ERR_PCI_SCRIPT_INVENTORY',
      message_en:
        `This file mounts a payment element at ${where}, so PCI DSS 4.0.1 req. 6.4.3 applies, ` +
        `but no ${INVENTORY_FILENAME} exists at the project root. Every script that runs on a ` +
        `payment page must be inventoried with a written business justification.`,
      message_es:
        `Este archivo monta un elemento de pago en la ${whereEs}, así que aplica ` +
        `el requisito 6.4.3 de PCI DSS 4.0.1, pero no hay ningún ${INVENTORY_FILENAME} en la raíz del ` +
        `proyecto. Todo script que corra en una página de pago debe estar inventariado y justificado.`,
      suggested_fix:
        `Create ${INVENTORY_FILENAME} at the project root, one entry per external script:\n` +
        `{\n  "scripts": [\n    { "src": "https://js.stripe.com/v3", "justification": "PSP card tokenisation", "authorised_by": "you@example.com", "integrity": null }\n  ]\n}\n` +
        `Re-review it whenever a script is added — that review is the 6.4.3 control, not the file itself.\n` +
        `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
    };
  }

  const inv = readInventory(invPath);
  if (!inv.ok) {
    const detail =
      inv.reason === 'malformed'
        ? 'it is not valid JSON'
        : inv.reason === 'unreadable'
          ? 'it could not be read'
          : 'it lists zero scripts';
    return {
      rule: RULE_ID,
      level: 'deny',
      code: 'ERR_PCI_SCRIPT_INVENTORY',
      message_en:
        `This file mounts a payment element at ${where}, and ${INVENTORY_FILENAME} exists but ${detail}. ` +
        `An empty or broken inventory does not satisfy PCI DSS 4.0.1 req. 6.4.3.`,
      message_es:
        `Este archivo monta un elemento de pago en la ${whereEs} y ${INVENTORY_FILENAME} ` +
        `existe, pero ${detail === 'it is not valid JSON' ? 'no es JSON válido' : detail === 'it could not be read' ? 'no se pudo leer' : 'no lista ningún script'}. ` +
        `Un inventario vacío o roto no cumple el requisito 6.4.3 de PCI DSS 4.0.1.`,
      suggested_fix:
        `Fill in ${invPath} with one entry per external script loaded on this page ` +
        `(src, justification, who authorised it, and the expected integrity hash where one applies).\n` +
        `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
    };
  }

  // --- (b) every non-PSP third-party script needs integrity + crossorigin ---------------
  for (const t of tags) {
    const host = hostOf(t.src || '');
    if (!host) continue; // relative / same-origin script — not third party
    if (isExemptHost(host, exempt)) continue; // PSP loader: versionless by design, never demand SRI
    if (isSriIncompatible(t.src)) {
      // Turnstile / reCAPTCHA / hCaptcha cannot be hashed. Authorising them in the inventory
      // is the only control that exists, so that — not integrity= — is what we ask for.
      if (inventoryDeclares(invPath, t.src, host)) continue;
      return {
        rule: RULE_ID,
        level: 'deny',
        code: 'ERR_PCI_SCRIPT_INVENTORY',
        message_en:
          `Line ${t.line} loads ${host} on a payment page (element mounted at ${where}). That script is ` +
          `generated per request, so it cannot carry an SRI hash — which means the only PCI DSS 4.0.1 ` +
          `control left for it is req. 6.4.3: it must be listed in ${INVENTORY_FILENAME} with a written ` +
          `justification. It is not listed.`,
        message_es:
          `La línea ${t.line} carga ${host} en una página de pago (el elemento se monta en la ` +
          `${whereEs}). Ese script se genera en cada petición, así que no puede ` +
          `llevar hash SRI: el único control que queda es el requisito 6.4.3 de PCI DSS 4.0.1, o sea ` +
          `declararlo en ${INVENTORY_FILENAME} con su justificación por escrito. Ahí no aparece.`,
        suggested_fix:
          `Do NOT try to add integrity= — the file changes on every request and the page would stop ` +
          `loading. Add it to ${invPath} instead:\n` +
          `  { "src": "${t.src}", "justification": "bot protection on the payment page", ` +
          `"authorised_by": "you@example.com", "integrity": null }\n` +
          `Then make sure your 11.6.1 change-detection tooling watches the payment page's script list.\n` +
          `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
      };
    }
    const hasIntegrity = /\bintegrity\s*=/i.test(t.attrs);
    const hasCrossorigin = /\bcrossorigin\s*=/i.test(t.attrs);
    if (hasIntegrity && hasCrossorigin) continue;
    const missing = !hasIntegrity && !hasCrossorigin
      ? 'integrity= and crossorigin='
      : !hasIntegrity
        ? 'integrity='
        : 'crossorigin=';
    const missingEs = missing.replace(' and ', ' ni ');
    return {
      rule: RULE_ID,
      level: 'deny',
      code: 'ERR_PCI_SCRIPT_INVENTORY',
      message_en:
        `Line ${t.line} loads third-party script ${host} on a payment page (element mounted at ${where}) ` +
        `without ${missing}. PCI DSS 4.0.1 req. 11.6.1 requires an integrity check on every script a ` +
        `payment page executes, except the PSP's own loader.`,
      message_es:
        `La línea ${t.line} carga el script de terceros ${host} en una página de pago (el elemento se monta ` +
        `en la ${whereEs}) sin ${missingEs}. El requisito 11.6.1 de PCI DSS 4.0.1 exige ` +
        `verificación de integridad en todo script que ejecute una página de pago, salvo el loader del PSP.`,
      suggested_fix:
        `Pin the version and add both attributes:\n` +
        `  <script src="${t.src}" integrity="sha384-..." crossorigin="anonymous"></script>\n` +
        `Generate the hash with: curl -s "${t.src}" | openssl dgst -sha384 -binary | openssl base64 -A\n` +
        `Better still, self-host it so the payment page loads nothing you do not control.\n` +
        `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
    };
  }

  // --- (c) no analytics or tag manager on the payment page ------------------------------
  for (const a of ANALYTICS_HOSTS) {
    const re = new RegExp(a.re.source, a.re.flags.includes('g') ? a.re.flags : a.re.flags + 'g');
    let m;
    while ((m = re.exec(masked)) !== null) {
      const line = lineOf(masked, m.index);
      // Naming an origin is not loading it: a CSP directive, a consent blocklist, or a config
      // array of hosts the checkout deliberately refuses to run must never be denied.
      if (!LOAD_SIGNAL_RE.test(line)) continue;
      if (BLOCKLIST_RE.test(line)) continue;
      return analyticsFinding(a.label, lineAt(masked, m.index), where, whereEs);
    }
  }
  for (const a of ANALYTICS_CALLS) {
    const m = a.re.exec(code);
    if (m) {
      return analyticsFinding(a.label, lineAt(code, m.index), where, whereEs);
    }
  }

  return null;
}

function analyticsFinding(label, line, where, whereEs) {
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_PCI_SCRIPT_INVENTORY',
    message_en:
      `Line ${line} runs ${label} on a payment page (element mounted at ${where}). Analytics and tag ` +
      `managers can rewrite the DOM, so they pull the page into PCI scope and break SAQ A eligibility — ` +
      `this is the exact mechanism behind Magecart-style skimming.`,
    message_es:
      `La línea ${line} ejecuta ${label} en una página de pago (el elemento se monta en la ` +
      `${whereEs}). Los tag managers y las analíticas pueden reescribir el DOM: ` +
      `meten la página en el alcance de PCI y te sacan del SAQ A. Es el mecanismo exacto del skimming tipo Magecart.`,
    suggested_fix:
      `Move ${label} off the payment page. Fire the conversion event from the server (on the verified ` +
      `webhook) or from the post-payment confirmation page, which is out of PCI scope.\n` +
      `If it genuinely must stay, it needs an entry in payment-page-scripts.json with a written ` +
      `justification and it must be covered by your 11.6.1 change-detection tooling.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
