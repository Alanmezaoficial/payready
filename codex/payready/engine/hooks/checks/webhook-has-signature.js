// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 3 — Webhook handlers must verify request signature.
 *
 * Triggers on files that look like webhook handlers (path or content heuristics).
 * Requires presence of at least one canonical verifier call OR the explicit
 * `// @pagokit:signature-verified` tag for custom wrappers.
 *
 * Bypass: `// pagokit-ignore: webhook-has-signature -- <reason>`.
 */

const path = require('node:path');
const {
  isWebhookFilePath,
  hasIgnoreTag,
  hasSignatureVerifiedTag,
  stripCommentsAndStrings,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'webhook-has-signature';

// Verifier function calls / patterns we accept as proof of signature verification.
const VERIFIER_PATTERNS = [
  /stripe\.webhooks\.constructEvent/, // Stripe Node
  /stripe\.Webhook\.construct_event/, // Stripe Python
  /constructEvent\s*\(/,
  /verify[A-Z]?\w*Signature\s*\(/, // verifySignature, verifyMpSignature, verifyLemonSignature
  /verify[_]\w*signature\s*\(/i, // python/php naming
  /verify[A-Z]?\w*Checksum\s*\(/, // verifyChecksum, verifyWompiChecksum
  /verify[A-Z]?\w*Webhook\s*\(/,
  /verify[_]webhook[_]signature/i,
  /createHmac\s*\(/, // crypto.createHmac (sha256 etc.) — stripped strings hide the algorithm name
  /createHash\s*\(/, // crypto.createHash for Wompi-style checksum verification
  /HMAC[._]new\s*\(/, // Python hmac.new
  /Hmac::new/, // Rust/Ruby
  /WebhookSignature\.verify/, // some SDK wrappers
  /timingSafeEqual\s*\(/, // if timingSafeEqual is present, verification logic is too
  // --- found by the self-audit: correct code the check would have BLOCKED ---------------
  // Standard Webhooks providers (Polar, Dodo, Whop, Recurrente, Yoco) are told to verify
  // with the off-the-shelf svix package rather than hand-rolling crypto. Not recognising it
  // would make the validator reject exactly the implementation the fragment recommends.
  /\bnew\s+Webhook\s*\(/,                    // svix (Node): new Webhook(secret).verify(...)
  /\bWebhook\s*\([^)]*\)\s*\.\s*verify\s*\(/, // svix (Python): Webhook(secret).verify(...)
  /\bwh\.verify\s*\(/,                        // the conventional svix variable name
  /\bverifyWebhook\s*\(/,
  /\.verify\s*\(\s*(?:payload|raw_?[Bb]ody|body)\b/, // generic SDK verifier on the raw body
  /\bcrypto\.verify\s*\(/,                    // asymmetric_rsa
  /\bjwt\.verify\s*\(|\bjwtVerify\s*\(|\bjose\./,  // asymmetric_jws
  /\bcompare_digest\s*\(/,                     // Python constant-time compare
  /\bhash_equals\s*\(/,                        // PHP constant-time compare
];

/** The hardcoded shapes above, plus every verifier name declared in the catalog. */
function verifierPatterns() {
  const fromCatalog = utils.catalogVerifierRegex();
  return fromCatalog ? VERIFIER_PATTERNS.concat([fromCatalog]) : VERIFIER_PATTERNS;
}

// Files that LOOK like webhooks by extension but aren't payment-related — skip
const NON_PAYMENT_KEYWORDS = ['clerk', 'inngest', 'resend', 'svix', 'github'];

// Signals that a POST handler is receiving a PROVIDER CALLBACK rather than a browser
// request. Without one of these, "payment SDK + POST handler" also describes every checkout,
// refund and portal endpoint in the project.
const WEBHOOK_SIGNALS = [
  /headers\s*(?:\.get\s*\(\s*|\[\s*)['"][^'"]*(?:signature|signatur|checksum|webhook|hmac|callback-token|event-signature)/i,
  /\brequest\.headers\[['"][^'"]*(?:signature|checksum|webhook)/i,      // python/php style
  /\bevent\s*\.\s*(?:type|id|created|data)\b/,                        // dispatching a provider event
  /\bpayload\s*\.\s*(?:event|type|meta)\b/,
  /\b(?:webhook|callback|notification|ipn)_?(?:secret|token|event|payload)\b/i,
  /switch\s*\(\s*\w*\.?(?:event_?type|type)\s*\)/i,
];

function looksLikeWebhookFile(filePath, content) {
  if (isWebhookFilePath(filePath)) return true;
  if (!content) return false;
  // SDK package names come from the catalog, so a new provider is detected without editing
  // this file.
  const hasPaymentImport = utils.hasPaymentSdkImport(content)
    || /import\s+stripe/i.test(content)
    || /from\s+stripe/i.test(content);
  if (!hasPaymentImport) return false;

  const hasHandler = /export\s+async\s+function\s+POST/.test(content)
    || /app\.post\s*\(\s*['"][^'"]*webhook/i.test(content)
    || /router\.post\s*\(\s*['"][^'"]*webhook/i.test(content)
    || /@app\.post\s*\(\s*['"][^'"]*webhook/i.test(content);
  if (!hasHandler) return false;

  const code = stripCommentsAndStrings ? content : content;
  return WEBHOOK_SIGNALS.some((re) => re.test(code));
}

function isExclusionPath(filePath, content) {
  const norm = (filePath || '').toLowerCase();
  if (content) {
    for (const kw of NON_PAYMENT_KEYWORDS) {
      if (new RegExp(`from\\s+['"][^'"]*${kw}`, 'i').test(content)) return true;
    }
  }
  return false;
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!filePath || !content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;

  if (!looksLikeWebhookFile(filePath, content)) return null;
  if (isExclusionPath(filePath, content)) return null;

  // Tag-based bypass for custom verifiers
  if (hasSignatureVerifiedTag(content)) return null;

  // Strip comments and strings before pattern matching so docs don't false-positive
  const stripped = stripCommentsAndStrings(content);

  for (const pattern of verifierPatterns()) {
    if (pattern.test(stripped)) {
      return null; // passes — verifier present
    }
  }

  // No verifier found — deny
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_WEBHOOK_NO_SIG',
    message_en: `Webhook handler does not verify request signature (Rule 3). The file at ${path.basename(filePath)} looks like a payment webhook but no signature verification call was detected.`,
    message_es: `El handler del webhook no verifica la firma de la petición (Regla 3). El archivo ${path.basename(filePath)} parece un webhook de pagos pero no se detectó verificación de firma.`,
    suggested_fix:
      `Add the canonical verifier for your provider:\n` +
      `- Stripe: stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET).\n` +
      `- Mercado Pago: verify HMAC-SHA256 over the manifest string id:<data.id>;request-id:<x-request-id>;ts:<ts>;.\n` +
      `- Wompi: verifyWompiChecksum(event, process.env.WOMPI_EVENTS_SECRET).\n` +
      `- Lemon Squeezy: verifyLemonSignature(rawBody, signature, process.env.LEMONSQUEEZY_WEBHOOK_SECRET).\n` +
      `If you use a custom wrapper (e.g., lib/auth/payments.ts), add "// @pagokit:signature-verified" above the handler function.\n` +
      `To bypass entirely: "// pagokit-ignore: ${RULE_ID} -- documented reason".`,
  };
}

module.exports = { run, RULE_ID, _VERIFIER_PATTERNS: verifierPatterns() };
