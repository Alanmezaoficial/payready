// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * UserPromptSubmit preflight.
 *
 * Two things worth catching before Claude ever sees the prompt:
 *
 *   1. A LIVE API key pasted into the conversation. This is the most common real-world
 *      credential leak in agent workflows — the key ends up in the transcript, in any
 *      logging, and often in a screenshot. No other payments tool catches it.
 *   2. An instruction to disable a security control. "Skip the signature check", "turn off
 *      the hook", "just ignore the validator". The user is allowed to do that — but through
 *      the documented, logged escape hatch, not by talking the model out of it.
 *
 * Blocking a prompt is heavy-handed, so the gating is tight: only LIVE key shapes (never test
 * keys), and only explicit disable-the-control phrasing.
 */

const utils = require('../lib/utils');

const RULE_ID = 'prompt-preflight';

// Deliberately live-only. A test key in a prompt is normal and useful.
const HARDCODED_LIVE = [
  { name: 'Stripe secret key', re: /\bsk_live_[A-Za-z0-9]{16,}/ },
  { name: 'Stripe restricted key', re: /\brk_live_[A-Za-z0-9]{16,}/ },
  { name: 'Stripe webhook secret', re: /\bwhsec_[A-Za-z0-9]{24,}/ },
  { name: 'Mercado Pago access token', re: /\bAPP_USR-[A-Za-z0-9]{16,}-[0-9]{6,}-[a-z0-9]{16,}-[0-9]+/ },
  { name: 'Wompi private key', re: /\bprv_prod_[A-Za-z0-9]{16,}/ },
  { name: 'Lemon Squeezy live key', re: /\blmnsq_live_[A-Za-z0-9_-]{30,}/ },
  { name: 'Flutterwave secret key', re: /\bFLWSECK-[A-Za-z0-9]{16,}/ },
  { name: 'Xendit production key', re: /\bxnd_production_[A-Za-z0-9_-]{16,}/ },
  { name: 'Paystack secret key', re: /\bsk_live_[A-Za-z0-9]{20,}/ },
  { name: 'Razorpay live key', re: /\brzp_live_[A-Za-z0-9]{10,}/ },
  { name: 'PayPal live client secret', re: /\bE[A-Za-z0-9_-]{60,}/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'generic private key block', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
];

// Only explicit "turn the control off" phrasing. Discussing the rules must stay allowed.
const DISABLE_PATTERNS = [
  /\b(?:skip|disable|bypass|turn off|remove|ignore|omit|drop)\b[^.\n]{0,40}\b(?:signature|hmac)\s*(?:verification|check|validation)/i,
  /\b(?:skip|disable|bypass|turn off|remove|ignore)\b[^.\n]{0,30}\b(?:the\s+)?(?:pagokit\s+)?(?:hook|validator|security check)s?\b/i,
  /\bdon'?t\s+(?:bother\s+)?(?:verify|verifying|validate|validating|check|checking)\b[^.\n]{0,30}\b(?:signature|webhook|hmac)/i,
  /\b(?:without|no need (?:for|to))\b[^.\n]{0,20}\bsignature\s*(?:verification|check)/i,
  /\bstore\b[^.\n]{0,30}\b(?:card number|full pan|cvv|cvc)\b/i,
];

function livePatterns() {
  const out = HARDCODED_LIVE.slice();
  const seen = new Set(out.map((p) => p.re.source));
  try {
    for (const re of utils.livePatterns()) {
      if (!seen.has(re.source)) { seen.add(re.source); out.push({ name: 'provider live credential', re }); }
    }
  } catch { /* catalog unavailable; the hardcoded set still applies */ }
  return out;
}

/**
 * @param {{prompt: string}} ctx
 * @returns {null | {rule, level, code, message_en, message_es, suggested_fix}}
 */
function run(ctx) {
  const prompt = (ctx && (ctx.prompt || ctx.user_input || ctx.user_message)) || '';
  if (!prompt || typeof prompt !== 'string') return null;

  for (const { name, re } of livePatterns()) {
    const m = prompt.match(re);
    if (!m) continue;
    // Never echo the value. Show only enough to identify which one.
    const hint = `${m[0].slice(0, 8)}…${m[0].slice(-2)}`;
    return {
      rule: RULE_ID,
      level: 'deny',
      code: 'ERR_LIVE_KEY_IN_PROMPT',
      message_en: `That prompt contains what looks like a LIVE credential (${name}, ${hint}). It has not been sent. Treat it as compromised: rotate it in the provider dashboard now, then put the new value in .env and refer to it by name.`,
      message_es: `Ese prompt trae algo que parece una credencial de PRODUCCIÓN (${name}, ${hint}). No se envió. Dala por comprometida: rótala ya en el panel del proveedor, y guarda la nueva en .env para referirte a ella por nombre.`,
      suggested_fix:
        'Never paste a live key into a conversation — it lands in the transcript and in any logging.\n' +
        'Put it in .env (which must be gitignored) and say "use the key in STRIPE_SECRET_KEY".\n' +
        'Test-mode keys are fine to share and are not blocked.',
    };
  }

  for (const re of DISABLE_PATTERNS) {
    if (!re.test(prompt)) continue;
    return {
      rule: RULE_ID,
      level: 'warn',
      code: 'ERR_CONTROL_DISABLE_REQUEST',
      message_en:
        'That reads as a request to disable a security control. If you genuinely need to, use the documented escape hatch so the decision is recorded: `// pagokit-ignore: <rule> -- <reason>`, which is logged to .pagokit/audit.log. Talking the model out of the check instead leaves no trace.',
      message_es:
        'Eso suena a pedir que se desactive un control de seguridad. Si de verdad lo necesitas, usa la vía documentada para que quede registrado: `// pagokit-ignore: <regla> -- <motivo>`, que se guarda en .pagokit/audit.log. Convencer al modelo de saltárselo no deja rastro.',
      suggested_fix:
        'The rules exist for failures that are silent: an unsigned webhook accepts forged events, and nothing throws.\n' +
        'If the rule is wrong for your case, the ignore comment is the right tool — it is a decision on the record.',
    };
  }

  return null;
}

module.exports = { run, RULE_ID };
