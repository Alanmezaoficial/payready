// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * SECURITY_RULES Rule 14 — Webhook event dispatch must be bounded by an allowlist.
 *
 * A webhook handler that dispatches on the event type without a bounded set of
 * accepted types will run fulfilment logic for events it was never designed for:
 * a `default:` branch that grants access, an if/else-if chain closed by an
 * `else` that grants access, or a `handlers[event.type]()` lookup that reaches
 * `constructor`/`__proto__`. The provider can add a new event type at any time
 * and the handler silently starts acting on it.
 *
 * What makes a dispatch unbounded is a catch-all branch that ACTS, not the
 * absence of one: a `switch` with no `default:` and an if/else-if chain with no
 * terminal `else` are both bounded — an event type nobody named runs nothing.
 *
 * Fires only when the file is a webhook handler AND it dispatches on an
 * event-type expression AND the dispatch is unbounded in one of three concrete
 * ways. A `default:` that only logs or records the delivery, a handler with an
 * explicit allowlist on the event type, and any non-webhook file all pass.
 *
 * Bypass: `// pagokit-ignore: webhook-event-allowlist -- <reason>`.
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

const RULE_ID = 'webhook-event-allowlist';

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** `a.b?.c` — a plain member expression, no calls, no indexes. */
const MEMBER = '[A-Za-z_$][\\w$]*(?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*)*';

/**
 * Property names that carry the event type. Seeded from every provider's
 * `webhook.event_type_pointer` in the catalog, so a new provider whose type
 * lives at /meta/event_name is covered without touching this file.
 */
function eventTypeProps() {
  const props = new Set([
    'type', 'event', 'action', 'topic',
    'event_type', 'eventType', 'event_name', 'eventName',
  ]);
  for (const p of loadProviders().providers || []) {
    const ptr = p.webhook && p.webhook.event_type_pointer;
    if (!ptr) continue;
    const last = String(ptr).split('/').filter(Boolean).pop();
    if (last) props.add(last);
  }
  return Array.from(props);
}

/**
 * Bare identifiers accepted as a discriminant on their own. `type` and `event`
 * are deliberately excluded — too many non-payment meanings.
 */
const BARE_DISCRIMINANTS = new Set([
  'eventtype', 'event_type', 'eventname', 'event_name', 'evttype', 'evtname',
]);

function isEventTypeExpr(expr, props, aliases) {
  if (!expr) return false;
  const clean = expr.replace(/\s+/g, '');
  const parts = clean.split(/\??\./).filter(Boolean);
  const last = parts[parts.length - 1];
  if (!last) return false;
  if (parts.length === 1) {
    const low = last.toLowerCase();
    return BARE_DISCRIMINANTS.has(low) || Boolean(aliases && aliases.has(low));
  }
  return props.includes(last);
}

function lineOf(content, idx) {
  return content.slice(0, Math.max(0, idx)).split('\n').length;
}

/**
 * The body of the `default:` label only — up to the next `case` at the same
 * nesting depth. A `default:` written above the cases it precedes must not be
 * charged with what those cases do.
 */
function defaultBody(switchBody, defIdx) {
  let depth = 0;
  for (let i = defIdx; i < switchBody.length; i++) {
    const c = switchBody[i];
    if (c === '{' || c === '(' || c === '[') depth++;
    else if (c === '}' || c === ')' || c === ']') depth--;
    else if (depth === 0 && /^case\b/.test(switchBody.slice(i, i + 5)) && i > defIdx) {
      return switchBody.slice(defIdx, i);
    }
  }
  return switchBody.slice(defIdx);
}

/** Index of the `}` closing the `{` at `openIdx`, or -1. */
function matchBlock(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// State-mutation detection (what makes a `default:` branch dangerous)
// ---------------------------------------------------------------------------

const DB_ROOTS = /^(prisma|db|database|knex|sql|supabase|pool|pg|mongoose|sequelize|drizzle|orm|tx|trx|conn|connection|repo|repository|models?|store)$/i;
const DB_METHODS = /^(create|createMany|update|updateMany|upsert|delete|deleteMany|destroy|insert|insertInto|save|increment|decrement|execute|write)$/i;

/**
 * Names that mean "we recorded that we saw it", not "we acted on it".
 * A `default:` that writes to prisma.webhookLog is the CORRECT pattern and must
 * never be denied — this is the single biggest false-positive risk in this rule.
 */
const LOGISH = /(log|audit|unknown|unhandled|unrecognis|unrecognized|ignored|skipped|metric|trace|debug|telemetry|dead[_-]?letter|inbox|journal|archive|webhook|event|delivery|deliveries|notification|payload|received|processed|dedup|idempot)/i;

const FULFILMENT_CALL = /\b(fulfill|fulfil|fulfillOrder|fulfilOrder|grantAccess|grantEntitlement|grant|provisionAccess|provision|sendEmail|sendMail|markPaid|markAsPaid|creditWallet|refundOrder|upgradePlan|activateSubscription|deliverOrder)\s*\(/i;

/** Does this block of code mutate application state (as opposed to logging)? */
function hasStateMutation(code) {
  if (FULFILMENT_CALL.test(code)) return true;
  // Not anchored on `await`: `prisma.order.update(...)` fired and forgotten still
  // grants the entitlement, it just does not wait around for the answer.
  const re = new RegExp('(?:^|[^\\w$.])([A-Za-z_$][\\w$]*)((?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*)+)\\s*\\(', 'g');
  let m;
  while ((m = re.exec(code)) !== null) {
    const root = m[1];
    const chain = m[2].replace(/\s+/g, '');
    const method = chain.split(/\??\./).filter(Boolean).pop();
    if (!DB_ROOTS.test(root)) continue;
    if (!DB_METHODS.test(method || '')) continue;
    if (LOGISH.test(root + chain)) continue; // recording the unknown event — fine
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Allowlist evidence (any of these means the dispatch IS bounded)
// ---------------------------------------------------------------------------

/**
 * Local names that hold the event type: `const eventType = event.type`,
 * `const { type: kind } = event`. Without these, a handler that reads the type
 * into a variable and gates on that variable looks unbounded.
 */
function eventTypeAliases(stripped, props) {
  const aliases = new Set(BARE_DISCRIMINANTS);
  const alt = props.map(escapeRe).join('|');

  const assign = new RegExp(
    '\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::[^=;\\n]+)?=\\s*(' + MEMBER + ')\\s*[;\\n)]',
    'g'
  );
  let m;
  while ((m = assign.exec(stripped)) !== null) {
    if (isEventTypeExpr(m[2], props)) aliases.add(m[1].toLowerCase());
  }

  const destructure = new RegExp(
    '\\b(?:const|let|var)\\s*\\{([^}]*)\\}\\s*=\\s*([A-Za-z_$][\\w$]*(?:\\s*\\??\\.\\s*[A-Za-z_$][\\w$]*)*)',
    'g'
  );
  while ((m = destructure.exec(stripped)) !== null) {
    if (!/event|evt|payload|body|notification|msg|message|webhook/i.test(m[2])) continue;
    for (const part of m[1].split(',')) {
      const pm = new RegExp('^\\s*(' + alt + ')\\s*(?::\\s*([A-Za-z_$][\\w$]*))?\\s*$').exec(part);
      if (pm) aliases.add((pm[2] || pm[1]).toLowerCase());
    }
  }
  return aliases;
}

/**
 * The dispatch is bounded when a membership test gates the *event type*.
 *
 * The name of the array is not evidence: a file that happens to hold an
 * `ALLOWED_CURRENCIES` list would otherwise switch this whole rule off. What
 * counts is what the membership test is applied to.
 */
function hasAllowlistEvidence(stripped, props, aliases) {
  const re = new RegExp('(?:includes|has|indexOf|contains)\\s*\\(\\s*(' + MEMBER + ')\\s*[),]', 'g');
  let m;
  while ((m = re.exec(stripped)) !== null) {
    const expr = m[1].replace(/\s+/g, '');
    if (isEventTypeExpr(expr, props)) return true;
    if (!expr.includes('.') && aliases.has(expr.toLowerCase())) return true;
  }
  return false;
}

/**
 * Guards that make a dynamic `map[key]` lookup safe. Every one of them has to
 * name the map — a `hasOwnProperty` on some unrelated object elsewhere in the
 * file guards nothing.
 */
function indexDispatchGuarded(stripped, mapName) {
  const m = escapeRe(mapName);
  if (new RegExp('Object\\s*\\.\\s*hasOwn\\s*\\(\\s*' + m + '\\b').test(stripped)) return true;
  if (new RegExp('hasOwnProperty\\s*\\.\\s*call\\s*\\(\\s*' + m + '\\b').test(stripped)) return true;
  if (new RegExp('\\b' + m + '\\s*\\.\\s*hasOwnProperty\\s*\\(').test(stripped)) return true;
  if (new RegExp('\\bin\\s+' + m + '\\b').test(stripped)) return true;
  if (new RegExp('\\b' + m + '\\s*(?::[^=;]*)?=\\s*new\\s+Map\\b').test(stripped)) return true;
  if (new RegExp('\\b' + m + '\\s*\\.\\s*get\\s*\\(').test(stripped)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Provider resolution + required-event diffing
// ---------------------------------------------------------------------------

function resolveProvider(filePath, content) {
  const { providers } = loadProviders();
  const list = providers || [];
  const norm = String(filePath || '').toLowerCase().replace(/\\/g, '/');
  const flat = norm.replace(/[^a-z0-9]/g, '');
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

/** Event-type string literals the handler names, read from the RAW content. */
function handledEventLiterals(content) {
  const out = new Set();
  const patterns = [
    /\bcase\s+(['"])([^'"\n]{2,80})\1/g,
    /===?\s*(['"])([^'"\n]{2,80})\1/g,
    /(['"])([A-Za-z][\w.\-]{2,60})\1\s*:/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) out.add(m[2]);
  }
  return out;
}

function missingRequiredEvents(provider, content) {
  const required = (provider && provider.webhook && provider.webhook.required_events_minimum) || [];
  if (!required.length) return [];
  const handled = handledEventLiterals(content);
  return required.filter((e) => !handled.has(e));
}

// ---------------------------------------------------------------------------

/**
 * From the `if` at `ifIdx`, walk the else-if chain and return the body of the
 * terminal `else`, or null when the chain has none.
 *
 * A chain with no terminal `else` is bounded exactly the way a `switch` with no
 * `default:` is: an event type nobody named simply falls through and nothing
 * runs. The unbounded shape is the opposite one — a final `else` that acts.
 */
function terminalElseBody(stripped, ifIdx) {
  let i = ifIdx;
  for (let guard = 0; guard < 32; guard++) {
    const open = stripped.indexOf('{', i);
    if (open === -1) return null;
    const close = matchBlock(stripped, open);
    if (close === -1) return null;
    const tail = stripped.slice(close + 1, close + 80);
    const em = /^\s*else\b/.exec(tail);
    if (!em) return null; // chain ends without an else — bounded
    const afterElse = close + 1 + em[0].length;
    if (/^\s*if\b/.test(stripped.slice(afterElse, afterElse + 12))) {
      i = afterElse;
      continue;
    }
    const rest = stripped.slice(afterElse);
    const braced = /^\s*\{/.exec(rest);
    if (!braced) {
      // `else <single statement>` — read to the end of the statement.
      const semi = rest.indexOf(';');
      return rest.slice(0, semi === -1 ? Math.min(rest.length, 200) : semi + 1);
    }
    const eOpen = afterElse + braced[0].length - 1;
    const eClose = matchBlock(stripped, eOpen);
    return stripped.slice(eOpen, eClose === -1 ? undefined : eClose);
  }
  return null;
}

function isWebhookFile(filePath, content, stripped) {
  if (isWebhookFilePath(filePath)) return true;
  const verifier = catalogVerifierRegex();
  if (verifier && verifier.test(stripped)) return true;
  if (/stripe\.webhooks\.constructEvent|constructEvent\s*\(/.test(stripped)) return true;
  return false;
}

function buildFinding(kind, line, provider, missing, extra) {
  const provName = provider ? (provider.name || provider.id) : null;
  const missingNote = missing.length
    ? `\nAlso: the handler does not name ${provName}'s minimum event set — missing: ${missing.join(', ')}.`
    : '';

  const bodies = {
    switch_default: {
      en: `The webhook's \`switch\` on the event type has a \`default:\` branch that mutates state (line ${line}). Any event type the provider adds later — including ones this handler was never designed for — falls into it and gets fulfilled.`,
      es: `El \`switch\` sobre el tipo de evento tiene un \`default:\` que modifica estado (línea ${line}). Cualquier tipo de evento que el proveedor agregue después cae ahí y termina cumplido, aunque este handler nunca se haya diseñado para él.`,
      fix: `Restrict \`default:\` to logging and a 200 ack:\n  default:\n    console.log('unhandled event', event.type);\n    break;\nand move fulfilment into the explicit \`case\` labels you support.`,
    },
    if_chain: {
      en: `The if/else-if chain on the event type ends in an \`else\` that mutates state (line ${line}). That \`else\` catches every event type the chain does not name — including ones the provider adds later — and fulfils them.`,
      es: `La cadena if/else-if sobre el tipo de evento termina en un \`else\` que modifica estado (línea ${line}). Ese \`else\` atrapa todos los tipos que la cadena no nombra —incluidos los que el proveedor agregue después— y los da por cumplidos.`,
      fix: `Leave the final \`else\` for logging and the 200 ack:\n  } else {\n    console.log('unhandled event', event.type);\n  }\nand keep fulfilment in the branches that name an event type explicitly.`,
    },
    dynamic_index: {
      en: `The webhook dispatches through \`${extra}[event.type](...)\` (line ${line}) with no own-property guard. An unexpected event type resolves to an inherited member such as \`constructor\` or \`toString\`, and any type outside the map is unbounded.`,
      es: `El webhook despacha con \`${extra}[event.type](...)\` (línea ${line}) sin verificar que la clave sea propia. Un tipo inesperado puede resolver a un miembro heredado como \`constructor\` o \`toString\`, y cualquier tipo fuera del mapa queda sin acotar.`,
      fix: `Guard the lookup before calling it:\n  if (!Object.hasOwn(${extra || 'handlers'}, event.type)) return new Response(null, { status: 200 });\n  await ${extra || 'handlers'}[event.type](event);\nor build the map with \`new Map()\` and use \`.get(event.type)\`.`,
    },
  };

  const b = bodies[kind];
  return {
    rule: RULE_ID,
    level: 'deny',
    code: 'ERR_EVENT_UNBOUNDED',
    message_en: `${b.en} (Rule 14)`,
    message_es: `${b.es} (Regla 14)`,
    suggested_fix:
      `${b.fix}${missingNote}\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

function run(ctx) {
  const { filePath, content } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  if (!isWebhookFile(filePath, content, stripped)) return null;

  const props = eventTypeProps();
  const aliases = eventTypeAliases(stripped, props);
  if (hasAllowlistEvidence(stripped, props, aliases)) return null;

  const provider = resolveProvider(filePath, content);
  const missing = missingRequiredEvents(provider, content);

  // ---- (c) dynamic index dispatch: handlers[event.type](...) --------------
  const idxRe = new RegExp(
    '([A-Za-z_$][\\w$]*)\\s*\\[\\s*(' + MEMBER + ')\\s*\\]\\s*\\(', 'g'
  );
  let m;
  while ((m = idxRe.exec(stripped)) !== null) {
    if (!isEventTypeExpr(m[2], props, aliases)) continue;
    const mapName = m[1];
    if (indexDispatchGuarded(stripped, mapName)) continue;
    return buildFinding('dynamic_index', lineOf(content, m.index), provider, missing, mapName);
  }

  // ---- (a) switch with a state-mutating default: --------------------------
  const switchRe = new RegExp('switch\\s*\\(\\s*(' + MEMBER + ')\\s*\\)', 'g');
  while ((m = switchRe.exec(stripped)) !== null) {
    if (!isEventTypeExpr(m[1], props, aliases)) continue;
    const open = stripped.indexOf('{', m.index + m[0].length);
    if (open === -1) continue;
    const close = matchBlock(stripped, open);
    if (close === -1) continue;
    const body = stripped.slice(open, close);
    const defMatch = /\bdefault\s*:/.exec(body);
    if (!defMatch) continue; // no default at all — bounded by its cases
    const defBody = defaultBody(body, defMatch.index);
    if (!hasStateMutation(defBody)) continue; // logs / returns / breaks — correct
    return buildFinding(
      'switch_default',
      lineOf(content, open + defMatch.index),
      provider,
      missing,
      null
    );
  }

  // ---- (b) if/else-if chain closed by a state-mutating else ---------------
  const ifRe = new RegExp('if\\s*\\(\\s*!?\\s*(' + MEMBER + ')\\s*[=!]==?', 'g');
  while ((m = ifRe.exec(stripped)) !== null) {
    if (!isEventTypeExpr(m[1], props, aliases)) continue;
    const elseBody = terminalElseBody(stripped, m.index);
    if (!elseBody) continue; // no catch-all branch — bounded by its conditions
    if (!hasStateMutation(elseBody)) continue; // the else logs and acks — correct
    return buildFinding('if_chain', lineOf(content, m.index), provider, missing, null);
  }

  return null;
}

module.exports = { run, RULE_ID };
