// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';
/**
 * SECURITY_RULES Rule 21 — a stored card with nowhere to store the network transaction id.
 *
 * Mastercard requires the stored Trace ID (TLID) on every economically-related
 * merchant-initiated transaction from 23 October 2026, and Visa's Original Transaction ID
 * already drives approval rates today. A merchant-initiated charge that cannot be linked
 * back to the cardholder-initiated transaction that authorised it is not a warning: it is
 * a decline, on a subscription renewal, silently, for every customer at once.
 *
 * The check pairs two facts that live in different files: this file sets up a saved card
 * (setup_future_usage / SetupIntent / off_session / vaulting), and the project's schema
 * has no column to hold the id the network will hand back. It runs at the Stop phase
 * because that is the only moment both halves are on disk — from a single mid-edit ctx it
 * degrades to a warning, because the migration may simply not be written yet.
 *
 * Bypass: `// pagokit-ignore: network-txn-id-persistence -- <reason>`.
 */

const fs = require('node:fs');
const path = require('node:path');
const {
  hasIgnoreTag,
  stripCommentsAndStrings,
  isSourceCodeFile,
  isAllowlistedTestFile,
  hasPaymentSdkImport,
  catalogSdkCallRegex,
  loadProviders,
} = require('../lib/utils');
const utils = require('../lib/utils');

const RULE_ID = 'network-txn-id-persistence';

/** The identifier, in every casing a real schema uses. */
const TLID_RE =
  /network_transaction_id|networkTransactionId|original_transaction_id|originalTransactionId|\btlid\b/i;

/**
 * Signals that this file sets up a stored credential for later merchant-initiated use.
 * `strong` signals are unambiguous provider APIs. `weak` signals are ordinary English
 * words in a payments costume, so they additionally require the file to be payments code.
 */
const STRONG_MIT_SIGNALS = [
  /\bsetup_future_usage\b/,
  /\bsetupFutureUsage\b/,
  /\bsetupIntents\.create\s*\(/,
  /\bSetupIntent\b/,
  /\boff_session\s*:\s*true\b/,
  /\boffSession\s*:\s*true\b/,
  /\bMerchantInitiated\b/,
  /\bmerchant_initiated\b/,
];

const WEAK_MIT_SIGNALS = [
  /\bsave_?[Cc]ard\b/,
  /\bsave_?payment_?method\b/,
  /\bsavePaymentMethod\b/,
  // `vault` on its own is HashiCorp Vault far more often than it is a card vault, and
  // `cardToken` on its own is how every read-only "your saved cards" list names a row.
  // The noun that follows is what makes either of them a stored credential.
  /\bvault(?:ed|ing)?[_-]?(?:card|cards|token|tokens|payment|paymentmethod|credential)s?\b/i,
  /\b(?:card|payment_?method)_?vault\b/i,
  /\bstored_?credential\b/i,
  // Mercado Pago: a customer card reused by a subscription.
  /\bpre_?[Aa]pproval\b/,
  /\bauto_?recurring\b/,
  /\bcard_?token_?id\b/i,
  // Wompi: a stored payment source charged without the cardholder present.
  /\bpayment_?source_?id\b/i,
  /\brecurrent\s*:\s*true\b/,
  /\brecurring\s*:\s*true\b/,
];

/* ------------------------------------------------------------------ *
 * Bounded schema discovery
 * ------------------------------------------------------------------ */

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.nuxt', '.svelte-kit', 'dist', 'build', 'out',
  'coverage', 'vendor', '__pycache__', '.venv', 'venv', 'env', 'target', '.turbo',
  '.cache', 'tmp', 'temp', '.terraform',
]);

const SCHEMA_BASENAMES = new Set([
  'schema.prisma', 'schema.rb', 'structure.sql', 'models.py', 'schema.ts', 'schema.js',
  'schema.sql', 'schema.mjs', 'models.rb', 'entities.ts',
]);

const SCHEMA_DIRS = new Set([
  'migrations', 'migration', 'migrate', 'versions', 'prisma', 'drizzle', 'db',
  'database', 'alembic', 'supabase', 'schema', 'models', 'entities',
]);

const SCHEMA_EXTS = new Set(['.sql', '.prisma', '.ts', '.js', '.mjs', '.py', '.rb']);

/**
 * Proof that a candidate really declares a database schema.
 *
 * `schema.ts` is at least as often a zod/yup request validator as it is a Drizzle table,
 * and `models.py` is as often a pydantic model as a Django one. Concluding "this project
 * has one schema file and it lacks the column" from a zod file is a deny built on a
 * false premise, so a candidate only counts once its CONTENT says schema.
 */
const DB_SCHEMA_MARKER_RE =
  /CREATE\s+TABLE|ALTER\s+TABLE|CREATE\s+INDEX|^\s*model\s+\w+\s*\{|^\s*datasource\s+\w+\s*\{|create_table|add_column|add_reference|change_table|ActiveRecord::(?:Schema|Migration)|@Entity\b|@Column\b|pgTable\s*\(|sqliteTable\s*\(|mysqlTable\s*\(|models\.Model\b|db\.Column\s*\(|sa\.Column\s*\(|Column\s*\(\s*\w|op\.create_table|def\s+(?:up|down|change)\b/im;

const MAX_DIRS = 240;
const MAX_FILES_READ = 40;
const MAX_BYTES = 512 * 1024;

/** Is this file plausibly a schema or a migration? */
function isSchemaCandidate(filePath, parentDirName) {
  const base = path.basename(filePath).toLowerCase();
  const ext = path.extname(base);
  if (base.endsWith('.prisma')) return true;
  if (SCHEMA_BASENAMES.has(base)) return true;
  if (!SCHEMA_DIRS.has(parentDirName)) return false;
  if (!SCHEMA_EXTS.has(ext)) return false;
  // Inside a migrations/ or drizzle/ directory, the filename is arbitrary.
  return true;
}

/**
 * Breadth-first, depth- and budget-capped scan for schema/migration files.
 * Returns { files: string[], scanned: number }. Cheap by construction: it never
 * descends into dependency or build directories and stops after MAX_FILES_READ hits.
 */
function findSchemaFiles(projectDir) {
  const found = [];   // [{ file, content }] — content already proven to be a DB schema
  if (!projectDir) return found;
  let dirBudget = MAX_DIRS;
  const queue = [{ dir: projectDir, depth: 0 }];
  while (queue.length && dirBudget > 0 && found.length < MAX_FILES_READ) {
    const { dir, depth } = queue.shift();
    dirBudget--;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    const dirName = path.basename(dir).toLowerCase();
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        if (depth < 4) queue.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue;
      if (found.length >= MAX_FILES_READ) break;
      if (!isSchemaCandidate(full, dirName)) continue;
      try {
        const stat = fs.statSync(full);
        if (stat.size > MAX_BYTES) continue;
        const body = fs.readFileSync(full, 'utf8');
        if (!DB_SCHEMA_MARKER_RE.test(body)) continue;   // a validator, not a schema
        found.push({ file: full, content: body });
      } catch {
        /* unreadable file proves nothing */
      }
    }
  }
  return found;
}

/** Does any schema file already carry the network transaction id? */
function schemaHasTlid(files) {
  return files.some((f) => TLID_RE.test(f.content));
}

/**
 * Does a path segment name a catalog provider? `app/api/wompi/recurring/route.ts` is
 * payments code whether or not it reaches the SDK through a local wrapper module, and
 * a wrapper (`@/lib/wompi`) is how most projects actually import one.
 */
function pathNamesProvider(filePath) {
  if (!filePath) return false;
  const segments = String(filePath).replace(/\\/g, '/').toLowerCase().split('/').filter(Boolean);
  if (!segments.length) return false;
  segments[segments.length - 1] = segments[segments.length - 1].replace(/\.[a-z0-9]+$/, '');
  const collapsed = segments.map((seg) => seg.replace(/[^a-z0-9]+/g, ''));
  for (const provider of loadProviders().providers || []) {
    const slugs = new Set();
    if (provider.id) slugs.add(String(provider.id).toLowerCase());
    const name = String(provider.name || '').toLowerCase().trim();
    if (name) slugs.add(name.replace(/[^a-z0-9]+/g, ''));
    slugs.delete('');
    if (segments.some((seg) => slugs.has(seg)) || collapsed.some((seg) => slugs.has(seg))) {
      return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */

function firstLineMatching(lines, patterns) {
  for (let i = 0; i < lines.length; i++) {
    for (const re of patterns) {
      if (re.test(lines[i])) return { line: i + 1, source: lines[i].trim().slice(0, 80) };
    }
  }
  return null;
}

function run(ctx) {
  const { filePath, content, projectDir, phase } = ctx;
  if (!content) return null;
  if (hasIgnoreTag(content, RULE_ID)) return null;
  if (!isSourceCodeFile(filePath)) return null;
  if (isAllowlistedTestFile(filePath)) return null;

  const stripped = stripCommentsAndStrings(content);
  const lines = stripped.split('\n');
  const rawLines = String(content).split('\n');

  // The file being written may itself be the place the id lands — never block that. But
  // the mention has to be on a line that survives comment-stripping: `// TODO: persist
  // network_transaction_id` silences the whole rule otherwise, which is the cheapest
  // possible bypass. The raw line is what is tested, so a raw-SQL string still counts.
  for (let i = 0; i < rawLines.length; i++) {
    if (/\S/.test(lines[i] || '') && TLID_RE.test(rawLines[i])) return null;
  }

  let hit = firstLineMatching(lines, STRONG_MIT_SIGNALS);
  if (!hit) {
    const weak = firstLineMatching(lines, WEAK_MIT_SIGNALS);
    if (!weak) return null;
    // A weak signal only counts inside code that is demonstrably a payments integration.
    const sdkCall = catalogSdkCallRegex();
    const isPayments =
      hasPaymentSdkImport(content) ||
      (sdkCall ? sdkCall.test(stripped) : false) ||
      pathNamesProvider(filePath);
    if (!isPayments) return null;
    hit = weak;
  }

  // Cross-file half: without a project directory there is nothing to conclude.
  if (!projectDir) return null;
  let schemaFiles;
  try {
    if (!fs.existsSync(projectDir)) return null;
    schemaFiles = findSchemaFiles(projectDir);
  } catch {
    return null;
  }
  if (!schemaFiles.length) return null;          // no schema at all → nothing to conclude
  if (schemaHasTlid(schemaFiles)) return null;   // the column exists → nothing to say

  const atStop = phase === 'stop';
  // relPath climbs out of the project with ../../.. when filePath is not under
  // projectDir; the absolute path is more useful than that.
  const rel = utils.relPath(filePath, projectDir);
  const where = rel && !rel.startsWith('..') ? rel : filePath;

  const n = schemaFiles.length;
  const countEn =
    n === 1
      ? 'the one schema/migration file in this project has no column'
      : `none of the ${n} schema/migration files in this project declares a column`;
  const countEs =
    n === 1
      ? 'el único archivo de esquema/migración del proyecto no tiene una columna'
      : `ninguno de los ${n} archivos de esquema/migración del proyecto declara una columna`;

  return {
    rule: RULE_ID,
    level: atStop ? 'deny' : 'warn',
    code: 'ERR_MIT_NO_TLID',
    message_en:
      `${where} stores a card for later merchant-initiated charges (line ${hit.line}), but ${countEn} ` +
      `for the network transaction id (network_transaction_id / original_transaction_id / TLID). ` +
      `Mastercard requires the ` +
      `stored Trace ID on every economically-related MIT from 23 October 2026, and Visa already scores ` +
      `unlinked MITs down — an unlinked renewal is a decline, not a warning.`,
    message_es:
      `${where} guarda una tarjeta para cobros posteriores iniciados por el comercio (línea ${hit.line}), ` +
      `pero ${countEs} para el id de transacción de red ` +
      `(network_transaction_id / original_transaction_id / TLID). ` +
      `Mastercard exige el Trace ID guardado en toda MIT económicamente relacionada desde el 23 de octubre ` +
      `de 2026, y Visa ya castiga las MIT sin vínculo: una renovación sin vínculo es un rechazo, no un aviso.`,
    suggested_fix:
      `Add a nullable string column next to your saved payment method — e.g. Prisma ` +
      `"networkTransactionId String? @map(\\"network_transaction_id\\")", SQL ` +
      `"ALTER TABLE payment_methods ADD COLUMN network_transaction_id text" — then persist the value the ` +
      `network returns on the FIRST cardholder-initiated charge ` +
      `(Stripe: charge.payment_method_details.card.network_transaction_id) and send it back on every ` +
      `off-session charge.\n` +
      `To bypass: "// pagokit-ignore: ${RULE_ID} -- reason".`,
  };
}

module.exports = { run, RULE_ID };
