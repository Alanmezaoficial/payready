// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
'use strict';

/**
 * PagoKit — shared validator utilities.
 *
 * Pure CommonJS, no external deps. Loaded by checks/ via require().
 */

const fs = require('node:fs');
const path = require('node:path');

const PLUGIN_ROOT = path.resolve(__dirname, '..', '..');
const PROVIDERS_PATH = path.join(
  PLUGIN_ROOT,
  'skills',
  'payment-advisor',
  'data',
  'providers.json'
);

let _providersCache = null;
function loadProviders() {
  if (_providersCache) return _providersCache;
  try {
    const raw = fs.readFileSync(PROVIDERS_PATH, 'utf8');
    _providersCache = JSON.parse(raw);
    return _providersCache;
  } catch (err) {
    return { providers: [] };
  }
}

const CURRENCIES_PATH = path.join(
  PLUGIN_ROOT, 'skills', 'payment-advisor', 'data', 'currencies.json'
);

let _currenciesCache = null;
function loadCurrencies() {
  if (_currenciesCache) return _currenciesCache;
  try {
    _currenciesCache = JSON.parse(fs.readFileSync(CURRENCIES_PATH, 'utf8'));
  } catch (err) {
    _currenciesCache = { currencies: [] };
  }
  return _currenciesCache;
}

/** Currency codes whose minor unit is not 2 - the ones a reflexive x100 gets wrong. */
function nonStandardExponentCurrencies() {
  const out = { zero: [], three: [] };
  for (const c of loadCurrencies().currencies) {
    if (c.exponent === 0) out.zero.push(c.code);
    else if (c.exponent === 3) out.three.push(c.code);
  }
  return out;
}

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Live-key patterns, derived from the catalog rather than hardcoded.
 *
 * This is the difference between a validator that protects four providers and one that
 * protects every provider in the catalog. A hardcoded list means a new provider's live key
 * is not scanned for at all - a silent failure in the exact place that is the product.
 */
function livePatterns() {
  const out = [];
  for (const p of loadProviders().providers || []) {
    for (const c of p.credentials || []) {
      if (c.live_pattern) {
        try { out.push(new RegExp(c.live_pattern.replace(/^\^/, '').replace(/\$$/, ''))); } catch (e) { /* skip bad regex */ }
      } else if (c.live_prefix) {
        out.push(new RegExp(escapeRe(c.live_prefix) + '[A-Za-z0-9_\\-]{16,}'));
      }
    }
    for (const raw of (p.detection && p.detection.live_key_patterns) || []) {
      out.push(new RegExp(escapeRe(raw) + '[A-Za-z0-9_\\-]{16,}'));
    }
  }
  return out;
}

/** Does this content import a payment SDK belonging to any catalog provider? */
function hasPaymentSdkImport(content) {
  if (!content) return false;
  const pkgs = [];
  for (const p of loadProviders().providers || []) {
    for (const s of (p.detection && p.detection.sdk_import_patterns) || []) pkgs.push(escapeRe(s));
    for (const langs of Object.values(p.sdks || {})) {
      if (langs && langs.pkg) pkgs.push(escapeRe(langs.pkg));
    }
  }
  if (!pkgs.length) return false;
  const alt = pkgs.join('|');
  return new RegExp("from\\s+['\"](?:" + alt + ")").test(content)
    || new RegExp("require\\s*\\(\\s*['\"](?:" + alt + ")").test(content)
    || new RegExp('^\\s*import\\s+(?:' + alt + ')\\b', 'm').test(content);
}

/** Verifier function names declared by any catalog provider. */
function catalogVerifierNames() {
  const names = [];
  for (const p of loadProviders().providers || []) {
    for (const n of (p.detection && p.detection.verifier_names) || []) names.push(n);
  }
  return names;
}

/** Regex matching any catalog-declared verifier call. */
function catalogVerifierRegex() {
  const names = catalogVerifierNames().map(escapeRe);
  if (!names.length) return null;
  return new RegExp('(?:' + names.join('|') + ')\\s*\\(');
}

/** Provider-SDK call sites that mark a file as payments-relevant. */
function catalogSdkCallRegex() {
  const calls = [];
  for (const p of loadProviders().providers || []) {
    for (const c of (p.detection && p.detection.sdk_call_patterns) || []) calls.push(escapeRe(c));
  }
  if (!calls.length) return null;
  return new RegExp('(?:' + calls.join('|') + ')');
}

/** Credential env var names declared by the catalog, for doctor and secret checks. */
function catalogCredentials() {
  const out = [];
  for (const p of loadProviders().providers || []) {
    for (const c of p.credentials || []) out.push({ provider: p.id, ...c });
  }
  return out;
}

/**
 * Return true if the file path looks like a webhook handler file for ANY of the
 * known providers. Uses providers.json's `webhook.expected_filenames` per provider.
 *
 * For generic names that overlap with non-payment files (events, notifications,
 * callback, ipn), require ALSO that the path contains a /webhook/ segment to
 * avoid false-positiving every lib/events.ts in the repo.
 */
function isWebhookFilePath(filePath) {
  if (!filePath) return false;
  const base = path.basename(filePath, path.extname(filePath)).toLowerCase();
  const dirParts = filePath.toLowerCase().split(/[\\/]/);

  // Direct generic patterns
  if (base === 'webhook' || base === 'webhooks') return true;
  if (dirParts.some((p) => p === 'webhook' || p === 'webhooks')) return true;
  if (dirParts.includes('api') && dirParts.includes('webhook')) return true;

  // Names known to be ambiguous on their own — only accept them if the path
  // also contains a webhook/ segment OR matches the exact provider-specific name.
  const AMBIGUOUS_NAMES = new Set([
    'events', 'notifications', 'callback', 'ipn', 'hook', 'hooks',
  ]);
  const pathContainsWebhookSegment =
    dirParts.includes('webhook') || dirParts.includes('webhooks');

  // Provider-specific via providers.json
  const { providers } = loadProviders();
  for (const provider of providers || []) {
    const filenames = provider.webhook?.expected_filenames || [];
    for (const name of filenames) {
      const lname = name.toLowerCase();
      // Exact-match always counts
      if (base === lname) {
        if (AMBIGUOUS_NAMES.has(lname) && !pathContainsWebhookSegment) {
          continue; // ambiguous name + no webhook segment → skip
        }
        return true;
      }
      // Substring match only for unambiguous provider-specific names
      // (e.g., "stripe-webhook", "wompi-webhook" should match).
      if (
        !AMBIGUOUS_NAMES.has(lname) &&
        lname.includes('webhook') &&
        base.includes(lname)
      ) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Return true if the file is in an allowlisted location (tests, fixtures, examples).
 */
function isAllowlistedTestFile(filePath) {
  if (!filePath) return false;
  const norm = filePath.toLowerCase().replace(/\\/g, '/');

  // Test/spec directories and filenames
  if (norm.includes('/__tests__/')) return true;
  if (norm.includes('/tests/')) return true;
  if (norm.includes('/test/')) return true;
  if (norm.includes('/spec/')) return true;
  if (norm.match(/\.test\.[a-z]+$/)) return true;
  if (norm.match(/\.spec\.[a-z]+$/)) return true;
  if (norm.match(/\.fixture\./)) return true;
  if (norm.match(/\/__fixtures__\//)) return true;

  // Plugin's own templates contain example code — skip
  if (norm.includes('/skills/integration-builder/templates/')) return true;
  if (norm.includes('/agente-pagokit/skills/')) return true;

  // node_modules, .git
  if (norm.includes('/node_modules/')) return true;
  if (norm.includes('/.git/')) return true;

  return false;
}

/**
 * Skip non-source files. Markdown is documentation. JSON/YAML/lock files are data.
 */
function isSourceCodeFile(filePath) {
  if (!filePath) return false;
  const ext = path.extname(filePath).toLowerCase();
  return [
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.py',
    '.php',
    '.rb',
    '.go',
    '.rs',
    '.java', '.kt',
    '.cs',
  ].includes(ext);
}

/**
 * Detect a `// pagokit-ignore: <rule>` (or `# pagokit-ignore: <rule>` for Python/Ruby/etc.)
 * anywhere in the file content. Returns true if the rule is ignored.
 */
function hasIgnoreTag(content, ruleId) {
  if (!content || !ruleId) return false;
  const escapedRule = ruleId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    `(?:\\/\\/|#|\\*|<!--)\\s*pagokit-ignore:\\s*${escapedRule}\\b`,
    'i'
  );
  return pattern.test(content);
}

/**
 * Detect the `// @pagokit:signature-verified` tag (special-case for webhook-has-signature).
 */
function hasSignatureVerifiedTag(content) {
  if (!content) return false;
  return /@pagokit:signature-verified/i.test(content);
}

/**
 * Walk up parent directories from `startDir` looking for `filename`. Returns the
 * absolute path of the first match, or null. Stops when it hits the filesystem root
 * or a `.git` directory marker.
 */
function walkUpForFile(startDir, filename) {
  if (!startDir || !filename) return null;
  let dir = path.resolve(startDir);
  while (true) {
    const candidate = path.join(dir, filename);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
    const gitMarker = path.join(dir, '.git');
    if (fs.existsSync(gitMarker)) {
      return null; // stop at repo root if .gitignore not found
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null; // reached filesystem root
    dir = parent;
  }
}

/**
 * Strip line comments and block comments and string literals from JS/TS content.
 * Returns a stripped version with comments/strings replaced by spaces (preserves
 * line numbers and column offsets). Used for analysis that should ignore comments
 * and strings.
 *
 * Simple character-by-character scanner; handles common cases but is not a full parser.
 */
function stripCommentsAndStrings(code) {
  if (!code) return '';
  const out = [];
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    const next = code[i + 1];

    // Line comment
    if (c === '/' && next === '/') {
      out.push('  ');
      i += 2;
      while (i < n && code[i] !== '\n') {
        out.push(' ');
        i++;
      }
      continue;
    }
    // Block comment
    if (c === '/' && next === '*') {
      out.push('  ');
      i += 2;
      while (i < n - 1 && !(code[i] === '*' && code[i + 1] === '/')) {
        out.push(code[i] === '\n' ? '\n' : ' ');
        i++;
      }
      out.push('  ');
      i += 2;
      continue;
    }
    // String literals (single, double, template) — replace with spaces
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      out.push(' ');
      i++;
      while (i < n && code[i] !== quote) {
        if (code[i] === '\\' && i + 1 < n) {
          out.push(' ');
          out.push(code[i + 1] === '\n' ? '\n' : ' ');
          i += 2;
          continue;
        }
        if (quote === '`' && code[i] === '$' && code[i + 1] === '{') {
          // Template literal interpolation — keep contents
          let depth = 1;
          out.push(' ');
          out.push(' ');
          i += 2;
          while (i < n && depth > 0) {
            if (code[i] === '{') depth++;
            else if (code[i] === '}') depth--;
            out.push(depth > 0 ? code[i] : ' ');
            i++;
          }
          continue;
        }
        out.push(code[i] === '\n' ? '\n' : ' ');
        i++;
      }
      out.push(' ');
      i++;
      continue;
    }

    out.push(c);
    i++;
  }
  return out.join('');
}

/**
 * Get a short relative path from $CLAUDE_PROJECT_DIR for display.
 */
function relPath(filePath, projectDir) {
  if (!filePath || !projectDir) return filePath || '';
  try {
    return path.relative(projectDir, filePath);
  } catch {
    return filePath;
  }
}

/**
 * Detect the project's stack from manifest files.
 *
 * Returns one of: 'nextjs-app-router', 'nextjs-pages-router', 'express', 'fastapi',
 * 'django', 'flask', 'laravel', 'rails', 'unknown'.
 */
function detectStack(projectDir) {
  if (!projectDir || !fs.existsSync(projectDir)) return 'unknown';

  // Node-based stacks
  const pkgPath = path.join(projectDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps['next']) {
        if (fs.existsSync(path.join(projectDir, 'app'))) return 'nextjs-app-router';
        if (fs.existsSync(path.join(projectDir, 'pages'))) return 'nextjs-pages-router';
        return 'nextjs-app-router';
      }
      if (deps['express']) return 'express';
      if (deps['@nestjs/core']) return 'nestjs';
      if (deps['hono']) return 'hono';
    } catch {}
  }

  // Python
  for (const reqFile of ['requirements.txt', 'pyproject.toml', 'Pipfile']) {
    const p = path.join(projectDir, reqFile);
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, 'utf8').toLowerCase();
        if (content.includes('fastapi')) return 'fastapi';
        if (content.includes('django')) return 'django';
        if (content.includes('flask')) return 'flask';
      } catch {}
    }
  }

  // PHP / Ruby
  if (fs.existsSync(path.join(projectDir, 'composer.json'))) return 'laravel';
  if (fs.existsSync(path.join(projectDir, 'Gemfile'))) return 'rails';

  return 'unknown';
}

module.exports = {
  loadCurrencies,
  nonStandardExponentCurrencies,
  livePatterns,
  hasPaymentSdkImport,
  catalogVerifierNames,
  catalogVerifierRegex,
  catalogSdkCallRegex,
  catalogCredentials,
  PLUGIN_ROOT,
  loadProviders,
  isWebhookFilePath,
  isAllowlistedTestFile,
  isSourceCodeFile,
  hasIgnoreTag,
  hasSignatureVerifiedTag,
  walkUpForFile,
  stripCommentsAndStrings,
  relPath,
  detectStack,
};
