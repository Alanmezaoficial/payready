#!/usr/bin/env node
// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Runs every validator against every fenced code sample PagoKit ships.
 *
 * The templates and fragments are what the model copies. A defect there becomes a defect in
 * every generated integration — so the plugin has to pass its own checks. This already found
 * a template that documented "do not trust the client amount" in its anti-patterns and then
 * did exactly that four lines up.
 *
 * Run: npm run self:audit
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHECKS_DIR = path.join(ROOT, 'hooks/checks');
const SCAN = ['skills/integration-builder/templates', 'skills/integration-builder/fragments', 'skills/webhook-verifier'];

const LANG_EXT = { ts: 'ts', typescript: 'ts', tsx: 'tsx', js: 'js', javascript: 'js', jsx: 'jsx', python: 'py', py: 'py', php: 'php', ruby: 'rb', rb: 'rb', go: 'go' };

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}

/** Guess the path a snippet would land at, so path-sensitive checks behave realistically. */
function inferPath(mdPath, code, ext) {
  const first = (code.split('\n').find((l) => /^\s*(\/\/|#)\s*\S+\.\w+/.test(l)) || '').trim();
  const named = first.replace(/^\s*(\/\/|#)\s*/, '').split(/\s+/)[0];
  if (named && /\.\w+$/.test(named) && !named.startsWith('http')) return named;
  const base = path.basename(mdPath, '.md');
  if (/webhook|signature|_preamble|hmac|asymmetric|shared_secret|body_embedded|standard_webhooks|signed_headers|mtls|refetch|sdk_verifier/.test(base)) {
    return `app/api/webhook/provider/route.${ext}`;
  }
  if (/checkout|one-time|one_time|hosted|intent|widget|direct_charge/.test(base)) return `app/api/checkout/route.${ext}`;
  if (/refund/.test(base)) return `app/api/refund/route.${ext}`;
  if (/subscription|billing|portal/.test(base)) return `app/api/billing/route.${ext}`;
  return `lib/payments/${base}.${ext}`;
}

// These reason about a whole file. A fragment that shows only the raw-body capture is not
// an unsigned webhook handler, it is four lines of an example — so applying them to every
// fenced block produces noise, not findings.
const WHOLE_FILE_ONLY = new Set(['webhook-has-signature', 'network-txn-id-persistence', 'raw-body']);

// These judge the surrounding PROJECT, not the snippet: whether a script inventory exists,
// whether .gitignore covers .env, whether another webhook route is already registered. The
// plugin repo is not a merchant project, so their verdict here is meaningless either way.
const PROJECT_LEVEL = new Set(['pci-script-integrity', 'gitignore-check', 'existing-webhook-check', 'einvoice-obligation']);

/** Does this snippet define a complete request handler, or is it an excerpt? */
function isCompleteHandler(code) {
  // An explicit continuation marker means the author is showing one stage on purpose:
  //   // ... provider-specific verification (see templates/<provider>/webhook.md)
  if (/(?:\/\/|#)\s*\.\.\.[^\n]*\b(see|from|per|in)\b/i.test(code)) return false;
  const declaresHandler = /export\s+(?:async\s+)?function\s+(POST|GET)|async\s+def\s+\w+\s*\(\s*request|@router\.(post|get)|@app\.(post|route)|router\.post\s*\(|app\.post\s*\(/.test(code);
  const returnsResponse = /return\s+(?:new\s+)?(?:NextResponse|Response|res\.|jsonify|HTTPException|\{|PlainTextResponse)/.test(code)
    || /res\.(?:status|send|json)\s*\(/.test(code);
  return declaresHandler && returnsResponse && code.split('\n').length >= 12;
}

const checks = fs.readdirSync(CHECKS_DIR).filter((f) => f.endsWith('.js'))
  .map((f) => ({ id: f.replace(/\.js$/, ''), mod: require(path.join(CHECKS_DIR, f)) }))
  .filter((c) => typeof c.mod.run === 'function' && c.id !== 'prompt-preflight');

const files = SCAN.flatMap((d) => walk(path.join(ROOT, d)));
let samples = 0;
const findings = [];

for (const file of files) {
  const md = fs.readFileSync(file, 'utf8');
  for (const m of md.matchAll(/```(\w+)\n([\s\S]*?)```/g)) {
    const ext = LANG_EXT[m[1].toLowerCase()];
    if (!ext) continue;
    const code = m[2];
    if (code.split('\n').length < 4) continue;
    samples++;
    const line = md.slice(0, m.index).split('\n').length;
    const filePath = inferPath(file, code, ext);
    const complete = isCompleteHandler(code);
    for (const { id, mod } of checks) {
      if (PROJECT_LEVEL.has(id)) continue;
      if (WHOLE_FILE_ONLY.has(id) && !complete) continue;
      let r;
      try { r = mod.run({ filePath, content: code, toolName: 'Write', projectDir: ROOT, phase: 'post' }); }
      catch (e) { findings.push({ file, line, id, level: 'error', msg: e.message }); continue; }
      if (r) findings.push({ file: path.relative(ROOT, file), line, id, level: r.level, code: r.code, msg: r.message_en });
    }
  }
}

const denies = findings.filter((f) => f.level === 'deny');
const warns = findings.filter((f) => f.level === 'warn');
const errors = findings.filter((f) => f.level === 'error');

console.log(`Self-audit: ${samples} code samples across ${files.length} documents, ${checks.length} validators\n`);
for (const f of [...errors, ...denies, ...warns]) {
  console.log(`  [${f.level.toUpperCase()}] ${f.file}:${f.line} · ${f.id}${f.code ? ` (${f.code})` : ''}`);
  console.log(`          ${String(f.msg).split('\n')[0].slice(0, 160)}`);
}
console.log(`\n  ${denies.length} deny · ${warns.length} warn · ${errors.length} crash`);

// Warnings are advisory by design and several fire legitimately on reference snippets that
// deliberately show a partial handler. Only a hard deny or a crashing check fails the build.
process.exit(denies.length || errors.length ? 1 : 0);
