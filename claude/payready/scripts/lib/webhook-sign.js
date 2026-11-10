// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Deterministic webhook signing and verification, driven entirely by provider data.
 *
 * This is the counterpart to the security validators: instead of asserting that a
 * generated handler is correct, it PROVES it. sign() produces a valid event, verify()
 * accepts it, and flipping one byte makes verify() reject. That round-trip is a test,
 * not a promise — and it is what lets /pagokit:test work for every provider instead of
 * only for the one with a CLI.
 *
 * HMAC vs plain digest is inferred from the template, not from a separate field:
 * if signed_payload_template contains {secret}, the secret is part of the hashed input
 * (a plain digest, e.g. Wompi). If it does not, the secret is the MAC key (an HMAC,
 * e.g. Stripe). The scheme describes itself.
 */
const crypto = require('node:crypto');

class UnsignableError extends Error {
  constructor(family, reason) {
    super(`verification_family "${family}" cannot be signed locally: ${reason}`);
    this.family = family;
    this.unsignable = true;
  }
}

// ------------------------------------------------------------------ helpers
function jsonPointer(obj, pointer) {
  if (!pointer || pointer === '') return obj;
  return pointer.replace(/^\//, '').split('/').reduce((acc, key) => {
    if (acc == null) return undefined;
    return acc[key.replace(/~1/g, '/').replace(/~0/g, '~')];
  }, obj);
}

function headerLookup(headers, name) {
  const want = String(name).toLowerCase();
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() === want) return v;
  }
  return undefined;
}

function decodeSecret(secret, encoding) {
  switch (encoding) {
    case 'base64_decode': return Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
    case 'base64_encode': return Buffer.from(Buffer.from(secret, 'utf8').toString('base64'), 'utf8');
    case 'hex_decode': return Buffer.from(secret, 'hex');
    case 'pem': return secret;
    case 'none':
    case 'raw':
    case undefined:
    default: return Buffer.from(secret, 'utf8');
  }
}

function encodeDigest(buf, encoding) {
  switch (encoding) {
    case 'hex_upper': return buf.toString('hex').toUpperCase();
    case 'base64': return buf.toString('base64');
    case 'base64url': return buf.toString('base64url');
    case 'none': return buf.toString('hex');
    case 'hex':
    default: return buf.toString('hex');
  }
}

const NODE_HASH = {
  sha256: 'sha256', sha512: 'sha512', sha384: 'sha384', sha1: 'sha1', md5: 'md5',
  'rsa-sha1': 'sha1', 'rsa-sha256': 'sha256', rs256: 'sha256', es256: 'sha256', es512: 'sha512',
};

/**
 * Expand signed_payload_template against the concrete request.
 * Placeholders: {raw_body} {timestamp} {secret} {api_key} {header:NAME} {body:/ptr} {body_props}
 */
function resolveTemplate(template, ctx) {
  const { rawBody, timestamp, secret, apiKey, headers, parsedBody, webhook } = ctx;
  return String(template).replace(/\{([^}]+)\}/g, (match, token) => {
    if (token === 'raw_body') return rawBody;
    if (token === 'timestamp') return String(timestamp ?? '');
    if (token === 'secret') return secret;
    if (token === 'api_key') return apiKey ?? '';
    if (token === 'notification_url') return ctx.notificationUrl ?? '';
    if (token.startsWith('header:')) return String(headerLookup(headers, token.slice(7)) ?? '');
    if (token.startsWith('body:')) {
      const v = jsonPointer(parsedBody, token.slice(5));
      return v === undefined || v === null ? '' : String(v);
    }
    if (token === 'body_props') {
      // Wompi-style: the event carries the ordered list of property paths it signed.
      const propsPtr = (webhook && webhook.signed_properties_pointer) || '/signature/properties';
      const props = jsonPointer(parsedBody, propsPtr) || [];
      return props
        .map((p) => {
          const v = p.split('.').reduce((a, k) => (a == null ? undefined : a[k]), parsedBody);
          return v === undefined || v === null ? '' : String(v);
        })
        .join('');
    }
    return match; // leave unknown placeholders visible rather than silently blanking them
  });
}

function computeMac(webhook, signedString, secret) {
  const algo = NODE_HASH[webhook.hash_algo] || 'sha256';
  const templateHasSecret = String(webhook.signed_payload_template || '').includes('{secret}');
  let raw;
  if (templateHasSecret) {
    // The secret is part of the hashed input, so this is a plain digest, not an HMAC.
    raw = crypto.createHash(algo).update(signedString, 'utf8').digest();
  } else {
    raw = crypto.createHmac(algo, decodeSecret(secret, webhook.secret_encoding)).update(signedString, 'utf8').digest();
  }
  return encodeDigest(raw, webhook.digest_encoding);
}

function packHeader(webhook, signature, timestamp) {
  const fmt = webhook.header_format || { kind: 'raw' };
  if (fmt.kind === 'kv') {
    const sep = fmt.separator || ',';
    const eq = fmt.assign || '=';
    const parts = [];
    if (fmt.timestamp_key && timestamp !== undefined) parts.push(`${fmt.timestamp_key}${eq}${timestamp}`);
    parts.push(`${fmt.signature_key || 'v1'}${eq}${signature}`);
    return parts.join(sep);
  }
  if (fmt.kind === 'prefixed') return `${fmt.prefix || ''}${signature}`;
  return signature;
}

function unpackHeader(webhook, headerValue) {
  const fmt = webhook.header_format || { kind: 'raw' };
  if (fmt.kind === 'kv') {
    const sep = fmt.separator || ',';
    const eq = fmt.assign || '=';
    const map = {};
    for (const part of String(headerValue).split(sep)) {
      const i = part.indexOf(eq);
      if (i === -1) continue;
      map[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return { signature: map[fmt.signature_key || 'v1'], timestamp: map[fmt.timestamp_key] };
  }
  if (fmt.kind === 'prefixed') {
    const p = fmt.prefix || '';
    return { signature: String(headerValue).startsWith(p) ? String(headerValue).slice(p.length) : String(headerValue) };
  }
  return { signature: String(headerValue) };
}

const SIGNABLE = new Set([
  'hmac_raw_body', 'hmac_timestamp_body', 'hmac_field_concat', 'hmac_body_transform',
  'body_embedded_sig', 'standard_webhooks', 'shared_secret_header', 'signed_headers',
]);

function assertSignable(webhook) {
  const fam = webhook.verification_family;
  if (SIGNABLE.has(fam)) return;
  if (fam === 'asymmetric_rsa' || fam === 'asymmetric_jws') {
    throw new UnsignableError(fam, 'asymmetric schemes need the provider private key; use a fixture captured from the provider sandbox');
  }
  if (fam === 'sdk_verifier') throw new UnsignableError(fam, "the provider's own SDK owns verification");
  if (fam === 'mtls_or_ip') throw new UnsignableError(fam, 'authenticity comes from transport, not from a payload signature');
  if (fam === 'none_refetch' || fam === 'none') throw new UnsignableError(fam, 'this provider does not sign its callbacks at all');
  throw new UnsignableError(fam, 'unknown verification family');
}

// --------------------------------------------------------------------- sign
/**
 * Produce a signed synthetic event for a provider.
 * @returns {{headers: object, body: string, signature: string, timestamp: number|undefined}}
 */
function signEvent(provider, opts = {}) {
  const webhook = provider.webhook;
  assertSignable(webhook);
  const secret = opts.secret ?? 'whsec_pagokit_test_secret_do_not_use_in_production';
  const payload = opts.payload ?? { id: 'evt_pagokit_test', type: 'test.event' };
  const timestamp = opts.timestamp ?? 1780000000;
  const headers = { 'content-type': 'application/json', ...(opts.extraHeaders || {}) };

  let body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  let parsedBody = typeof payload === 'string' ? JSON.parse(payload) : payload;

  if (webhook.verification_family === 'shared_secret_header') {
    // No MAC at all: the header IS the secret. Modelling it honestly is the point —
    // it tells the generator there is no second line of defence here.
    headers[webhook.signature_header || 'x-callback-token'] = secret;
    return { headers, body, signature: secret, timestamp: undefined };
  }

  const ctx = { rawBody: body, timestamp, secret, apiKey: opts.apiKey, headers, parsedBody, webhook,
    notificationUrl: opts.notificationUrl };
  const template = webhook.signed_payload_template || '{raw_body}';

  if (webhook.signature_location === 'body_field') {
    // The signature lives inside the body, so the body must be built first, then rewritten
    // with the checksum. Wompi is the canonical case.
    const signedString = resolveTemplate(template, ctx);
    const signature = computeMac(webhook, signedString, secret);
    const ptr = (webhook.signature_pointer || '/signature/checksum').replace(/^\//, '').split('/');
    let node = parsedBody;
    for (let i = 0; i < ptr.length - 1; i++) node = node[ptr[i]] ??= {};
    node[ptr[ptr.length - 1]] = signature;
    body = JSON.stringify(parsedBody);
    return { headers, body, signature, timestamp };
  }

  const signedString = resolveTemplate(template, ctx);
  const signature = computeMac(webhook, signedString, secret);
  headers[(webhook.signature_header || 'x-signature').toLowerCase()] = packHeader(webhook, signature, timestamp);
  return { headers, body, signature, timestamp, signedString };
}

// ------------------------------------------------------------------- verify
/**
 * Verify a signed event the same way a generated handler would.
 * @returns {{valid: boolean, reason?: string}}
 */
function verifyEvent(provider, { headers, body, secret, now } = {}) {
  const webhook = provider.webhook;
  try { assertSignable(webhook); } catch (e) { return { valid: false, reason: e.message }; }

  let parsedBody;
  try { parsedBody = JSON.parse(body); } catch { return { valid: false, reason: 'body is not JSON' }; }

  if (webhook.verification_family === 'shared_secret_header') {
    const got = headerLookup(headers, webhook.signature_header || 'x-callback-token');
    if (got === undefined) return { valid: false, reason: 'shared secret header missing' };
    const a = Buffer.from(String(got)), b = Buffer.from(String(secret));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { valid: false, reason: 'shared secret mismatch' };
    return { valid: true };
  }

  let presented, timestamp;
  if (webhook.signature_location === 'body_field') {
    presented = jsonPointer(parsedBody, webhook.signature_pointer || '/signature/checksum');
    timestamp = webhook.timestamp_pointer ? jsonPointer(parsedBody, webhook.timestamp_pointer) : undefined;
  } else {
    const hv = headerLookup(headers, webhook.signature_header);
    if (hv === undefined) return { valid: false, reason: `signature header "${webhook.signature_header}" missing` };
    const un = unpackHeader(webhook, hv);
    presented = un.signature;
    timestamp = un.timestamp;
    if (webhook.timestamp_source === 'header' && webhook.timestamp_pointer) {
      timestamp = headerLookup(headers, webhook.timestamp_pointer);
    }
  }
  if (!presented) return { valid: false, reason: 'no signature present' };

  // Replay window. Checked BEFORE the MAC so a stale-but-valid event is still rejected.
  const tol = webhook.recommended_tolerance_seconds;
  if (tol && timestamp !== undefined && timestamp !== null && webhook.timestamp_source !== 'none') {
    const nowSec = now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - Number(timestamp)) > tol) {
      return { valid: false, reason: `timestamp outside the ${tol}s tolerance window (replay)` };
    }
  }

  // Rebuild the signed string. For a body-embedded signature the checksum field must be
  // excluded, which it naturally is: the template names the signed properties explicitly.
  const ctx = { rawBody: body, timestamp, secret, headers, parsedBody, webhook };
  const expected = computeMac(webhook, resolveTemplate(webhook.signed_payload_template || '{raw_body}', ctx), secret);

  const a = Buffer.from(String(expected)), b = Buffer.from(String(presented));
  if (a.length !== b.length) return { valid: false, reason: 'signature length mismatch' };
  if (!crypto.timingSafeEqual(a, b)) return { valid: false, reason: 'signature mismatch' };
  return { valid: true };
}

module.exports = { signEvent, verifyEvent, resolveTemplate, jsonPointer, UnsignableError, SIGNABLE };
