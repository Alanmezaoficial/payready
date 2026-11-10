// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Deterministic provider recommendation.
 *
 * The advisor used to be prose: "base = 5, add the modifiers, rank". An LLM doing that
 * arithmetic over 40 providers is a lottery, and the answer could not be tested or
 * audited. This makes it a pure function: same profile in, same ranking out, with every
 * filter and every modifier recorded so "why not X?" has an exact answer.
 *
 * The model's job becomes explaining the result, not computing it.
 */
const { loadAll, covers } = require('./catalog');

const BASE_SCORE = 5;

// Roles that cannot acquire. The research put it plainly: an orchestrator is never a
// substitute for a provider, it is a layer. Same for metered-billing and entitlement layers.
const LAYER_ROLES = new Set(['orchestrator', 'billing_layer', 'entitlement_layer', 'tax_engine', 'qualification_layer']);

const LATAM = ['AR','BO','BR','CL','CO','CR','DO','EC','GT','HN','MX','NI','PA','PE','PR','PY','SV','UY','VE'];
const EU_ISH = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE','UK','EU'];

/** Which score_modifier keys this profile activates. Pure, and enumerable for tests. */
function activeModifiers(profile, catalog) {
  const on = [];
  const buyers = profile.buyer_regions || [];
  const seller = profile.seller_country;
  const crossBorder = buyers.some((b) => b !== seller);
  const cashCategories = new Set(['cash_voucher']);
  const methodById = Object.fromEntries(catalog.methods.methods.map((m) => [m.id, m]));
  const required = profile.required_methods || [];

  if (seller === 'US' && profile.product_type === 'saas') on.push('us_saas');
  if (profile.billing_mode === 'subscription' && buyers.some((b) => EU_ISH.includes(b))) on.push('eu_subscription');
  if (profile.product_type === 'digital_goods' && crossBorder) on.push('digital_goods_cross_border');
  if (profile.needs_tax_automation) on.push('wants_no_fiscal_overhead');
  if ((profile.use_cases || []).includes('marketplace') || profile.product_type === 'marketplace') on.push('marketplace_multi_seller');
  if (profile.platform === 'ios' && profile.product_type === 'digital_goods') on.push('ios_digital_goods');
  if (LATAM.includes(seller) && profile.entity_type === 'individual') on.push('latam_individual_seller');
  if (required.length && required.every((m) => methodById[m] && cashCategories.has(methodById[m].category))) on.push('needs_cash_payment_only');
  return on;
}

/**
 * Aggregator vs N-locals, as an encoded rule rather than a vibe.
 * Returns a score delta plus the reasoning, so the advisor can explain the trade-off.
 */
function aggregatorAdjustment(provider, profile, catalog) {
  if (provider.role !== 'aggregator') return { delta: 0, notes: [] };
  const targets = new Set([profile.seller_country, ...(profile.buyer_regions || [])].filter(Boolean));
  const n = targets.size;
  const notes = [];
  let delta = 0;

  if (n === 1 && targets.has(profile.seller_country)
      && covers(provider.merchant_domicile_regions, profile.seller_country)) {
    return { delta: -99, veto: true,
      notes: ['Single domestic market: a local acquirer gets domestic interchange, an aggregator charges cross-border.'] };
  }
  if (n > 1) { delta += 3 * (n - 1); notes.push(`Covers ${n} target markets through one integration.`); }
  if (!targets.has(profile.seller_country) || !covers(provider.merchant_domicile_regions, profile.seller_country)) {
    delta += 4; notes.push('No local legal entity needed in the target market.');
  }
  if (profile.needs_payouts || profile.needs_fx_consolidation) { delta += 3; notes.push('Handles payouts and FX consolidation.'); }
  const regions = catalog.regions.regions;
  for (const t of targets) {
    const r = regions[t];
    if (r && (!r.primary_providers || !r.primary_providers.length)) { delta += 3; notes.push(`${t} has no self-serve local provider.`); }
    if (r && r.requires_local_acquirer) { delta -= 3; notes.push(`${t} requires a locally licensed acquirer.`); }
    if (r && r.instant_rail && !provider.methods.includes(r.instant_rail)) {
      delta -= 4; notes.push(`Does not reach ${t}'s dominant rail (${r.instant_rail}).`);
    }
  }
  if (provider.onboarding && provider.onboarding.model !== 'self_serve') {
    delta -= 5; notes.push('Onboarding is not self-serve.');
  }
  return { delta, notes };
}

/** Fee on a concrete transaction, in real money, with the arithmetic shown. */
function computeFee(provider, amount, currency, catalog) {
  const f = provider.fees || {};
  const pct = f.card_domestic_pct;
  if (pct === undefined || amount === undefined) return null;
  const fixedKey = Object.keys(f).find((k) => k.startsWith('card_domestic_fixed_'));
  const fixedCurrency = fixedKey ? fixedKey.replace('card_domestic_fixed_', '').toUpperCase() : null;
  const fixed = fixedKey ? f[fixedKey] : 0;
  const sameCurrency = !fixedCurrency || fixedCurrency === currency;
  const cur = catalog.currencies.currencies.find((c) => c.code === currency);
  const dp = cur ? Math.min(cur.exponent, 2) : 2;

  const variable = (amount * pct) / 100;
  const total = variable + (sameCurrency ? fixed : 0);
  const round = (n) => Number(n.toFixed(dp));
  return {
    currency,
    percent: pct,
    fixed: sameCurrency ? fixed : null,
    fixed_currency: fixedCurrency,
    fixed_not_applied_reason: sameCurrency ? null : `fixed fee is quoted in ${fixedCurrency}, not ${currency}`,
    variable: round(variable),
    total: round(total),
    net: round(amount - total),
    explanation: `${pct}% of ${amount} ${currency}${sameCurrency && fixed ? ` + ${fixed} ${currency}` : ''} = ${round(total)} ${currency}`,
  };
}

/** The main entry point. Pure: no I/O beyond the catalog it is handed. */
function advise(profileInput, catalog = loadAll()) {
  const profile = {
    seller_country: null, buyer_regions: [], billing_mode: 'one_time', required_methods: [],
    entity_type: 'company', product_type: 'unknown', use_cases: [], needs_tax_automation: false,
    platform: 'web', example_amount: undefined, example_currency: undefined,
    needs_keys_within_days: null, ...profileInput,
  };
  if (!profile.buyer_regions.length && profile.seller_country) profile.buyer_regions = [profile.seller_country];

  const providers = catalog.providers.providers;
  const regions = catalog.regions.regions;
  const methodById = Object.fromEntries(catalog.methods.methods.map((m) => [m.id, m]));
  const region = regions[profile.seller_country] || null;
  const rejected = [];
  const disclosures = [];

  // A sanctioned market is a refusal, not a ranking problem.
  if (region && region.unsupported) {
    return {
      profile, region_code: profile.seller_country, region,
      candidates: [], rejected: [], recommendation: null, fallback_used: false, refused: true,
      refusal_reason: `${profile.seller_country} is marked unsupported (${region.reason}). PagoKit will not recommend a provider here.`,
      disclosures: [],
    };
  }

  if (profile.example_currency && !catalog.currencies.currencies.some((c) => c.code === profile.example_currency)) {
    disclosures.push(`Currency ${profile.example_currency} is not in the catalog; fee figures are omitted.`);
  }
  const cur = catalog.currencies.currencies.find((c) => c.code === profile.example_currency);
  if (cur && cur.exponent !== 2) {
    disclosures.push(`${cur.code} has ${cur.exponent} decimal places, not 2. Amounts must be sent at exponent ${cur.exponent} — a reflexive x100 would be wrong.`);
  }

  // Use-case hard blocks come before scoring: a blocked provider is not a low-ranked
  // provider, it is a wrong answer.
  const blocked = new Map();
  for (const name of profile.use_cases || []) {
    const uc = catalog.use_cases.use_cases[name];
    for (const id of (uc && uc.blocked_providers) || []) {
      blocked.set(id, (uc.blocked_reason) || `blocked by use case "${name}"`);
    }
  }

  // Two different things a use case can say about roles, and conflating them gives the wrong
  // answer in opposite directions:
  //
  //   required_layer  — ADDITIVE. The layer is needed IN ADDITION to a provider. Metered AI
  //                     billing needs a metering layer AND something that can acquire, so
  //                     restricting to the layer would hide the payment provider.
  //   required_role   — EXCLUSIVE. Only that role is a valid answer. For iOS digital goods,
  //                     Apple rejects the build for any external card payment — including one
  //                     taken by a merchant of record — so a card PSP is not merely worse,
  //                     it is not an answer at all.
  const wantedRoles = new Set();   // additive: allowed through alongside providers
  const exclusiveRoles = new Set(); // exclusive: nothing else qualifies
  for (const name of profile.use_cases || []) {
    const uc = catalog.use_cases.use_cases[name];
    if (!uc) continue;
    if (uc.required_layer) wantedRoles.add(uc.required_layer);
    if (uc.required_role) { wantedRoles.add(uc.required_role); exclusiveRoles.add(uc.required_role); }
  }
  if (profile.required_role) wantedRoles.add(profile.required_role);
  if (profile.required_layer) wantedRoles.add(profile.required_layer);

  const scored = [];
  for (const p of providers) {
    const reject = (filter, reason) => { rejected.push({ id: p.id, name: p.name, filter, reason }); return true; };

    if (p.status !== 'active' && p.status !== 'preview') { reject('status', `status is "${p.status}"`); continue; }
    if (blocked.has(p.id)) { reject('use_case_block', blocked.get(p.id)); continue; }

    // A layer is not a provider. An orchestrator routes to acquirers without acquiring; a
    // billing or entitlement layer sits on top of one. Offering any of them as the answer to
    // "how do I take a payment" sends the user to something that cannot take the payment.
    // They surface only when the use case explicitly asks for that role.
    if (exclusiveRoles.size && !exclusiveRoles.has(p.role)) {
      reject('required_role', `this situation needs a ${[...exclusiveRoles].join(' or ').replace(/_/g, ' ')}; ${p.name} is a ${p.role.replace(/_/g, ' ')} and cannot satisfy it.`);
      continue;
    }
    if (LAYER_ROLES.has(p.role) && !wantedRoles.has(p.role)) {
      const roleWords = p.role.replace(/_/g, ' ');
      const article = /^[aeiou]/i.test(roleWords) ? 'an' : 'a';
      reject('role', `${p.name} is ${article} ${roleWords}, and cannot accept a payment on its own${(p.layers_over || []).length ? ` — it sits on top of ${p.layers_over.join(', ')}` : '. It needs an acquirer underneath it'}.`);
      continue;
    }

    const buyersCovered = profile.buyer_regions.filter((b) => covers(p.method_coverage_regions, b));
    if (!buyersCovered.length) { reject('region', `does not accept payments from ${profile.buyer_regions.join(', ')}`); continue; }

    if (profile.seller_country && !covers(p.merchant_domicile_regions, profile.seller_country)) {
      reject('merchant_domicile', `a merchant in ${profile.seller_country} cannot open an account (coverage is for buyers, not sellers)`); continue;
    }

    if (profile.billing_mode === 'subscription' && !p.supports.subscriptions) { reject('billing_mode', 'no native subscription support'); continue; }
    if (profile.billing_mode === 'one_time' && !p.supports.one_time) { reject('billing_mode', 'no one-time payment support'); continue; }

    const missing = (profile.required_methods || []).filter((m) => !p.methods.includes(m));
    if (missing.length) { reject('methods', `does not support ${missing.map((m) => (methodById[m] ? methodById[m].label : m)).join(', ')}`); continue; }

    const denied = (profile.required_methods || []).filter((m) => methodById[m] && methodById[m].deny_list);
    if (denied.length) { reject('methods', `${denied.join(', ')} is a retired rail`); continue; }

    if (profile.entity_type === 'individual' && p.kyc && p.kyc.individual_allowed === false) {
      reject('kyc', 'does not onboard individuals'); continue;
    }
    if (profile.entity_type === 'individual' && p.kyc && p.kyc.individual_constraints && !profile.meets_individual_constraints) {
      disclosures.push(`${p.name}: individuals must meet ${JSON.stringify(p.kyc.individual_constraints)}.`);
    }

    // Onboarding gate. A generated integration a developer cannot get credentials for is
    // worth less than no recommendation, because it burns their week.
    const ob = p.onboarding || {};
    const smallSeller = ['individual', 'solo', 'smb'].includes(profile.entity_type);
    if (smallSeller && (ob.model === 'sales_gated' || ob.model === 'partner_certification')) {
      // Not a timing question. There is a sales process, and it does not run for one person.
      reject('onboarding', `onboarding is "${ob.model}" — there is a sales process, and it is not open to an individual or small seller. A recommendation you cannot get credentials for costs more than no recommendation.`);
      continue;
    }
    if (ob.model === 'application_review' && smallSeller && profile.needs_keys_within_days) {
      const days = parseInt(String(ob.time_to_keys_days || '').split('-').pop(), 10);
      if (days && days > profile.needs_keys_within_days) {
        reject('onboarding', `onboarding is under review and takes ~${ob.time_to_keys_days} days, longer than the ${profile.needs_keys_within_days} you have`); continue;
      }
    }

    const mods = activeModifiers(profile, catalog);
    const applied = mods
      .filter((k) => p.score_modifiers && p.score_modifiers[k] !== undefined)
      .map((k) => ({ key: k, delta: p.score_modifiers[k] }));
    const agg = aggregatorAdjustment(p, profile, catalog);
    if (agg.veto) { reject('aggregator_rule', agg.notes[0]); continue; }

    let score = BASE_SCORE + applied.reduce((s, m) => s + m.delta, 0) + agg.delta;

    // A provider PagoKit can actually build for is worth more than one it can only
    // describe — but only as a tiebreaker, never enough to beat a better regional fit.
    if (p.integration_level === 'build') score += 0.5;
    else if (p.integration_level === 'generic') score += 0.25;

    // regions.json ranks primary_providers deliberately: that ordering encodes local
    // knowledge (who is the default in this market) that no generic modifier captures.
    // Weighted small enough to break ties without ever outvoting a real modifier.
    const rank = region ? (region.primary_providers || []).indexOf(p.id) : -1;
    if (rank === 0) score += 0.75;
    else if (rank === 1) score += 0.4;
    else if (rank > 1) score += 0.2;

    const caveats = [];
    if (p.integration_level === 'advise') {
      caveats.push('PagoKit will NOT write this integration for you. You get the recommendation, the fee maths and a checklist; the code is yours to write from the provider docs.');
    } else if (p.integration_level === 'generic') {
      caveats.push('PagoKit generates a working scaffold from this provider\'s verification family rather than hand-written templates. Review it against the provider docs before going live.');
    }
    if (p.notification_model === 'return_url_commit') {
      caveats.push('This provider does not send webhooks. It requires a commit call on return — an uncommitted transaction auto-reverses.');
    }
    if (p.notification_model === 'ping_then_poll' || p.webhook.payload_authoritative === false) {
      caveats.push('The callback payload is not authoritative: the handler must re-fetch the transaction before acting on it.');
    }
    if (p.mor && p.mor.is_mor) {
      caveats.push(`Merchant of record: ${p.name} sells to your customer and pays you. It handles ${(p.mor.handles || []).join(', ')} — and disables ${(p.mor.disables_capabilities || []).join(', ') || 'nothing'}.`);
    }
    if (ob.model && ob.model !== 'self_serve') caveats.push(`Onboarding is ${ob.model} (~${ob.time_to_keys_days || 'unknown'} days to keys).`);
    for (const ap of (p.anti_patterns || []).slice(0, 2)) caveats.push(ap);

    const why = [];
    why.push(`Accepts payments from ${buyersCovered.join(', ')}.`);
    if (profile.required_methods.length) why.push(`Supports ${profile.required_methods.map((m) => (methodById[m] ? methodById[m].label : m)).join(', ')}.`);
    if (profile.billing_mode === 'subscription') why.push('Native subscription billing.');
    if (p.mor && p.mor.is_mor && profile.needs_tax_automation) why.push('Handles tax collection and remittance as merchant of record.');

    scored.push({
      id: p.id, name: p.name, integration_level: p.integration_level, role: p.role,
      wave: p.wave, status: p.status, notification_model: p.notification_model,
      verification_family: p.webhook.verification_family,
      webhook_confidence: p.webhook.evidence && p.webhook.evidence.confidence,
      score: Number(score.toFixed(2)), base: BASE_SCORE, modifiers: applied,
      local_rank: rank >= 0 ? rank : null,
      aggregator_adjustment: agg.delta ? { delta: agg.delta, notes: agg.notes } : null,
      fee: computeFee(p, profile.example_amount, profile.example_currency, catalog),
      onboarding: ob, why, caveats,
      last_verified_at: p.last_verified_at, docs_url: p.docs_url,
    });
  }

  scored.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  let fallback_used = false;
  let candidates = scored;
  if (!candidates.length && region) {
    fallback_used = true;
    const fb = (region.fallback_cross_border_mor || [])
      .map((id) => providers.find((p) => p.id === id)).filter(Boolean);
    candidates = fb.map((p) => ({
      id: p.id, name: p.name, integration_level: p.integration_level, role: p.role,
      score: BASE_SCORE, base: BASE_SCORE, modifiers: [], aggregator_adjustment: null,
      fee: computeFee(p, profile.example_amount, profile.example_currency, catalog),
      onboarding: p.onboarding || {},
      why: [`No provider matched your filters in ${profile.seller_country}. ${p.name} is the cross-border merchant-of-record fallback.`],
      caveats: ['Cross-border MoR fallback: higher fees than a local provider, and limited checkout branding.'],
      last_verified_at: p.last_verified_at, docs_url: p.docs_url,
    }));
  }

  if (region) {
    if (region.requires_local_acquirer) {
      disclosures.push(`${profile.seller_country}: ${region.local_acquirer_reason || 'domestic acceptance requires a locally licensed acquirer.'}`);
    }
    if (region.instant_rail) disclosures.push(`${profile.seller_country}'s dominant instant rail is \`${region.instant_rail}\`. Outside card-mature markets, pick the rail before the provider.`);
    if (region.tax && region.tax.einvoice && region.tax.einvoice.mandate) {
      disclosures.push(`${profile.seller_country} mandates ${region.tax.einvoice.mandate.toUpperCase()} e-invoicing. "The payment worked" is not "you can invoice it" — issuing the fiscal document is a separate legal obligation unless a merchant of record does it for you.`);
    }
    if (region.installments_expected) disclosures.push(`Buyers in ${profile.seller_country} expect installments. A checkout without them converts worse.`);
  }

  return {
    profile, region_code: profile.seller_country, region,
    active_modifiers: activeModifiers(profile, catalog),
    candidates, rejected, fallback_used, refused: false,
    recommendation: candidates[0] || null,
    disclosures,
  };
}

module.exports = { advise, activeModifiers, computeFee, aggregatorAdjustment, BASE_SCORE };
