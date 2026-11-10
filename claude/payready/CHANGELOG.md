# Changelog

All notable changes to PagoKit are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-08-31

### Added

- **The family-keyed fragment library** — 33 fragments: 14 webhook verification families,
  3 notification models, 5 checkout patterns, 4 billing modes, 4 money concerns, 3 compliance
  artifacts. This is what makes the catalog scale: a fragment is written once per capability
  family rather than once per provider, so adding provider 43 costs a data entry and a small
  override instead of two dozen documents.
- **`npm run check:fragments`** — every provider a fragment NAMES is verified against the
  catalog. An audit of the first draft found six invented family members; this makes that
  class of error a build failure rather than something a reader has to catch.

### Fixed

Found by an adversarial pass that executed every fenced code block against the reference
signer rather than reading it:

- **The base webhook fragment acknowledged without verifying.** Its Express example elided
  verification behind a comment and returned 200, so a model copying it would emit a handler
  that acknowledges every forged event. It also called an undefined function after the
  transaction committed and before the response — producing precisely the failure its own
  opening paragraph warns about: a 500, a provider retry, the retry hitting the dedup row and
  getting its 200, and the event silently lost.
- **A misattributed signature scheme.** One fragment taught that a provider signs a
  re-serialised body when its catalog entry says it signs the untouched bytes with a
  unix-seconds id — which also means a tolerance window is available, so the fragment was
  discarding that provider's only replay defence beyond deduplication.
- **A re-fetch that always 404s** — it used the notification's own id where the endpoint takes
  the payment id, and the re-fetch is the entire security argument of that family.
- **Two 500s where the answer was 400.** Decoding a non-UTF-8 body raises inside the verifier,
  and an unhandled exception there becomes a traceback plus a provider retry instead of a
  silent rejection. Anyone can post those bytes.
- **Six invented family members**, and one real provider filed under the wrong family — its
  classic webhooks carry no signature at all.

## [0.2.1] — 2026-08-31

### Added

- **`npm run self:audit`** — every validator run against every fenced code sample PagoKit
  ships. The templates are what the model copies, so a defect there becomes a defect in every
  generated integration. It found three on its first run, all fixed below. Now part of CI.
- **Seven new use cases** (11 total): metered AI usage, high-risk verticals, card present,
  agentic seller, B2B net terms, cross-border payouts, nonprofit donations — with the
  `blocked_providers` and role fields the v0.2.0 schema added but nothing used yet.

### Fixed

- **A checkout route was denied for not verifying a webhook signature.** The content heuristic
  treated "imports a payment SDK + exports a POST handler" as a webhook, which describes every
  checkout, refund and portal endpoint ever written. Found only by running the hooks end to
  end against a real project layout — every unit fixture had used a webhook-shaped path. This
  is the false-positive class that gets a tool uninstalled, because the developer is right and
  there is no way to satisfy the check.
- **`verifySignature(` was not recognised as verification.** The pattern required an uppercase
  letter immediately after "verify", so it matched `verifyMpSignature` but not the single most
  likely name a generated verifier has. Same bug in the Checksum and Webhook variants.
- **svix-based verification was not recognised** — the standard_webhooks fragment recommends
  it, and the validator would have blocked exactly that. Asymmetric verification and the
  Python and PHP constant-time comparisons were missing too.
- **A shipped template contradicted its own anti-patterns section.**
  `templates/mercadopago/subscription.md` set `transaction_amount` from the client-supplied
  value four lines above an entry telling the reader not to.
- **iOS digital goods recommended a merchant of record** after blocking the card processors.
  From the store's point of view that is the same external card payment and gets the build
  rejected identically. It now routes to the entitlement layer, and `required_role` is
  exclusive while `required_layer` is additive — conflating them failed in opposite directions.
- **A sales-gated provider was offered to an individual seller.** Bolivia was answering Adyen.
  It is not a timing question: there is a sales process and it does not run for one person.
- **An orchestrator was recommended as if it could take a payment.** A layer is not a provider.
- `verifierPatterns()` recursed infinitely when the catalog yielded no verifier names — a hung
  hook is worse than a failing one.

## [0.2.0] — 2026-08-31 · Foundation

A rebuild of the parts that would not survive the roadmap. v0.1.0 worked at four providers and
was built on assumptions that break around the tenth — so this release fixes the architecture
before adding anything to the catalog.

### Added

**A second and third deterministic engine.** v0.1.0 shipped one (the hook validators) and did
the other two jobs in prose.

- `scripts/advise.js` — provider recommendation as a pure function. The ranking used to be
  "base 5, add the modifiers, sort", written in a SKILL.md for a model to execute. It is now
  reproducible, testable, and records every filter that rejected a provider and every modifier
  that fired, so "why not X?" has an exact answer.
- `scripts/sign-event.js` — generates a validly signed synthetic event for any provider, from
  the same catalog data the verifier is generated from. `/pagokit:test` previously only worked
  for the one provider with a CLI.

**Schema v2**, because roughly 60% of the providers on the roadmap were not expressible:

- `webhook.verification_family` (14 values) replaces free-text `algorithm`, plus
  `signed_payload_template`, `hash_algo`, `secret_encoding`, `digest_encoding`,
  `signature_location` and `header_format`. Defaulting to SHA-256 and hex is wrong for roughly
  one provider in four.
- `notification_model` — not every provider sends webhooks. A `return_url_commit` provider
  auto-reverses an uncommitted transaction, which is a money-loss bug rather than a gap.
- `payload_authoritative` and `signature_covers_body` force a re-fetch where a "verified"
  payload is still forgeable.
- `credentials[]` replaces the single key pattern; some providers need four.
- `onboarding.model`, so the advisor stops recommending providers a solo developer cannot get
  keys for.
- `merchant_domicile_regions` vs `method_coverage_regions` — where you can open an account is
  not where buyers can pay.
- `integration_level` (build / generic / advise) — the honesty contract for a wide catalog.
- `evidence` on every webhook and checkout claim.
- `role`, `layers_over`, `mor`, `settlement`, `pci`, `recurring`, `agentic`, `iap`, `metered`.

**`currencies.json`** — 106 currencies with their ISO 4217 exponent. A reflexive `× 100`
overcharges 100× in JPY, KRW and CLP, and 10× in KWD, BHD and OMR — where it also breaks
providers that hash the amount at its ISO exponent, sending the developer to debug the
signature instead of the exponent.

**101 payment methods**, up from 27: LATAM, European, Asian, African and MENA instant rails,
mobile money, mobile IAP, card-present and benefits rails. `reversibility` replaces the
`irreversible` boolean, because "refund the charge" does not exist on A2A rails and the
generated refund path was fiction there. Retired rails (giropay, Sofort) are present with
`deny_list` so the generator refuses to emit them.

**A fragment library keyed by capability family** — 14 webhook families, 5 checkout patterns,
3 notification models, 4 billing modes, 4 money concerns, 3 compliance artifacts. Providers
differ in a small number of ways and those ways repeat, so a fragment is written once per
family rather than once per provider.

**New validators**, covering failures that are silent: wrong currency exponent, unbounded
webhook event dispatch, PCI DSS 4.0.1 script integrity, agentic payment token scope, refunds
on irreversible rails, slow webhook acknowledgement, non-constant-time secret comparison,
merchant-of-record capability conflicts, missing network transaction id for recurring charges,
e-invoicing obligations, secret encoding mismatches, card data in transit, client-trusted
amounts, secrets reachable from the client bundle, and verification with the API key instead of
the webhook secret.

**Two new hooks.** `SessionStart` re-injects the security rules after compaction drops them.
`UserPromptSubmit` blocks a live credential pasted into a prompt — the most common real-world
leak in agent workflows — and flags requests to disable a security control, pointing at the
documented escape hatch that logs the decision.

**Five new commands:** `/pagokit:compare`, `/pagokit:coverage`, `/pagokit:add`,
`/pagokit:migrate`, `/pagokit:harden`.

**Three new skills:** `tax-advisor` (the merchant-of-record trade-off, and the e-invoicing
obligation that must be collected at checkout or it cannot be satisfied at all),
`subscription-lifecycle` (everything after `subscription.create`, where production subscriptions
actually break), `payment-migrator`.

**`ABOUT.md`**, and `userConfig` in the manifest with a `strictMode` that promotes advisory
validators to blocking.

### Changed

- **The catalog is now sharded.** `providers/<id>.json` is the source of truth;
  `providers.json` and a slim `providers.index.json` are generated. The advisor loaded the
  entire catalog on every run, which at 40 providers would have cost roughly 50k tokens per
  conversation.
- **`templates/compiled/` is gone.** Those eight files became `fixtures/`, a CI regression
  baseline. Pre-compilation bought speed that was never real and regression safety that is —
  so the safety is kept and the 960-file trajectory is not.
- **Provider names removed from 20+ places of prose** across the skills, the subagent and the
  commands. `signatures.md`, the doctor's per-provider checks and both READMEs' tables are now
  generated from the catalog, with drift checks in CI.
- **`/pagokit:test` is universal** rather than Stripe-only, and refuses to "test" a provider
  whose notification model is not a webhook, because that proves nothing.
- **README rewritten.** The old pitch was "you lose days choosing between 30 gateways". The
  real problem is that the integration written afterwards is wrong in ways that do not throw.
- **Assets cut from 43MB to 2MB** (resampled and palette-quantised, visually unchanged), plus
  two theme-aware SVG diagrams.
- CI now gates on data integrity, four test suites, five drift checks and a hook smoke test.

### Fixed

- **India listed Stripe as its primary provider.** Stripe India has been invite-only since May
  2024 and is oriented to international acceptance, not domestic INR collection — the
  highest-frequency wrong answer PagoKit could give. India now reports no primary provider and
  says why.
- **Wompi's payload was treated as authoritative.** Its checksum covers only the properties
  listed in `signature.properties`, so every other field is attacker-controllable. Now marked
  non-authoritative with a mandatory re-fetch. The new integrity checks surfaced this.
- **Four validators hardcoded the four shipped providers'** SDK names, verifier functions and
  live-key prefixes. Any provider added afterwards would have passed every security check
  *without being checked* — a silent failure in exactly the part that is the product. They now
  read from the catalog.
- **The doctor hardcoded env var names** for four providers in prose, so it silently audited
  nothing for any other.
- **`validate-data.js` missed** duplicate ids, unknown region and currency references, reverse
  coverage lies, and treated undeclared methods as a warning — a green CI run over a broken
  catalog.
- **`docs/COVERAGE.md` stamped today's date**, so every regeneration dirtied the file and drift
  could not be checked. It now stamps the data's verification date.
- **The README and the advisor skill listed different Phase 2 provider sets.** The plugin
  contradicted itself; the roadmap is now stated once.
- Puerto Rico claimed Stripe as a primary provider while Stripe's coverage never listed PR.

### Enforced by CI

- `verified_by: "llm-generated"` can never carry `confidence: "high"`.
- `integration_level` of `build` or `generic` requires a high-confidence webhook scheme —
  otherwise the generator emits re-fetch and a TODO instead of a verifier. A verifier built on
  a guessed scheme looks correct and accepts forged events.

## [0.1.0] — 2026-05-21 · Phase 1

Initial public release: 4 providers (Stripe, Mercado Pago, Wompi, Lemon Squeezy), 2 stack
adapters, 3 ORM adapters, 2 deploy targets, 47 templates, 7 deterministic validators with 42
unit tests, 3 slash commands, 5 skills, 1 subagent, bilingual EN/ES output, and the
`// pagokit-ignore:` escape hatch logged to `.pagokit/audit.log`.
