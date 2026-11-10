# About PagoKit

## The problem is not choosing

Every article about payment integration frames the problem as *choice*: thirty gateways,
which one do I pick? That framing is wrong, and it is why so much payment code is broken.

Choosing takes an afternoon. What takes weeks — and what silently fails in production — is
everything after the choice:

- The webhook that verifies a signature but never checks a timestamp, so a captured event
  can be replayed forever.
- The webhook that verifies against the API key instead of the signing secret, fails every
  event, and sends the developer to debug the hashing algorithm.
- The `amount * 100` that overcharges a Japanese customer by a hundred times, because JPY
  has no minor unit.
- The refund endpoint written for a Pix integration, where refunding a charge is not an
  operation that exists.
- The `payment_intent.succeeded` handler that grants access, on an endpoint anyone who
  knows the URL can post to.
- The integration that works perfectly and still leaves the merchant legally non-compliant
  in Mexico, because a successful payment is not an issued CFDI.

None of these throw. Most of them pass code review. Several of them cost real money in a
direction nobody notices until a customer complains.

**PagoKit exists to make those mistakes hard to write.**

---

## The thesis: three deterministic engines

PagoKit is a Claude Code plugin, which means it runs in your terminal next to your code, with
no service in the middle. That constraint is deliberate, and it shapes everything.

An LLM asked to write a payment integration will produce something plausible. Plausible is
the exact failure mode that matters here: a webhook that *looks* verified, a fee calculation
that *looks* right, a provider recommendation that *sounds* reasoned. So the parts that must
be correct are not left to the model. They are ordinary programs, with tests.

### 1. Validators that block

Security rules are not advice in a markdown file that the model may or may not follow. They
are Node processes wired to Claude Code's `PreToolUse` and `PostToolUse` hooks. When the model
tries to write a webhook handler with no signature check, the write is **denied** and the
model is told why. It cannot argue with a non-zero exit code.

There is an escape hatch — `// pagokit-ignore: <rule> -- <reason>` — because sometimes the
tool is wrong and the developer is right. Every use is logged to `.pagokit/audit.log`, so a
bypass is a decision on the record rather than a silent hole.

### 2. A recommendation engine that shows its work

The advisor does not score providers by reasoning about them. It runs `scripts/advise.js`,
a pure function: the same situation always produces the same ranking, and every rejection
carries the filter that caused it. "Why didn't you recommend X?" has an exact answer, not a
plausible one.

That also makes the advice testable. Every wrong answer PagoKit could give is a fixture:
Chile answered with a provider that does not acquire there, India answered with a provider
that is invite-only for domestic collection, a subscription recommended on a provider with no
recurring billing. They run in CI.

### 3. A signer that proves the verifier works

Webhook signature schemes are described in the catalog as typed data — the hash, the
encodings, the exact signed-string template, where the signature travels. From that same data,
PagoKit can **generate a validly signed event**. So testing a handler is not "it returned 200":
it is a valid event that must be accepted, a forged one that must be rejected, and a replayed
one that must be rejected.

Before this, `/pagokit:test` only worked for the one provider with a CLI. Now it works for
every provider whose scheme is expressible — which is most of them.

---

## What PagoKit will and will not build for you

A wide catalog is only useful if it is honest about its own edges. Every provider carries an
`integration_level`:

| Level | What it means |
|---|---|
| **build** | Hand-written fragments exist. PagoKit writes the full idiomatic integration. |
| **generic** | No hand-written fragments, but the verification family and checkout pattern are verified. PagoKit writes a working scaffold and tells you it is a scaffold. |
| **advise** | The data is verified enough to recommend, compare and cost — but the flow is not expressible generically. PagoKit gives you the recommendation and a checklist, and says plainly that the code is yours to write. |

The advisor states the level every single time. A tool that quietly generates a scaffold from
a scheme nobody verified is worse than a tool that admits the gap, because the failure is
invisible until someone forges an event.

---

## How the data stays honest

A catalog of forty providers rots. Fees change, APIs get versioned, companies get acquired,
and a document that was accurate in May is quietly wrong by November. Three mechanisms fight
that, and all three run in CI:

**Evidence on every claim.** Each webhook and fee field carries `{source_url, verified_at,
confidence, verified_by}`. Without it, "asserted" and "verified" are indistinguishable.

**The evidence rule.** A claim marked `verified_by: llm-generated` can never carry
`confidence: high`. Only verification against the provider's own documentation earns that.

**The generator invariant.** If `webhook.evidence.confidence` is not `high`, the generator
**must not emit a signature verifier**. It emits the re-fetch path, event-id deduplication,
and a loud TODO with the documentation link. This single rule turns "verify forty providers
carefully" from a promise into a property the build enforces.

---

## The security model

Twelve rules, in `skills/payment-advisor/SECURITY_RULES.md`, with three enforcement tiers:

- **VALIDATOR** — a deterministic Node check that blocks the write. The model cannot skip it.
- **SYSTEM-PROMPT** — injected into the implementer subagent every turn.
- **GUIDE** — documented in the fragments the generated code is composed from.

The validators cover the failures that are silent: an unsigned webhook, a body parsed before
verification, `Math.random()` as an idempotency key, a live key inline in source, a `.env`
written before `.gitignore` covers it, a currency multiplied at the wrong exponent, a
comparison of a signature with `===`, card data crossing the merchant's own server, a refund
call on a rail that cannot be refunded.

Notably absent: any claim that PagoKit makes you compliant. It does not. It writes code that
avoids specific known failures, and it tells you which obligations remain yours.

---

## Architecture

```
.claude-plugin/plugin.json      Manifest
commands/                       Slash commands
skills/
  payment-advisor/              Decides. Runs the engine, explains the result.
    data/                       The catalog: providers, methods, regions, currencies
  project-analyzer/             Observes. Detects stack, ORM, deploy target, use cases.
  integration-builder/          Plans. Resolves fragments by capability family.
    fragments/                  Keyed by family, not by provider — that is the whole trick.
    templates/                  Hand-written material for build-level providers.
  webhook-verifier/             The signature reference, generated from the catalog.
  doctor/                       Audits an existing integration, read-only.
agents/integration-specialist   Executes. The only component that writes files.
hooks/                          The validators, and the dispatcher that runs them.
scripts/                        The engines, the generators, and the tests.
```

The load-bearing idea is in `fragments/`. Providers differ in a small number of ways, and
those ways repeat: there are roughly fourteen webhook verification families across every
payment provider that exists. Write one fragment per family and adding a provider costs a
data entry. Write one per provider and the file count is `providers × stacks × billing modes`,
which at realistic numbers is several hundred documents that all have to be edited together
when one convention changes.

---

## What PagoKit is not

- **Not a payment provider.** It never touches money, holds funds, or sees a transaction.
- **Not a service.** No account, no API key, no telemetry. It reads your project locally and
  writes files locally. The only network calls are the ones your generated code makes to your
  chosen provider.
- **Not legal or tax advice.** It tells you an e-invoicing mandate exists in your market and
  what it is called. Whether you have satisfied it is between you and your accountant.
- **Not a compliance certification.** No tool can make you PCI compliant. PagoKit keeps card
  data out of your server, generates the script inventory PCI DSS 4.0.1 requires, and tells
  you which SAQ level your architecture implies.
- **Not a replacement for reading the provider's docs.** It is a way to not read all thirty of
  them.

---

## Contributing

The most valuable contributions are, in order: verifying a webhook scheme against a
provider's own documentation and raising its confidence; adding a stack adapter (which
benefits every provider at once); and tightening a validator that produced a false positive
on real code.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Every provider addition is gated by
`npm run verify`, which runs the schema checks, the integrity invariants, the validator
fixtures, the advisor fixtures and the signature round-trips.

---

## Who maintains it

**Enrique Rocha** — [`tododeia.com`](https://tododeia.com) ·
[`@soyenriquerocha`](https://instagram.com/soyenriquerocha) · `enrique@tododeia.com`

AI consulting, agents and automations. Based in Miami.

Security issues: `security@tododeia.com` or a
[GitHub Security Advisory](https://github.com/Hainrixz/agente-pagokit/security/advisories/new).
Please do not open a public issue for a vulnerability. See [`SECURITY.md`](./SECURITY.md).

[MIT](./LICENSE) · `tododeia.`
