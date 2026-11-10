---
description: Audit a hand-written payment integration and FIX what it finds. Unlike /payready:doctor, which is read-only, this one writes.
argument-hint: "[--dry-run]"
---

# /payready:harden

For integrations PayReady did not write. Most payment code in the world was written by hand
and has at least one of the silent failures the validators exist to catch.

Run `--dry-run` first by default, and only write after the user has seen the list.

## 1. Find the integration

Glob for webhook routes, payment SDK imports, checkout endpoints and migrations. Identify the
provider from the SDK import and the key prefixes in `.env.example` — matched against the
catalog's `detection` and `credentials` entries, not guessed.

## 2. Run every validator against the existing files

The checks in `hooks/checks/` are ordinary functions. Call them directly on each candidate
file rather than waiting for a write to trigger them:

```bash
node -e "
const check = require('./hooks/checks/webhook-has-signature');
console.log(check.run({ filePath: '<path>', content: require('fs').readFileSync('<path>','utf8'), toolName:'Write', projectDir: process.cwd() }));
"
```

Do this for every rule, on every payments file. That is the whole audit — the same checks that
would have blocked the code as it was written.

## 3. Check what the validators cannot see

- Does the handler verify with the **webhook secret**, not the API key? These are different
  values and mixing them fails silently forever.
- Is there replay protection at all — a timestamp window, or dedup against a persisted event
  id? Signature verification alone does not stop replay.
- Are the amounts converted at the **currency's** exponent? Check `currencies.json`.
- Is there a refund path on a rail where refunds do not exist?
- Are all of the provider's `required_events_minimum` routed, or does the switch silently drop
  the ones nobody thought about — `charge.dispute.created`, `subscription.payment_failed`?
- Is `.env` gitignored, and has it ever been committed? `git log --all --full-history -- .env`
  answers that, and the answer is sometimes yes.

## 4. Report, then fix

```
PayReady hardening report — <provider> · <n> files audited

CRITICAL   <what an attacker or a bug can do today, in one line>
HIGH       ...
MEDIUM     ...

<n> critical · <n> high · <n> medium
```

Order by what an attacker can actually do, not by rule number. An unsigned webhook is not "one
finding among five" — it means anyone who knows the URL can grant themselves a paid account.

Then fix them one at a time, smallest blast radius first, running the test suite between
changes if the project has one. Write `PAGOKIT_INTEGRATION.md` at the end so
`/payready:doctor` can audit it from now on.

## Anti-patterns

- Do not rewrite a working integration wholesale. Fix the specific defects.
- Do not change the provider. That is `/payready:migrate`.
- Do not "fix" something by adding a `pagokit-ignore` comment.
- Do not touch a live key, or move a project from test to live mode.
- If a fix would change behaviour visible to customers — a different webhook URL, a new
  required env var — stop and say so before writing.
