---
description: Send synthetic webhook events to your local integration — valid, forged and replayed — and verify the handler responds correctly. Works for every provider in the catalog, not just the one with a CLI.
argument-hint: "[--provider <id>] [--port 3000] [--path /api/webhook/<provider>]"
---

# /payready:test

Prove the webhook handler actually works: that it accepts a genuine event, and — more
importantly — that it **rejects** a forged one and a replayed one. A handler that accepts
everything looks identical to a correct one until someone forges a `payment.succeeded`.

## Phase A — Identify the integration

1. Read `PAGOKIT_INTEGRATION.md` for the provider id, the webhook path and the stack.
   If it is missing, ask which provider, then confirm the route by globbing for the
   provider's `expected_filenames`.
2. Work out the dev port from `package.json` scripts (Next and Express default to 3000,
   FastAPI to 8000). Ask only if you cannot tell.
3. Read the provider entry to learn its `notification_model`. **If it is not `webhook`,
   stop and say so** — a `return_url_commit` provider never calls a webhook, and testing one
   proves nothing. For those, verify the commit call instead.

## Phase B — Generate the events

PayReady derives the signature from the same catalog data the verifier was generated from,
so a passing test means the two agree. This works for every provider whose verification
family is locally signable:

```bash
node scripts/sign-event.js --provider <id> --secret "$WEBHOOK_SECRET" \
  --url "http://localhost:<port><webhook_path>" --curl
```

Use a disposable signing secret in an isolated local test instance. Keep live secrets out of the transcript, terminal arguments and fixtures.

Run three cases, in this order:

| Case | Command | Expected |
|---|---|---|
| Valid | `--mode valid` | 2xx |
| Forged signature | `--mode forged` | **400** |
| Replayed timestamp | `--mode replay` | **400** |

`--mode forged` flips one character of an otherwise well-formed signature, so only the
cryptographic check can catch it — which is exactly what is being tested. `--mode replay`
backdates the timestamp past the provider's tolerance window.

If a provider has no signed timestamp, `--mode replay` is not meaningful. Test event-id
deduplication instead: send the same valid event twice and confirm the second one is a
no-op that still returns 200.

If `sign-event.js` exits with `[SKIP]`, the family is not locally signable (asymmetric
schemes, SDK-owned verification, mTLS). Say so and point at the provider's sandbox rather
than fabricating a signature.

## Phase C — Live provider CLI, where one exists

If the provider ships a CLI that forwards real events, offer it as a second, higher-fidelity
pass — it exercises the provider's own signing rather than PayReady's reconstruction. Run it
in the background, never in the foreground, and use the ephemeral signing secret it prints.

## Output

```
PayReady webhook test — <provider> (<verification_family>)

[PASS] Valid signature      → 200
[PASS] Forged signature     → 400
[PASS] Replayed timestamp   → 400
[INFO] Events routed: <n> of <required_events_minimum count>
[FAIL] <what went wrong, and the exact next step>

<n> PASS · <n> FAIL · <n> INFO
```

A `[FAIL]` on the forged or replayed case is the serious one: it means the endpoint accepts
events an attacker can mint. Say that plainly rather than listing it as one failure among
several.

Finish by pointing at `/payready:doctor` for the static audit.

## Anti-patterns

- Do not modify `.env` or `.env.local`.
- Do not run a provider CLI in the foreground — it blocks the session.
- Do not sign a forged event with the user's real secret and call it a forgery test: a
  correctly-signed event is not forged. Use `--mode forged`, which corrupts the signature.
- Do not skip the replay case. Signature verification alone does not stop replay.
- Do not report a pass you did not observe.
