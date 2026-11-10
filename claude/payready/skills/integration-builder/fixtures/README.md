# Golden fixtures — not templates

These files were `templates/compiled/` in v0.1. They are **no longer loaded when generating
an integration**; they are the regression baseline for the composition engine.

Pre-compilation was doing two jobs: speed and regression safety. Speed was never real — the
model reads a composed plan just as fast as a pre-written one. Regression safety is real, so
it is kept, but as a CI artifact rather than as user-facing templates.

The arithmetic is the reason: `provider × stack × billing` is multiplicative. At four
providers and two stacks it is eight files. At forty providers, eight stacks and three
billing modes it is 960 files of ~250 lines each — 240,000 lines of prose that all have to be
re-edited when one webhook convention changes. That is not a maintenance problem, it is a
correctness problem.

Fragments keyed by **capability family** are additive instead: there are ~14 webhook families
across any number of providers, so a fragment is written once per family. Adding provider 41
costs one JSON entry plus a small override, not 24 compiled documents.

`npm run check:fixtures` regenerates these combos from the fragments and diffs them. A
fragment edit that changes generated output for a shipped combo fails the build instead of
reaching a user.
