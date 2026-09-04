---
name: implement
description: Write the change under Ghostr's never-list and style rules, with the test written alongside rather than after. Use after grill-with-docs, for any change that touches Rust.
---

# Implement

Assumes `grill-with-docs` has already named the invariants in play. If it has
not, go back — this step has no idea what it is allowed to do.

## The never-list, in the order it costs

Full text in CLAUDE.md §4. The ones that get broken by accident rather than on
purpose:

1. **Never persist raw memory content in plaintext.** Not in a debug dump, a
   cache, a temp file, or a committed fixture (I1).
2. **Never log memory content, persona facets, entity names, or key material.**
   `MemoryId`, never `memory.body` (I8).
3. **Never rewrite a sealed footage or a chain link.** Corrections are
   amendments in the *current* day (I2, I3).
4. **Never bypass the egress gate.** No HTTP client outside `ghostr-llm` (I4, I5).
5. **Never `unwrap()`, `expect()` or `panic!()` in library code.**
6. **Never add a dependency without justifying it in the PR body** (§4.9).
7. **Never let third-party corpus text reach a prompt's instruction channel.**
   It is data, always (§T7).

## Style that is load-bearing, not taste

- **Newtypes over primitives.** `MemoryId(Uuid)`, not `Uuid`. This is what stops
  a quest leaf being hashed as a memory leaf.
- **Two CBOR codecs, never conflated.** `canonical` for anything hashed; plain
  `ciborium` via `encode_row` for storage. Hashing a row payload, or storing a
  canonical one, are both bugs.
- **Async only where there is real I/O.** `core`, scoring, persona merge stay
  synchronous — that is what makes them property-testable.
- **Comments explain why.** Name the invariant a line protects:
  `// I2: sealed footage is immutable`. A comment restating the code is noise.
- **Nothing calls `SystemTime::now()` or `OsRng` outside the composition root.**
  Use the `Clock` and `Rng` traits, or the test is not deterministic.

## Write the test with the code, not after

A PR without tests is not done (CLAUDE.md §6). The layer decides the kind:
golden vectors *and* proptests for hashing; NIP vectors verbatim for crypto; a
"no plaintext in raw DB bytes" assertion for store; a table over every
`Sensitivity` × policy for the egress gate; a fake-clock, fake-model, seeded-RNG
full loop for engine.

**Name tests after the behaviour, not the function.**
`a_configured_cutoff_decides_which_day_a_memory_lands_in`, not `test_cutoff`.
The next step needs a *named* test to point at.

## Then

Go to `prove`. Do not go straight to `gate` — a green suite is not evidence that
the new guard does anything.
