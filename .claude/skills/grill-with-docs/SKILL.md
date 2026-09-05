---
name: grill-with-docs
description: Before writing any code for Ghostr, read the docs that govern the change and write down which invariants it touches and which questions the docs do not answer. Use at the start of every task, however small.
---

# Grill the docs before the code

**The docs are the source of truth, not a description of the code.** When they
disagree with the code, the code is wrong until a human says otherwise
(CLAUDE.md §9). So the first move is never `grep` for a function — it is finding
out what the change is *allowed* to do.

This is the one step that never gets skipped, on the smallest task as much as
the largest. It is cheap and it is the only thing standing between a plausible
patch and a broken invariant.

## Read, in this order

1. **CLAUDE.md** — §3 the invariants, §4 the never-list, §5 style.
2. **docs/SPEC.md** — the section that governs the thing being changed. Search
   for the type or command by name.
3. **docs/THREAT_MODEL.md** — **mandatory** before touching `ghostr-crypto`,
   `ghostr-store`, `ghostr-anchor`, or the egress gate in `ghostr-llm`.
4. **docs/ARCHITECTURE.md** — only when the change crosses a crate boundary.
5. **docs/ROADMAP.md** — to check the work belongs to the current milestone.
   Don't scaffold ahead of it (§9).

## Produce this before touching a file

A short written block, in the reply, with three parts:

```
Governed by:   SPEC §5.2, THREAT_MODEL §T7
Invariants:    I4 (every model call goes through the trait), I7 (held-out only)
Docs silent on: whether a replica should know its own chain id
```

**"Invariants: none" is an answer that has to be earned**, not the default. If
the change touches storage, hashing, key material, egress, relays or the chain,
at least one invariant applies.

## The two exits

- **The docs answer everything** → go to `implement` for a small change, or
  `to-spec`/`to-tickets` for a large one.
- **The docs are silent or ambiguous** → **stop**. Do not pick quietly. Go to
  `to-spec`. A silent decision in a threat-bearing system is how invariants die
  (§9).

## If the docs and the code disagree

Say so, in the reply, before doing anything else. The code is the thing that
changes. Never soften a claim in the docs to match a shortcut in the code — if
the implementation cannot meet the invariant, change the implementation or
escalate (§9).
