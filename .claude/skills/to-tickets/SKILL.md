---
name: to-tickets
description: Split a large change into tasks that each carry a falsifiable acceptance check, so "done" is observable rather than asserted. Use for multi-crate or multi-day work; skip it for a single contained change.
---

# A ticket without a falsifiable check is a wish

Use `TaskCreate` for each. The rule that makes this worth doing at all:

**Every ticket names the observation that would prove it is done, and the
observation must be one that can fail.**

- Bad: "wire the cutoff policy into the engine" — done is a matter of opinion.
- Good: "a vault with `cutoff_minute_of_day = 720` seals a 13:00 note into the
  *next* day; a named test asserts both sides of the boundary" — done is a
  command that exits zero, and it can fail.

## Shape

```
Subject:     Bind before printing the serve banner
Description: What is wrong now, why it matters, and the observation that
             settles it.
```

The description carries the *why*, because the ticket outlives the context that
produced it. Six weeks later "wire up MemoryLock" means nothing; "MemoryLock
borrows its region, so nothing that owns a secret can hold one — SecretBytes is
moved out of every constructor, so locking at construction pins the pre-move
address" is still actionable.

## When to skip this step

A change that fits in one PR with one concern does not need tickets. Splitting
it produces ceremony, not clarity. Route straight to `implement`.

## Sizing

**One concern per ticket, because one concern per PR** (CLAUDE.md §8). If a
ticket would produce a diff containing both a refactor and a feature, it is two
tickets. The test: can its PR body state a single reason for existing?

## The check

Read the ticket list back. Any ticket whose acceptance check is "it works" or
"tests pass" is not yet a ticket — say which command, on which input, expecting
what.
