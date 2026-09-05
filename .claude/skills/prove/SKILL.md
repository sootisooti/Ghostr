---
name: prove
description: Mutation-check every guard added — delete it, confirm a named test fails, restore it. Use before opening any PR that adds a check, a branch, or a validation. This is the step that catches tests passing for the wrong reason.
---

# Prove the test is testing the thing

A green suite proves the code compiles and nothing regressed. It does **not**
prove the new guard does anything. The only cheap evidence for that is to break
the guard on purpose.

## The loop

For each guard the change adds:

1. **Delete it** — or invert it, or replace the condition with `true`.
2. **Run the suite.** A test must fail, and you must be able to *name* it.
3. **Restore the guard.** Re-run. Green.
4. **Record the pair** for the PR body:

```markdown
| Deleted | Test that failed |
|---|---|
| `ready()` after the bind → moved before it | `a_taken_port_is_never_announced_as_ready` |
| days fed newest-first | both direction tests |
```

## When nothing fails

The guard is untested. Write the test *now* — this is the whole point of the
step, not an inconvenience.

## When something fails for the wrong reason

This is the finding that makes the step worth its cost. Read the failure and
check it is failing *because of the guard*, not incidentally. In one sweep this
caught four tests that were passing without exercising anything:

| Looked fine | Actually |
| --- | --- |
| a 2-word logged row as an exemplar | below `MIN_EXEMPLAR_WORDS`, so the trust check never ran |
| searching a `Debug` render for a phrase | the field is `Vec<MemoryId>`; the phrase was never going to be there |
| a relay double proving a `kinds` filter | the double ignored filters, so the query under test was invisible |
| an intruder rejected by the `d`-tag check | rejected by decryption first; the check never ran |

Each had been green for weeks.

## Mirrored pairs

When a bug would produce the *exact reverse* of the truth — a series fed
backwards, a sign flipped, a comparison inverted — one test passes against it.
`a_ghost_getting_better_trends_above_its_window_average` and
`..._getting_worse_trends_below_...` are one guard, not two tests: either alone
would pass against an EWMA fed newest-first.

Ask of every new assertion: **is there a wrong implementation this would still
pass against?** If yes, that is the test you have not written.

## Beyond code

The same question applies to anything that reports success. A screenshot harness
that writes twenty pictures of an error card looks exactly like one that worked
— so it now refuses to record a run where the page is showing an error. If a
step can only report success, it is not checking anything.
