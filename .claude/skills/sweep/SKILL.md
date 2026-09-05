---
name: sweep
description: Find public functions whose only callers are tests — documented promises with nothing keeping them. Use when looking for real defects in code that already has a green suite, or before claiming a milestone is complete.
---

# Documented promises with nothing keeping them

```sh
cargo xtask unused-pub
```

A `pub fn` in a library crate is a promise that something calls it. When the
only references sit after a file's `#[cfg(test)]`, the function is implemented,
documented, property-tested, and dead — and whatever its doc comment promises is
not happening anywhere.

This sweep found six real defects in one pass. **None of them looked like bugs
from inside the code**, and every one had a green suite:

| Found | What was actually wrong |
| --- | --- |
| `may_be_exemplar`, `may_source_stance` | a hostile feed note could evidence a persona claim (§T7) |
| `cutoff::window_for` | the engine had a second, midnight-only window, so `cutoff_minute_of_day` decided nothing — its documented default included |
| `mirror_as_nip78` | the NIP-78 fallback SPEC Q3 rests on was never published or read |
| `ewma` | the score carried no trend, so a user could not tell an improving 72% from a decaying one |
| `config.relays` | a field with no parser arm; the CLI told users to write the line the parser rejected |
| restore's genesis | a restored vault failed `ghostr verify` — while the M3 exit criterion "full restore on a clean machine" was ticked |

## Triaging a candidate

For each line the report prints, answer **"what calls this?"** out loud:

- *"The trait object in `ops.rs`"* → fine, the tool cannot see through traits.
- *"A macro expands to it"* → fine.
- *"...nothing"* → **you have found something.** The question that follows is
  the valuable one: *what did the docs promise this would do, and what is
  happening instead?* That gap is the defect, and it is usually bigger than the
  missing call.

## It only looks at functions

`unused-pub` reads `pub fn`. **An enum variant or a struct field that nothing
constructs is invisible to it**, and that is not a hypothetical: `LeafKind::Quest`
and `Tag::QuestLeaf` are referenced by nothing but `ghostr-core`'s own property
tests, so the day's quest set is not in the Merkle tree — while CLAUDE.md and
the README both said it was. Found by reading a ROADMAP criterion that
contradicted them, not by the tool.

So when a claim rests on a *type* rather than a call — a leaf kind, a hash tag,
a field that ought to be populated — grep for the variant and check who
constructs it. The question is the same one: what puts this here?

## It under-reports

References match by bare name, so a namesake elsewhere hides a dead function.
`MemoryLock::is_locked` has no production caller and is not in the report,
because `Keystore::is_locked` shares its name. **An empty report means nothing
was found, not that there is nothing to find** — on `crypto`, `store`, `anchor`
and the egress gate, still sweep by hand.

## Then

Fix through `implement` → `prove`. Fixing one of these without a mutation check
is how the fix ends up as dead as the function was: twice in one sweep the
mutation check found the *test* was wrong rather than the guard.
