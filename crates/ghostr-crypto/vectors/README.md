# Vendored test vectors

Copied verbatim from upstream and **never edited**. A vector adjusted to match
our output is not a test — it is a transcription of a bug (CLAUDE.md §6).

| File | Source | Retrieved |
| --- | --- | --- |
| `nip44.vectors.json` | <https://github.com/paulmillr/nip44> (`nip44.vectors.json`), the reference vectors NIP-44 points at | 2026-08-27 |

Re-vendoring means replacing a file wholesale and reading the diff, not patching
one case. If upstream changes a vector, that is a change to the protocol and
belongs in its own commit with the reasoning.
