# CLAUDE.md — working conventions for Ghostr

Read this before touching anything. It is the short version of
[docs/SPEC.md](docs/SPEC.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), plus the rules that aren't written
down anywhere else.

**Current state: M0, M1 and M2 are implemented; M3 is under way.** The vault,
ingest, the Memoria pipeline, the hash chain, `ghostr verify`, the egress gate,
the encrypted vector index, persona distillation, and the daily quest loop —
issue, answer, score — all work, and all work with no model at all, because
every model call falls back to a deterministic path. `ghostr serve` puts the
loop on a page a phone can open. The three model-written quest kinds
(`VoiceProbe`, `Counterfactual`, `Prediction`) land through
`ghostr_quests::llm`, and the day's quest set is committed into the footage
Merkle tree. M3 has its crypto, its event codec, its relay transport, `ghostr
sync`/`restore`, auto-seal, and the nostr feed adapter — so hostile text now
enters the corpus and the `TrustLevel::ThirdParty` gate is load-bearing rather
than declared.

**M3's public surface is not built.** Backup, sync, restore and the feed are in
and tested; the ghost manifest, attestation publishing and ghost notes are types
in `ghostr-nostr` with no caller. That was invisible because the exit criteria
never covered them — "every exit criterion is met" was true and read as "M3 is
done". They are now listed unchecked in
[docs/ROADMAP.md](docs/ROADMAP.md), along with the NIP submission, which is a
human's to make.

Run `cargo xtask scaffold-status` to see what is still unimplemented,
`cargo xtask lint-deps` to check the dependency rules in §2, and `cargo xtask
unused-pub` to find public functions whose only callers are tests.

**The process is in [.claude/skills/](.claude/skills/), not in this file.** This
file says what the rules are; the skills say how the work moves through them.
See §10 for which ones a given change needs.

---

## 1. What this project is, in four sentences

Ghostr builds a "digital ghost": an agent that clones a user's identity from
their own data and proves the clone is accurate through daily verification
quests. Identity is a nostr keypair; the day's memory is compiled into a
structured *footage*, hash-chained, and anchored to Bitcoin via OpenTimestamps.
Everything is local-first, encrypted at rest, and every model call sits behind a
trait so a local model can be swapped in. Privacy is not a feature of this
product — it is the product.

---

## 2. Architecture in one screen

```
core ← crypto ← store
core ← llm                        (the ONLY crate that talks to a model provider)
core, crypto ← anchor, nostr
core, store, llm ← ingest, persona, memoria, quests
all ← engine ← cli
```

| Crate | Owns |
| --- | --- |
| `ghostr-core` | Domain types, canonical CBOR, tagged hashing, Merkle. **Zero I/O, zero async.** |
| `ghostr-crypto` | NIP-06/19/44, keystore, `Signer`. The only place secret bytes exist. |
| `ghostr-store` | Encrypted SQLite, blobs, vector index. |
| `ghostr-llm` | `LanguageModel`/`Embedder` traits, prompts, **the egress gate**. |
| `ghostr-ingest` | `IngestAdapter` + feature-gated source adapters. Under `nostr` only, depends on `ghostr-nostr` so the feed adapter can re-verify what a relay returned. |
| `ghostr-persona` | Persona build / merge / diff / retrieval. |
| `ghostr-memoria` | The daily compile pipeline. |
| `ghostr-quests` | Generation, verdicts, scoring, fidelity math. |
| `ghostr-anchor` | Commitment chain (pure) + OpenTimestamps (network). |
| `ghostr-nostr` | Relay client, event codec for kinds 31780–31789. |
| `ghostr-engine` | Composition root: wiring, scheduling, job queue, local API, and the page it serves. |
| `ghostr-cli` | The `ghostr` binary. |
| `ghostr-testkit` | Fixtures, fake clock/rng/model. **dev-dependency only.** |

**Dependency rules (CI-enforced via `xtask lint-deps`):**
1. `ghostr-core` gets no I/O dependencies. Ever.
2. No sideways deps between `ingest`/`persona`/`memoria`/`quests` — compose them
   in `engine`. `ingest → nostr` under the `nostr` feature is downward, not
   sideways, and is there so signature, author and kind are re-checked in the
   crate that makes corpus out of the result.
3. Only `ghostr-llm` may depend on a provider SDK or an HTTP client for
   inference.
4. Only `ghostr-crypto` touches secret key bytes.
5. Nothing depends on `engine` or `cli`.

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 3. The invariants

These are from SPEC §2. Breaking one is a bug, never a tradeoff, never "just for
now."

| # | Invariant |
| --- | --- |
| I1 | Raw memory content is never persisted in plaintext, anywhere, at any time. |
| I2 | A sealed footage is immutable. Corrections are amendments in later footage. |
| I3 | The commitment chain has no gaps and is never rewritten. |
| I4 | Every LLM call goes through the `LanguageModel` trait. |
| I5 | Nothing leaves the device without passing the egress policy and being logged. |
| I6 | The ghost commits to its answer before the user sees the quest. |
| I7 | The fidelity score is computed only over held-out quests. |
| I8 | Secret key material never appears in a domain type, log, error, or `Debug`. |
| I9 | Nothing published to a relay contains plaintext identity data. |
| I10 | Ghost-authored public content is always tagged as ghost-authored. |

If a task seems to require violating one, stop and raise it. It means either the
task or the invariant is wrong, and that's a decision for a human.

---

## 4. Never do these

Ordered by how much damage they cause.

1. **Never persist raw memory content in plaintext.** Not in a debug dump, not in
   a cache, not in a temp file, not in a test fixture that lands in the repo, not
   "temporarily while I figure out the encryption." (I1)
2. **Never log memory content, persona facets, entity names, or key material.**
   Log ids and counts. `MemoryId`, not `memory.body`. (I8)
3. **Never rewrite a sealed footage or a chain link.** Corrections are amendments
   in the *current* day's footage. (I2, I3)
4. **Never bypass the egress gate.** No HTTP client to a provider outside
   `ghostr-llm`, no "quick test call", no `reqwest` in another crate's
   `Cargo.toml`. (I4, I5) The local API in `ghostr-engine` is a *server*, not a
   client: it accepts connections and never opens one.
5. **Never send `Sensitivity::Secret` to a remote provider.** There is no
   override flag and there must never be one. `egress_allow` in a vault's
   config cannot name `embedding` either — there is no remote embedding path
   and configuration must not be able to invent one.
6. **Never put a secret key, seed, or passphrase in a domain type.** Use `KeyRef`
   and go through `Signer`.
7. **Never change canonical serialization or a hash tag without a migration plan
   and a new version tag.** It silently invalidates every existing chain, which
   is unrecoverable for users.
8. **Never make a network call in a test.** `#[ignore]` the integration suite.
9. **Never add a dependency without justifying it in the PR description.** This
   is a supply-chain-sensitive project (THREAT_MODEL §T8).
10. **Never write `unsafe` outside `ghostr-crypto`**, and there only with a safety
    comment and a second reviewer.
11. **Never `unwrap()`, `expect()`, or `panic!()` in library code.** Return an
    error. `expect()` is acceptable in tests and in `main` after argument
    validation.
12. **Never invent nostr event kinds outside 31780–31789** without updating
    SPEC §9 in the same PR.
13. **Never let third-party corpus text reach the instruction channel of a
    prompt.** It's data, always. (THREAT_MODEL §T7)
14. **Never commit real personal data**, even your own, even redacted. Fixtures
    are synthetic and generated by `ghostr-testkit`.

---

## 4a. The scaffold exception

While a crate is unimplemented it carries a marked allow block:

```rust
// SCAFFOLD: ...
#![allow(unused_variables, dead_code, clippy::todo)]
```

`clippy::todo` is denied workspace-wide by §5, and `unused_variables` and
`dead_code` fire because a diverging body never reads its arguments or calls its
helpers. Parameters keep real names rather than `_` prefixes so the signatures
stay readable.

**Delete the block as you fill a crate in.** The allows are per-crate and marked
so they can be removed one crate at a time and counted in the meantime — an
exception nobody measures becomes permanent. `xtask scaffold-status` counts them.

Do not add a lint to that block. If a new lint fires, either it is telling you
something true or the code is wrong.

---

## 5. Code style

**Rust edition 2024, MSRV = latest stable minus one**, pinned in
`rust-toolchain.toml`.

- `cargo fmt` with the default profile. No custom `rustfmt.toml` bikeshedding.
- `cargo clippy --all-targets --all-features -- -D warnings`. Additionally deny
  `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`,
  `clippy::todo`, and `clippy::dbg_macro` in non-test code.
- `#![forbid(unsafe_code)]` at the top of every crate except `ghostr-crypto`.
- **Errors:** `thiserror` enums per crate in libraries; `anyhow` only in
  `ghostr-cli` and `xtask`. Errors carry ids and context, never content.
- **Two CBOR codecs, never conflated.** `ghostr_core::canonical` is for anything
  that gets **hashed**: it sorts map keys by encoded bytes and rejects floats, so
  one value has exactly one representation. Encrypted **row payloads** use plain
  `ciborium` via `ghostr-store`'s `encode_row`, because storage needs no such
  guarantee and the canonical encoder would reject the `f32` fields that scores
  legitimately use. Hashing a row payload, or storing a canonical one, are both
  bugs.
- **Newtypes over primitives.** `MemoryId(Uuid)`, not `Uuid`. `Hash32([u8; 32])`,
  not `[u8; 32]`. This is what stops a quest leaf from being hashed as a memory
  leaf.
- **Async only where there's real I/O.** `core`, scoring math, and persona
  merge/diff stay synchronous — that's what makes them property-testable.
- **`#[non_exhaustive]`** on public enums that will grow (`SourceKind`,
  `QuestKind`, `MemoryKind`).
- **No `impl Debug` that prints content.** Hand-write `Debug` for anything
  carrying memory content or keys; print the id and a length.
- **Comments explain why, not what.** A comment restating the code is noise; a
  comment naming the invariant a line protects is the most valuable thing in the
  file. Reference invariants explicitly: `// I2: sealed footage is immutable`.
- **Doc comments on every public item**, and `#![warn(missing_docs)]` in
  libraries.
- Module layout: `mod.rs`-free (`foo.rs` + `foo/`), one type per file when the
  file exceeds ~300 lines.

---

## 6. Testing expectations

**A PR without tests is not done.** The specific expectations by layer:

| Layer | Required |
| --- | --- |
| Hashing / chain / Merkle | Golden vectors (committed, fixed) **and** `proptest` invariants |
| Crypto | NIP-06/19/44 vectors from the NIPs repo, verbatim, unmodified |
| Store | Round-trip + a test asserting no plaintext appears in raw DB bytes |
| Egress gate | Table test over every `Sensitivity` × policy combination |
| Memoria / persona | Fixture corpora + `insta` snapshots for prompts and outputs |
| Scoring | Pure property tests: monotonicity, CI bounds, calibration |
| Engine | Full-loop integration: fake clock, fake model, seeded RNG, no network |

Specific rules:

- **`cargo nextest run` is the runner.** Tests must pass with
  `--test-threads=1` and in parallel.
- **Determinism is mandatory.** Nothing calls `SystemTime::now()` or `OsRng`
  outside the composition root — use the `Clock` and `Rng` traits. A flaky test
  is a design bug, not a retry candidate.
- **Test the boundaries that will actually break:** the cutoff at midnight, a
  timezone change mid-day, an empty day, a missed seal, a late-arriving memory, a
  duplicate `seq`, a shredded memory in an anchored day.
- **Adversarial fixtures are part of the suite.** A corpus containing prompt
  injection is a permanent CI fixture, not a one-off check (THREAT_MODEL §T7).
- **Snapshot changes get reviewed like code.** A changed prompt snapshot is a
  behaviour change to the persona model — say so in the PR.

---

## 7. Commit format

**Conventional Commits**, scoped by crate:

```
<type>(<scope>): <subject>

<body: why, not what>

<footer: refs, breaking changes>
Signed-off-by: Name <email>
```

- **Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`,
  `sec` (security-relevant), `spec` (SPEC/threat-model changes).
- **Scopes:** the crate without the prefix — `core`, `crypto`, `store`, `llm`,
  `ingest`, `persona`, `memoria`, `quests`, `anchor`, `nostr`, `engine`, `cli`,
  `testkit` — or `docs`, `ci`, `deps`.
- **Subject:** imperative, lowercase, no trailing period, ≤ 72 chars.
- **DCO sign-off required** (`git commit -s`). No CLA — this project will never
  ask for copyright assignment.
- Breaking changes: `!` after the scope and a `BREAKING CHANGE:` footer.
  **Any change to hashing, canonical serialization, or the chain format is
  breaking**, even if it compiles, because it invalidates users' chains.

Examples:

```
feat(anchor): add OTS proof upgrade queue with exponential backoff
fix(memoria): seal on wake after a missed cutoff, keeping the chain gapless (I3)
sec(llm): deny Secret sensitivity on all remote paths, add table test
spec(docs): resolve Q5 — anchor receipts default to local-only
```

---

## 8. Pull requests

- **One concern per PR.** A refactor and a feature in one diff is two PRs.
- **The PR body says why.** Link the SPEC section or invariant it serves.
- **Docs move with code.** A behaviour change that leaves SPEC.md stale is
  incomplete. A change to storage, crypto, anchoring, relays, or the egress gate
  that leaves THREAT_MODEL.md stale is incomplete.
- **Security-sensitive paths need a second reviewer**: `ghostr-crypto`,
  `ghostr-anchor`, `ghostr-store`, and the egress gate in `ghostr-llm`.
- **Resolving an Open Question** (SPEC §14) means moving the answer into the body
  of the spec and striking the question with a note on what was decided and why —
  not just deleting it.

---

## 9. Working on this repo as an agent

- **The docs are the source of truth, not a description of the code.** When they
  disagree with the code, the code is wrong until a human says otherwise.
- **When the spec is ambiguous, don't silently pick.** Add an Open Question to
  SPEC §14 with a recommendation, or ask. Silent decisions in a threat-bearing
  system are how invariants die.
- **Don't scaffold ahead of the milestone.** M0 does not need a persona module.
  Empty crates and placeholder traits are cost with no value.
- **Prefer deleting to abstracting.** A boundary that stops enforcing an
  invariant should be merged away, not preserved out of politeness.
- **Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before touching anything
  in `crypto`, `store`, `anchor`, or the egress gate.** Then update it in the
  same PR.
- **Never soften a claim in the docs to match a shortcut in the code.** If the
  implementation can't meet the invariant, change the implementation or escalate
  — do not edit the promise.

---

## 10. The process, as steps rather than a prompt

Everything in §1–§9 is a *rule*. Rules are only as good as the process that
makes somebody apply them, and a process that lives in one long instruction is
one nobody can check a step of. So it is split into skills in
[.claude/skills/](.claude/skills/), each ending in an artifact somebody can look
at:

| Skill | Ends with |
| --- | --- |
| [`grill-with-docs`](.claude/skills/grill-with-docs/SKILL.md) | the invariants this change touches, written down, and what the docs don't answer |
| [`to-spec`](.claude/skills/to-spec/SKILL.md) | a numbered Open Question in SPEC §14 with a recommendation |
| [`to-tickets`](.claude/skills/to-tickets/SKILL.md) | tasks whose acceptance check can fail |
| [`implement`](.claude/skills/implement/SKILL.md) | the change, and the test, written together |
| [`prove`](.claude/skills/prove/SKILL.md) | a table of *guard deleted → named test that failed* |
| [`gate`](.claude/skills/gate/SKILL.md) | the CI commands, green, in both thread shapes |
| [`sweep`](.claude/skills/sweep/SKILL.md) | `cargo xtask unused-pub` triaged, each candidate answered |

**Not every change needs every step.** Routing:

| The change | The route |
| --- | --- |
| A fix, a rename, one contained behaviour | `grill-with-docs` → `implement` → `prove` → `gate` |
| A feature crossing crates, or a milestone | `grill-with-docs` → `to-spec` → `to-tickets` → `implement` → `prove` → `gate` |
| Looking for defects in code that is already green | `sweep` → `grill-with-docs` → `implement` → `prove` → `gate` |
| A docs-only change | `grill-with-docs` → `gate` |

Two are never skipped. **`grill-with-docs`**, because a change that does not
know which invariant it touches cannot avoid breaking it. **`prove`**, because a
green suite is evidence that nothing regressed and no evidence at all that the
new guard does anything — it has caught four tests passing for the wrong reason,
each green for weeks.

The point is not the skills. It is that a step which cannot be inspected is not
a step: a process that only produces "done" produces nothing a reviewer can
disagree with. Every skill above ends in something they can.
