# Contributing to Ghostr

Thanks for looking. Ghostr is pre-alpha and unbuilt, which makes this the
cheapest moment in the project's life to change its mind.

**The most useful contribution right now is disagreement.** Start with the
[Open Questions](docs/SPEC.md#14-open-questions) — eighteen of them, each with a
recommended answer, none of them settled. If you think a recommendation is
wrong, especially in the anchoring scheme or the threat model, open an issue.

---

## Read first

| If you're going to… | Read |
| --- | --- |
| Anything | [CLAUDE.md](CLAUDE.md) — conventions, and the *never do* list |
| Change behaviour | [docs/SPEC.md](docs/SPEC.md) |
| Add or move a crate | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Touch crypto, store, anchor, or the egress gate | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — **required** |
| Pick something to work on | [docs/ROADMAP.md](docs/ROADMAP.md) |

The docs are the source of truth, not a description of the code. Where they
disagree with the code, the code is wrong until a human says otherwise.

---

## Current state

**The workspace is a scaffold.** Types, traits, and signatures are defined;
every body is `todo!()`. That is deliberate — the shape is meant to be
reviewable before anything is implemented.

```console
$ cargo xtask scaffold-status   # what is still unimplemented, per crate
$ cargo xtask lint-deps         # dependency-direction rules
```

Every crate carries a marked scaffold allow:

```rust
// SCAFFOLD: ...
#![allow(unused_variables, dead_code, clippy::todo)]
```

`clippy::todo` is denied workspace-wide by [CLAUDE.md](CLAUDE.md) §5; this is
the documented exception. **Delete the block as you fill a crate in** — the
allows are per-crate and marked precisely so they can be removed one crate at a
time. An exception nobody measures becomes permanent.

---

## Setup

```console
$ git clone https://github.com/sootisooti/Ghostr
$ cd Ghostr
$ cargo build --workspace
```

The toolchain is pinned in `rust-toolchain.toml`; rustup will fetch it. Nothing
else is required — there is no database, no model, and no network dependency in
the build.

Optional but recommended:

```console
$ cargo install cargo-nextest cargo-deny
```

---

## Before you push

```console
$ cargo fmt --all
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo test --workspace
$ cargo xtask lint-deps
```

All four run in CI, plus an MSRV check and `cargo-deny`. Running them locally
costs a minute; a red CI run costs a round trip.

---

## What CI enforces

| Job | What it checks |
| --- | --- |
| `fmt` | `cargo fmt --all --check` |
| `clippy` | All targets, all features, warnings denied |
| `test` | `cargo test --workspace --all-features` |
| `build` | The **default** feature set specifically — the offline path must keep compiling on its own |
| `arch` | `cargo xtask lint-deps`, then a scaffold report |
| `msrv` | `cargo check` on the declared minimum, 1.93 |
| `deny` | Licences, advisories, and banned crates |

`arch` is the unusual one. It enforces rules a module boundary cannot and a code
review will eventually miss:

- `ghostr-core` keeps its five-crate allowlist and gains no I/O dependency.
- No sideways dependencies between `ingest`, `persona`, `memoria`, and `quests`.
- Only `ghostr-llm` may depend on an inference HTTP client or provider SDK.
- `ghostr-testkit` is a dev-dependency only.
- Nothing depends on `ghostr-engine` or `ghostr-cli`.

---

## The rules that are not style

Most conventions are negotiable. These are not, and a PR that breaks one will be
asked to change rather than debated. The full list with reasoning is
[CLAUDE.md](CLAUDE.md) §3–4.

1. **No plaintext persistence of raw memories.** Not in a debug dump, a cache, a
   temp file, or a committed fixture.
2. **Never log memory content, persona facets, entity names, or key material.**
   Log ids and counts. This is why content-carrying types have hand-written
   `Debug` impls — do not "fix" one by deriving it.
3. **Never rewrite a sealed footage or a chain link.** Corrections are
   amendments in the current day.
4. **Never bypass the egress gate.** No HTTP client to a provider outside
   `ghostr-llm`, not even for a quick test.
5. **Never send `Sensitivity::Secret` to a remote provider.** There is no
   override flag and there must never be one.
6. **Never change canonical serialization or a hash tag** without a migration
   plan and a version bump. It silently invalidates every existing chain, and
   users cannot migrate — the old hashes are already in Bitcoin.
7. **Never make a network call in a test.**
8. **Never commit real personal data**, even your own, even redacted. Fixtures
   come from `ghostr-testkit`.

---

## Commits

Conventional Commits, scoped by crate, with a DCO sign-off:

```
feat(anchor): add OTS proof upgrade queue with exponential backoff

Calendars publish on their own schedule, so retries are patient rather
than aggressive: hourly for a day, then daily for a week.

Signed-off-by: Your Name <you@example.com>
```

- **Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`,
  `sec`, `spec`.
- **Scopes:** the crate without its prefix (`core`, `crypto`, `store`, `llm`,
  `ingest`, `persona`, `memoria`, `quests`, `anchor`, `nostr`, `engine`, `cli`,
  `testkit`), or `docs`, `ci`, `deps`.
- **Sign off** with `git commit -s`. There is no CLA — this project will never
  ask for copyright assignment, because a CLA on a privacy tool is a signal that
  a relicense is being kept available.
- Any change to hashing, canonical serialization, or the chain format is
  **breaking**, even when it compiles.

## Pull requests

- **One concern per PR.** A refactor and a feature in one diff is two PRs.
- **Say why in the body**, and link the SPEC section or invariant it serves.
- **Move the docs with the code.** A behaviour change that leaves SPEC.md stale
  is incomplete; so is a storage, crypto, anchoring, relay, or egress change that
  leaves THREAT_MODEL.md stale.
- **Justify new dependencies** in the PR description. The tree is small on
  purpose.
- Security-sensitive paths — `ghostr-crypto`, `ghostr-anchor`, `ghostr-store`,
  and the egress gate in `ghostr-llm` — need a second reviewer.

## Tests

A PR without tests is not done. Expectations by layer are in
[CLAUDE.md](CLAUDE.md) §6. The parts most often skipped:

- **Determinism.** Nothing calls `SystemTime::now()` or `OsRng` outside the
  composition root — use `Clock` and `Rng` from `ghostr-testkit`. A flaky test
  is a design bug, not a retry candidate.
- **The boundaries that actually break.** The cutoff at midnight, a timezone
  change mid-day, an empty day, a missed seal, a late-arriving memory, a
  duplicate `seq`, a shredded memory in an anchored day.
- **Adversarial fixtures.** `ghostr-testkit::adversarial` is a permanent part of
  the suite, not a one-off check. `InjectionKind::all()` is a table — a defence
  proven against one attack and assumed for the rest is not proven.
- **Properties, not only examples**, on anything hashed. A golden vector pins
  the case somebody thought of; a `proptest` invariant covers the ones nobody
  did. That distinction is worth more here than almost anywhere, because a
  commitment bug cannot be migrated away from — the old hashes are already in
  Bitcoin.

`ghostr-testkit` is where you start. `CorpusGenerator` hands back the ground
truth it planted, so a test can assert the pipeline *found* something rather
than merely produced something; `ScriptedModel` makes a model's failure modes
reachable; `FixedClock` walks a month or a DST boundary in microseconds.

---

## Good first contributions

- **Argue with an Open Question.** Genuinely the highest-value thing available.
- **An ingest adapter.** Implement `IngestAdapter`, register it, add a
  fixture test. Nothing else in the tree changes — that contract is small on
  purpose.
- **Fill in a scaffolded module.** `cargo xtask scaffold-status` shows where the
  work is. `ghostr-core`'s hashing and Merkle code is the highest-leverage
  place to start, and it is pure, so it is testable with fixed vectors.
- **Break the threat model.** If you can find something [it claims](docs/THREAT_MODEL.md)
  that is not true, that is the most valuable bug report this project can
  receive right now.

## Security

`SECURITY.md` with a disclosure address must exist before any code ships, and
does not yet. Until it does, open a normal issue for anything non-sensitive, and
for anything sensitive say so in an issue **without details** and wait for a
contact channel.

## Licence

MIT. By contributing you agree your work is licensed under it.
