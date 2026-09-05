---
name: gate
description: Run exactly what CI runs, in both thread shapes, before pushing. Use immediately before every commit and push. A push that turns CI red costs a cycle and the reviewers' trust.
---

# Run what CI runs, before CI does

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings          # default features too
RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features
cargo xtask lint-deps                               # ARCHITECTURE §2 rules
cargo xtask scaffold-status                         # should stay at 0
cargo nextest run --all-features                    # or cargo test
cargo nextest run --all-features -- --test-threads=1
```

## Why each one is not optional

- **Both feature sets.** `--all-features` compiles code the default build does
  not. A `#[cfg]` arm can be broken in exactly one of them, and the default
  build is what users get.
- **Both thread shapes.** Tests must pass in parallel *and* serially
  (CLAUDE.md §6). A test that only passes one way has a shared-state bug — a
  flaky test is a design bug, not a retry candidate.
- **`lint-deps`.** The dependency direction rules in ARCHITECTURE §2 are the
  thing keeping `reqwest` out of `ghostr-core` and secret bytes out of every
  crate but `ghostr-crypto`. Prose does not enforce that; this does.
- **rustdoc with `-D warnings`.** A broken intra-doc link means a doc comment is
  pointing at something that no longer exists — usually the exact function a
  refactor moved.

## Before pushing, also

- **Re-read the diff adversarially.** What would make CI reject this?
- **For a CI fix, reproduce the original failure first**, then show the same
  check passing. Otherwise you are guessing.
- **Rebased onto a new base? Run it again.** The suite that passed against the
  old base has not run against this one.

One validated push beats three speculative ones.

## Deps

If the diff adds a dependency, the PR body must justify it — this is a
supply-chain-sensitive project (THREAT_MODEL §T8). `cargo-deny` will pass a
crate that is perfectly fine and still unnecessary.
