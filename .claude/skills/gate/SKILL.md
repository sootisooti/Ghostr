---
name: gate
description: Run exactly what CI runs, in both thread shapes, before pushing. Use immediately before every commit and push. A push that turns CI red costs a cycle and the reviewers' trust.
---

# Run what CI runs, before CI does

```sh
set -e   # or check every exit status by hand; see the warning below
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets -- -D warnings            # default features too
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo xtask lint-deps                                 # ARCHITECTURE §2 rules
cargo xtask scaffold-status                           # should stay at 0
cargo xtask unused-pub                                # a report; read it
cargo nextest run --all-features                      # or cargo test
cargo nextest run --all-features -- --test-threads=1
```

## Judge these by their exit status, never by grepping their output

This cost a red CI once already, and the failure looked exactly like success.

`RUSTDOCFLAGS=-D warnings cargo doc …` — **unquoted** — makes the shell read
`warnings` as the command name and `RUSTDOCFLAGS=-D` as its environment. The
result is `warnings: command not found`, exit 127, and *no output at all*. A
step that pipes into `grep -E "^(error|warning)"` then finds nothing and reports
clean. The quotes are load-bearing.

The general rule, and it is the same one `prove` makes about tests: **a check
whose only failure mode is "printed something I grepped for" is not a check.**
Read the exit status. `set -e`, or `cmd || echo FAILED`, or look at `$?` — but
do not conclude a build passed because a pipeline was quiet.

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
