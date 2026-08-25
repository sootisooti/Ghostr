# Ghostr

**A digital ghost.** An agent that progressively clones your identity from your
own data, and then has to *prove* the clone is accurate — every day, out loud,
against you.

Identity is a nostr keypair. Memory is a hash chain anchored to Bitcoin. The
corpus never leaves your device unencrypted.

---

## What it is

Ghostr ingests what you write and what you record — nostr notes, RSS, exported
social archives, markdown vaults, journal entries, structured logs of places and
people and habits — and builds a **persona model**: a versioned, diffable,
human-readable description of your voice, your opinions, your relationships, and
your routines.

Then it does the part that makes it more than a chatbot with your name on it.

Every day the ghost issues a handful of **quests**: falsifiable claims made *as
you*.

> *"You'd say the tooling argument is a distraction from the actual bug."*
> *"You saw Nan today."*
> *"Given the choice you'd take the late train and read."*

You confirm, correct, or reject. Corrections feed back into the persona model.
The agreement rate becomes a **fidelity score**, tracked over time, scored only
on quests the model never got to learn from.

The product goal is a single number climbing: the point at which the ghost's
answers and yours are indistinguishable often enough, over a long enough record,
that the account is *provably* your ghost.

At the end of each day, **Memoria** compiles everything into a **footage** — a
structured recap with highlights, people, mood, open threads, and unresolved
loops. Footage isn't a summary for you to read. It's the substrate the ghost
remembers with.

Each footage is hashed, chained to yesterday's hash, and the chain tip is
anchored to Bitcoin via OpenTimestamps. No content goes on-chain. What you get is
a tamper-evident record that this memory, and this fidelity score, existed on
that day — which is what makes the number mean anything.

## Why it exists

Three reasons, in order of how much they matter.

**1. A fidelity score nobody can check is marketing.** Any system can claim it
models you well. Ghostr's claim is falsifiable by construction: the ghost commits
to an answer before you see it, a fixed slice of quests is held out from
training, decoy quests catch rubber-stamping, and the whole quest-and-verdict
record is committed to a hash chain anchored in Bitcoin. You cannot retroactively
manufacture a good score. Neither can we.

**2. Your identity corpus is the most sensitive data you own, so it should never
be somebody's asset.** Ghostr is local-first and encrypted at rest. Every LLM
call goes through a trait, so a local model drops in. Every byte that leaves the
device passes an egress policy and lands in an audit log you can read. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the honest version, including
what still leaks.

**3. A memory that can be silently edited is not a memory.** Append-only,
chained, anchored. Corrections are amendments, never rewrites.

## Status

**Pre-alpha. The workspace is scaffolded; no behaviour is implemented.**

Every type, trait, and signature is defined and documented. Every body is
`todo!()`. That is deliberate: the shape is meant to be reviewable before
anything is built, and the anchoring scheme and privacy boundary are far cheaper
to get right on paper than in a migration.

```console
$ cargo build --workspace        # 14 crates, compiles clean
$ cargo xtask scaffold-status    # what is still unimplemented, per crate
$ cargo xtask lint-deps          # dependency-direction rules, enforced in CI
```

| Document | What's in it |
| --- | --- |
| [docs/SPEC.md](docs/SPEC.md) | Data model, quest loop, Memoria pipeline, anchoring scheme, nostr event kinds, open questions |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Cargo workspace layout, dependency direction, key traits |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What an attacker gets in each scenario, and what stops them |
| [docs/ROADMAP.md](docs/ROADMAP.md) | M0–M4, each shippable on its own |
| [CLAUDE.md](CLAUDE.md) | Working conventions for this repo |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, CI, commit format, good first contributions |

Milestone **M0** (encrypted local journal with an anchored, verifiable history —
no LLM involved) is the next thing to be built. See the
[roadmap](docs/ROADMAP.md).

## Quickstart

> **Placeholder.** Nothing below works yet. It is here to pin down the shape of
> the CLI before it exists, and it will be replaced with real instructions when
> M0 lands.

```console
$ cargo install ghostr-cli          # not yet published

$ gst init                          # generate or import a NIP-06 seed, create the keystore
$ gst source add ~/notes            # point it at a markdown vault
$ gst note "shipped the parser, still stuck on the tz bug"
$ gst seal                          # compile today's footage, chain it, anchor it

$ gst quest                         # answer today's quests
$ gst fidelity                      # where the ghost is at
$ gst verify --from genesis         # re-derive the chain, check the Bitcoin attestation
```

## Platform constraints

These are non-negotiable and every design decision downstream respects them:

- **Rust**, cargo workspace, local-first. No mandatory server.
- **Identity is a nostr keypair** (secp256k1). NIP-06 derivation, NIP-19
  encoding, NIP-44 for encrypted payloads, addressable events for app data.
- **Bitcoin anchoring** via OpenTimestamps. Hashes only — never content.
- **Privacy is the product.** Encrypted at rest, LLM behind a trait, explicit
  egress policy, auditable egress log.
- **MIT licensed**, open source, contributor-friendly.

## Contributing

The most useful contribution right now is disagreement. The design is unbuilt,
which makes it cheap to change.

Start with the **Open Questions** at the end of [docs/SPEC.md](docs/SPEC.md) —
each one has a recommended answer and none of them are settled. Open an issue if
you think a recommendation is wrong, especially in the anchoring scheme or the
threat model.

Conventions for code and commits live in [CLAUDE.md](CLAUDE.md).

## License

MIT. See [LICENSE](LICENSE).
