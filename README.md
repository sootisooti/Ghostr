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

**Pre-alpha. Milestones M0 and M1 are implemented; M2 onward is scaffolded.**

M0 works end to end: an encrypted local vault, markdown ingest, deterministic
daily footage, a Bitcoin-anchored hash chain, and `ghostr verify`.

M1 adds the daily recap: journal and structured-log sources, the six-stage
Memoria pipeline with threads and amendments, local embeddings over an encrypted
vector index, and — before any remote provider existed — the egress gate, its
policy, its pseudonymising redactor, and its append-only audit log.

**No model is compiled into a default build**, which makes "works offline"
checkable in one command rather than claimed:

```console
$ cargo tree -p ghostr-cli | grep -c ghostr-llm
0
$ cargo tree -p ghostr-cli --features llm-local | grep -c ghostr-llm
2
```

`--features llm-local` adds an Ollama-compatible runtime on loopback, and
`--features llm-remote` adds providers that can only be reached through the
gate. (The one network dependency a default build *does* carry is `ureq`, for
OpenTimestamps — `ghostr anchor` is the single command that touches the
network.) Either way the pipeline falls back to its deterministic path when a model
is absent, so a runtime being down costs the recap its polish and never costs
the day its seal.

Everything beyond M1 — the persona model, quests, the fidelity score, relays —
is defined and documented with `todo!()` bodies, so the shape is reviewable
before it is built. `ghostr-testkit` is implemented ahead of them: a synthetic
corpus generator that hands back its own ground truth, a scripted model, a
deterministic clock and RNG, and a permanent set of hostile fixtures.

```console
$ cargo build --workspace        # 14 crates, compiles clean
$ cargo test --workspace         # 400+ tests, none touching the network
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

Milestone **M2** (the persona model, quests, and the fidelity score) is the next
thing to be built. See the [roadmap](docs/ROADMAP.md).

## Quickstart

A default build runs **entirely offline with no model**. `anchor` is the one
command that touches the network, and it degrades to a recorded failure rather
than blocking anything.

```console
$ cargo build --release                    # not yet published to crates.io
$ alias ghostr=./target/release/ghostr

$ ghostr init --tz Asia/Bangkok            # generate a nostr keypair, encrypt to disk
$ ghostr source add markdown ./notes/      # says what you are agreeing to, first
$ ghostr source add structlog ./health/ --schema health
$ ghostr source sync                       # pull from every enabled source
$ ghostr journal add "shipped the parser"  # straight into the encrypted vault
$ ghostr recap today                       # today's recap, sealing nothing
$ ghostr memoria --date today              # compile and seal today's footage
$ ghostr thread list                       # what is still open
$ ghostr footage list                      # sealed days, with their chain links
$ ghostr footage show 1                    # highlights, people, mood, open threads
$ ghostr egress log                        # everything that has left this device
$ ghostr anchor                            # stamp the chain tip via OpenTimestamps
$ ghostr verify                            # re-derive the chain from genesis
```

Health and location logs are added as `Secret`, which means they never leave the
device under any policy — and `source add` says so where you will read it:

```console
$ ghostr source add structlog ./health/ --schema health
added src:9f21ab04  structured_log
  trust        self-reported
  sensitivity  secret  (never leaves this device)
  network      no
```

Before anything can go to a remote model, you can see exactly what would:

```console
$ ghostr memoria --date today --dry-run --remote
dry run for 2026-08-24 — nothing was sent
  5 memory(ies) in the window
  2 withheld as Secret (never offered to the gate at all)

  [0] would send 521 byte(s), 2 name(s) pseudonymised
      ...
      <corpus trust="first-party">
      Dinner with @Person A and @Person B about #moving.
      </corpus>
```

`ghostr verify` exits non-zero on a broken chain, so it composes:

```console
$ ghostr verify && echo "history intact"
chain   OK  (2 day(s) from genesis)
roots   OK

anchors 0 confirmed, 1 pending, 1 unanchored
history intact
```

**What M0 gives you, with no AI involved:** an encrypted local journal whose
history cannot be silently altered, with a Bitcoin timestamp proving each day
existed. The persona model, quests, and the fidelity score arrive in M2 — see the
[roadmap](docs/ROADMAP.md).

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
