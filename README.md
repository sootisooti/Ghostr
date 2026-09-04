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

M2 is under way, and the daily loop now runs end to end on a stock build. The
persona model distils, versions, and diffs: voice, relationships, and routines
are computed from the corpus exactly — sentence lengths and punctuation rates
are arithmetic, not estimates — while opinions, boundaries, and lore wait for a
model rather than being guessed. On top of it, quests are issued with their
answers already committed, answered, and scored:

```console
$ ghostr quest issue                # commits to every answer, then asks
$ ghostr quest list                 # the ghost's answer stays sealed
$ ghostr quest answer qst:a1b2c3d4 correct --text "not how I'd put it"
$ ghostr fidelity                   # never a bare percentage
```

And on a screen, because a daily ritual that takes five minutes does not get
done. `ghostr serve` binds a Unix socket by default; `--http` adds a loopback
listener, and putting it on the wifi for a phone takes one more flag that exists
to make you say so out loud:

```console
$ ghostr serve --http
listening on ~/.local/share/ghostr/ghostr.sock
  a unix socket: no port, no network, owner-only

open  http://127.0.0.1:7749/#t=10bdc441…
  this machine only
```

The page is one file compiled into the binary — no CDN, no npm, no build step —
and it declares a manifest and an icon, so **Add to Home Screen** gives you an
app rather than a bookmark. Four screens: today's recap with a box to write in,
the day's quests, the score, and the vault's state. The token is in the URL
fragment, which browsers never send to a server and proxies never log.

Without a model the generator asks the kinds it can do well — clozes over
sentences you wrote and recall claims about routines it counted — rather than
inventing the three that need a model to write their prompt. What is *not* yet
there: those three kinds, a keyboard loop fast enough to be a daily ritual, and
committing the day's quest set into the footage Merkle tree. Relays are still
defined with `todo!()` bodies, so the shape is reviewable before it is built.

`ghostr-testkit` landed ahead of all of it: a synthetic corpus generator that
hands back its own ground truth, a scripted model, a deterministic clock and
RNG, and a permanent set of hostile fixtures.

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

What remains of milestone **M2** is the model-written quest kinds and a quest UI
worth using daily. See the [roadmap](docs/ROADMAP.md).

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
$ ghostr source add nostr --pubkey npub1… --relay wss://relay.example
$ ghostr source sync                       # pull from every enabled source
$ ghostr journal add "shipped the parser"  # straight into the encrypted vault
$ ghostr recap today                       # today's recap, sealing nothing
$ ghostr memoria --date today              # compile and seal today's footage
$ ghostr thread list                       # what is still open
$ ghostr footage list                      # sealed days, with their chain links
$ ghostr footage show 1                    # highlights, people, mood, open threads
$ ghostr persona distill                   # propose a model of you; read the diff
$ ghostr persona adopt                     # nothing uses it until you adopt it
$ ghostr persona show                      # what the ghost thinks you are like
$ ghostr quest issue                       # today's claims, answers committed first
$ ghostr quest list                        # answer them; the ghost's answer is sealed
$ ghostr fidelity                          # the score, with what qualifies it
$ ghostr serve --http                      # the same loop, on a screen
$ ghostr egress log                        # everything that has left this device
$ ghostr anchor                            # stamp the chain tip via OpenTimestamps
$ ghostr verify                            # re-derive the chain from genesis
$ ghostr passphrase                        # rewrap the seed; the journal is untouched
$ ghostr sync                              # encrypted backup to your relays
$ ghostr restore                           # rebuild on a new machine, seed only
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

A nostr feed is the one source that carries somebody else's writing, and it says
so in the same place:

```console
$ ghostr source add nostr --pubkey npub180cvv07… --relay wss://relay.example
added src:9b3538a1  nostr_feed
  trust        third-party
  sensitivity  public
  network      yes — this source will talk to the internet
```

**third-party** is a security control rather than a quality score. Content at
that level is summarised and kept, and it never becomes a voice exemplar, never
sources a claim about what you believe, and never contributes to a relationship
or routine the ghost thinks is yours. The adapter returns it unconditionally —
not as a function of whose feed you named — so it cannot be relaxed from a
settings file. Whether your *own* signed notes should be an exception is
[SPEC §14 Q23](docs/SPEC.md), and the answer today is no.

The relays are the feed's own. Adding a feed does not touch the relay list your
encrypted backup is published to, and reading a feed needs no publishing relays
configured at all.

Nor is the relay believed about what it served: every event's signature, author
and kind is re-checked after the transport has already checked them, and
anything the filter did not ask for is dropped and counted where you will see
it.

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

**What this gives you with no AI involved:** an encrypted local journal whose
history cannot be silently altered, with a Bitcoin timestamp proving each day
existed — plus a ghost distilled by counting rather than guessing, and a daily
loop that checks it against you and reports a number with its evidence attached.
What a model adds is the three quest kinds that need one to write their prompt,
and opinions and lore in the persona — see the [roadmap](docs/ROADMAP.md).

### On your phone

The daily loop is a thing you do in a spare minute, which means it has to be on
the device you actually carry. `ghostr serve` puts it there — the vault stays on
your computer and the phone is only a screen onto it.

**Two thresholds first**, because both are invisible until you hit them:

| Before this works | You need |
| --- | --- |
| `ghostr persona distill` | **20 sealed memories.** Roughly three weeks of journalling, or one `source sync` over notes you already have. |
| `ghostr fidelity` | **10 scored quests.** A score over fewer is noise, so there is not one. |

Then, on the computer holding the vault:

```console
$ ghostr serve --http 0.0.0.0:7749 --lan

  THIS VAULT IS NOW ON THE NETWORK, at 0.0.0.0:7749.

  Anyone who can reach that address and holds the token below can read
  your memories, your quests, and your score. [...]

open  http://192.168.1.42:7749/#t=b23c0486...

  point a phone camera at this:

      █▀▀▀▀▀█  ▀▄▄▀▄▀ ▄ █ █ ▄▀█  █ █▀▀█ █▀▀▀▀▀█
      █ ███ █ █ ▀▄ █▀▀▄ ▄▄▀▄▄   ▀██▀▀ █ █ ███ █
      ...
```

Point the camera at the code and the phone opens the page — the alternative is
typing a 64-character token on a phone keyboard, which nobody does twice.

In Safari, **Share → Add to Home Screen** gives it an icon and drops the browser
chrome, so it opens like an app.

### Sealing the day without remembering to

The loop only works if days actually close, and nobody remembers a command every
evening. Set `auto_seal = true` and `ghostr serve` closes each day once it is
over.

It lives in `serve` rather than a cron job for one reason: **cron would need
your passphrase**, in an environment variable or a file. `serve` already holds an
unlocked vault, so nothing new has to hold a secret.

It waits `seal_grace_hours` (6 by default) past the cutoff before closing a day,
because people write the day up afterwards — on the train, the next morning, on
Sunday for the whole week. Sealing at midnight would strand those notes as
amendments to a day that is already closed. It also fills in days missed while
the machine was off, oldest first, up to `seal_backfill_days`.

It is **off by default**, because sealing is irreversible: a sealed footage is
immutable and a correction becomes an amendment in a later day. Turning that on
for someone who did not ask is a decision about their history made on their
behalf.

`--lan` is a second flag on purpose: `--http 0.0.0.0:7749` is one keystroke away
from `--http 127.0.0.1:7749`, and the difference is who on the wifi can read your
journal. The token is the only thing standing between them and it, and this is
plaintext HTTP — so use it on a network you trust, and stop the server when you
are done. There is no account and no password reset: the token is printed once,
and restarting `serve` mints a new one.

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

The most useful contribution right now is disagreement. Most of the design is
still cheap to change.

Start with the **Open Questions** at the end of [docs/SPEC.md](docs/SPEC.md) —
each one has a recommended answer and none of them are settled. Open an issue if
you think a recommendation is wrong, especially in the anchoring scheme or the
threat model.

Conventions for code and commits live in [CLAUDE.md](CLAUDE.md).

## License

MIT. See [LICENSE](LICENSE).
