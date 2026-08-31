# Ghostr — Roadmap

**Status:** Draft v0.4 · M0 and M1 shipped, M2 complete, M3 under way

Five milestones. The rule for all of them: **each one ships something a person
would actually use, on its own, with no promise of the next.** If a milestone's
only value is that it unblocks the following one, it's a task list, not a
milestone, and it gets merged into its neighbour.

No dates. Ordering and exit criteria only.

| | Milestone | Ships | LLM? | Network? |
| --- | --- | --- | --- | --- |
| **M0** | Vault & Chain | Encrypted journal with Bitcoin-anchored, verifiable history | No | OTS only |
| **M1** | Memoria | Daily structured recap from your own notes | Yes (local) | OTS only |
| **M2** | Ghost & Quests | The loop: persona, quests, fidelity score | Yes | OTS only |
| **M3** | Nostr Surface | Publishing, sync, feed ingest, public attestation | Yes | Relays |
| **M4** | Fidelity & Federation | Multi-device, third-party verification, richer sources, UI | Yes | Relays |

---

## M0 — Vault & Chain

> **Ships:** an encrypted, local-first journal whose history cannot be silently
> altered, with a Bitcoin timestamp proving each day existed.

Genuinely useful with zero AI: anyone who needs a tamper-evident personal log —
a researcher's lab notebook, a founder's decision journal, someone documenting
harassment — can use this and stop here.

**Scope**
- Workspace skeleton: `core`, `crypto`, `store`, `anchor`, `engine`, `cli`,
  `testkit`. CI, `rustfmt`, `clippy`, `cargo-deny`, MSRV pin.
- `ghostr-core`: `Memory`, `Footage`, `Sensitivity`, ids, canonical CBOR,
  tagged hashing, Merkle tree.
- `ghostr-crypto`: NIP-06 derivation, NIP-19 encoding, Argon2id KEK, keystore
  (file + OS keychain), `Signer` for the local key.
- `ghostr-store`: encrypted SQLite, per-row AAD, append-only memory table,
  blob store, migrations.
- `ghostr-anchor`: the commitment chain (pure), OTS client, upgrade queue,
  `.ots` persistence, verification against a block header source.
- CLI: `init`, `ingest`, `memoria`, `footage list|show`, `anchor`, `verify`,
  `status`. (`note`, `unlock`, and `export` moved to M1 with the daemon; the
  binary is `ghostr`, not `ghostr`.)
- **Footage at M0 is mechanical** — window, memory ids, commitment, `sealed_at`.
  No highlights, no mood, no threads. Those need a model and arrive in M1. The
  chain is complete and correct from day one, which is the point: getting the
  hashing scheme wrong later means a migration nobody can perform.

**Exit criteria**
- [x] `ghostr verify` passes from genesis and names the exact `seq` on tampering.
- [x] Golden hash vectors committed; changing serialization fails a test loudly.
- [x] A test asserts no plaintext memory content appears in the raw DB bytes.
- [x] Crypto-shred a memory; the chain still verifies (SPEC Q6).
- [x] NIP-06/19 test vectors from the NIPs repo pass verbatim.
- [x] An empty day still seals and the chain stays gapless.
- [ ] A day sealed today is OTS-**confirmed** within 24h on mainnet.
      *Submission works and produces a valid `.ots`; upgrading a pending proof
      to a Bitcoin attestation is the one M0 criterion carried into M1.*
- [ ] Missed cutoff (machine asleep) seals on wake.
      *Half-done in M1: `cutoff::pending_windows` computes every window a
      sleeping machine missed, in order and gapless. What is still absent is the
      scheduler that runs them, which arrives with the job queue.*

**Explicitly not in M0:** any LLM, any relay, persona, quests, entities.

---

## M1 — Memoria

> **Ships:** a daily structured recap compiled from your own notes, by a model
> running on your machine, that never phones anywhere.

Stands alone as a private daily-review tool. Still no ghost.

**Scope**
- `ghostr-llm`: `LanguageModel` + `Embedder` traits, `ModelDescriptor` with
  locality, prompt assembly, structured output with schema validation.
- **The egress gate lands here, before any remote provider exists.** Policy,
  `EgressLog`, redaction, pseudonymization, `ghostr egress log`. Building the gate
  after the first provider is how gates get bypassed.
- One local provider (Ollama-compatible) and one remote (opt-in, off by default),
  so the trait is proven against two shapes.
- `ghostr-ingest` with `markdown`, `journal`, `structlog` adapters.
- `ghostr-memoria`: the six-stage pipeline (SPEC §6) — highlights, `PersonBeat`s,
  `MoodReading`, threads with stable `ThreadId`s, `unresolved`, amendments.
- Local entity resolution + an encrypted vector index. Local embeddings only
  (SPEC Q13, resolved: encrypted exhaustive scan, not `sqlite-vec`).
- CLI: `source add/list/sync`, `recap [date]`, `thread list`, `egress log`,
  `journal add/import`, `memoria --dry-run --remote`.

**Exit criteria**
- [x] Full pipeline runs offline with an ~8B-class local model, no network except
      OTS. *Also runs with no model at all: every model call falls back to the
      deterministic path, so a runtime being down costs the recap its polish and
      never costs the day its seal (I3).*
- [x] Every highlight cites ≥ 1 `memory_id`; validation drops those that don't.
      *`drop_unevidenced` is the filter, `validate_draft` the backstop, and the
      count of what was dropped is printed rather than swallowed.*
- [x] A thread opened on day 3 and resolved on day 9 shows as a closed loop.
- [x] `Sensitivity::Secret` is denied to every remote provider under every policy
      configuration — table test, all branches.
- [x] `ghostr egress log` shows a complete record after a remote run; a
      `--dry-run --remote` prints exactly what *would* leave, before it leaves.
- [x] Late-arriving memories become amendments, never retro-edits (SPEC I2).
- [x] Snapshot tests on prompts; a prompt change shows as a reviewable diff.

**Carried into M2**
- A *remote* memoria run. `--dry-run --remote` shows exactly what would leave
  and the gate is complete behind it, but routing a real run at a remote
  provider is not wired up — M1's claim is the offline pipeline, and shipping a
  remote path nobody had a reason to use yet would be scope for its own sake.
- Retrieval. The vector index and the local embedder are implemented and
  tested, but nothing queries them yet: retrieval is what persona and quests
  need, and they arrive in M2.

**Not in M1:** persona, quests, relays.

**Landed after M1, ahead of M2.** `ghostr-testkit` is implemented — the
deterministic clock and RNG, a scripted model, a recording egress log, a
synthetic corpus generator that hands back its own ground truth, and the
adversarial fixtures. M2's first exit criterion is a 30-day run on a synthetic
corpus, which cannot be written until that crate exists; building it alongside
M2 would have meant ad-hoc fixtures per test, rewritten once the shape was
clear. Core also gained the `proptest` invariants CLAUDE.md §6 asks for on
hashing and Merkle proofs, which found and fixed a loose depth bound in
`verify_inclusion`.

---

## M2 — Ghost & Quests

> **Ships:** the actual product. A ghost that models you, asks you to check it,
> and reports a score you can't fake.

**Scope**
- `ghostr-persona`: distillation from footage, all six facets, versioning,
  `PersonaDiff`, retrieval with a token budget.
- `ghostr-quests`: generation across all six `QuestKind`s, priority selection
  (SPEC §4.2), answer commitments (I6), holdout marking, decoys, verdict intake,
  `PersonaDelta` queue.
- `Scorer`: per-quest scoring, Wilson intervals, Brier + ECE calibration,
  `IntegritySignals`, convergence evaluation.
- Quest UI in the CLI — a fast keyboard loop, because a daily ritual that takes
  90 seconds gets done and one that takes 5 minutes does not.
- CLI: `quest`, `fidelity [--facet]`, `persona show/diff/history`, `ask` (talk to
  the ghost).

**Progress**
- [x] `ghostr-persona`: distillation, versioning, `PersonaDiff`, retrieval, and
      `persona show/distill/adopt/diff/history`. Voice, relationships, and
      routines are computed exactly; opinions, boundaries, and lore await the
      model path.
- [x] `ghostr-quests`: answer commitments, holdout marking, decoys, priority
      selection, verdict intake, the `PersonaDelta` queue, and the `Scorer` —
      Wilson intervals, Brier + ECE, `IntegritySignals`, convergence.
- [x] The loop, wired: `quest issue/list/show/answer`, `fidelity`, quest
      storage with an immutable commitment column, and corrections that reach
      distillation exactly once.
- [x] Generation for the three kinds that need a model to write their prompt:
      `VoiceProbe`, `Counterfactual`, `Prediction`. Written through
      `ghostr_quests::llm`, validated against a schema, and admitted only if the
      kind is one of those three, the claim cites evidence, and the ghost's
      answer is non-empty. Without a model the generator still emits fewer
      quests of the kinds it can do well (SPEC Q7) — on a stock build that
      remains `Cloze`, `Preference`, and `FactRecall`, byte-identical to before
      (`no_drafts_is_exactly_todays_behaviour`).
- [x] A loop fast enough to be a daily ritual: `ghostr serve` puts the day's
      quests, the day's recap, the score, and a box to write in on a page a
      phone can install to its Home Screen, one tap per verdict. The CLI's
      `quest answer` remains for scripts.
- [ ] A recurring task that is *completed* is invisible to routine distillation.
      `routines()` counts threads still open at each cutoff, and a thread opened
      and closed the same day appears in no `open_threads` anywhere — so the
      commonest shape of a habit ("- [ ] run" then "- [x] run") produces no
      routine. Fixing it means footage recording closed loops with their titles,
      which changes a hashed commitment and needs a migration plan (CLAUDE.md
      §4.7).

**Exit criteria**
- [x] 30-day run on a synthetic corpus produces a fidelity score with a Wilson
      interval, a per-facet breakdown, and integrity signals beside it
      (`quest_flow::a_month_of_answered_quests_produces_a_qualified_score`).
      Whether the score *rises* is a claim about a model that is not wired in
      yet, so it is not asserted.
- [x] Held-out corrections provably never reach distillation — the store
      refuses the insert, the intake refuses to build the delta, and the
      integration suite asserts the queue is non-empty before checking it.
- [x] Answer commitments verify on every verdict; a mismatch rejects it. The
      answer is recomputed from the quest, so an edited claim fails too.
- [x] Decoys are detected and `decoy_confirm_rate` is surfaced beside the score,
      and a confirmed decoy is called out on the spot rather than only in the
      monthly aggregate.
- [ ] Local-model quality benchmarked per `QuestKind`; the floor is documented
      and the pipeline degrades by kind rather than emitting bad quests (Q7).
- [x] `persona diff` between two versions is readable by someone who isn't a
      developer.
- [ ] Quest sets and verdicts are committed into the day's Merkle tree and
      anchored. Today a score names the chain `seq` it was computed at, which
      dates it but does not commit the quests themselves.
- [ ] Median time to answer 5 quests, measured on real users: under 2 minutes.
      The page exists; the measurement does not.

**Not in M2:** relays, multi-device, publishing.

---

## M3 — Nostr Surface

> **Ships:** your ghost on nostr — encrypted backup and sync across your devices,
> your feed as a source, and an optional public attestation.

**Progress:** the crypto and the codec are done. `ghostr-crypto` carries NIP-44
v2 (checked against all 128 reference vectors), NIP-19 `nprofile`/`naddr`, the
NIP-01 event id, and a `Signer` the local keystore implements. `ghostr-nostr`
turns payloads into events and back: the `ghostr/v1/...` `d`-tag namespace, the
NIP-78 mirror, per-kind account separation, and ghost disclosure enforced by the
builder. What remains is the transport — the relay websocket — plus NIP-59 gift
wrap, which is blocked on [SPEC §14 Q20](SPEC.md#14-open-questions).

**Scope**
- `ghostr-nostr`: relay client, NIP-44 v2, event codec for kinds 31780–31789 with
  the NIP-78 (30078) mirror, NIP-65 relay lists, NIP-59 gift wrap (opt-in),
  NIP-46 remote signer.
- Ghost keypair (account `1'`) + signed `GhostManifest`; revocation flow.
- Encrypted sync/backup: footage, persona versions, quests to relays. Single
  sealing device named in the manifest (SPEC Q10); others are read/ingest
  replicas.
- Nostr feed and RSS ingest adapters. **`TrustLevel::ThirdParty` enforcement is a
  hard gate here** — this is the milestone where hostile text first enters the
  corpus (THREAT_MODEL §T7).
- Optional `FidelityAttestation` publishing (31786), signed and chain-bound.
- Optional ghost publishing (kind 1) with mandatory disclosure tags (SPEC §9.3),
  off by default, explicit per-scope opt-in.
- Padding, jitter, and a Tor/SOCKS5 option for relay and calendar traffic.
- CLI: `relay add/list`, `sync`, `ghost create/revoke`, `publish attestation`,
  `restore`.

**Exit criteria**
- [ ] Full restore from relays on a clean machine, seed only.
- [ ] Two devices, one sealer: the replica cannot advance `seq`; a forced attempt
      is rejected by the store's uniqueness constraint.
- [ ] No plaintext identity data on any relay — asserted by a test that inspects
      published event bodies (SPEC I9).
- [x] Every ghost-authored event carries disclosure tags; a test proves an event
      without them cannot be constructed — `GhostNoteBuilder` is the only
      constructor and emits them unconditionally
      (`a_ghost_note_cannot_be_built_without_disclosure`).
- [ ] Injected instructions in an ingested nostr note do not alter footage or
      produce a persona claim — adversarial corpus fixture in CI.
- [x] Ciphertext lengths are bucketed; publish times jittered. Bucketing is
      NIP-44 v2's own plaintext padding rather than a second pass over the
      ciphertext — `nip44_bucketing_already_quantises_length` is what holds that
      claim to account, and a ciphertext-side padder would only have corrupted
      the payload.
- [ ] Anchor receipts default to local-only; publishing requires an explicit flag
      and uses the anchor key (SPEC Q5).
- [x] The kind block is checked against the live registry — fetched
      2026-08-27, no kind in 31700–31899 is registered, so 31780–31789 is free.
      **NIP not yet submitted**, so the block is unclaimed rather than ours; the
      `ghostr/v1/...` `d` tag is the real identifier and the NIP-78 mirror is
      what makes that true in practice (SPEC Q3).

**Not in M3:** GUI, third-party verifier tooling.

---

## M4 — Fidelity & Federation

> **Ships:** a ghost anyone can independently verify, fed by everything you've
> ever posted, with a UI your non-technical friend can use.

**Scope**
- **Standalone verifier** — a small binary/library that validates an exported
  bundle (chain, inclusion proofs, OTS, manifest signature, recomputed score)
  with no Ghostr install and no trust in our client. Until this exists,
  "provably his ghost" rests on trusting our binary; this is the milestone that
  removes that.
- Social archive adapters: X/Twitter, Mastodon, Reddit exports, generic
  GDPR-dump ingest with dated backfill.
- Richer structured logs: places, health, media, habits.
- Calibration work: convergence thresholds re-derived from real cohort data
  (SPEC Q9), per-facet convergence reporting, long-horizon `Prediction` scoring.
- "Ghost speaks" mode with guardrails: `Boundary` facet enforcement, refusal on
  low-confidence topics, always-on disclosure.
- Native desktop shell over the same local API the CLI and the served page use.
- Direct OP_RETURN anchoring as an opt-in alternative to OTS (SPEC Q4).
- Adapter authoring guide + `ghostr-testkit` conformance suite, so third-party
  sources are contributable without touching the core.

**Exit criteria**
- [ ] A third party verifies a published attestation end to end using only the
      standalone verifier and a Bitcoin header source.
- [ ] A 5-year X archive backfills into a coherent chain of dated footage.
- [ ] Convergence thresholds updated from real data, with the analysis published.
- [ ] "Ghost speaks" refuses out-of-distribution and boundary-violating prompts
      more often than it confabulates — measured, not asserted.
- [ ] A contributor ships an ingest adapter without modifying any existing crate.
- [ ] Desktop shell reaches feature parity with the CLI for the daily loop.

---

## Cross-cutting, every milestone

Not optional, not deferred to "polish":

- **THREAT_MODEL.md updated in the same PR** as any change to its subject matter.
  A stale threat model on a privacy product is a lie with a timestamp.
- **SPEC.md updated in the same PR** as any behaviour change. Docs are the source
  of truth here, not a description of it.
- **No network calls in tests.** Real relay/OTS interaction is `#[ignore]`d and
  run nightly.
- **Open Questions get resolved as they're settled** — the answer moves into the
  body of the spec and the question is struck, with a note saying what was
  decided and why.
- **Migrations are written before the schema change that needs them**, and a test
  migrates a fixture DB from every prior version.

---

## Deliberately unscheduled

Not "later" as a soft no — genuinely undecided, and listed so nobody assumes
they're coming.

- **Death, succession, inheritance** (SPEC Q12). The obvious endgame for a
  digital ghost, and it needs its own spec and its own threat model, largely
  about the consent of people in the corpus who are still alive.
- **Fine-tuning / LoRA on the corpus.** Would break diffability, auditability,
  and deletability — the three properties the persona model exists to have.
- **Mobile.** The store and engine are portable; the daily loop wants a phone.
  No plan yet.
- **Multi-user or shared ghosts.** Different product.
- **Voice / video cloning.** Different consent problem entirely.
