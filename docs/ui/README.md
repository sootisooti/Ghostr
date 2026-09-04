# Looking at the UI

`ghostr serve` puts the daily loop on a page a phone can open. This directory
is how that page gets reviewed by someone who is not going to read the Rust:
[gallery.md](gallery.md) is every screen at five real device sizes, taken from
the running product.

**To comment, quote the screen and the device** — "iPhone SE, Quests: the five
verdict buttons wrap into a ragged block" is actionable; "the buttons look off"
is not. Open questions already known are at the bottom of this file.

## The screenshots are of the product, not of a mock

The pipeline is: build a vault out of invented notes with the real binary, serve
it with `ghostr serve --http`, point a headless browser at it, click the real
nav, screenshot. Nothing is drawn by hand. A screen that does not exist cannot
appear in the gallery, and a screen that regressed cannot keep looking right —
which is the entire reason to keep images in the repo rather than a Figma link.

The harness refuses to record a broken run. If the page shows an error card
instead of content, it stops with a message and writes nothing. This is not
theoretical: an earlier run left a server from a *previous* run holding the
port, every request came back 401, and twenty screenshots of the "this tab has
no token" screen were committed as if they were the design. Two things came out
of that — the check in the harness, and a fix in the product, because `ghostr
serve` was printing its URL, token and QR code *before* binding the listener and
would happily hand you a link to somebody else's vault.

## Regenerating

```sh
cargo build --release
tools/ui-preview/demo.sh          # writes docs/ui/shots/ and docs/ui/gallery.md
```

Needs `python3` and Playwright. A global install is fine — point
`PLAYWRIGHT_PATH` at its package directory:

```sh
PLAYWRIGHT_PATH=/usr/lib/node_modules/playwright tools/ui-preview/demo.sh
```

Playwright is deliberately **not** a workspace dependency. A screenshot harness
has no business in the build graph of a thing that holds a user's memories
(CLAUDE.md §4.9), and nothing in CI depends on it.

`gallery.md` is generated from the same device and tab lists that drove the
browser, so it cannot describe a device that was not shot. Don't edit it; edit
`tools/ui-preview/shots.mjs`.

The shots are palette-quantised on the way out (`shrink.py`, ~2.4 MB → ~950 KB,
visually identical on flat UI), because a gallery that is meant to be
regenerated adds its full weight to git history every time. It is skipped with a
note if Pillow is not installed.

## What is in the demo vault

`tools/ui-preview/seed.py` writes thirty days of markdown notes — wins, drags,
open tasks, a few people, the odd musing — and `demo.sh` runs the real loop over
them:

| | |
| --- | --- |
| 29 days sealed | so the chain, the recap and the Vault counts are real |
| today left open | the unsealed day with a box to write in is the screen a user actually opens |
| persona distilled and adopted | quests need something to quiz you on |
| a month of answered quests | so Fidelity has a sample, an interval and a trend |
| today's quests unanswered | the Quests screen is the daily interaction; an empty one shows the empty state instead |

**Every name and note is invented.** No real personal data goes in a fixture,
not even redacted (CLAUDE.md §4.14).

**The numbers move between runs.** Which quests are held out, and which get
decoys, come from the composition root's RNG, which is real entropy outside
tests. So the score is 87% one run and 92% the next. The layout is what is
under review here; if you need a fixed number, that is a `Clock`/`Rng` seam the
demo does not currently use.

## Devices, and why these five

| Device | Why it is in the list |
| --- | --- |
| iPhone 13 Pro Max | the common large phone; the reference |
| iPhone SE | 320 CSS pixels — the narrowest thing anyone still uses, and where wrapping breaks |
| Pixel 7 | Android, and a different device pixel ratio |
| iPad mini | the smallest tablet; the first size where a phone layout starts to look stretched |
| Desktop 1440 | a laptop, where a phone layout looks *most* stretched |

## Known, and open for comment

- **Fixed, worth a second opinion.** The bottom nav used to span the whole
  window. On a 1440px monitor that put "Today" in one corner and "Vault" in the
  other, a thousand pixels from the content they belong to. It now lines up with
  the reading column, so the bar still reaches the screen edge but its buttons
  sit under the text. Compare `desktop-*.png` and `ipad-mini-*.png`.
- **Open: the verdict buttons on a 320px screen.** On iPhone SE the five
  verdicts wrap 1 / 1 / 2 / 1. Every button is still a full tap target, but the
  arrangement is accidental rather than designed. A two-column grid would be
  tidier; a deliberate "primary on its own row, the rest in pairs" might read
  better. This is a taste call and has not been made.
- **Open: a tablet and a laptop get a phone layout.** One centred column, one
  screen at a time, tab bar at the bottom. It is honest and it works, but an
  iPad has room to show the day and its quests side by side. Whether that is
  worth a second layout — or whether one layout everywhere is the point — is a
  product decision, not a CSS one.
