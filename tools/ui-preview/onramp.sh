#!/usr/bin/env bash
# Walks a vault up the on-ramp and checks the page at every rung.
#
# The stages exist so that neither surface offers a step the other knows is
# impossible. That claim is about a *sequence*: each rung has to show the right
# thing while the vault is actually on it, which a fixture cannot fake and a
# unit test cannot reach, because the gate is JavaScript.
#
#   tools/ui-preview/onramp.sh
#
# Needs: a debug or release build, and Playwright (globally installed is fine —
# set PLAYWRIGHT_PATH to its package directory).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
GHOSTR=${GHOSTR:-$ROOT/target/debug/ghostr}
: "${PLAYWRIGHT_PATH:=playwright}"
export PLAYWRIGHT_PATH

# Not a secret: this vault holds invented notes and is thrown away.
export GHOSTR_PASSPHRASE="correct horse battery staple"

[ -x "$GHOSTR" ] || { echo "build first: cargo build -p ghostr-cli" >&2; exit 1; }

VAULT=$WORK/vault
rm -rf "$VAULT"; mkdir -p "$VAULT"
G() { "$GHOSTR" --home "$VAULT" "$@"; }

G init >/dev/null

# A port of its own, so running this while a real `ghostr serve` is up does not
# fail on a collision with it — or, worse, drive that vault instead of this one.
PORT=${PORT:-$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')}
G serve --http "127.0.0.1:$PORT" >"$WORK/serve.log" 2>&1 &
SERVE=$!
trap 'kill $SERVE 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do grep -q '#t=' "$WORK/serve.log" && break; sleep 0.25; done
URL=$(grep -o "http://127.0.0.1:$PORT/#t=[0-9a-f]*" "$WORK/serve.log" | head -1)
if [ -z "$URL" ]; then
  echo "server never printed a URL:" >&2
  cat "$WORK/serve.log" >&2
  exit 1
fi

check() { node "$ROOT/tools/ui-preview/onramp.mjs" "$URL" "$1"; }

echo "on-ramp:"
check empty

G journal add "First note. Synthetic, like every fixture in this repo." >/dev/null
check building_corpus

# One short of the floor would still be `building_corpus`; the point of the
# rung is the boundary, so go exactly to it.
NEED=$(G status | awk '$1=="next"{print}' | grep -o '[0-9]*/[0-9]*' | cut -d/ -f2)
HAVE=$(G status | awk '$1=="memories"{print $2}')
for i in $(seq $((HAVE + 1)) "${NEED:-20}"); do
  G journal add "Note $i. Synthetic filler so a persona has something to distil." >/dev/null
done
check ready_to_distill

G persona distill --adopt >/dev/null
check no_open_quests

G quest issue >/dev/null
check answering

echo "every rung offered a step that works"
