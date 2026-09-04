#!/usr/bin/env bash
# Builds a demo vault and shoots the served UI at real device sizes.
#
# Everything here goes through the real binary. The screenshots are of the
# product, not of a mock, so a screen that does not exist cannot appear in one
# and a screen that regressed cannot keep looking fine.
#
#   tools/ui-preview/demo.sh [out-dir]
#
# Needs: a release build, python3, and Playwright (globally installed is fine —
# set PLAYWRIGHT_PATH to its package directory).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$ROOT/docs/ui/shots}
WORK=${WORK:-$(mktemp -d)}
GHOSTR=$ROOT/target/release/ghostr
: "${PLAYWRIGHT_PATH:=playwright}"
export PLAYWRIGHT_PATH

# Not a secret: this vault holds invented notes and is thrown away. A real one
# never takes its passphrase from an environment variable.
export GHOSTR_PASSPHRASE="correct horse battery staple"

[ -x "$GHOSTR" ] || { echo "build first: cargo build --release" >&2; exit 1; }

NOTES=$WORK/notes
VAULT=$WORK/vault
rm -rf "$NOTES" "$VAULT"
G() { "$GHOSTR" --home "$VAULT" "$@"; }

python3 "$ROOT/tools/ui-preview/seed.py" "$NOTES"
FIRST=$(ls "$NOTES" | head -1 | sed 's/\.md$//')

G init --tz Asia/Bangkok >/dev/null
G source add markdown "$NOTES" >/dev/null
G source sync >/dev/null

# Seal every day but today: today stays open, because an unsealed day with a
# box to write in is the screen a user actually opens.
for i in $(seq 0 28); do
  G memoria --date "$(date -u -d "$FIRST +$i day" +%Y-%m-%d)" >/dev/null 2>&1 || true
done

G persona distill >/dev/null && G persona adopt >/dev/null

# A month of answered quests, so the score has a sample and a trend. Answered
# day by day: the generator will not re-ask a claim that is still open, so
# issuing a whole month first would produce one day's worth.
for i in $(seq 0 28); do
  day=$(date -u -d "$FIRST +$i day" +%Y-%m-%d)
  G quest issue "$day" >/dev/null 2>&1 || true
  k=0
  for id in $(G quest list 2>/dev/null | grep -oE "qst:[0-9a-f]{8}"); do
    k=$((k + 1))
    # Improving over the month, so the trend has a direction to show.
    if [ $((k % 7)) -eq 0 ] || { [ "$i" -lt 12 ] && [ $((k % 3)) -eq 0 ]; }; then
      G quest answer "$id" reject >/dev/null 2>&1 || true
    else
      G quest answer "$id" confirm >/dev/null 2>&1 || true
    fi
  done
done

# Today's, left unanswered: the Quests screen is the daily interaction, and an
# empty one shows the empty state rather than the screen under review.
G quest issue today >/dev/null 2>&1 || true

# An OS-assigned port rather than the default 7749, so this never lands on a
# vault the user is already serving. The banner is printed only after the bind
# succeeds, so a URL in the log is a URL to *this* server.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
G serve --http "$PORT" > "$WORK/serve.log" 2>&1 &
SERVE=$!
trap 'kill $SERVE 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do
  grep -qE "http://127\.0\.0\.1:$PORT/#t=" "$WORK/serve.log" && break
  sleep 0.25
done
URL=$(grep -oE "http://127\.0\.0\.1:$PORT/#t=[0-9a-f]{64}" "$WORK/serve.log" | head -1)
[ -n "$URL" ] || { echo "serve did not start"; cat "$WORK/serve.log"; exit 1; }
kill -0 $SERVE 2>/dev/null || { echo "serve exited"; cat "$WORK/serve.log"; exit 1; }

node "$ROOT/tools/ui-preview/shots.mjs" "$URL" "$OUT"
python3 "$ROOT/tools/ui-preview/shrink.py" "$OUT"
echo "vault: $VAULT"
