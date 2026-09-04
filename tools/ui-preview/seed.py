#!/usr/bin/env python3
"""Writes a synthetic month of notes for the UI preview.

Every name, place and event here is invented. Fixtures are synthetic
(CLAUDE.md §4.14) — a screenshot harness is exactly the kind of thing that
quietly acquires somebody's real diary otherwise.

Deterministic: same notes every run, so two screenshot runs differ only where
the UI differs.
"""

import datetime
import pathlib
import random
import sys

DAYS = 30

PEOPLE = ["@nan", "@somchai", "@priya", "@ravi"]
PLACES = ["the river path", "the tea shop", "the co-working floor", "the night market"]
WINS = [
    "Shipped the parser after three days stuck on it",
    "Finally got the migration to run clean",
    "Rewrote the retry loop and it is half the size",
    "Fixed the timezone bug that has been haunting the seal",
    "Got the phone build working over the wifi",
]
DRAGS = [
    "Meetings all morning, nothing to show for it",
    "Spent the afternoon chasing a flake that was my own test",
    "Too tired to think straight after lunch",
    "Waited on a review that never came",
]
TASKS = [
    "call the bank about the transfer",
    "book the flight",
    "do the groceries",
    "renew the lease",
    "reply to the tax letter",
]
MUSINGS = [
    "Still not sure the daily loop survives a bad week. Worth watching.",
    "I keep writing the same three sentences about focus. That is probably the signal.",
    "Wrote less today and thought more. Not sure that trade is real.",
    "The best hour was the one nobody booked.",
]


def main(out: pathlib.Path, end: "datetime.date") -> None:
    rng = random.Random(20260105)
    out.mkdir(parents=True, exist_ok=True)

    # Ending today, so the Today screen has something on it. A preview whose
    # first screen reads "nothing today" shows the empty state and hides the
    # one people actually look at.
    start = end - datetime.timedelta(days=DAYS - 1)
    for i in range(DAYS):
        day = start + datetime.timedelta(days=i)
        lines = [f"---", f"date: {day}", "---", ""]
        lines.append(rng.choice(WINS) if i % 3 else rng.choice(DRAGS))
        lines.append("")
        if i % 2 == 0:
            who = rng.choice(PEOPLE)
            where = rng.choice(PLACES)
            lines.append(f"Walked {where} with {who}. Good to catch up.")
            lines.append("")
        # A recurring task, so routines have something to count, plus a one-off.
        lines.append(f"- [{'x' if i % 4 == 3 else ' '}] {TASKS[i % len(TASKS)]}")
        if i % 5 == 0:
            lines.append(f"- [ ] {rng.choice(TASKS)}")
        lines.append("")
        lines.append(rng.choice(MUSINGS))
        lines.append("")
        (out / f"{day}.md").write_text("\n".join(lines))
    print(f"wrote {DAYS} notes to {out}")


if __name__ == "__main__":
    end = (
        datetime.date.fromisoformat(sys.argv[2])
        if len(sys.argv) > 2
        else datetime.date.today()
    )
    main(pathlib.Path(sys.argv[1]), end)
