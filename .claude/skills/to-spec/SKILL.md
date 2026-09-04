---
name: to-spec
description: Turn a question the docs do not answer into a SPEC §14 Open Question with a recommendation, instead of deciding it silently in code. Use whenever grill-with-docs finds the spec ambiguous.
---

# An unanswered question becomes an Open Question, not a default

CLAUDE.md §9: *"When the spec is ambiguous, don't silently pick."* The failure
mode this prevents is not a wrong decision — it is a decision nobody knows was
made. A default buried in a function is unreviewable; a numbered question in
SPEC §14 is something a human can say no to.

## Write it as

Append to **docs/SPEC.md §14**:

```markdown
**Q23. Are the user's own nostr notes third-party input?**

`NostrFeedAdapter` tags everything `TrustLevel::ThirdParty`, including notes
signed by the vault's own key. That is safe and it is also wrong: the user's
own writing is the best voice evidence there is, and this discards it.

*Recommendation:* no — a note whose author pubkey equals the vault identity,
whose signature verifies, is first-party. It needs the identity check to be in
the adapter, which it is.
```

Four parts, all required:

| Part | Why |
| --- | --- |
| The question, as a question | So it can be answered yes or no |
| What the code does **today** | So a reader knows the cost of doing nothing |
| Why it is genuinely open | Distinguishes "undecided" from "not yet written down" |
| A recommendation | An open question without one is work handed back, not forward |

## Then keep going

Adding the question does **not** block the task. Implement the rest under the
current behaviour, state the assumption in the PR body, and leave the question
open. Only stop entirely if proceeding either way would be unsafe or would make
the work useless if the answer comes back the other way.

## Resolving one later

Resolving an Open Question means **moving the answer into the body of the spec**
and striking the question with a note on what was decided and why — not deleting
it (CLAUDE.md §8). The record of what was considered is worth as much as the
decision.

## The check

`grep -c '^\*\*Q' docs/SPEC.md` went up by one, and the new entry has all four
parts. If the answer went into a code comment instead, this step did not happen.
