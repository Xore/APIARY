"""Interim polarity-aware matching for rubric `forbidden` lists (#1946, option 1).

The corpus scorer checked forbidden terms by plain substring containment, so it
could not tell "this function has a buffer overflow" from "this function
prevents buffer overflows". On #159's benign near-neighbour control
(`safe_strcpy`) that flipped a correct answer into a failed gate, purely on
wording -- twice in four temperature-0 runs of the same digest (issue #1946).

This module is option 1 from that issue, deliberately simple and deterministic
because the scorers that use it run at temperature 0 with fixed seeds: an
occurrence of a forbidden term is discarded only when a small, fixed character
window immediately before it carries one of a closed list of negation or
prevention cues. Anything else still counts as a hit. Same input, same verdict,
every time.

Known limits, accepted on purpose rather than papered over:
  * The cue list is closed and inflection-blind: "prevents" is listed,
    "prevented" is not; contractions match literally ("doesn't"), but other
    spellings do not.
  * The window is positional, not grammatical. "Without further analysis, this
    function appears to be benign" would drop the hit although nothing negated
    the claim; rare in practice, worth knowing.
  * A true assertion far from its cue ("...and that means there is no exploit
    path, so the function is safe" long after "exploit") behaves exactly as
    containment would.

It is an interim measure either way. The durable home for false-positive
control is claim-pool adjudication (#1805-f), where a wrong assertion is
adjudicated as a false claim instead of matched lexically.
"""

import re
from typing import Iterable

# Exactly the cue list scoped in issue #1946, plus nothing more. Matching is on
# word boundaries so "not" does not fire inside "nothing".
NEGATION_CUES = (
    "prevent",
    "prevents",
    "not",
    "no",
    "avoids",
    "avoiding",
    "protects against",
    "does not",
    "doesn't",
    "without",
)

# Characters immediately preceding a term occurrence that are searched for a
# cue. Must exceed the longest cue ("protects against", 16 chars) plus a short
# connective ("a ", "an "), or phrases like "protects against a buffer
# overflow" would be missed; must stay small so distant mentions of "not"
# cannot clear an unrelated hit.
CUE_WINDOW_CHARS = 24

_CUE_PATTERN = re.compile(
    r"\b(?:" + "|".join(
        # Longest first so alternation can never stop at a prefix cue inside a
        # phrase cue ("does not" vs "not").
        re.escape(cue).replace(r"\ ", r"\s+")
        for cue in sorted(NEGATION_CUES, key=len, reverse=True)
    ) + r")\b",
    re.IGNORECASE,
)


def _negated_before(lowered_text: str, start: int) -> bool:
    """True iff a cue occurs wholly inside the window ending where the hit starts."""
    window_start = max(0, start - CUE_WINDOW_CHARS)
    return _CUE_PATTERN.search(lowered_text[window_start:start]) is not None


def forbidden_hit(text: str, terms: Iterable[str]) -> bool:
    """Polarity-aware replacement for plain substring containment (#1946).

    True iff some occurrence of some term stands WITHOUT a negation/prevention
    cue immediately before it -- i.e. only then should a gate fire and the
    answer lose its point. Case-insensitive; every occurrence is examined, so a
    single unnegated mention anywhere fires even if other mentions were negated.
    """
    lowered = (text or "").lower()
    for term in terms:
        needle = (term or "").lower()
        if not needle:
            continue
        start = lowered.find(needle)
        while start != -1:
            if not _negated_before(lowered, start):
                return True
            start = lowered.find(needle, start + len(needle))
    return False
