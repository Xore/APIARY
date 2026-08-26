"""Polarity-aware matching for rubric `forbidden` term lists (#1946).

A `forbidden` list is a false-positive control: it exists so a model that
wrongly claims the analyzed code is dangerous loses the control point. Plain
substring containment cannot tell an assertion from its denial -- or from a
comparison that attributes the hazard to something else entirely. Live from
the Tier A baseline runs (#1805-b): qwen2.5-coder:7b lost safe_strcpy's point
in two of six runs for writing that the function is "a common security
measure to prevent buffer overflows" -- a correct description of safe code,
and exactly the reasoning the control case wants to reward.

This module is deliberately a documented heuristic, interim until claim-pool
adjudication (#1805-f) scores prose claims structurally and retires it:

* Left word boundary only (`(?<!\\w)`): "invulnerable" does not carry
  "vulnerable", while inflections like "buffer overflows" still do. Staying
  lenient on the right keeps the control strong against genuine claims.
* A cue ending shortly before the hit flips its polarity, allowing only
  non-word characters (punctuation, markdown) and lone articles in between:
  "prevent buffer overflows", "is not vulnerable", "alternative to a
  vulnerable strcpy".

Known limitations, accepted rather than pretended away: a double negation
("does not fail to prevent") flips the wrong way; a payload mentioned but not
followed ("the evidence says 'appears to be benign'") has no local cue and
still counts as asserted. Both need reference resolution, which is what
#1805-f builds.
"""

import re

# Cues are matched against already-lowercased text.
_CUES = (
    r"\bnot\b",
    r"\bno\b",
    r"\bnever\b",
    r"\bwithout\b",
    r"\bcannot\b",
    r"\w+n['’]?t\b",  # doesn't / doesnt / won't / isn't ...
    r"prevent\w*",
    r"avoid\w*",
    r"protect\w*",
    r"mitigat\w*",
    r"defend\w*",
    r"lack\w*",
    r"missing",
    r"devoid",
    r"immune",
    r"incapable",
    r"unable",
    r"free(?:\s+(?:of|from))?",
    # Reference shifts: the hazard belongs to something other than the
    # analyzed artifact ("a secure alternative to a vulnerable strcpy").
    r"alternativ\w*\s+to",
    r"replacement\s+for",
    r"replac\w+",
    r"rather\s+than",
    r"instead\s+of",
    r"in\s+contrast\s+to",
    r"unlike",
)

# Between a cue's end and the term start, allow bounded sequences of: runs of
# non-word characters (spaces, punctuation, markdown asterisks), lone articles
# or other functor words ("to prevent buffer overflows", "alternative to a
# vulnerable strcpy"), and the light verbs negated phrases run through
# ("doesn't contain a stack overflow"). Content words are excluded on purpose:
# "no amount of renaming hides this buffer overflow" keeps its early "no" from
# flipping the assertion it actually makes.
_FUNCTORS = (
    "a", "an", "the", "of", "to", "and", "or", "any", "all", "its", "their",
    "this", "that", "these", "those",
    "can", "could", "may", "might", "will", "would",
    "contain", "contains", "have", "has", "had",
    "include", "includes", "show", "shows", "exhibit", "exhibits",
)
def _flex(cue: str) -> str:
    """Intra-cue separators survive markdown and punctuation ('alternative**
    to'), so a written space or \\s+ becomes a short non-word gap."""
    return cue.replace(r"\s+", "[^\\w]{0,6}").replace(" ", "[^\\w]{0,6}")


_CUE_PIECE = (
    "(?:" + "|".join(_flex(c) for c in _CUES) + ")"        # a cue ...
    "(?:"                                   # ... then a short bridge of ...
    r"[^\w]+"                               # punctuation/whitespace/markdown
    r"|\s+(?:" + "|".join(_FUNCTORS) + r")\b"  # or one functor word
    "){0,6}$"
)
_CUE_AT_TERM = re.compile(_CUE_PIECE)

# Occurrences considered are whole words on their left edge only: "vulnerable"
# must not be carried by "invulnerable", while plural/inflected forms on the
# right ("buffer overflows") keep counting -- leniency belongs on the side
# that strengthens the control, not weakens it.
_OCCURRENCE = {}  # needle -> compiled r"(?<!\w)<needle>", filled lazily


def _occurrences(needle: str):
    pat = _OCCURRENCE.get(needle)
    if pat is None:
        pat = re.compile(r"(?<!\w)" + re.escape(needle))
        _OCCURRENCE[needle] = pat
    return pat


# Context examined before each candidate hit. The bridge cap above bounds how
# far back a matching cue may sit; this window just has to be longer than any
# cue phrase that could legitimately connect within that cap.
WINDOW = 80


def asserted_hits(text: str, terms) -> list[str]:
    """The distinct terms whose occurrence *asserts* the hazard.

    A term counts when at least one of its occurrences carries no flipping cue
    before it; later denied mentions cannot rescue an asserted one ("no buffer
    overflow here, but sloppy strcpy invites buffer overflow").
    """
    lowered = (text or "").lower()
    hits: list[str] = []
    for term in terms:
        needle = (term or "").strip().lower()
        if not needle:
            continue
        asserted = False
        for _ in _occurrences(needle).finditer(lowered):
            if not _CUE_AT_TERM.search(lowered[max(0, _.start() - WINDOW):_.start()]):
                asserted = True
                break
        if asserted and needle not in hits:
            hits.append(needle)
    return hits
