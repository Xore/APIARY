#!/usr/bin/env python3
"""Regression test for #2030: claims.py's deterministic adjudication rung
compared an atomic claim against the *whole* ground_truth paragraph.

The rubric's ground truths are compound prose -- xor_decode_loop's is two
sentences, the XOR mechanism and a separate symmetry note -- but an atomic
claim only ever asserts one fact. Embedding the claim against the whole
paragraph dilutes that one fact against every other sentence's vocabulary,
so a correct restatement can land below the fixed 0.80 cosine bar simply
because the ground truth happened to also mention something else.

The fix (claims.split_ground_truth) breaks the ground truth into
sentence-level sub-facts and adjudicate_deterministic takes the best
claim-vs-sub-fact match instead of claim-vs-paragraph.

No Ollama here, same as tests/test_claims.py: a bag-of-words term-frequency
embedder stands in for a real embedding model. It's a legitimate stand-in
for exactly the property this bug depends on -- averaging in more unrelated
words pulls a vector's direction away from a short match's -- which is all
a cosine-similarity regression test needs.
"""
import importlib.util
import inspect
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CLAIMS_MODULE = REPO_ROOT / "analysis" / "ghidra" / "benchmarks" / "claims.py"


def _load_claims():
    spec = importlib.util.spec_from_file_location("claims_2030_fix", CLAIMS_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {CLAIMS_MODULE} as a module")
    mod = importlib.util.module_from_spec(spec)
    # claims.py's dataclasses rely on `from __future__ import annotations`,
    # which resolves annotations by looking the module up in sys.modules --
    # it must be registered there before exec_module runs.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


claims = _load_claims()


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _bag_of_words_embedder(*texts: str):
    """Deterministic term-frequency embedder over a vocabulary fixed across
    every text this test will embed, so every returned vector is the same
    length -- claims.cosine zips two vectors positionally, so embeddings of
    differing length would silently compare truncated garbage."""
    vocab = sorted({tok for text in texts for tok in _tokenize(text)})
    index = {tok: i for i, tok in enumerate(vocab)}

    def embed(text: str) -> list[float]:
        vector = [0.0] * len(vocab)
        for tok in _tokenize(text):
            vector[index[tok]] += 1.0
        return vector

    return embed


# A claim and the one sentence that actually answers it.
CLAIM_TEXT = "The function XORs each byte of the buffer using a single repeating key."
MATCH_SENTENCE = "The function XORs every byte of the buffer with a single repeating key byte."

# Four sentences sharing ~no vocabulary with the claim, so joining them with
# MATCH_SENTENCE dilutes a whole-paragraph embedding without changing what
# the paragraph, sentence-by-sentence, actually asserts.
FILLER_SENTENCES = (
    "It also validates a network socket handshake before accepting any inbound connection.",
    "A background thread periodically rotates the on disk log files to limit disk usage.",
    "The command line parser rejects any option string longer than sixty four characters.",
    "Error codes are translated into human readable messages before being written to stderr.",
)

ONE_SENTENCE_GROUND_TRUTH = MATCH_SENTENCE
FIVE_SENTENCE_GROUND_TRUTH = " ".join((MATCH_SENTENCE,) + FILLER_SENTENCES)


def _embedder():
    return _bag_of_words_embedder(
        CLAIM_TEXT, ONE_SENTENCE_GROUND_TRUTH, FIVE_SENTENCE_GROUND_TRUTH, *FILLER_SENTENCES
    )


def test_split_ground_truth_breaks_a_compound_paragraph_into_sentences():
    """#2030's own example: xor_decode_loop's ground truth is two sentences
    -- the XOR mechanism, then a symmetry note -- and the fix's unit of
    comparison must be the sentence, not the paragraph."""
    two_sentence = (
        "XORs every byte of a buffer with a single-byte key, in place, "
        "length-bounded loop. A generic decode/encode primitive, symmetric "
        "(same function decodes and encodes)."
    )
    facts = claims.split_ground_truth(two_sentence)
    assert len(facts) == 2
    assert facts[0].startswith("XORs every byte")
    assert facts[1].startswith("A generic decode")


def test_split_ground_truth_of_a_single_sentence_is_unchanged():
    one_sentence = "Walks a singly linked list, accumulating an integer field from each node."
    assert claims.split_ground_truth(one_sentence) == [one_sentence]


def test_split_ground_truth_of_empty_string_is_empty():
    assert claims.split_ground_truth("") == []
    assert claims.split_ground_truth("   ") == []


def test_adjudicate_deterministic_routes_through_the_sentence_split():
    """Structural guard: adjudicate_deterministic must actually call
    split_ground_truth rather than reintroduce a second, inline
    paragraph-comparison path that happens to pass the behavioural tests
    below for the wrong reason."""
    source = inspect.getsource(claims.adjudicate_deterministic)
    assert "split_ground_truth" in source


def test_claim_against_one_sentence_ground_truth_reaches_the_threshold():
    """Baseline: a claim that restates the entire (single-sentence) ground
    truth must clear the default 0.80 cosine bar."""
    embed = _embedder()
    claim = claims.Claim(case="xor_decode_loop", text=CLAIM_TEXT)
    assert claims.adjudicate_deterministic(claim, ONE_SENTENCE_GROUND_TRUTH, embed) is True


def test_claim_against_five_sentence_ground_truth_also_reaches_the_threshold():
    """The core #2030 regression case: the same claim, the same matching
    sentence, but now surrounded by four unrelated sentences in one
    ground_truth paragraph. Pre-fix, adjudicate_deterministic embedded the
    whole paragraph and this fell below 0.80 (see the next test for the
    exact number) even though the ground truth plainly contains the
    answer. Post-fix it must still adjudicate true because the fix checks
    each sentence and the matching one alone still clears the bar."""
    embed = _embedder()
    claim = claims.Claim(case="xor_decode_loop", text=CLAIM_TEXT)
    assert claims.adjudicate_deterministic(claim, FIVE_SENTENCE_GROUND_TRUTH, embed) is True


def test_function_does_not_compare_the_claim_against_the_whole_paragraph():
    """Makes the regression explicit rather than implicit in the pass/fail
    of the test above. Comparing the claim against the 5-sentence ground
    truth joined into one string -- the pre-#2030 behaviour -- lands below
    the 0.80 bar, proving the true result above cannot be coming from a
    whole-paragraph comparison; it must be coming from a per-sentence one."""
    embed = _embedder()
    whole_paragraph_similarity = claims.cosine(embed(CLAIM_TEXT), embed(FIVE_SENTENCE_GROUND_TRUTH))
    assert whole_paragraph_similarity < 0.80


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
