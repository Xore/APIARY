#!/usr/bin/env python3
"""Regression test for #2113: HONEYPOT_SELF_IPS (a process-global env var)
was mutated by tests in two backend-service modules --
events.rs::fleet_attribution_tests::a_configured_public_address_is_recognised_as_ours
and dashboard.rs::tests::self_addresses_reads_config_and_always_keeps_the_tunnel.
Cargo runs a crate's tests on parallel threads by default, so the two
tests' set_var/remove_var/read sequences on the same variable could
interleave and fail intermittently depending on thread scheduling -- with
a failure message that reads like a product regression ("an unconfigured
public address was recognised as ours") rather than a test-harness race.
dashboard.rs's test even documented the hazard internally ("these run as
one test rather than racing each other"), but that only serialized cases
*within* its own module.

By the time this orchestrator run picked up #2113, the same bug had
already been independently filed as #2142 and fixed there (PR #2142,
"fix(dashboard): one serialized HONEYPOT_SELF_IPS test crate-wide",
merged 2026-08-26) -- #2113 is a duplicate that was never linked to that
PR, so it never auto-closed. The fix shipped is issue option 1 from
#2113's own "What needs to change" list: fold events.rs's two
configuration-dependent assertions into dashboard.rs's existing
serialized env test, and delete the standalone events.rs test that raced
it -- rather than adding a shared Mutex (option 2) or refactoring
self_addresses() off std::env (option 3). That leaves exactly one test in
the whole crate that mutates HONEYPOT_SELF_IPS, so there is nothing left
to race: the other module doesn't touch the variable at all any more.

This test locks in that source-level contract -- verified behaviorally by
running `cargo test -- fleet_attribution_tests dashboard::tests
--test-threads=8` ten consecutive times (0 failures) plus the full 481
test crate suite (0 failures) -- so a future edit can't quietly
reintroduce a second mutator of the same process-global variable.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND_SRC = REPO_ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "src"
DASHBOARD_RS = BACKEND_SRC / "dashboard.rs"
EVENTS_RS = BACKEND_SRC / "events.rs"

ENV_VAR = "HONEYPOT_SELF_IPS"
SOLE_MUTATOR_FN = "self_addresses_reads_config_and_always_keeps_the_tunnel"
# Named in #2113 as one half of the race; must not come back as a
# standalone test mutating the env var from a second module.
DELETED_RACING_TEST = "a_configured_public_address_is_recognised_as_ours"

MUTATION_RE = re.compile(rf'(?:set|remove)_var\("{ENV_VAR}"')

# Every fleet_attribution_tests function that never touched the env var --
# the fix must be additive (race removed) not subtractive (coverage lost).
SURVIVING_EVENTS_TESTS = [
    "a_fleet_address_is_never_an_attacker",
    "a_real_attacker_address_is_not_mistaken_for_ours",
    "the_tunnel_peer_is_dropped_rather_than_shown_as_the_source",
    "dionaeas_nested_peer_is_promoted_when_the_flat_field_is_absent",
    "a_nested_peer_that_is_also_ours_stays_unattributed",
    "the_promoted_field_still_wins_when_it_holds_a_real_address",
    "a_low_log_level_alone_does_not_make_a_line_noise",
    "the_explorer_excludes_the_fleet_probing_itself",
]


def _text(path):
    assert path.exists(), f"expected file missing: {path}"
    return path.read_text(encoding="utf-8")


def _extract_fn_body(text, signature_snippet, source):
    """Slice out a Rust function's full body via brace counting, from
    signature_snippet to its matching closing brace -- robust against the
    nested {}/vec![]/assert_eq!() blocks inside a test body, unlike a
    fixed-size or next-divider window."""
    start = text.index(signature_snippet)
    brace_start = text.index("{", start)
    depth = 0
    i = brace_start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    raise AssertionError(f"unbalanced braces scanning {signature_snippet!r} in {source}")


def test_source_files_exist():
    assert DASHBOARD_RS.exists(), f"dashboard.rs not found at {DASHBOARD_RS}"
    assert EVENTS_RS.exists(), f"events.rs not found at {EVENTS_RS}"


def test_events_rs_no_longer_mutates_the_env_var():
    """The whole point of the fix: events.rs must not set/remove
    HONEYPOT_SELF_IPS anywhere, at all -- if it does, a second concurrent
    mutator is back and the #2113 race is back with it."""
    text = _text(EVENTS_RS)
    matches = MUTATION_RE.findall(text)
    assert not matches, (
        f"events.rs still mutates {ENV_VAR} ({len(matches)} occurrence(s)) -- "
        "this reintroduces the #2113 race with dashboard.rs's test"
    )


def test_the_deleted_racing_test_has_not_come_back():
    text = _text(EVENTS_RS)
    assert f"fn {DELETED_RACING_TEST}" not in text, (
        f"events.rs re-introduces {DELETED_RACING_TEST}, the standalone test "
        "#2113 identified as racing dashboard.rs's env test"
    )


def test_exactly_one_function_in_dashboard_rs_mutates_the_env_var():
    text = _text(DASHBOARD_RS)
    test_mod_start = text.index("\nmod tests {")
    test_mod = text[test_mod_start:]
    fn_names = re.findall(r"\n    fn (\w+)\(", test_mod)
    fn_starts = [m.start() for m in re.finditer(r"\n    fn (\w+)\(", test_mod)]
    boundaries = fn_starts + [len(test_mod)]

    mutating_fns = set()
    for match in MUTATION_RE.finditer(test_mod):
        idx = match.start()
        for name, start, end in zip(fn_names, boundaries, boundaries[1:]):
            if start <= idx < end:
                mutating_fns.add(name)
                break

    assert mutating_fns == {SOLE_MUTATOR_FN}, (
        f"expected only {SOLE_MUTATOR_FN!r} to mutate {ENV_VAR} in dashboard.rs's "
        f"test module, found: {mutating_fns} -- a second mutator brings the race back"
    )


def test_sole_mutator_documents_the_crate_wide_contract():
    text = _text(DASHBOARD_RS)
    test_mod_start = text.index("\nmod tests {")
    fn_start = text.index(f"fn {SOLE_MUTATOR_FN}(", test_mod_start)
    preamble = text[test_mod_start:fn_start]
    assert "only test in the crate allowed to mutate" in preamble, (
        f"{SOLE_MUTATOR_FN} lost the doc comment stating the crate-wide "
        "contract -- a future reader has no way to know a second mutating "
        "test anywhere else in the crate is unsafe"
    )


def test_sole_mutator_retains_the_relocated_configuration_dependent_assertions():
    """#2113's fix folded events.rs's two configuration-dependent cases
    (an unconfigured public address is not ours / the same address
    configured is ours) into this test rather than dropping them -- the
    assertion set must be preserved, not just the race removed."""
    text = _text(DASHBOARD_RS)
    body = _extract_fn_body(text, f"fn {SOLE_MUTATOR_FN}(", "dashboard.rs")
    assert body.count('is_fleet_address("203.0.113.4")') >= 2, (
        'expected both the unconfigured (false) and configured (true) '
        'is_fleet_address("203.0.113.4") checks inside the sole mutator'
    )
    assert "an unconfigured public address must not count as ours" in body
    assert "the same address configured is ours" in body


def test_no_other_env_mutation_hides_outside_the_sole_mutator():
    """Belt-and-braces: even if a second HONEYPOT_SELF_IPS mutation landed
    inside dashboard.rs under a differently-named test, the earlier test
    would already catch it -- this asserts the same thing a different way,
    by removing the sole mutator's own body from the file and checking
    nothing mutation-shaped remains."""
    text = _text(DASHBOARD_RS)
    body = _extract_fn_body(text, f"fn {SOLE_MUTATOR_FN}(", "dashboard.rs")
    remainder = text.replace(body, "", 1)
    matches = MUTATION_RE.findall(remainder)
    assert not matches, f"found {ENV_VAR} mutation(s) in dashboard.rs outside of {SOLE_MUTATOR_FN}: {matches}"


@pytest.mark.parametrize("fn_name", SURVIVING_EVENTS_TESTS)
def test_events_rs_non_racing_tests_survive(fn_name):
    text = _text(EVENTS_RS)
    assert f"fn {fn_name}(" in text, (
        f"events.rs is missing {fn_name} -- #2113's fix must not drop test "
        "coverage, only the racing env mutation"
    )


def test_events_rs_value_only_test_still_covers_its_original_values():
    text = _text(EVENTS_RS)
    body = _extract_fn_body(text, "fn a_real_attacker_address_is_not_mistaken_for_ours(", "events.rs")
    for value in ('"46.19.138.10"', '"8.8.8.8"', '"2606:4700::1111"', '""', '"not-an-ip"'):
        assert value in body, f"a_real_attacker_address_is_not_mistaken_for_ours lost its {value} case"


def test_production_self_addresses_still_reads_the_env_var_directly():
    """#2113 offered a third option -- refactor self_addresses() off
    std::env so tests never touch process state -- but the fix actually
    shipped was test-only (option 1). Confirm the production code path is
    unchanged: it still reads the process-global variable directly, so
    deployments still configure HONEYPOT_SELF_IPS the same way as before."""
    text = _text(DASHBOARD_RS)
    body = _extract_fn_body(text, "fn self_addresses() -> Vec<String> {", "dashboard.rs")
    assert f'std::env::var("{ENV_VAR}")' in body


def test_is_fleet_address_still_delegates_to_self_addresses():
    text = _text(EVENTS_RS)
    body = _extract_fn_body(text, "pub fn is_fleet_address(ip: &str) -> bool {", "events.rs")
    assert "crate::dashboard::self_addresses()" in body


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
