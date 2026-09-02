#!/usr/bin/env python3
"""#2290: the URL-credential leak rule must exempt reserved example hosts,
and nothing else.

Redaction code has to be tested, and testing it means committing a URL that
looks like a credential so the sanitiser can be shown stripping it --
`vault-worker/tests/test_worker.py` asserts exactly that, and before this
exemption the gate flagged it.

The exemption is keyed on a property that makes a leak impossible rather
than on a filename: RFC 2606 / RFC 6761 reserved names (`.example`, `.test`,
`.invalid`, `.localhost`) are guaranteed never to resolve to anyone's
service, so a credential written against one is unusable by construction.
That keeps the vault-worker fixture readable as the plain URL it is
testing, which matters -- a redaction test whose input is stitched together
from fragments is much harder to read as proof that redaction works.

Note the deliberate asymmetry with THIS file, which does assemble its
fixtures at runtime (see the helpers below). A gate's own self-test needs
values the gate must *flag*, and no property can exempt those without
punching a hole in the rule being tested. Runtime assembly is the
convention the checker already documents for that narrow case (#2285,
#2604). Ordinary code gets the readable literal; only the gate's self-test
pays the fragment cost.

The risk in any exemption is that it quietly widens. These tests pin both
directions -- that reserved hosts pass, and that every real host and every
other pattern still fails -- so a future edit cannot loosen it without
turning one of them red.
"""
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check-public-leaks.py"

_spec = importlib.util.spec_from_file_location("check_public_leaks", CHECKER)
leaks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(leaks)



# This file is a test *for* the leak gate, so it necessarily needs strings
# that the gate must flag. Written literally, they would make this file a
# finding -- the self-harbor problem the checker already documents for
# #2285 and #2604. The established convention there is to assemble such
# values at runtime from fragments, which is what these helpers do: the
# forbidden sequence never appears contiguously in the source, while the
# value handed to the patterns at runtime is byte-for-byte the real thing.
def _cred_url(host: str) -> str:
    return "http" + "s://" + "user" + ":" + "hunter2" + "@" + host + "/x"


def _private_key_marker() -> str:
    return "-----BEGIN " + "OPENSSH " + "PRIVATE KEY" + "-----"


def hits(text: str) -> list[str]:
    """Reasons the pattern table reports for `text`, exemptions applied."""
    found = []
    for pattern, reason in leaks.PATTERNS:
        for match in pattern.finditer(text):
            if leaks._is_exempt(reason, match):
                continue
            found.append(reason)
    return found


class ReservedHostUrlExemptionTest(unittest.TestCase):
    def test_reserved_hosts_are_not_reported(self):
        for host in ("evil.example", "foo.test", "nope.invalid", "box.localhost"):
            with self.subTest(host=host):
                self.assertEqual(
                    hits(_cred_url(host)), [],
                    f"{host} is reserved and can never resolve to a real service",
                )

    def test_the_actual_fixture_in_the_vault_worker_test_is_clean(self):
        """The concrete string this exemption exists for."""
        fixture = REPO_ROOT / "vault-worker" / "tests" / "test_worker.py"
        if not fixture.exists():          # the worker lands in this same PR
            self.skipTest("vault-worker test fixture not present")
        self.assertEqual(
            [r for r in hits(fixture.read_text())
             if r == leaks.URL_CREDENTIAL_REASON], [],
        )

    # --- the exemption must not widen -------------------------------

    def test_real_hosts_are_still_reported(self):
        for host in ("evil.com", "example.com", "internal.corp",
                     "sub.example.org", "10.0.0.5"):
            with self.subTest(host=host):
                self.assertIn(
                    leaks.URL_CREDENTIAL_REASON,
                    hits(_cred_url(host)),
                    f"{host} is a resolvable host -- a credential here is real",
                )

    def test_a_reserved_name_used_as_a_label_not_a_tld_is_still_reported(self):
        """`example.com` and `test.evil.com` merely *contain* a reserved
        word; only a reserved suffix makes a host unresolvable."""
        for host in ("example.com", "test.evil.com", "invalid.co.uk"):
            with self.subTest(host=host):
                self.assertIn(
                    leaks.URL_CREDENTIAL_REASON,
                    hits(_cred_url(host)),
                )

    def test_other_patterns_are_never_exempted_by_a_reserved_host(self):
        """A private key next to a reserved hostname is still a private key."""
        text = ("see " + _cred_url("thing.example") + "\n"
                + _private_key_marker() + "\n")
        self.assertIn("private key", hits(text))

    def test_exemption_predicate_ignores_unrelated_reasons(self):
        """_is_exempt keys on the URL-credential reason specifically."""
        for _pattern, reason in leaks.PATTERNS:
            if reason == leaks.URL_CREDENTIAL_REASON:
                continue
            with self.subTest(reason=reason):
                match = leaks.PATTERNS[-1][0].search(
                    _cred_url("thing.example")
                )
                self.assertFalse(leaks._is_exempt(reason, match))


if __name__ == "__main__":
    unittest.main()
