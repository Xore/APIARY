#!/usr/bin/env python3
"""Test wordpot/wordpot_patch.py -- five build-time patches, three files.

The patches match on exact upstream text and run at image build time, so a
mismatch surfaces as a failed build with a string error several layers
down. Worse, the ones that *do* apply can still be wrong in ways a build
never notices: a listener that never starts, a field the worker reads that
the sensor never writes, a spliced import in the wrong place.

What is really being protected here is #1908. wordpot used to resolve
X-Forwarded-For whenever REMOTE_ADDR was the WireGuard tunnel peer -- which
on its raw port is every request, since portbridge relays it without
`:pp`. Confirmed against the running stack: a request to the raw port
carrying `X-Forwarded-For: 198.51.100.77` was logged as
"198.51.100.77 probed for the login page". Anyone could file their traffic
under any address. The rule is gone, and these tests exist so it cannot
come back quietly.

The fixture is upstream gbrindisi/wordpot at the pinned ref, copied rather
than abbreviated -- the hellpot equivalent was abbreviated and passed while
the real patch failed on anchors the fixture had trimmed away.

Usage: wordpot/tests/test_wordpot_patch.py
"""
import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATCH = HERE.parent / "wordpot_patch.py"

UPSTREAM_LOGGER = '''import logging
from wordpot import app

LOGGER = logging.getLogger('wordpot')


def setup_logging():
    handler = logging.FileHandler(app.config['LOGFILE'])
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
'''

UPSTREAM_INIT = '''from flask import Flask
from wordpot.plugins import PluginsManager

app = Flask('wordpot')

pm = PluginsManager()
'''

UPSTREAM_MAIN = '''#!/usr/bin/env python

from wordpot import app, pm, parse_options, check_options
from wordpot.logger import *

check_options()

if __name__ == '__main__':
    parse_options()
    LOGGER.info('Checking command line options')
    check_options()

    LOGGER.info('Honeypot started on %s:%s', app.config['HOST'], app.config['PORT'])
    app.run(debug=app.debug, host=app.config['HOST'], port=int(app.config['PORT']))
'''


def load(root: Path):
    """Load the patch module with its targets pointed at a fixture tree."""
    spec = importlib.util.spec_from_file_location("wordpot_patch", PATCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.LOGGER_TARGET = root / "wordpot" / "logger.py"
    module.INIT_TARGET = root / "wordpot" / "__init__.py"
    module.MAIN_TARGET = root / "wordpot.py"
    return module


class WordpotPatch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        (self.root / "wordpot").mkdir()
        (self.root / "wordpot" / "logger.py").write_text(UPSTREAM_LOGGER)
        (self.root / "wordpot" / "__init__.py").write_text(UPSTREAM_INIT)
        (self.root / "wordpot.py").write_text(UPSTREAM_MAIN)
        self.module = load(self.root)

    def apply(self):
        self.module.main()
        return {
            "logger": (self.root / "wordpot" / "logger.py").read_text(),
            "init": (self.root / "wordpot" / "__init__.py").read_text(),
            "main": (self.root / "wordpot.py").read_text(),
        }

    def test_all_five_patches_apply(self):
        out = self.apply()
        self.assertIn("JSON logging", out["logger"])
        self.assertIn("port-preserving remote_addr", out["init"])
        self.assertIn("_PreservePortMiddleware(app.wsgi_app)", out["init"])
        self.assertIn("Traefik-only second listener", out["main"])

    def test_the_middleware_no_longer_decides_the_source(self):
        # The defect itself. Any reintroduction of header trust here is a
        # spoofing hole on the raw port, where the condition it would test
        # is true for every single request.
        out = self.apply()
        self.assertNotIn("HTTP_X_FORWARDED_FOR", out["init"])
        self.assertNotIn("_TUNNEL_PEER_IP", out["init"])
        self.assertIn("'%s:%s' % (addr, port)", out["init"])

    def test_the_forwarding_headers_are_recorded_not_resolved(self):
        # The worker needs them to adjudicate the proxied path, so they
        # have to reach the log line -- as evidence, never as a verdict.
        out = self.apply()
        self.assertIn("HTTP_X_FORWARDED_FOR", out["logger"])
        self.assertIn("HTTP_CF_CONNECTING_IP", out["logger"])
        self.assertIn("'xff'", out["logger"])
        self.assertIn("'cf_connecting_ip'", out["logger"])

    def test_the_log_line_carries_the_door_and_the_port(self):
        # dst_port is what tells the two paths apart; src_port is what the
        # via_port join needs. Resolving XFF used to drop the port, leaving
        # a bare address that the worker's parser rejected outright -- so
        # every proxied event was silently discarded.
        out = self.apply()
        self.assertIn("entry['dst_port']", out["logger"])
        self.assertIn("entry['src_port']", out["logger"])
        self.assertIn("entry['src_ip']", out["logger"])

    def test_the_sentence_is_left_alone(self):
        # Everything already on disk resolves from the message text, and
        # the worker still falls back to it.
        out = self.apply()
        self.assertIn("'message': record.getMessage()", out["logger"])

    def test_the_second_listener_starts_before_the_first_blocks(self):
        # app.run() never returns, so a listener started after it would
        # never exist -- and nothing about that would look wrong.
        out = self.apply()
        proxied = out["main"].index("_proxied_thread.start()")
        blocking = out["main"].index("app.run(debug=app.debug")
        self.assertLess(proxied, blocking)
        self.assertIn("_proxied_thread.daemon = True", out["main"])

    def test_the_second_listener_uses_the_agreed_port(self):
        out = self.apply()
        self.assertIn(str(self.module.WORDPOT_PROXIED_PORT), out["main"])
        self.assertEqual(self.module.WORDPOT_PROXIED_PORT, 8090)

    def test_applying_twice_changes_nothing(self):
        once = self.apply()
        self.module.main()
        self.assertEqual(once["logger"], (self.root / "wordpot" / "logger.py").read_text())
        self.assertEqual(once["init"], (self.root / "wordpot" / "__init__.py").read_text())
        self.assertEqual(once["main"], (self.root / "wordpot.py").read_text())

    def test_it_refuses_to_run_against_drifted_upstream(self):
        # Claiming success while silently matching nothing is the failure
        # mode worth guarding: the image would build and the sensor would
        # log plain text with no fields at all.
        (self.root / "wordpot" / "logger.py").write_text(
            UPSTREAM_LOGGER.replace("formatter = logging.Formatter", "fmt = logging.Formatter")
        )
        with self.assertRaises(SystemExit):
            self.module.main()

    def test_the_result_parses(self):
        # The injected code is Python 2 in production, but every construct
        # used is valid in both, so a parse here catches the splice errors
        # that matter (indentation, unbalanced braces from .format).
        out = self.apply()
        for name, text in out.items():
            with self.subTest(file=name):
                ast.parse(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
