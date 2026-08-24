#!/usr/bin/env python3
"""Test hellpot/xff_trust_patch.py (#1876) and its composition with #1419's.

Two build-time string patches run in sequence against the same file, and
the second matches on the first's output. That coupling is invisible at
review time and silently breaks if either patch's text is touched -- the
patch would raise, the image build would fail, and the reason would be a
string mismatch several layers down. So it is asserted here.

The fixture is upstream's real getRealRemote(), which is also what
router_patch.py's own OLD constant matches, so there is no third copy of
that text to drift.

Usage: hellpot/tests/test_xff_trust_patch.py
"""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROUTER_PATCH = HERE.parent / "router_patch.py"
XFF_PATCH = HERE.parent / "xff_trust_patch.py"

# Upstream yunginnanet/HellPot internal/http/router.go, the shape both
# patches are written against.
UPSTREAM = '''package http

import (
	"github.com/valyala/fasthttp"
)

func getRealRemote(ctx *fasthttp.RequestCtx) string {
	xrealip := string(ctx.Request.Header.Peek(config.HeaderName))
	if len(xrealip) > 0 {
		return xrealip
	}
	return ctx.RemoteIP().String()
}
'''


def load(path: Path, target: Path):
    """Load a patch module with its TARGET pointed at a fixture."""
    source = path.read_text().replace(
        'Path("/build/internal/http/router.go")', f'Path({str(target)!r})'
    )
    spec = importlib.util.spec_from_loader(path.stem, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102
    return module


class XffTrustPatch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.target = Path(self.dir.name) / "router.go"
        self.target.write_text(UPSTREAM)
        self.addCleanup(self.dir.cleanup)

    def apply_both(self):
        load(ROUTER_PATCH, self.target).main()
        load(XFF_PATCH, self.target).main()
        return self.target.read_text()

    def test_the_second_patch_matches_the_first_patchs_output(self):
        # The coupling this file exists to protect: xff_trust_patch's OLD is
        # router_patch's NEW. Either one edited alone breaks the build.
        result = self.apply_both()
        self.assertIn("trust XFF from the tunnel peer only (#1876)", result)
        self.assertIn("drop spoofable X-Real-IP trust", result)

    def test_it_refuses_to_run_before_router_patch(self):
        # Applied to upstream directly there is nothing to match, and the
        # patch must say so rather than silently leaving the file alone.
        with self.assertRaises(SystemExit):
            load(XFF_PATCH, self.target).main()

    def test_applying_twice_changes_nothing(self):
        first = self.apply_both()
        load(XFF_PATCH, self.target).main()
        self.assertEqual(first, self.target.read_text())

    def test_the_result_is_valid_go(self):
        self.apply_both()
        # gofmt -e parses and reports syntax errors; a patch that produces
        # unparseable Go fails the image build with a far less obvious
        # message than this one.
        proc = subprocess.run(
            ["gofmt", "-e", str(self.target)], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_it_adds_only_the_imports_that_are_missing(self):
        # A duplicate import is a compile error, not a no-op.
        self.target.write_text(UPSTREAM.replace('import (\n', 'import (\n\t"net"\n'))
        result = self.apply_both()
        self.assertEqual(result.count('"net"'), 1, result)
        self.assertEqual(result.count('"strings"'), 1, result)

    def test_the_trust_rule_is_the_one_that_makes_it_safe(self):
        # #1419 removed header trust because it was spoofable. This may only
        # reintroduce it behind the tunnel-peer check, and must take the
        # last hop -- Cloudflare appends rather than replaces, so the
        # leftmost hop is client-controlled.
        result = self.apply_both()
        self.assertIn('const tunnelPeerIP = "10.8.0.1"', result)
        self.assertIn("host != tunnelPeerIP", result)
        self.assertIn("hops[len(hops)-1]", result)


if __name__ == "__main__":
    unittest.main()
