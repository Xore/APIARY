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

# Upstream yunginnanet/HellPot internal/http/router.go at the pinned ref,
# both the function router_patch.py rewrites and the log builder
# xff_trust_patch.py adds a field to. Copied from the real file rather than
# abbreviated: the patches match on exact text, so a fixture that is merely
# similar would pass while the real build failed.
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

func hellPot(ctx *fasthttp.RequestCtx) {
	path, pok := ctx.UserValue("path").(string)
	if len(path) < 1 || !pok {
		path = "/"
	}

	remoteAddr := getRealRemote(ctx)

	slog := log.With().
		Str("USERAGENT", string(ctx.UserAgent())).
		Str("REMOTE_ADDR", remoteAddr).
		Interface("URL", string(ctx.RequestURI())).Logger()
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

    def test_both_patches_apply_to_the_same_file(self):
        result = self.apply_both()
        self.assertIn("record the forwarded header, adjudicate in the worker", result)
        self.assertIn("drop spoofable X-Real-IP trust", result)

    def test_the_header_is_recorded_and_not_acted_on(self):
        # The whole point of the redesign. HellPot cannot tell its two paths
        # apart -- both show the tunnel peer -- so it must not decide. It
        # logs the header; the worker, which holds portbridge's connection
        # log, decides.
        result = self.apply_both()
        self.assertIn('Str("XFF", string(ctx.Request.Header.Peek("X-Forwarded-For")))', result)
        # REMOTE_ADDR keeps the true peer *and its port*: the via_port join
        # depends on that port, which is why #1419 chose RemoteAddr().
        self.assertIn("return ctx.RemoteAddr().String()", result)
        # And nothing in the sensor may resolve the header itself.
        self.assertNotIn("tunnelPeerIP", result)

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

    def test_it_needs_no_new_imports(self):
        # Recording the header uses only what the function already has, so
        # the patch never touches the import block -- which is where the
        # earlier, deciding version could have introduced a duplicate import
        # and turned a logging change into a compile error.
        result = self.apply_both()
        before = UPSTREAM[UPSTREAM.index("import ("):UPSTREAM.index(")", UPSTREAM.index("import ("))]
        after = result[result.index("import ("):result.index(")", result.index("import ("))]
        self.assertEqual(before, after)

    def test_it_refuses_to_run_before_router_patch(self):
        # router_patch.py owns getRealRemote(); this one only adds a log
        # field, so it can apply to unpatched upstream too. What it must not
        # do is claim success when its own target is missing.
        self.target.write_text(UPSTREAM.replace("slog := log.With().", "slog := log.Output()."))
        with self.assertRaises(SystemExit):
            load(XFF_PATCH, self.target).main()


if __name__ == "__main__":
    unittest.main()
