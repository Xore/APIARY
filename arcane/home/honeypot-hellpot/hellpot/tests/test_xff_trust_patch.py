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

ProxiedPortAgreement additionally guards the second-door port across
stacks (#2192): besides this patch module it is spelled in compose.yml,
vps/docker-compose.yml and the enrichment worker's sensors.rs, and no
language can import from the others -- so each spelling is read where it
lives and required to equal the patch constant, instead of a keep-in-step
comment being trusted to hold them together (#2187 documents how that
trust worked out).

GalahProxiedPortAgreement extends the same guard to galah's own second
door (#2211, sibling of #2192 left out of #2199's scope): galah has no
patch module, so config.yaml's native `ports:` list stands in as the
reference spelling. wordpot had the same exposure but was retired in
#2381 before this guard was written, so it is not covered here.

Usage: hellpot/tests/test_xff_trust_patch.py
"""
import importlib.util
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROUTER_PATCH = HERE.parent / "router_patch.py"
XFF_PATCH = HERE.parent / "xff_trust_patch.py"

# The other homes of the port (#2192). xff_trust_patch.py's
# HELLPOT_PROXIED_PORT is the reference spelling -- it is what HellPot
# actually binds -- and these are read as text because none of them can
# import it: the publishing stack's compose, the VPS bridge table, and the
# worker's Rust constant.
HELLPOT_COMPOSE = HERE.parents[1] / "compose.yml"
VPS_COMPOSE = HERE.parents[4] / "vps" / "docker-compose.yml"
WORKER_SENSORS = (
    HERE.parents[4]
    / "arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment/sensors.rs"
)

# galah has the same second-door split (#1891) and the same cross-file
# exposure (#2211, sibling of #2192): its listen port is native to
# config.yaml's own `ports:` list rather than a build-time patch constant,
# but nothing importable ties that list to compose.yml's publish line, the
# VPS socat dial, or the worker's Rust const either.
GALAH_COMPOSE = HERE.parents[4] / "arcane/home/honeypot-galah/compose.yml"
GALAH_CONFIG = HERE.parents[4] / "arcane/home/honeypot-galah/galah/config.yaml"


def galah_proxied_port():
    """The reference spelling for galah's second-door port: config.yaml's
    own `ports:` list, which galah reads natively -- no patch constant like
    hellpot's HELLPOT_PROXIED_PORT exists to import instead. The file
    documents 8888 as the raw door and 8890 as Traefik-only, in that order,
    so the second entry is taken by position rather than by hardcoding
    either number here."""
    ports = re.findall(r"^\s*-\s*port:\s*(\d+)\s*$", GALAH_CONFIG.read_text(), re.M)
    if len(ports) != 2:
        raise AssertionError(
            "expected exactly 2 ports in galah/config.yaml, found %d" % len(ports)
        )
    return ports[-1]


def vps_service_block(service):
    """One top-level service block out of vps/docker-compose.yml."""
    lines = VPS_COMPOSE.read_text().splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith("  %s:" % service)]
    if len(starts) != 1:
        raise AssertionError("expected one %s service, found %d" % (service, len(starts)))
    end = next(
        (i for i in range(starts[0] + 1, len(lines)) if re.match(r"^  \S", lines[i])),
        len(lines),
    )
    return "\n".join(lines[starts[0]:end])


# Upstream yunginnanet/HellPot internal/http/router.go at the pinned ref:
# every region the two patches touch, copied from the real file rather than
# abbreviated. The patches match on exact text, so a fixture that is merely
# similar would pass while the real build failed -- and it did, when #1908
# added two anchors this fixture had trimmed away as scenery.
UPSTREAM = '''package http

import (
	"bufio"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"

	"github.com/yunginnanet/HellPot/heffalump"
	"github.com/yunginnanet/HellPot/internal/config"
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

// Serve starts our HTTP server and request router
func Serve() error {
	log = config.GetLogger()
	l := config.HTTPBind + ":" + config.HTTPPort

	r := router.New()

	srv := getSrv(r)

	//goland:noinspection GoBoolExpressions
	if !config.UseUnixSocket || runtime.GOOS == "windows" {
		log.Info().Str("caller", l).Msg("Listening and serving HTTP...")
		return srv.ListenAndServe(l)
	}

	return nil
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


    def test_the_two_doors_become_separate_listeners(self):
        # The reason the sensor can answer "which way in" at all. While
        # both paths landed on config.HTTPPort, portbridge's connection log
        # was the only thing that could tell them apart -- and it answers by
        # port alone over a six-hour window, so on the proxied path a
        # coincidental match would file a request against an unrelated
        # attacker.
        result = self.apply_both()
        self.assertIn("Traefik-only second listener", result)
        # Spelled through the patch module: this assertion was itself a
        # fifth copy of the port until #2192, so a change there would have
        # "passed" while guarding the old value.
        port = load(XFF_PATCH, self.target).HELLPOT_PROXIED_PORT
        self.assertIn('proxied := config.HTTPBind + ":" + "{}"'.format(port), result)
        self.assertIn("go func() {", result)
        # The raw listener still runs, and still returns.
        self.assertIn("return srv.ListenAndServe(l)", result)

    def test_the_listen_port_is_recorded_on_every_request(self):
        result = self.apply_both()
        self.assertIn('Str("DST_PORT", localPort(ctx))', result)
        self.assertIn("func localPort(ctx *fasthttp.RequestCtx) string {", result)

    def test_the_helper_is_declared_at_file_scope(self):
        # It went inside hellPot() the first time, which Go rejects. The
        # build catches that, but only after a full image build.
        result = self.apply_both()
        helper = result.index("func localPort(")
        handler = result.index("func hellPot(")
        self.assertLess(helper, handler, "localPort must precede hellPot, not nest in it")

    def test_the_added_imports_are_in_sorted_order(self):
        # gofmt is enforced on the real tree, and an import spliced at the
        # top of the block would fail it long after this patch ran.
        result = self.apply_both()
        block = result[result.index("import ("):result.index(")", result.index("import ("))]
        # gofmt sorts within each blank-line-separated group, not across
        # them; the additions belong to the stdlib group, which is first.
        stdlib = block.split("\n\n")[0]
        names = [line.strip().strip('"') for line in stdlib.splitlines() if line.strip().startswith('"')]
        self.assertIn("net", names)
        self.assertIn("strconv", names)
        self.assertEqual(names, sorted(names), "gofmt keeps the stdlib group sorted")

    def test_the_result_is_valid_go(self):
        self.apply_both()
        # gofmt -e parses and reports syntax errors; a patch that produces
        # unparseable Go fails the image build with a far less obvious
        # message than this one.
        proc = subprocess.run(
            ["gofmt", "-e", str(self.target)], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_each_added_import_appears_exactly_once(self):
        # Recording the header needed nothing new, and #1908's listen-port
        # helper needs net and strconv. Adding an import twice is the way
        # this turns a logging change into a compile error, and a re-run
        # over an already-patched file is exactly how it would happen.
        result = self.apply_both()
        block = result[result.index("import ("):result.index(")", result.index("import ("))]
        for name in ('"net"', '"strconv"'):
            self.assertEqual(block.count(name + "\n"), 1, name)

    def test_applying_twice_changes_nothing(self):
        once = self.apply_both()
        load(XFF_PATCH, self.target).main()
        self.assertEqual(self.target.read_text(), once)

    def test_it_refuses_to_run_before_router_patch(self):
        # router_patch.py owns getRealRemote(); this one only adds a log
        # field, so it can apply to unpatched upstream too. What it must not
        # do is claim success when its own target is missing.
        self.target.write_text(UPSTREAM.replace("slog := log.With().", "slog := log.Output()."))
        with self.assertRaises(SystemExit):
            load(XFF_PATCH, self.target).main()


class ProxiedPortAgreement(unittest.TestCase):
    """#2192: the second-door port exists as text in several stacks at once,
    and nothing can import across them. Each copy's comment used to say
    "Kept in step with" the others, which works until it doesn't -- #2187 is
    what that looks like two years later -- and the failure here is silent:
    patch says X while compose publishes Y means a TCP reset on every
    proxied request; patch says X while the worker says Z means every
    proxied event skips adjudication and files under the wrong source. So
    agreement is asserted against HELLPOT_PROXIED_PORT, which is the one
    spelling something actually listens on."""

    def setUp(self):
        # Same loading dance as XffTrustPatch, minus the fixture: only the
        # module's constants are needed below, and main() -- the sole reader
        # of TARGET -- never runs.
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.module = load(XFF_PATCH, Path(self.dir.name) / "router.go")

    def test_the_publish_line_matches_the_listener(self):
        port = self.module.HELLPOT_PROXIED_PORT
        published = re.findall(
            r"^\s*-\s*\$\{HP_BIND:[^}]*\}:(\d+):(\d+)\s*$",
            HELLPOT_COMPOSE.read_text(),
            re.M,
        )
        # Both halves: socat dials the host side while HellPot binds the
        # container side, so drift in either direction of the mapping resets
        # every proxied request.
        self.assertIn(
            (port, port),
            published,
            "compose.yml publishes {} but the patched listener is on {}".format(
                published, port
            ),
        )

    def test_the_socat_dial_matches_the_listener(self):
        port = self.module.HELLPOT_PROXIED_PORT
        dialed = re.findall(
            r"TCP4:[0-9.]+:(\d+)", vps_service_block("socat-hp-hellpot")
        )
        # The VPS half of the same door: a dial at any other port is
        # connection refused on the Traefik-only path, invisible to the raw
        # path and to the healthcheck, which both stay green.
        self.assertEqual(
            [port],
            dialed,
            "socat-hp-hellpot dials {} but the patched listener is on {}".format(
                dialed, port
            ),
        )

    def test_the_worker_adjudicates_on_the_same_port(self):
        port = self.module.HELLPOT_PROXIED_PORT
        declared = re.search(
            r'const HELLPOT_PROXIED_PORT:\s*&str\s*=\s*"(\d+)";',
            WORKER_SENSORS.read_text(),
        )
        self.assertIsNotNone(declared, "HELLPOT_PROXIED_PORT missing from sensors.rs")
        self.assertEqual(
            port,
            declared.group(1),
            "sensors.rs adjudicates DST_PORT {} but the patched listener is on {}".format(
                declared.group(1), port
            ),
        )


class GalahProxiedPortAgreement(unittest.TestCase):
    """#2211, sibling of #2192/ProxiedPortAgreement above: galah's second
    door (#1891) has the same "spelled in several stacks, nothing can
    import across them" exposure as hellpot's -- config.yaml, compose.yml's
    publish line, the VPS socat dial, and the worker's Rust const all name
    the same port with no shared source of truth. Unlike wordpot (retired
    in #2381, out of scope here), galah's host and container halves are
    meant to be equal, same as hellpot's, so this reuses that shape
    directly rather than modeling a legitimate skew."""

    def test_the_publish_line_matches_the_listener(self):
        port = galah_proxied_port()
        published = re.findall(
            r"^\s*-\s*\$\{HP_BIND:[^}]*\}:(\d+):(\d+)\s*$",
            GALAH_COMPOSE.read_text(),
            re.M,
        )
        self.assertIn(
            (port, port),
            published,
            "compose.yml publishes {} but config.yaml's second door is {}".format(
                published, port
            ),
        )

    def test_the_socat_dial_matches_the_listener(self):
        port = galah_proxied_port()
        dialed = re.findall(
            r"TCP4:[0-9.]+:(\d+)", vps_service_block("socat-hp-galah")
        )
        self.assertEqual(
            [port],
            dialed,
            "socat-hp-galah dials {} but config.yaml's second door is {}".format(
                dialed, port
            ),
        )

    def test_the_worker_adjudicates_on_the_same_port(self):
        port = galah_proxied_port()
        declared = re.search(
            r'const GALAH_PROXIED_PORT:\s*&str\s*=\s*"(\d+)";',
            WORKER_SENSORS.read_text(),
        )
        self.assertIsNotNone(declared, "GALAH_PROXIED_PORT missing from sensors.rs")
        self.assertEqual(
            port,
            declared.group(1),
            "sensors.rs adjudicates port {} but config.yaml's second door is {}".format(
                declared.group(1), port
            ),
        )


if __name__ == "__main__":
    unittest.main()
