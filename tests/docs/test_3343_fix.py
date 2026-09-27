#!/usr/bin/env python3
"""Regression tests for #3343: Arkime must be able to install its own index
templates, and the translation of them into composable templates must actually
run.

The issue was filed because Elasticsearch applies no *legacy* template to an
index as soon as any composable template matches it, so Arkime's `db.pl`
templates silently never applied -- `firstPacket` mapped `long` instead of
`date`, no `wordSplit` analyzer, no `dynamic_templates`, IPs typed as text.
#3346 added `arkime/composable-templates.js` to translate them, and left the
residual refusal ("Elasticsearch refuses to create *or update* any legacy
template while the `*` catch-all exists, so `db.pl` can never refresh its
templates again") open.

What could quietly undo this, and is therefore asserted here rather than
assumed:

* **the translation call being folded into a comment.** `arkime-init`'s
  command is a YAML `>` folded block scalar, and a folded scalar joins every
  run of adjacent non-empty lines with a single space. On main the node
  invocation sat directly under its comment with no blank line between, so the
  whole thing rendered as one `fi` line with a trailing comment and
  `composable-templates.js` had *never once run* -- #3346's fix was inert
  while still reading as correct in the YAML. The other 90 lines of that
  command folded cleanly, and `bash -n` accepts the result either way, so
  nothing caught it. These tests render the scalar the way Compose does and
  assert the commands survive as commands.
* `db.pl` being left to race the catch-all instead of having it removed for
  the duration -- the `shadow` subcommand, and the bounded retry for the one
  race a shadow cannot cover (a template created *while* `db.pl` runs).
* the shadow deleting more than it should: every other family's template
  (`dionaea-*`, `ml-anomalies`, ...) has to survive, and the stashed bodies
  have to come back, or one fix becomes a cluster-wide replica regression.
* a hand-rolled list of the templates that happen to overlap today. The
  matcher is Elasticsearch's own `simpleMatch` glob semantics, so a renamed or
  second catch-all is covered too; that is asserted behaviourally.
* the catch-all's comment claiming an Arkime exclusion that composable
  templates cannot express. Those `-arkime_...` entries were literal index
  names matching nothing, and the prose told the next reader they were
  excluded.

The `tests/docs/` CI row installs pytest and nothing else (see quality.yml),
so the render is done by a small dependency-free folded-scalar reader, with a
PyYAML cross-check where PyYAML happens to be available. The Node tests are
skipped where Node is not, the same way test_3321_fix.py guards its optional
pieces.
"""
from __future__ import annotations

import json
import os
import stat
import pathlib
import shutil
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "arcane/home/honeypot-init/compose.yml"
ES_SETUP = REPO_ROOT / "arcane/home/honeypot-init/analysis/elasticsearch-setup.sh"
SCRIPT = REPO_ROOT / "arcane/home/honeypot-init/arkime/composable-templates.js"

NODE = shutil.which("node")
node_only = pytest.mark.skipif(NODE is None, reason="node not installed")

# The two Arkime index families #3343 is about, as db.pl names them.
SESSIONS_LEGACY = {
    "order": 99,
    "index_patterns": ["arkime_sessions3-*"],
    "settings": {"index": {"refresh_interval": "60s"}},
    "mappings": {
        "properties": {"firstPacket": {"type": "date"}, "node": {"type": "keyword"}},
        "dynamic_templates": [
            {"*Ip": {"match_mapping_type": "ip", "mapping": {"type": "ip"}}},
            {"*Tokens": {"match_mapping_type": "string", "mapping": {"type": "text", "analyzer": "wordSplit"}}},
        ],
    },
}
SESSIONS_ECS_LEGACY = {
    "order": 1,
    "index_patterns": ["arkime_sessions3-*"],
    "settings": {"index": {"total_fields": {"limit": 10000}}},
    "mappings": {
        "properties": {"tags": {"type": "keyword"}},
        # The ECS catch-all. If it ended up ahead of *Ip/*Tokens every IP and
        # token field would be a string, which is the exact regression #3283
        # found on the live cluster.
        "dynamic_templates": [
            {"strings_as_keyword": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}
        ],
    },
}
HISTORY_LEGACY = {
    "order": 99,
    "index_patterns": ["arkime_history_v1-*"],
    "settings": {"index": {"refresh_interval": "60s"}},
    "mappings": {"properties": {"sourceIP": {"type": "ip"}}},
}

CATCH_ALL = {
    "index_patterns": ["*"],
    "priority": 1,
    "template": {"settings": {"index.number_of_replicas": 0}},
}
IP_FIX = {
    "index_patterns": ["arkime_sessions3-*"],
    "priority": 10,
    "template": {"mappings": {"properties": {"source": {"properties": {"ip": {"type": "ip"}}}}}},
}
# Neither of these has anything to do with Arkime. Losing them is the failure
# mode a too-eager shadow would cause.
DIONAEA = {"index_patterns": ["dionaea-*"], "priority": 5, "template": {"settings": {"index.number_of_shards": 1}}}
ML = {"index_patterns": ["ml-anomalies", "ml-worker-*"], "priority": 5, "template": {}}

# A sessions index that predates the generated template and carries no
# lifecycle name -- what #3283's adoption pass exists to pick up.
PRE_EXISTING_SESSIONS = "arkime_sessions3-2026.09.01"
SESSIONS_POLICY = "arkime-sessions-30d"


# ------------------------------------------------------------ the render ----


def unfold_service_command(text: str, service: str) -> str:
    """Render a service's `command:` the way Compose does, with no dependencies.

    Only what this repository actually uses is implemented: a `command:` list
    whose script is one `>` folded block scalar. In a folded scalar every run
    of adjacent non-empty lines is joined with a single space and each empty
    line becomes a newline -- which is exactly the rule that swallowed the
    `node` call on main, so getting it right is the point of the helper.
    """
    lines = text.splitlines()

    # Exactly two spaces of indent: a service key directly under `services:`,
    # not a nested mapping that happens to share the name.
    start = next(
        (i for i, ln in enumerate(lines)
         if ln.strip() == f"{service}:" and ln.startswith("  ") and not ln.startswith("   ")),
        None,
    )
    assert start is not None, f"service {service} not found"
    try:
        cmd = next(i for i in range(start, len(lines)) if lines[i].strip() == "command:")
    except StopIteration:
        raise AssertionError(f"{service} has no command:") from None

    def indent(ln: str) -> int:
        return len(ln) - len(ln.lstrip())

    key_indent = indent(lines[cmd])
    # The list items (`- /bin/sh`, `- -c`, `- >`) sit at one level in from the
    # key; the script itself is the block scalar under the `- >` item.
    item_indent, body_start = None, None
    for i in range(cmd + 1, len(lines)):
        ln = lines[i]
        if not ln.strip():
            continue
        if indent(ln) <= key_indent:
            break
        if item_indent is None:
            item_indent = indent(ln)
        if indent(ln) == item_indent and ln.lstrip()[1:].strip() == ">":
            body_start = i + 1
            break
    assert body_start is not None, f"{service}'s command is not a single folded block scalar"

    body: list[str] = []
    for ln in lines[body_start:]:
        if not ln.strip():
            body.append("")
            continue
        if indent(ln) <= item_indent:
            break  # dedented past the list: that is the next key
        body.append(ln)

    # A folded scalar's content indentation is that of its first non-empty line.
    # Only lines at exactly that indentation fold together: a *more* indented
    # line is literal content, which is why the shell bodies below survive while
    # the comment block above them collapses onto one line.
    pad = indent(next(ln for ln in body if ln.strip()))
    out: list[str] = []
    foldable = False  # the previous output line may still take a folded continuation
    blank = False
    for ln in body:
        if not ln.strip():
            blank = True
            continue
        text = ln[pad:].rstrip() if len(ln) >= pad else ln.strip()
        if indent(ln) > pad:
            out.append(text)
            foldable = False
        elif out and foldable and not blank:
            out[-1] += " " + text.strip()  # the fold that hid the node call
            foldable = True
        else:
            out.append(text)
            foldable = True
        blank = False
    return "\n".join(out)


@pytest.fixture(scope="module")
def arkime_init_command() -> str:
    return unfold_service_command(COMPOSE.read_text(encoding="utf-8"), "arkime-init")


# ------------------------------------------------------- the fold defect ----


def test_composable_templates_call_is_not_folded_into_a_comment(arkime_init_command):
    """The #3346 fix is only a fix if the call survives YAML folding.

    On main this rendered as a single `fi` line whose trailing comment
    happened to contain the whole invocation, so the script never ran.
    """
    commands = [ln for ln in arkime_init_command.splitlines() if ln.startswith("/opt/arkime/bin/node")]
    assert commands == ["/opt/arkime/bin/node /opt/arkime/composable-templates.js"], (
        "composable-templates.js is not a standalone command in the rendered "
        f"arkime-init script; it is folded into a comment. Rendered lines "
        f"mentioning it: {[ln for ln in arkime_init_command.splitlines() if 'composable-templates.js' in ln]}"
    )


def test_no_command_line_in_arkime_init_is_swallowed_by_a_comment(arkime_init_command):
    """Generalisation of the above, so the next command added does not repeat it.

    Any rendered line that starts a shell command but has a `#` before its
    first non-blank character other than its own shebang is code that YAML
    folded into prose. Cheap to assert and it fails loudly instead of turning
    into a silent no-op.
    """
    offenders = []
    for n, line in enumerate(arkime_init_command.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # A command whose first token is quoted or bracketed is not one we can
        # recognise; only flag the shapes this command actually uses.
        first = stripped.split()[0]
        if first.startswith(("'", '"')):
            continue
        if "#" in line[: len(line) - len(stripped)]:
            offenders.append((n, line))
    assert not offenders, f"commands folded into a comment: {offenders}"


def test_render_matches_pyyaml_when_available(arkime_init_command):
    """Keep the dependency-free reader honest against a real YAML parser.

    Compared with blank lines dropped: they decide *whether* two lines fold
    together, which is what this helper has to get right, but how many of them
    PyYAML emits around a more-indented block is cosmetic and never changes
    what the shell does.
    """
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed")
    parsed = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    real = parsed["services"]["arkime-init"]["command"][2]
    assert [ln for ln in real.splitlines() if ln.strip()] == \
        [ln for ln in arkime_init_command.splitlines() if ln.strip()]


def test_rendered_arkime_init_is_valid_shell(arkime_init_command):
    """`bash -n` passes on main too, but it must pass on the fixed script as well."""
    out = subprocess.run(["bash", "-n"], input=arkime_init_command, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


# ------------------------------------------------- shadow before db.pl ----


def test_shadow_runs_before_db_pl_and_restore_after(arkime_init_command):
    lines = [ln.strip() for ln in arkime_init_command.splitlines() if ln.strip()]

    shadow = next(i for i, ln in enumerate(lines) if ln.startswith("until /opt/arkime/bin/node") and ln.endswith("; do"))
    db_run = next(i for i, ln in enumerate(lines) if ln.startswith("arkime_db_run()"))
    generate = next(i for i, ln in enumerate(lines) if ln == "/opt/arkime/bin/node /opt/arkime/composable-templates.js")

    assert " shadow && arkime_db_run" in lines[shadow], lines[shadow]
    assert db_run < shadow, "the db.pl helper must be defined before the loop that calls it"
    assert generate > shadow, "the restore/regenerate pass must come after the shadow"
    # Exactly two invocations: one shadow, one generate. A third would mean a
    # subcommand crept in un-reviewed.
    invocations = [ln for ln in lines if "/opt/arkime/bin/node /opt/arkime/composable-templates.js" in ln]
    assert len(invocations) == 2, invocations
    assert invocations[0].endswith(" shadow && arkime_db_run; do")
    assert invocations[1] == "/opt/arkime/bin/node /opt/arkime/composable-templates.js"


def test_db_pl_retry_is_bounded_and_fails_loudly(arkime_init_command):
    """Three attempts, then give up -- and never write the readiness marker.

    `arkime-capture` and `arkime-viewer` both block on
    `/markers/arkime-init.done`, so an arkime-init that fails quietly instead
    of loudly would be an outage that looks healthy.
    """
    lines = [ln.strip() for ln in arkime_init_command.splitlines() if ln.strip()]
    loop = lines.index(next(ln for ln in lines if ln.startswith("until /opt/arkime/bin/node")))
    end = lines.index("done", loop)
    body = lines[loop + 1:end]

    assert any('-ge 3' in ln for ln in body), body
    assert "exit 1" in body, "a persistent db.pl failure must abort arkime-init, not loop forever"
    marker = lines.index("mkdir -p /markers && touch /markers/arkime-init.done")
    assert end < marker
    # `set -e` plus the explicit exit: the marker line must be unreachable on
    # the failure path, which it is because the loop exits the process first.
    assert lines[0] == "set -e"


def test_shell_counters_are_compose_escaped(arkime_init_command):
    """`$$`, not `$` -- and not in a comment either, which Compose interpolates too.

    A bare `$arkime_db_runs` makes `docker compose config` warn that the
    variable is not set. It is a shell counter, not an .env one; the only
    reference in the file was the doubled-dollar form this asserts, and it is
    the sole such escape in `arcane/` outside honeypot-conpot.
    """
    shell_lines = [ln for ln in arkime_init_command.splitlines() if "arkime_db_runs" in ln]
    assert shell_lines, "the retry counter is gone"
    for ln in shell_lines:
        assert "$arkime_db_runs" not in ln.replace("$$arkime_db_runs", ""), (
            f"a bare $arkime_db_runs makes docker compose config warn: {ln.strip()!r}"
        )


# ------------------------------------------- the catch-all's false claim ----


def test_catch_all_no_longer_claims_an_arkime_exclusion_it_cannot_express():
    """Composable templates have no exclusion syntax; `-arkime_...` was a name.

    Those entries matched nothing but an index literally called
    `-arkime_sessions3-*`, and the prose asserted they were "explicitly
    excluded below" -- so the next reader believed Arkime was untouched.
    """
    text = ES_SETUP.read_text(encoding="utf-8")
    put = next(ln for ln in text.splitlines() if "_index_template/single-node-replica-default" in ln)
    body = text[text.index(put):][:400]

    assert '"-arkime_sessions3-*"' not in text, "the inert exclusion entry is back in the catch-all"
    assert '"-arkime_history_v1-*"' not in text
    assert "explicitly excluded below" not in text, "the false exclusion claim is back in the comment"

    # What it does now, and the reason, must be stated where a reader lands.
    assert '"index_patterns":["*"]' in body, "the catch-all should be a plain [*] wildcard now"
    assert "no exclusion syntax" in text
    assert "arkime/composable-templates.js" in text, "the comment should point at the real mechanism"


def test_elasticsearch_setup_is_still_valid_shell():
    out = subprocess.run(["bash", "-n"], input=ES_SETUP.read_text(encoding="utf-8"), capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_elasticsearch_setup_keeps_a_bounded_non_fatal_arkime_wait():
    """The wait is an ordering nicety, not the fix -- it must not become a hang."""
    text = ES_SETUP.read_text(encoding="utf-8")
    assert "arkime_legacy_wait=60" in text
    assert "arkime_legacy_wait=$(( arkime_legacy_wait - 2 ))" in text
    # The old message promised a permanent failure; the shadow makes the worst
    # case a needless shadow/restore cycle instead.
    assert "see #2961" not in text, "the timeout message still claims db.pl cannot recover"


# ------------------------------------------- composable-templates.js shape ----


def test_script_declares_both_subcommands():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "if (mode === 'shadow') return shadow();" in text
    assert "'generate'" in text
    assert "unknown subcommand" in text, "an unknown subcommand must fail loudly"


def test_script_uses_elasticsearch_glob_semantics_not_a_hardcoded_list():
    """A renamed or second catch-all has to be shadowed too.

    The whole point is to stop hard-coding the names of the templates that
    happen to overlap today, so the matcher must implement `simpleMatch` rather
    than compare against a list.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    assert "function simpleMatch(pattern, value)" in text
    assert "STEMS" in text, "coverage has to be decided per family, not by one invented name"
    assert "coversStem" in text
    assert "single-node-replica-default" not in text.split("async function shadow()")[1].split("async function restore")[0], (
        "shadow() must decide what to delete by pattern, not by name"
    )


def test_script_does_not_resurrect_what_generate_just_rebuilt():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "const LEGACY_IP_FIX = 'arkime-sessions3-ip-fix';" in text
    assert "restore(new Set([...installed, LEGACY_IP_FIX]))" in text


# ------------------------------------------------- functional: node + stub ES ----


class _StubElasticsearch:
    """Just enough of ES to drive composable-templates.js end to end."""

    def __init__(self, index_templates: dict, legacy_templates: dict, indices=()):
        self.index_templates = dict(index_templates)
        self.legacy_templates = dict(legacy_templates)
        # #3283: the arkime_sessions3-* names the cluster already holds, which
        # `generate` adopts onto its policy. Empty by default so the #3343
        # assertions stay about templates; the adoption contract itself is
        # asserted in tests/docs/test_3283_fix.py, which owns that behaviour.
        #
        # A name maps to whatever index.lifecycle.name it currently carries, or
        # to None for "unmanaged, adopt me". A list is also accepted and reads
        # as all-unmanaged, so the fixtures above stay terse.
        self.indices = {name: None for name in indices} if not isinstance(indices, dict) else dict(indices)
        self.deleted: list[str] = []
        self.put_index_templates: dict = {}
        self.put_ilm_policies: dict = {}
        self.calls: list[str] = []

    def compose(self, probe: str) -> dict:
        """Answer `_simulate_index` by composing what the script really sent.

        Elasticsearch composes every matching composable template, so a canned
        reply would let the script's own post-install verification pass no
        matter what it installed. Composing from `put_index_templates` means a
        template that dropped a setting fails here instead of in production.
        """
        pattern = probe.replace("composable-check", "*")
        for tmpl in self.put_index_templates.values():
            if pattern in (tmpl.get("index_patterns") or []):
                return tmpl.get("template", {})
        return {}

    def handle(self, method: str, path: str, body) -> tuple[int, dict]:
        self.calls.append(f"{method} {path}")
        if method == "GET" and path == "/_index_template":
            return 200, {"index_templates": [
                {"name": name, "index_template": tmpl} for name, tmpl in self.index_templates.items()
            ]}
        if method == "DELETE" and path.startswith("/_index_template/"):
            name = path.rsplit("/", 1)[1]
            self.deleted.append(name)
            if name in self.index_templates:
                del self.index_templates[name]
                return 200, {"acknowledged": True}
            return 404, {"error": "resource_not_found_exception"}
        if method == "PUT" and path.startswith("/_index_template/"):
            name = path.rsplit("/", 1)[1]
            self.put_index_templates[name] = body
            self.index_templates[name] = body
            return 200, {"acknowledged": True}
        if method == "POST" and path.startswith("/_index_template/_simulate_index/"):
            return 200, {"template": self.compose(path.rsplit("/", 1)[-1])}
        if method == "GET" and path.startswith("/_template/"):
            name = path.rsplit("/", 1)[1]
            if name in self.legacy_templates:
                return 200, {name: self.legacy_templates[name]}
            return 404, {"error": "resource_not_found_exception"}
        # #3283: the policy `generate` installs immediately before the template
        # that names it, so the ordering that makes that safe can never depend
        # on this stub refusing the call. The body is recorded so the ordering
        # can be asserted rather than assumed.
        if method == "PUT" and path.startswith("/_ilm/policy/"):
            self.put_ilm_policies[path.rsplit("/", 1)[1]] = body
            return 200, {"acknowledged": True}
        if method == "GET" and path.startswith("/_cat/indices/"):
            return 200, [{"index": name} for name in self.indices]
        if method == "GET" and path.endswith("/_settings?flat_settings=true"):
            name = path.lstrip("/").split("/", 1)[0]
            if name not in self.indices:
                return 404, {"error": "resource_not_found_exception"}
            # Only the lifecycle name is modelled; a real reply carries every
            # flat setting, and the script reads this one.
            settings = {"index.lifecycle.name": self.indices[name]} if self.indices[name] else {}
            return 200, {name: {"settings": settings}}
        if method == "PUT" and path.endswith("/_settings"):
            name = path.lstrip("/").split("/", 1)[0]
            if name not in self.indices:
                return 404, {"error": "resource_not_found_exception"}
            self.indices[name] = (body or {}).get("index.lifecycle.name")
            return 200, {"acknowledged": True}
        raise AssertionError(f"stub Elasticsearch got an unexpected {method} {path}")


class _Handler(BaseHTTPRequestHandler):
    stub: _StubElasticsearch

    def _respond(self):
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw) if raw else None
        status, payload = self.stub.handle(self.command, self.path, body)
        out = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_PUT = do_POST = do_DELETE = _respond

    def log_message(self, *_args):  # keep pytest output readable
        pass


@contextmanager
def _serving(stub: _StubElasticsearch):
    handler = type("H", (_Handler,), {"stub": stub})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _run(url: str, shadow_file: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "ARKIME__elasticsearch": url, "SHADOW_FILE": str(shadow_file)}
    return subprocess.run([NODE, str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


@contextmanager
def _stubbed():
    stub = _StubElasticsearch(
        index_templates={
            "single-node-replica-default": CATCH_ALL,
            "arkime-sessions3-ip-fix": IP_FIX,
            "dionaea-30d": DIONAEA,
            "ml-anomalies": ML,
        },
        legacy_templates={
            "arkime_sessions3_template": SESSIONS_LEGACY,
            "arkime_sessions3_ecs_template": SESSIONS_ECS_LEGACY,
            "arkime_history_v1_template": HISTORY_LEGACY,
        },
        # #3283's adoption pass runs inside the same generate() that restores
        # the catch-all, so seeding one unmanaged index means the functional
        # tests below drive that path too rather than leaving it to a stub
        # that never receives the call.
        indices=[PRE_EXISTING_SESSIONS],
    )
    with _serving(stub) as url:
        yield stub, url


@node_only
def test_shadow_deletes_only_arkime_covering_templates_and_stashes_their_bodies(tmp_path):
    with _stubbed() as (stub, url):
        shadow_file = tmp_path / "shadow.json"
        out = _run(url, shadow_file, "shadow")
        assert out.returncode == 0, out.stderr

        assert set(stub.deleted) == {"single-node-replica-default", "arkime-sessions3-ip-fix"}, stub.deleted
        assert set(stub.index_templates) == {"dionaea-30d", "ml-anomalies"}, "a non-Arkime template was deleted"

        stashed = json.loads(shadow_file.read_text())
        assert set(stashed) == {"single-node-replica-default", "arkime-sessions3-ip-fix"}
        # A stash that kept only the name would restore an empty template.
        assert stashed["single-node-replica-default"] == CATCH_ALL
        assert stashed["arkime-sessions3-ip-fix"] == IP_FIX


@node_only
def test_generate_rebuilds_arkimes_templates_and_restores_everything_else(tmp_path):
    with _stubbed() as (stub, url):
        shadow_file = tmp_path / "shadow.json"
        assert _run(url, shadow_file, "shadow").returncode == 0

        out = _run(url, shadow_file)
        assert out.returncode == 0, out.stderr

        installed = stub.put_index_templates
        assert "arkime-sessions3" in installed, installed.keys()
        assert "arkime-history-v1" in installed

        # Everything that is not Arkime's own generated template came back...
        assert "single-node-replica-default" in installed
        assert installed["single-node-replica-default"] == CATCH_ALL
        assert set(stub.index_templates) == {"dionaea-30d", "ml-anomalies", "arkime-sessions3", "arkime-history-v1",
                                             "single-node-replica-default"}
        # ...and the stash is empty, so a crash later cannot replay a stale body.
        assert json.loads(shadow_file.read_text()) == {}


@node_only
def test_the_restoring_run_is_also_the_one_that_installs_retention(tmp_path):
    """#3283's obligations, checked from this suite's own fixture.

    The shadow/restore cycle and the retention pass are one run of one script
    now, so the run that puts the catch-all back is the same run that installs
    the policy and adopts the indices already on disk. The ordering is the
    part that breaks silently: an index template naming an ILM policy that
    does not exist yet fails index creation outright, and Elasticsearch
    validates it at index creation, not here.
    """
    with _stubbed() as (stub, url):
        shadow_file = tmp_path / "shadow.json"
        assert _run(url, shadow_file, "shadow").returncode == 0
        out = _run(url, shadow_file)
        assert out.returncode == 0, out.stderr

        assert SESSIONS_POLICY in stub.put_ilm_policies, sorted(stub.put_ilm_policies)
        assert stub.indices[PRE_EXISTING_SESSIONS] == SESSIONS_POLICY, (
            f"{PRE_EXISTING_SESSIONS} was not adopted onto the policy: "
            f"{stub.indices[PRE_EXISTING_SESSIONS]!r}"
        )

        order = [c for c in stub.calls
                 if c.startswith(("PUT /_ilm/policy/", "PUT /_index_template/arkime-sessions3"))]
        assert order.index(f"PUT /_ilm/policy/{SESSIONS_POLICY}") < \
               order.index("PUT /_index_template/arkime-sessions3"), (
            f"the policy was installed after the template naming it: {order}"
        )


@node_only
def test_generated_sessions_template_carries_arkimes_real_mappings(tmp_path):
    with _stubbed() as (stub, url):
        shadow_file = tmp_path / "shadow.json"
        assert _run(url, shadow_file, "shadow").returncode == 0
        assert _run(url, shadow_file).returncode == 0

        tmpl = stub.put_index_templates["arkime-sessions3"]
        assert tmpl["index_patterns"] == ["arkime_sessions3-*"]
        # Above the ip-fix fragment (10) it replaces and the catch-all (1).
        assert tmpl["priority"] == 11
        assert tmpl["template"]["settings"]["index"]["number_of_replicas"] == "0"
        # The live-cluster symptom from the issue: long instead of date.
        assert tmpl["template"]["mappings"]["properties"]["firstPacket"]["type"] == "date"
        assert tmpl["template"]["mappings"]["properties"]["node"]["type"] == "keyword"
        # The ip typing Arkime's ECS template provides and the #1191 fragment used to fake.
        assert tmpl["template"]["mappings"]["properties"]["source"]["properties"]["ip"]["type"] == "ip"
        assert tmpl["template"]["mappings"]["properties"]["destination"]["properties"]["ip"]["type"] == "ip"

        names = [next(iter(e)) for e in tmpl["template"]["mappings"]["dynamic_templates"]]
        # Higher order (99) first, so its *Ip/*Tokens rules are not shadowed by
        # the ECS catch-all at order 1. Reversed, every IP is a keyword again.
        assert names == ["*Ip", "*Tokens", "strings_as_keyword"], names

        history = stub.put_index_templates["arkime-history-v1"]
        assert history["template"]["settings"]["index"]["number_of_replicas"] == "0"
        # No ipFix for the history family, matching the issue's per-family scope.
        assert "source" not in history["template"]["mappings"]["properties"]


@node_only
def test_shadow_uses_glob_semantics_not_a_name_list(tmp_path):
    """A catch-all nobody anticipated must still be shadowed.

    Asking "does this match one invented probe name" instead of "can this match
    an index of the family" would have kept `arkime_sessions3-2*` and
    `arkime_history_v1-?` alive -- both of which overlap db.pl's
    `arkime_sessions3-*` / `arkime_history_v1-*` just as hard as a bare `*`.
    """
    stub = _StubElasticsearch(
        index_templates={
            "renamed-defaults": CATCH_ALL,
            "sessions-day-2": {"index_patterns": ["arkime_sessions3-2*"], "priority": 3, "template": {}},
            "history-one": {"index_patterns": ["arkime_history_v1-?"], "priority": 3, "template": {}},
            "sessions-any-year": {"index_patterns": ["arkime_sessions3?*"], "priority": 3, "template": {}},
            "arkime-stem-glob": {"index_patterns": ["arkime_*"], "priority": 3, "template": {}},
            "dionaea-30d": DIONAEA,
            "ml-anomalies": ML,
        },
        legacy_templates={},
    )
    with _serving(stub) as url:
        out = _run(url, tmp_path / "shadow.json", "shadow")
        assert out.returncode == 0, out.stderr
        assert set(stub.deleted) == {
            "renamed-defaults", "sessions-day-2", "history-one", "sessions-any-year", "arkime-stem-glob",
        }, stub.deleted
        assert set(stub.index_templates) == {"dionaea-30d", "ml-anomalies"}, "a non-Arkime template was deleted"


@node_only
def test_shadow_is_a_noop_on_a_cluster_with_nothing_to_shadow(tmp_path):
    """The first deploy on a clean cluster must not fail for lack of templates."""
    stub = _StubElasticsearch(index_templates={"dionaea-30d": DIONAEA, "ml-anomalies": ML}, legacy_templates={})
    with _serving(stub) as url:
        out = _run(url, tmp_path / "shadow.json", "shadow")
        assert out.returncode == 0, out.stderr
        assert "nothing to delete" in out.stdout
        assert stub.deleted == []


@node_only
def test_shadow_is_idempotent_across_the_retry_loop(tmp_path):
    """compose.yml re-shadows before every db.pl attempt; the second must be free.

    Re-deleting a template that is already in the stash would re-PUT a body the
    first attempt never got round to replacing, and re-deleting something the
    restore has already put back is a no-op by construction.
    """
    stub = _StubElasticsearch(
        index_templates={"single-node-replica-default": CATCH_ALL, "dionaea-30d": DIONAEA},
        legacy_templates={},
    )
    with _serving(stub) as url:
        shadow_file = tmp_path / "shadow.json"
        assert _run(url, shadow_file, "shadow").returncode == 0
        assert stub.deleted == ["single-node-replica-default"]
        out = _run(url, shadow_file, "shadow")
        assert out.returncode == 0, out.stderr
        assert stub.deleted == ["single-node-replica-default"], "a second shadow re-deleted something"
        assert "nothing to delete" in out.stdout
        assert json.loads(shadow_file.read_text()) == {"single-node-replica-default": CATCH_ALL}


@node_only
def test_generate_survives_a_crash_in_the_middle(tmp_path):
    """`set -e` + a half-restored cluster is the outage this whole issue is about."""
    stub = _StubElasticsearch(
        index_templates={"single-node-replica-default": CATCH_ALL},
        # _simulate_index reports the wrong replica count, so generate() throws
        # after its PUT.
        legacy_templates={"arkime_sessions3_template": SESSIONS_LEGACY},
    )
    with _serving(stub) as url:
        shadow_file = tmp_path / "shadow.json"
        assert _run(url, shadow_file, "shadow").returncode == 0

        # Make the simulation disagree with what generate() just installed.
        original = stub.handle

        def handle(method, path, body):
            if method == "POST":
                return 200, {"template": {"settings": {"index": {"number_of_replicas": "1"}}}}
            return original(method, path, body)

        stub.handle = handle  # type: ignore[method-assign]
        out = _run(url, shadow_file)
        assert out.returncode != 0, "a wrong replica count must fail the run"
        assert "single-node-replica-default" in stub.index_templates, (
            "the catch-all must be restored even when generate() fails, or every "
            "template-less index in the stack loses number_of_replicas until the next deploy"
        )


@node_only
def test_dry_run_changes_nothing(tmp_path):
    stub = _StubElasticsearch(index_templates={"single-node-replica-default": CATCH_ALL}, legacy_templates={})
    with _serving(stub) as url:
        env = {**os.environ, "ARKIME__elasticsearch": url, "SHADOW_FILE": str(tmp_path / "s.json"), "DRY_RUN": "1"}
        out = subprocess.run([NODE, str(SCRIPT), "shadow"], capture_output=True, text=True, env=env, timeout=60)
        assert out.returncode == 0, out.stderr
        assert "dry run" in out.stdout
        assert stub.deleted == []
        assert set(stub.index_templates) == {"single-node-replica-default"}
        assert not (tmp_path / "s.json").exists()


@node_only
def test_unknown_subcommand_fails_loudly(tmp_path):
    stub = _StubElasticsearch(index_templates={}, legacy_templates={})
    with _serving(stub) as url:
        out = _run(url, tmp_path / "s.json", "translate")
        assert out.returncode != 0
        assert "unknown subcommand" in out.stderr


@node_only
def test_shadow_stash_is_not_world_readable(tmp_path):
    """The stash holds the full body of templates deleted from the cluster, so
    it must not land world-readable. CodeQL flags a direct /tmp write
    (js/insecure-temp-file); the fix keeps a fixed path -- the shadow and
    generate passes are separate processes sharing it -- but creates the
    parent 0700 and the file 0600."""
    shadow = tmp_path / "nested" / "s.json"
    stub = _StubElasticsearch(
        index_templates={
            "single-node-replica-default": CATCH_ALL,
            "arkime-sessions3-ip-fix": IP_FIX,
        },
        legacy_templates={},
    )
    with _serving(stub) as url:
        out = _run(url, shadow, "shadow")
    assert out.returncode == 0, out.stderr
    assert shadow.exists()
    assert stat.S_IMODE(shadow.stat().st_mode) == 0o600, oct(shadow.stat().st_mode)
    assert stat.S_IMODE(shadow.parent.stat().st_mode) == 0o700, oct(shadow.parent.stat().st_mode)
