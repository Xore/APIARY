#!/usr/bin/env python3
"""Regression test for #3283: `arkime_sessions3-*` was the only index family
in the stack with no retention at all.

On 2026-09-21 every sensor's ingest stopped: the single node was at
`cluster.max_shards_per_node`'s 1000 default, each new daily index was
refused, and Filebeat routed everything to the dead-letter index (1.73 B
documents by 2026-09-24). #3362 fixed the dominant term (Zeek's 84 per-day
families became 84 per month) and #3344 cleared the unassigned replicas, but
the owner re-measured afterwards and found one family left:

    Nearly every family already has an ILM policy; only arkime_sessions3-*
    is unmanaged.

Unbounded, so the arithmetic never settles: one more index every day, forever.
The 12 daily indices already on disk were never going to expire either. This
test pins the four things that fix depends on, and the one place it must not
reach:

* the policy exists BEFORE the template that names it. Elasticsearch validates
  `index.lifecycle.name` at index creation, so a template naming a policy that
  is not there yet fails index creation outright. `arkime-init` and
  `elasticsearch-setup` are independent one-shots that race, and arkime-capture
  waits only on `arkime-init.done`, so a policy created by the other job could
  not be relied on to exist in time. This is the assertion that fails if
  someone "tidies" the two ensurePolicy/template calls into the other order,
  and nothing else in the repo would notice.
* the policy is delete-only and its min_age is the operator's single retention
  knob, not a hardcoded number.
* the composed template actually carries the policy -- asserted by running the
  script's own `_simulate_index` check against a stub that composes the answer
  from the template the script really sent, so a merge that dropped the setting
  fails instead of printing a green run.
* the indices that predate the template are adopted, and an index already
  carrying some other lifecycle name is left alone rather than clobbered.

Deliberately NOT asserted: that the two init jobs never race (they do, and
neither can be made to wait for the other), or that a raised shard cap is in
the repo. `cluster.max_shards_per_node` was raised to 1500 live to unblock
ingest; the real fix removes the need for it, and pinning the raised number in
the repo would mask a recurrence of exactly this bug. `grep max_shards_per_node`
stays empty on purpose.

The dependency-free half matters: quality.yml's tests/docs row installs only
pytest, so the compose-file assertion below uses text, not a YAML parse.
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import threading
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "arcane/home/honeypot-init/arkime/composable-templates.js"
COMPOSE = REPO_ROOT / "arcane/home/honeypot-init/compose.yml"
SETUP = REPO_ROOT / "arcane/home/honeypot-init/analysis/elasticsearch-setup.sh"
ENV_EXAMPLE = REPO_ROOT / "arcane/home/honeypot-init/.env.example"
STORAGE_DOC = REPO_ROOT / "docs/STORAGE.md"

POLICY = "arkime-sessions-30d"
SESSIONS_FAMILY = "arkime-sessions3"
SESSIONS_PATTERN = "arkime_sessions3-*"
CAT_PATH = f"/_cat/indices/{SESSIONS_PATTERN}?format=json&h=index&expand_wildcards=all"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed; the script under test is Node")

# --- an Elasticsearch that only knows what a test tells it -------------------

# The legacy templates db.pl installs, trimmed to the fields the merge reads.
# `lifecycle_name` is the knob for the one test that needs Arkime's own
# template to disagree with this stack's policy.
LEGACY_TEMPLATE = {
    "order": 1,
    "settings": {"index": {"refresh_interval": "5s"}},
    "mappings": {"properties": {"firstPacket": {"type": "date"}}},
    "aliases": {},
}
LEGACY_ECS_TEMPLATE = {
    "order": 2,
    "settings": {"index": {}},
    "mappings": {
        "dynamic_templates": [{"strings_as_keyword": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
        "properties": {"node": {"type": "keyword"}},
    },
    "aliases": {},
}


def _default_responses(*, lifecycle_name=None, indices=(), settings=None):
    """The route table for a healthy cluster with Arkime's templates installed.

    `indices` is the list of arkime_sessions3-* names `_cat/indices` reports;
    `settings` maps a name to the `index.lifecycle.name` it already carries
    (absent from the mapping means unmanaged).
    """
    sessions_legacy = json.loads(json.dumps(LEGACY_TEMPLATE))
    if lifecycle_name:
        sessions_legacy["settings"]["index"]["lifecycle.name"] = lifecycle_name
    routes = {
        ("GET", "/_template/arkime_sessions3_template"): (200, {"arkime_sessions3_template": sessions_legacy}),
        ("GET", "/_template/arkime_sessions3_ecs_template"): (200, {"arkime_sessions3_ecs_template": LEGACY_ECS_TEMPLATE}),
        # No history template: config.ini never sets `history=`, so this is the
        # live shape, and the family must be skipped rather than half-installed.
        ("GET", "/_template/arkime_history_v1_template"): (404, {"error": {"type": "resource_not_found_exception"}}),
        ("PUT", f"/_ilm/policy/{POLICY}"): (200, {"acknowledged": True}),
        ("PUT", f"/_index_template/{SESSIONS_FAMILY}"): (200, {"acknowledged": True}),
        # No entry for _simulate_index: the stub composes that one from the
        # template the script actually sent (see _Stub.compose), which is the
        # only way the script's own verification can fail.
        ("GET", CAT_PATH): (200, [{"index": name} for name in indices]),
        ("DELETE", "/_index_template/arkime-sessions3-ip-fix"): (404, {"error": {"type": "resource_not_found_exception"}}),
    }
    for name in indices:
        current = (settings or {}).get(name)
        body = {name: {"settings": {"index.lifecycle.name": current}}} if current else {name: {"settings": {}}}
        routes[("GET", f"/{name}/_settings?flat_settings=true")] = (200, body)
        routes[("PUT", f"/{name}/_settings")] = (200, {"acknowledged": True})
    return routes


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - silence the stub's stderr
        pass

    def _serve(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw.decode("utf-8")) if raw else None
        # Percent-decoded so a test can spell the wildcard as `*` and assert on
        # a readable path; the raw one is kept for the same reason.
        path = urllib.parse.unquote(self.path)
        self.server.calls.append((method, path, body))
        # Remember what was installed before answering, so a later
        # _simulate_index can be composed from it rather than looked up.
        self.server.record(method, path, body)
        status, payload = self.server.routes.get(
            (method, path), (404, {"error": {"type": "resource_not_found_exception"}})
        )
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        self._serve("GET")

    def do_PUT(self):  # noqa: N802
        self._serve("PUT")

    def do_POST(self):  # noqa: N802
        self._serve("POST")

    def do_DELETE(self):  # noqa: N802
        self._serve("DELETE")


class _Stub(ThreadingHTTPServer):
    """Threading so a keep-alive connection cannot deadlock the request loop."""

    daemon_threads = True

    def __init__(self, routes):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.routes = routes
        self.calls: list[tuple[str, str, object]] = []
        self.templates: dict[str, dict] = {}

    def compose(self, method: str, path: str):
        """The one answer the stub has to compute rather than look up.

        Elasticsearch answers `_simulate_index` by composing every matching
        composable template, so the stub does too -- from the template body
        the script really sent. Echoing a canned reply instead would make the
        script's own verification pass no matter what it installed.
        """
        if method != "POST" or not path.startswith("/_index_template/_simulate_index/"):
            return None
        pattern = path.rsplit("/", 1)[-1].replace("composable-check", "*")
        for body in self.templates.values():
            if pattern in (body.get("index_patterns") or []):
                return 200, {"template": body.get("template", {})}
        return 200, {"template": {}}

    def record(self, method: str, path: str, body) -> None:
        if method == "PUT" and path.startswith("/_index_template/"):
            self.templates[path.rsplit("/", 1)[-1]] = body or {}


@contextmanager
def stub_cluster(routes: dict):
    server = _Stub(routes)
    # Route the computed answers in front of the static table.
    original = dict(server.routes)
    server.routes = _Routing(original, server)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _Routing(dict):
    """Static routes first, then whatever the cluster has to compute."""

    def __init__(self, static, server):
        super().__init__(static)
        self.server = server

    def get(self, key, default=None):
        hit = super().get(key)
        if hit is not None:
            return hit
        computed = self.server.compose(*key)
        return computed if computed is not None else default


def run_script(routes: dict, *, env: dict | None = None, expect_ok: bool = True):
    """Run the real script against a stub cluster; return (calls, result)."""
    with stub_cluster(routes) as server:
        # The handler records into server.calls; the computed-route hook needs
        # the same object, so it is wired here rather than in __init__.
        handler_calls = server.calls
        environ = {"PATH": "/usr/bin:/bin", "ARKIME__elasticsearch": f"http://127.0.0.1:{server.server_address[1]}"}
        environ.update(env or {})
        result = subprocess.run(
            [NODE, str(SCRIPT)], capture_output=True, text=True, env=environ, timeout=60
        )
        calls = list(handler_calls)
    if expect_ok:
        assert result.returncode == 0, (
            f"composable-templates.js failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return calls, result


def mutations(calls):
    """Every request that changes cluster state, in order."""
    return [call for call in calls if call[0] in ("PUT", "POST", "DELETE")]


def body_for(calls, method, path):
    for call_method, call_path, body in calls:
        if (call_method, call_path) == (method, path):
            return body
    return None


def code_only(path: pathlib.Path) -> str:
    """A file with its comment lines removed.

    Prose about a setting is not a setting. Both assertions below are about
    what the repo *does* -- one owner for the policy, no pinned shard cap --
    and both files legitimately discuss those subjects in comments (the
    #2820 note in .env.example explains why the retention knob is a shard
    knob; the #3283 block in elasticsearch-setup.sh explains why the policy
    lives elsewhere). Reading the comments as configuration would make a
    documentation improvement look like the defect it documents.

    Whole-line comments only, which is the same granularity
    scripts/check-compose-env-docs.py uses.
    """
    return "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


# --------------------------------------------------------------------------
# The policy, and the ordering the whole fix rests on
# --------------------------------------------------------------------------


@needs_node
def test_policy_is_created_before_the_template_that_names_it():
    """The property that makes this safe on a cluster with no policy yet.

    `index.lifecycle.name` is validated when an index is created, not when a
    template is installed, so a template that names a missing policy produces a
    cluster whose every future sessions index fails. Creating the policy in
    elasticsearch-setup.sh instead would be a race: that job and arkime-init
    have no ordering between them, and arkime-capture starts on
    arkime-init.done alone.
    """
    calls, _ = run_script(_default_responses())
    order = [(method, path) for method, path, _ in calls]
    policy_at = order.index(("PUT", f"/_ilm/policy/{POLICY}"))
    template_at = order.index(("PUT", f"/_index_template/{SESSIONS_FAMILY}"))
    assert policy_at < template_at, (
        "the ILM policy must be installed before the index template that names "
        f"it, got policy at {policy_at} and template at {template_at}. With the "
        "order reversed, a fresh cluster accepts the template and then refuses "
        "every arkime_sessions3-* index for want of the policy (#3283)."
    )


@needs_node
@pytest.mark.parametrize(
    "env,expected",
    [
        ({"HONEYPOT_RETENTION_DAYS": "21"}, "21d"),
        ({"HONEYPOT_RETENTION_DAYS": "30"}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": "7"}, "7d"),
        # Unset, empty, and unusable values all fall back to the same 30 the
        # shell default in elasticsearch-setup.sh and honeypot-init/compose.yml
        # would produce, rather than to a window nobody chose.
        ({}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": ""}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": "   "}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": "0"}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": "-5"}, "30d"),
        ({"HONEYPOT_RETENTION_DAYS": "twenty"}, "30d"),
    ],
)
def test_policy_is_delete_only_and_scales_with_the_retention_knob(env, expected):
    calls, _ = run_script(_default_responses(), env=env)
    body = body_for(calls, "PUT", f"/_ilm/policy/{POLICY}")
    assert body is not None, f"no _ilm/policy/{POLICY} was installed"
    phases = body["policy"]["phases"]
    # `hot` must be present and empty, exactly like every policy in
    # elasticsearch-setup.sh's loop: a policy's phases are replaced wholesale,
    # so omitting it drops the phase rather than defaulting it.
    assert phases["hot"] == {"actions": {}}, f"hot phase is not empty: {phases['hot']}"
    assert phases["delete"]["min_age"] == expected, (
        f"delete.min_age is {phases['delete']['min_age']!r}, expected {expected!r} "
        f"for HONEYPOT_RETENTION_DAYS={env.get('HONEYPOT_RETENTION_DAYS')!r} (#3283)"
    )
    assert phases["delete"]["actions"] == {"delete": {}}
    assert set(phases) == {"hot", "delete"}, f"unexpected phases: {sorted(phases)}"


@needs_node
def test_installed_template_carries_the_policy_and_the_replica_count():
    """The template body, not just the policy PUT.

    This is what every *future* arkime_sessions3-* index is created from, so a
    template without the policy name leaves the family growing unmanaged while
    the run reports success.
    """
    calls, _ = run_script(_default_responses())
    template = body_for(calls, "PUT", f"/_index_template/{SESSIONS_FAMILY}")
    assert template is not None, "the composable template was never installed"
    index_settings = template["template"]["settings"]["index"]
    assert index_settings["lifecycle.name"] == POLICY, (
        f"template settings carry no lifecycle name: {index_settings}"
    )
    # #3283's other half is unchanged by this fix and must stay asserted: the
    # single node cannot allocate a replica (that was 12 unassigned shards).
    assert index_settings["number_of_replicas"] == "0"
    # And Arkime's own settings must survive the merge -- a template that
    # replaced the family wholesale would be a different regression.
    assert index_settings["refresh_interval"] == "5s", f"Arkime's own settings were lost: {index_settings}"
    assert template["index_patterns"] == [SESSIONS_PATTERN]
    # The verification the script performs on itself: _simulate_index is
    # answered by composing the template above, so a dropped setting fails here
    # rather than in production.
    simulate = [call for call in calls if call[0] == "POST" and "_simulate_index" in call[1]]
    assert simulate, "the script no longer simulates the composed template"


@needs_node
def test_arkimes_own_lifecycle_setting_cannot_override_this_stacks_policy():
    """The merge direction, pinned.

    `deepMerge(settings, clusterSettings)` puts the cluster's own settings last
    so they win. Arkime does not set `index.lifecycle.name` today; if a future
    db.pl did, the wrong direction would leave every new index on a policy
    this stack never created -- or with none at all.
    """
    calls, _ = run_script(_default_responses(lifecycle_name="some-arkime-policy"))
    template = body_for(calls, "PUT", f"/_index_template/{SESSIONS_FAMILY}")
    assert template["template"]["settings"]["index"]["lifecycle.name"] == POLICY, (
        "Arkime's legacy template overrode this stack's retention policy; the "
        "cluster-local settings must win the merge (#3283)"
    )


@needs_node
def test_the_history_family_is_installed_without_retention():
    """Scoping. `arkime_history_v1-*` is a different data class.

    config.ini never sets `history=`, so the family is not created at all, and
    search history is not session telemetry. Giving it this stack's session
    policy by accident would delete operator search history on a retention
    knob meant for network captures.
    """
    calls, _ = run_script(_default_responses())
    history = body_for(calls, "PUT", "/_index_template/arkime-history-v1")
    assert history is None, (
        "arkime_history_v1 was installed with a retention policy; the live "
        "cluster has no arkime_history_v1_template for it to translate (#3283)"
    )
    assert not any("arkime_history_v1-*" in path for _, path, _ in calls), (
        "the script adopted an arkime_history_v1-* index; that family is out of "
        "scope for #3283 and is not created on this stack"
    )


# --------------------------------------------------------------------------
# Adoption: the indices that predate the template
# --------------------------------------------------------------------------


@needs_node
def test_existing_unmanaged_indices_are_adopted():
    """Without this, the family keeps the size it has today while looking fixed.

    A composable template only governs indices created after it is installed.
    The 12 daily indices already on disk were never going to expire otherwise.
    """
    names = ["arkime_sessions3-2026.09.10", "arkime_sessions3-2026.09.23", "arkime_sessions3-2026.09.24"]
    calls, result = run_script(_default_responses(indices=names))
    for name in names:
        body = body_for(calls, "PUT", f"/{name}/_settings")
        assert body == {"index.lifecycle.name": POLICY}, (
            f"{name} was not adopted under {POLICY}: {body!r} (#3283)"
        )
    # The wildcard has to be asked for: enumerating the family is the only way
    # to reach indices created before this template existed.
    assert any(path == CAT_PATH for _, path, _ in calls), (
        f"the script never listed {SESSIONS_PATTERN}; it cannot adopt what it "
        "does not enumerate (#3283)"
    )
    assert "2 index(es) adopted" in result.stdout or "3 index(es) adopted" in result.stdout


@needs_node
def test_adoption_is_idempotent_and_never_clobbers_another_policy():
    """Two deploys in a row, and an operator's deliberate choice.

    `arkime-init` re-runs on every deploy, so the second run must be a no-op on
    indices the first run adopted. An index carrying a different lifecycle name
    is somebody's decision, and silently replacing it is how a retention
    change happens without anyone deciding to make one.
    """
    names = [
        "arkime_sessions3-2026.09.01",   # closed, still has to be reached
        "arkime_sessions3-2026.09.20",   # already adopted by an earlier run
        "arkime_sessions3-2026.09.22",   # operator set their own policy
    ]
    settings = {
        "arkime_sessions3-2026.09.20": POLICY,
        "arkime_sessions3-2026.09.22": "operator-chosen-90d",
    }
    calls, result = run_script(_default_responses(indices=names, settings=settings))

    adopted = [name for name in names if body_for(calls, "PUT", f"/{name}/_settings") is not None]
    assert adopted == ["arkime_sessions3-2026.09.01"], (
        f"adoption touched {adopted}; only the unmanaged index may be written "
        "(#3283)"
    )
    assert "operator-chosen-90d" in result.stdout, (
        "an index on another policy was left alone without saying so; this "
        "one-shot init job's log is the only place that can surface (#3283)"
    )
    assert "1 index(es) adopted, 1 already on" in result.stdout, (
        f"the summary does not distinguish adopted from already-managed: {result.stdout}"
    )


@needs_node
def test_a_cluster_with_no_sessions_indices_still_succeeds():
    """The fresh-cluster shape: nothing to adopt is not a failure.

    This is the path a first deploy takes, and it is also what runs on every
    deploy after the retention has aged the family down to nothing. An
    adoption step that treated an empty family as an error would take out
    Arkime on exactly those mornings.
    """
    calls, result = run_script(_default_responses(indices=[]))
    assert any(path == CAT_PATH for _, path, _ in calls)
    assert "0 index(es) adopted, 0 already on" in result.stdout, result.stdout


# --------------------------------------------------------------------------
# DRY_RUN
# --------------------------------------------------------------------------


@needs_node
def test_dry_run_prints_the_plan_and_changes_nothing():
    """The same script has to be inspectable before it is pointed at a cluster.

    DRY_RUN is how an operator reads the policy and the adoption list without
    installing it, so it must cover the new steps -- and must issue no writes,
    or "preview" would be a second, unreviewed way to change the cluster.
    """
    names = ["arkime_sessions3-2026.09.10", "arkime_sessions3-2026.09.20"]
    calls, result = run_script(
        _default_responses(indices=names, settings={"arkime_sessions3-2026.09.20": POLICY}),
        env={"DRY_RUN": "1"},
    )
    assert not mutations(calls), f"DRY_RUN issued writes: {mutations(calls)}"
    assert POLICY in result.stdout, "DRY_RUN does not print the policy it would install"
    assert "would adopt 2 existing arkime_sessions3-* index(es)" in result.stdout, result.stdout
    printed = [line for line in result.stdout.splitlines() if line.startswith("{")]
    assert len(printed) == 2, f"expected the policy and the template, got {printed}"


# --------------------------------------------------------------------------
# The wiring, without a YAML parse
# --------------------------------------------------------------------------


def _service_block(text: str, service: str) -> str:
    """One service's own lines, by indentation.

    Services sit at two spaces, so the body runs until the next line indented
    exactly two spaces and then a non-space. A substring search would also
    match the two spaces of a six-space `- FOO=` item line and stop early, and
    every "this key is absent" assertion below would then pass vacuously.
    """
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"  {service}:"), None)
    assert start is not None, f"service {service} not found"
    body = []
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith("   "):
            break
        body.append(line)
    assert body, f"_service_block({service}) returned nothing; the extractor is broken"
    return "\n".join(body)


def test_arkime_init_receives_the_retention_knob():
    """The derivation has to be fed, or it silently uses a hardcoded window.

    The script defaults to 30 days when the variable is absent, which is a
    silent divergence rather than a loud one: Arkime sessions would expire on
    their own schedule while every other family followed the operator's
    HONEYPOT_RETENTION_DAYS, and the family this issue is about would be the
    one knob does not reach.
    """
    body = _service_block(COMPOSE.read_text(encoding="utf-8"), "arkime-init")
    line = next(
        (l.strip() for l in body.splitlines() if "HONEYPOT_RETENTION_DAYS" in l and not l.strip().startswith("#")),
        None,
    )
    assert line == "- HONEYPOT_RETENTION_DAYS=${HONEYPOT_RETENTION_DAYS:-30}", (
        f"arkime-init does not pass the retention knob: {line!r}. The default "
        "must match elasticsearch-setup's own default or the two disagree (#3283)."
    )


def test_the_knob_is_documented_in_this_stacks_env_example():
    """compose-interpolated variables must be documented per stack.

    The same contract scripts/check-compose-env-docs.py enforces for every
    stack; asserted here too because the failure it prevents is specific --
    an operator who never learns the knob exists cannot shorten the one
    family that is still growing.
    """
    env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert re.search(r"^HONEYPOT_RETENTION_DAYS=", env_example, re.M), (
        "honeypot-init/.env.example no longer documents HONEYPOT_RETENTION_DAYS"
    )
    setup_block = _service_block(COMPOSE.read_text(encoding="utf-8"), "elasticsearch-setup")
    assert "HONEYPOT_RETENTION_DAYS=${HONEYPOT_RETENTION_DAYS:-30}" in setup_block, (
        "the default this test pins against elasticsearch-setup's own has moved"
    )


def test_the_policy_has_exactly_one_owner():
    """One definition, in the job that installs the template naming it.

    A second `curl -X PUT _ilm/policy/arkime-sessions-30d` in
    elasticsearch-setup.sh would be a second source of truth for the same age,
    in a job with no ordering against the one that has to create the policy
    before the template -- the exact race the ordering test rules out.
    """
    assert POLICY not in code_only(SETUP), (
        f"{POLICY} is now also defined in elasticsearch-setup.sh. The policy "
        "belongs to arkime-init, which installs the template naming it; a "
        "second definition is a second age and a race (#3283)."
    )
    assert POLICY in SCRIPT.read_text(encoding="utf-8")


def test_the_shard_cap_is_not_pinned_in_the_repo():
    """Deliberate, and the reason the real fix is the real fix.

    `cluster.max_shards_per_node` was raised from its 1000 default to 1500 as a
    live, reversible unblock on 2026-09-24. Keeping that number in the repo
    would buy headroom while making the recurrence invisible: the stack would
    sit comfortably under a ceiling nobody had looked at, until the day the
    next unbounded family appeared. So the ceiling stays at Elasticsearch's
    default, and the arithmetic has to add up instead.
    """
    for path in (SETUP, COMPOSE, ENV_EXAMPLE, REPO_ROOT / ".env.example"):
        text = code_only(path)
        assert "max_shards_per_node" not in text, (
            f"{path.name} pins cluster.max_shards_per_node. #3283's fix is that "
            "every family is bounded, not that the ceiling moves; raising it in "
            "the repo would hide the next one."
        )


def test_storage_doc_names_the_family_and_its_owner():
    """The gap was invisible, so the fix says where it lives.

    docs/STORAGE.md is the page that answers "what bounds this?", and
    arkime_sessions3-* was the one family it could not answer for.
    """
    text = STORAGE_DOC.read_text(encoding="utf-8")
    assert POLICY in text, f"docs/STORAGE.md does not mention {POLICY}"
    assert "arkime_sessions3-*" in text
    assert "arkime-init" in text, "the doc must say which job owns the policy"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
