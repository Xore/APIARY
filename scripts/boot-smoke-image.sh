#!/usr/bin/env bash
# boot-smoke-image.sh -- start one built image, wait for the image's own
# HEALTHCHECK to report healthy, assert the HTTP contract that tier answers,
# and always clean up. #3316.
#
# The gap this closes: containers.yml builds and image-security-scan.yml
# scans, but nothing ever *started* the result. A green compile gate and a
# clean vulnerability scan say nothing about the four things that decide
# whether a container comes up at all -- the entrypoint, the runtime user,
# the file layout, and the env contract. The #2183/#2299 boot-refusal class
# ("worker containers refuse to boot") was found live, on a deployed host,
# because of exactly that. This turns it into a build-time failure.
#
# Design notes worth keeping if you extend this:
#
#   * It runs the image *by ID*, not by tag. The brief for #3316 asks for
#     that and it is the whole point: a tag can be moved underneath the
#     step, so a green smoke on `honeypot-backend-service:pr-1234` is a
#     statement about whatever that tag resolved to at that instant. The ID
#     is what the build just produced, and it is what got pushed.
#
#   * The gate is the image's own HEALTHCHECK going healthy, not a probe
#     this script invented. That is deliberate: the healthcheck is part of
#     the artifact, so if it is wrong (wrong port, wrong path, a curl that
#     is not in the image) the smoke fails on the real defect instead of
#     passing against a substitute. The per-tier HTTP assertions below are
#     additive -- they check the *contract* (what a response says), not
#     merely that something answered.
#
#   * A container that exits during the wait fails immediately with its
#     logs, rather than burning the whole timeout first. The boot refusals
#     this exists to catch are exit-in-under-a-second, and the useful
#     artifact is the log line that says why ([E-SERVICE-TOKEN] and
#     friends), not a timeout message.
#
#   * No --rm. The container is removed in an EXIT trap *after* its logs
#     have been captured, because the whole point of a failure path is to
#     have the logs to show.
#
# Usage:
#   boot-smoke-image.sh --image-id <sha256:...> --name <container> \
#                       --container-port <port> [--env K=V]... \
#                       [--stub-es-env K]... [--health-timeout <seconds>] \
#                       [--expect-status <label> <path> <code-regex>]... \
#                       [--expect-redirect <label> <path> <substring>]... \
#                       [--expect-json <label> <path> <python-expr>]... \
#                       [--keep-image]
#
#   --image-id        required. sha256:<64 hex>. The image to run.
#   --name            required. Container name, so cleanup is unambiguous.
#   --container-port  required. Published on 127.0.0.1 with an ephemeral
#                     host port -- the homeserver runs one docker daemon
#                     behind seven runner users, so a fixed host port is a
#                     collision waiting to happen.
#   --env             repeatable. Extra container environment.
#   --stub-es-env     repeatable. Name of a container env var to point at a
#                     stub Elasticsearch this script starts (see below).
#   --health-timeout  seconds to wait for healthy. Default 120.
#   --expect-status   repeatable. GET <path> must answer with a status
#                     matching <code-regex> (a regex, so `30[27]` works).
#   --expect-redirect repeatable. GET <path> must answer 3xx with a Location
#                     containing <substring>.
#   --expect-json     repeatable. GET <path>, parse as JSON, assert the
#                     python expression over it. Same idiom as
#                     arcane/home/honeypot-dashboard/port-tests/lib.sh.
#   --keep-image      do not `docker rmi` the image afterwards.
#
# Exit status: 0 only if the image reached healthy AND every assertion
# held. Any other outcome exits non-zero after printing `docker logs`.
set -uo pipefail

die() {
  echo "boot-smoke-image: $*" >&2
  exit 1
}

# ------------------------------------------------------------- arguments ----

image_id=""
name=""
container_port=""
health_timeout=120
keep_image=0
envs=()
stub_es_vars=()
assertions=()

while [ $# -gt 0 ]; do
  case "$1" in
    --image-id)
      image_id=${2:?--image-id needs a value}
      shift 2
      ;;
    --name)
      name=${2:?--name needs a value}
      shift 2
      ;;
    --container-port)
      container_port=${2:?--container-port needs a value}
      shift 2
      ;;
    --health-timeout)
      health_timeout=${2:?--health-timeout needs a value}
      shift 2
      ;;
    --env)
      envs+=("${2:?--env needs a value}")
      shift 2
      ;;
    --stub-es-env)
      stub_es_vars+=("${2:?--stub-es-env needs a value}")
      shift 2
      ;;
    --expect-status)
      [ $# -ge 4 ] || die "--expect-status needs <label> <path> <code-regex>"
      assertions+=("status|$2|$3|$4")
      shift 4
      ;;
    --expect-redirect)
      [ $# -ge 4 ] || die "--expect-redirect needs <label> <path> <substring>"
      assertions+=("redirect|$2|$3|$4")
      shift 4
      ;;
    --expect-json)
      [ $# -ge 4 ] || die "--expect-json needs <label> <path> <python-expr>"
      assertions+=("json|$2|$3|$4")
      shift 4
      ;;
    --keep-image)
      keep_image=1
      shift
      ;;
    -h | --help)
      # Print this file's own leading comment block: a help text that drifts
      # out of date with the code below it is worse than no help text.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$image_id" ] || die "--image-id is required"
[ -n "$name" ] || die "--name is required"
[ -n "$container_port" ] || die "--container-port is required"
case "$image_id" in
  sha256:*) ;;
  *) die "--image-id must be an image ID (sha256:...), got: $image_id" ;;
esac
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "--image-id carries a malformed digest: $image_id"
[[ $health_timeout =~ ^[0-9]+$ ]] || die "--health-timeout must be whole seconds: $health_timeout"
[[ $container_port =~ ^[0-9]+$ ]] || die "--container-port must be a port number: $container_port"

# Reusing a name from a previous run would make "is this container healthy"
# answerable by a stale container, and the cleanup would then remove
# somebody else's. Refuse rather than guess.
if docker container inspect "$name" >/dev/null 2>&1; then
  die "a container named '$name' already exists; refusing to reuse it"
fi

# ------------------------------------------------------------------ work ----

work=$(mktemp -d)
stub_pid=""
container_started=0

cleanup() {
  # Order matters: the container first (so nothing is still writing into
  # $work), then the stub, then the scratch dir.
  if [ "$container_started" -eq 1 ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  if [ -n "$stub_pid" ]; then
    kill "$stub_pid" >/dev/null 2>&1 || true
    wait "$stub_pid" 2>/dev/null || true
  fi
  # The image came out of the build purely to be booted. Leaving a
  # 400 MB layer set behind on a daemon shared by seven runner users is
  # the kind of thing disk-usage-watch.yml exists to complain about, so
  # the default is to give the space back; --keep-image is the escape
  # hatch for someone who wants to poke at the failure by hand.
  if [ "$keep_image" -eq 0 ] && [ "$container_started" -eq 1 ]; then
    docker rmi "$image_id" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

# --------------------------------------------------------------- stub ES ----
#
# The brief for #3316 asks for a stub Elasticsearch, and here is the honest
# reason it earns its place rather than being set dressing: the 8.x client
# refuses to talk to a server that does not identify itself as
# Elasticsearch, so /readyz can only be exercised end-to-end against
# something that answers like ES. Against nothing at all, the backend still
# reaches healthy (its healthcheck is /livez, which has not touched ES since
# #3317 split liveness from readiness) and a stub nobody calls would prove
# nothing.
#
# It is a floor, not a mock: it answers the three things es.rs asks for --
# the root product document, _cluster/health, and the index-settings
# probe -- and nothing else. No query the dashboard would run is emulated,
# so a green result here says "the ES env contract is plumbed and the
# readiness path works", never "the backend can serve the dashboard".
#
# Bound to the docker bridge gateway rather than 0.0.0.0. The executor is a
# honeypot host with a public interface; a port that is open for the
# duration of a CI run, even on an ephemeral one, is not something to
# create as a side effect of a test. The container reaches it through
# --add-host host.docker.internal:host-gateway, which resolves to exactly
# this address.
#
# The port is chosen by the stub itself (bind port 0) and written to a file,
# so there is no close-then-reopen race for it.

STUB_ES_PY="$work/stub-es.py"

write_stub_es() {
  cat >"$STUB_ES_PY" <<'PY'
#!/usr/bin/env python3
"""The smallest thing an elasticsearch-rs 8.x client will talk to.

Answers three requests and logs nothing:
  GET /                     the product document (and the header the 8.x
                             client's transport requires before it will
                             issue any API call at all)
  GET /_cluster/health      -> green
  GET */_settings           -> {} (a fresh cluster: every dashboard-owned
                             index is created on its first write, so an
                             empty object is the honest "nothing is
                             write-blocked" answer)
Anything else gets {} with the product header, which keeps an unmodelled
call from turning into a connection error that reads like a boot failure.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "8.13.0"
NAME = "apiary-boot-smoke"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "elasticsearch/" + VERSION

    def log_message(self, *args):
        pass  # the runner log has the smoke's own output on it

    def _send(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.elasticsearch+json; compatible-with=8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/_cluster/health":
            self._send({
                "cluster_name": NAME,
                "status": "green",
                "timed_out": False,
                "number_of_nodes": 1,
                "number_of_data_nodes": 1,
                "discovered_master": True,
                "active_primary_shards": 0,
                "active_shards": 0,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0,
            })
            return
        if path.endswith("/_settings"):
            self._send({})
            return
        self._send({
            "name": NAME,
            "cluster_name": NAME,
            "cluster_uuid": "boot-smoke",
            "version": {
                "number": VERSION,
                "build_flavor": "default",
                "build_type": "docker",
                "lucene_version": "9.11.1",
            },
            "tagline": "You Know, for Search",
        })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    # Written after bind, so the file appearing is the signal that the
    # socket is already accepting -- no sleep-and-hope.
    with open(args.port_file, "w", encoding="utf-8") as handle:
        handle.write(str(server.server_address[1]))
    server.serve_forever()


if __name__ == "__main__":
    main()
PY
}

start_stub_es() {
  write_stub_es
  local gateway
  gateway=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
  if [ -z "$gateway" ]; then
    die "cannot read the docker bridge gateway; the stub Elasticsearch has to bind something the container can reach. Check that the default 'bridge' network exists on this executor."
  fi
  local port_file="$work/stub-es.port"
  rm -f -- "$port_file"
  python3 "$STUB_ES_PY" --bind "$gateway" --port 0 --port-file "$port_file" >/dev/null 2>&1 &
  stub_pid=$!
  local waited=0
  while [ ! -s "$port_file" ]; do
    if ! kill -0 "$stub_pid" 2>/dev/null; then
      die "the stub Elasticsearch exited before it bound a port"
    fi
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -gt 50 ]; then
      die "the stub Elasticsearch did not report a port within 10s (bridge gateway $gateway)"
    fi
  done
  es_url="http://$gateway:$(cat "$port_file")"
  echo "boot-smoke-image: stub Elasticsearch on $es_url (docker bridge gateway $gateway)"
}

es_url=""
if [ "${#stub_es_vars[@]}" -gt 0 ]; then
  start_stub_es
  for var in "${stub_es_vars[@]}"; do
    envs+=("$var=$es_url")
  done
fi

# ------------------------------------------------------------------- run ----

run_args=(
  run --detach --name "$name"
  # Ephemeral host port, loopback only. The image's own EXPOSE is a
  # container-side statement; this is what makes the tier reachable from
  # the runner without publishing anything off-box.
  --publish "127.0.0.1::${container_port}"
)
if [ "${#stub_es_vars[@]}" -gt 0 ]; then
  run_args+=(--add-host host.docker.internal:host-gateway)
fi
for env in "${envs[@]}"; do
  run_args+=(--env "$env")
done
run_args+=("$image_id")

if ! container_id=$(docker "${run_args[@]}" 2>&1); then
  die "could not start $image_id: $container_id"
fi
container_started=1
echo "boot-smoke-image: started $name ($container_id) as $image_id"
echo "boot-smoke-image: env: ${envs[*]:-<image defaults only>}"

# The published port. Parsed from docker port rather than assumed, so a
# change to how the mapping is written cannot silently point the assertions
# at nothing.
binding=$(docker port "$name" "${container_port}/tcp" 2>/dev/null | head -1)
if [ -z "$binding" ]; then
  die "no published port for ${container_port}/tcp on $name"
fi
host_port=${binding##*:}
case "$host_port" in
  '' | *[!0-9]*) die "could not read a host port from '$binding'" ;;
esac
base_url="http://127.0.0.1:$host_port"
echo "boot-smoke-image: $base_url -> container port $container_port"

# ---------------------------------------------------------- wait: health ----
#
# 120s default, and the arithmetic behind it: both dashboard images declare
# --start-period=20s --interval=15s --retries=5, so the first probe is at
# 20s and a genuinely broken image exhausts its own budget at 20 + 75 = 95s.
# 120 is above that with room for a slow runner, and well below the job
# timeout, so a wedged healthcheck reports as a smoke failure rather than
# as a job timeout with no explanation.

print_health_log() {
  local out
  out=$(docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}  exit={{.ExitCode}} {{printf "%q" .Output}}
{{end}}{{end}}' "$name" 2>/dev/null || true)
  if [ -n "$out" ]; then
    echo "--- last healthcheck probes for $name ---" >&2
    printf '%s' "$out" | tail -5 >&2
  fi
}

dump_failure() {
  local reason="$1"
  echo "boot-smoke-image: FAILED -- $reason" >&2
  echo "--- docker inspect $name ---" >&2
  docker inspect --format \
    'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' \
    "$name" >&2 2>&1 || true
  print_health_log
  echo "--- docker logs $name ---" >&2
  docker logs --tail 200 "$name" >&2 2>&1 || echo "(no logs available)" >&2
}

started_at=$(date +%s)
deadline=$((started_at + health_timeout))
# How long `.State.Health` has been absent. Not zero on the first poll: the
# daemon populates that struct as it creates the container, and treating the
# first `none` as authoritative would let a sub-second race turn a real
# healthcheck into "this image has none". Five seconds is comfortably past
# container creation and costs nothing on the images that do have one.
no_health_since=0
health_supported=0
while :; do
  state=$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$name" 2>/dev/null || true)
  if [ -z "$state" ]; then
    # The container vanished mid-wait. With no --rm that should not happen,
    # so treat it as a real fault rather than as "finished".
    dump_failure "container '$name' disappeared while waiting for it to become healthy"
    exit 1
  fi
  container_state=${state%%|*}
  health_state=${state##*|}
  if [ "$health_state" = "none" ]; then
    now=$(date +%s)
    [ "$no_health_since" -eq 0 ] && no_health_since=$now
    if [ $((now - no_health_since)) -ge 5 ]; then
      # Nothing to wait on. The assertions below are what gate this run, and
      # the warning after the loop says plainly that the health half of the
      # check did not happen -- a coverage gap, not a pass.
      health_supported=0
      break
    fi
  else
    health_supported=1
  fi

  case "$health_state" in
    healthy) break ;;
  esac
  case "$container_state" in
    exited | dead)
      # The #2183/#2299 shape: refused to boot and said why. The log is the
      # answer, so do not make anyone wait out the timeout for it.
      dump_failure "container $name exited ($container_state) before reporting healthy"
      exit 1
      ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    dump_failure "healthcheck did not report healthy within ${health_timeout}s (last: state=$container_state health=$health_state)"
    exit 1
  fi
  sleep 1
done

elapsed=$(( $(date +%s) - started_at ))
if [ "$health_supported" -eq 0 ]; then
  # Degrade loudly rather than pretend. An image with no HEALTHCHECK is a
  # coverage gap for this check, not a pass -- compose's health is exactly
  # what this is standing in for.
  echo "::warning title=No HEALTHCHECK to wait on::$name reports no HEALTHCHECK, so only the HTTP assertions below ran. An image that deploys without one is not being smoke-tested the way this step assumes."
  echo "boot-smoke-image: $name has no HEALTHCHECK to wait on after ${elapsed}s -- assertions only"
else
  echo "boot-smoke-image: $name reported healthy after ${elapsed}s"
fi

# ---------------------------------------------------------- assertions ------

failures=0

probe() {
  # probe <path> <header-out-file> -- prints the status code, leaves the
  # body and headers in the out file. A body is always written so a failure
  # can show what came back instead of only what code it carried.
  local path="$1" out="$2"
  local code
  code=$(curl -sS -o "$out.body" -D "$out.headers" -w '%{http_code}' \
    --max-time 30 "$base_url$path" 2>"$out.err" || true)
  printf '%s' "${code:-000}"
}

report() {
  local label="$1" path="$2" out="$3"
  {
    echo "  --- response body for $label (GET $path) ---"
    head -c 800 "$out.body" 2>/dev/null || echo "(none)"
    echo
    if [ -s "$out.err" ]; then
      echo "  --- curl stderr ---"
      cat "$out.err"
    fi
  } >&2
}

for assertion in "${assertions[@]}"; do
  IFS='|' read -r kind label path want <<<"$assertion"
  out="$work/assert.$RANDOM"
  code=$(probe "$path" "$out")
  ok=0
  case "$kind" in
    status)
      if [[ $code =~ ^($want)$ ]]; then
        ok=1
      fi
      ;;
    redirect)
      location=$(grep -i '^location:' "$out.headers" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2-)
      if [[ $code =~ ^30[0-9]$ ]] && printf '%s' "$location" | grep -qF -- "$want"; then
        ok=1
      fi
      ;;
    json)
      if printf '%s' "$want" | python3 -c '
import sys, json
try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        d = json.load(handle)
except Exception as error:  # noqa: BLE001 - reported, not raised
    sys.exit(f"not JSON: {error}")
try:
    assert eval(sys.argv[2]), "assertion failed"
except AssertionError:
    sys.exit("assertion failed: " + sys.argv[2])
' "$out.body" "$want" 2>"$out.pyerr"; then
        ok=1
      else
        cat "$out.pyerr" >&2
      fi
      ;;
  esac
  if [ "$ok" -eq 1 ]; then
    echo "  ok   $label (GET $path -> $code)"
  else
    echo "  FAIL $label (GET $path -> $code)" >&2
    report "$label" "$path" "$out" >&2
    failures=$((failures + 1))
  fi
  rm -f -- "$out.body" "$out.headers" "$out.err" "$out.pyerr"
done

if [ "$failures" -gt 0 ]; then
  dump_failure "$failures HTTP assertion(s) failed against a container that reported healthy"
  exit 1
fi

# #2214's shape, one level up: a smoke that asserted nothing and had no
# healthcheck to fall back on has measured nothing, and a green run that
# measured nothing is the failure mode this whole check exists to remove.
# Either half alone is a real signal and only warns; both absent is a
# wiring mistake in the caller and says so.
if [ "${#assertions[@]}" -eq 0 ] && [ "$health_supported" -eq 0 ]; then
  echo "::error title=Boot-smoke measured nothing::$name has no HEALTHCHECK and no --expect-* assertion was passed, so this run proved nothing. Pass at least one assertion (see the script's header for the per-tier shapes), or give the image a HEALTHCHECK."
  exit 1
fi

if [ "${#assertions[@]}" -eq 0 ]; then
  echo "::warning title=Boot-smoke asserted nothing::no --expect-* assertion was passed for $name, so only its own healthcheck was checked. That is a coverage gap, not a pass."
  echo "boot-smoke-image: $name reached healthy (no HTTP assertions were configured)"
  exit 0
fi

echo "boot-smoke-image: $name booted and answered every assertion"
exit 0
