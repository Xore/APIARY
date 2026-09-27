# PentAGI on the homeserver — what it was, and how it was closed down

Point-in-time record of the [PentAGI](https://github.com/vxcontrol/pentagi)
autonomous-pentest stack that was running on the `homeserver` (SSH alias;
`supermicro`, NVIDIA RTX 4000 Ada), captured **2026-09-27** and closed down the
same day. Reference: #3277.

**Outcome: the stack is stopped and cannot come back. Nothing was deleted.**
Volumes, compose files, `.env` and the terminal workloads all survive on the
host, so this is a shutdown rather than an uninstall and the inventory below
still describes reality.

Two things this doc deliberately does **not** carry, and why:

- **No configuration values, for any key.** For every key below the record is
  *set or unset* plus a character count. Set-vs-unset is the operationally
  useful part; the values are credentials, endpoints and salts and they live
  only in `/var/pentagi/.env` on the host.
- **No compose files.** `/var/pentagi/docker-compose*.yml` and
  `/var/pentagi/.env` are not committed here. The repo describes the stack;
  it does not carry it. `scripts/check-public-leaks.py` is what keeps it that
  way — it fails the build on a deployment `.env`, on a literal credential
  assignment, and on the homeserver's own address, among other things.

## Decision this record exists for

Niklas decided 2026-09-27 that PentAGI is **not wanted in the fleet**. It was
installed out-of-band on the homeserver, entirely outside the fleet's normal
mechanism (the Arcane/dockge-managed stacks under `/var/dockge/stacks/` that
every other service in this repo uses). Nothing in the repo referenced it
before this doc, and nothing references it operationally now.

#3277's Phase 1 (install PentAGI) and Phase 2 (install vLLM serving
Qwen3.5-27B-FP8, or wire up colibri) are **obsolete and were never executed as
written**. See "The LLM backend was never vLLM" below — the vLLM plan is the
single most misleading thing about that issue, and this doc exists partly to
stop it being repeated.

## How it ran

Compose project `pentagi`, working directory `/var/pentagi`, composed from
three files in that order:

```
/var/pentagi/docker-compose.yml
/var/pentagi/docker-compose.override.yml
/var/pentagi/docker-compose-graphiti.yml
```

Also present in `/var/pentagi` and not part of the composed project:
`docker-compose-langfuse.yml`, `docker-compose-observability.yml`,
`.env`, `.env.example`, `docker-ssl/`, `.bak/`, and an upstream `backend/`
checkout. All of it is left in place.

### Compose services (7)

State as captured, immediately before teardown. All seven declare
`restart: unless-stopped`.

| Container | Service | Image | State at capture | Published ports | Networks |
|---|---|---|---|---|---|
| `pentagi` | `pentagi` | `vxcontrol/pentagi:latest` | Up 2 days | **host LAN address**:8443→8443 (the only non-loopback binding in the stack) | `pentagi-network`, `langfuse-network`, `observability-network` |
| `pentagi-ollama-embedding` | `ollama-embedding` | `ollama/ollama:0.32.13` | Up 4 days | none — 11434 reachable on `pentagi-network` only | `pentagi-network` |
| `pentagi-vllm` | `vllm` | `vllm/vllm-openai:nightly` | **Exited (0), 4 days** | none | `pentagi-network` |
| `scraper` | `scraper` | `vxcontrol/scraper:latest` | Up 4 days | 127.0.0.1:9443→443 | `pentagi-network` |
| `pgvector` | `pgvector` | `vxcontrol/pgvector:latest` | Up 4 days (healthy) | 127.0.0.1:5432 | `pentagi-network` |
| `pgexporter` | `pgexporter` | `quay.io/prometheuscommunity/postgres-exporter:v0.16.0` | Up 4 days | 127.0.0.1:9187 | `pentagi-network` |
| `neo4j` | `neo4j` | `neo4j:5.26.2` | Up 3 days (healthy) | 127.0.0.1:7474, 127.0.0.1:7687 | `pentagi-network` |
| `graphiti` | `graphiti` | `vxcontrol/graphiti:latest` | Up 3 days (healthy) | 127.0.0.1:8000 | `pentagi-network` |

`pentagi-vllm` is the awkward one: it is **not a member of the composed
project as it stands today** — `vllm` is not a service in the current
`docker-compose.yml` — but the container still carried the `pentagi` project
label from an earlier revision of the file. It had already exited on its own
four days before capture. Because it had exited *on its own* rather than being
stopped, its `unless-stopped` policy would have brought it back on the next
Docker daemon restart; see "Why `down` was not sufficient on its own".

### The three terminals are not compose-managed

`pentagi-terminal-1`, `-2` and `-3` carry **no compose labels at all** — no
`com.docker.compose.project`, no `working_dir`, no `config_files`. PentAGI
creates and reaps them itself as agent execution sandboxes, so no
`docker compose` invocation in `/var/pentagi` can ever see or stop them. This
is the detail that makes a naive "just run `docker compose down`" insufficient.

| Container | Image | State at capture | Published ports | Restart policy | Network |
|---|---|---|---|---|---|
| `pentagi-terminal-1` | `vxcontrol/kali-linux` | Up 4 days | 0.0.0.0:28002, 0.0.0.0:28003 | `on-failure`, 5 retries | `bridge` |
| `pentagi-terminal-2` | `vxcontrol/kali-linux` | Up 4 days | 0.0.0.0:28004, 0.0.0.0:28005 | `on-failure`, 5 retries | `bridge` |
| `pentagi-terminal-3` | `vxcontrol/kali-linux` | Up 3 days | 0.0.0.0:28006, 0.0.0.0:28007 | `on-failure`, 5 retries | `bridge` |

Each keeps its own `pentagi-terminal-N-data` volume at `/work` and bind-mounts
the **host Docker socket** at `/var/run/docker.sock`. Note the divergence from
the brief this doc was written against: the terminals are `on-failure:5`, not
`unless-stopped` — which matters, because `docker stop` on them lands exit 137
(SIGKILL after the 10s grace period), a non-zero code that `on-failure` would
otherwise treat as a crash and restart.

### Networks

Three, all owned by the `pentagi` compose project and all now removed:

| Network | Declared | Notes |
|---|---|---|
| `pentagi-network` | `external: true` in the compose file | the stack's private network; every service except the terminals |
| `langfuse-network` | project-owned | only `pentagi` was ever attached |
| `observability-network` | project-owned | only `pentagi` was ever attached |

No other stack on the host referenced any of the three; they were exclusive to
PentAGI and are not recreated by anything in `/var/dockge/stacks/`.

### Volumes (all preserved)

`pentagi_pentagi-data`, `pentagi_pentagi-ssl`, `pentagi_pentagi-ollama`,
`pentagi_pentagi-embedding`, `pentagi_pentagi-postgres-data`,
`pentagi_scraper-ssl`, `pentagi_neo4j_data`, `pentagi_huggingface-cache`,
`pentagi-terminal-1-data`, `pentagi-terminal-2-data`,
`pentagi-terminal-3-data`.

## The LLM backend was never vLLM

#3277 Phase 2 proposed vLLM serving Qwen3.5-27B-FP8 with CPU offload. **That
did not happen.** The `vllm` service had been exited with code 0 for four days
before capture, and the ollama path is what is configured: `OLLAMA_SERVER_URL`
and `EMBEDDING_URL` both point at a 11434 endpoint on `pentagi-network` — an
in-network compose service, not a host port, not a cloud API. The separate
`pentagi-ollama-embedding` container is the ollama instance serving that port,
so the embedding and LLM configurations both resolve inside `pentagi-network`.

`LLM_SERVER_URL` and `OPEN_AI_SERVER_URL` are also both set, to an `https`
endpoint on a public domain with no explicit port, and `OPEN_AI_KEY` /
`LLM_SERVER_KEY` are both set. So the stack had a live OpenAI-compatible
endpoint configured alongside ollama. Which of the two a given request actually
used is **not** recorded here — the value of `LLM_SERVER_MODEL` is not
reproduced in this doc, and neither is anything else. What is recorded is the
part that matters for the shutdown decision: the configured model backend is
**not** the vLLM container, and `pentagi-vllm` contributed nothing.

### `ghidra-ollama-1` was never PentAGI's

The homeserver's 18.4 GiB `llama-server` holding VRAM belongs to
`ghidra-ollama-1`, which serves `qwen3:14b` on 127.0.0.1:11434 for the Ghidra
analysis stack. It looks superficially like "the ollama PentAGI was pointed
at" and is a different service in a different compose project
(`/var/dockge/stacks/apiary/analysis/ghidra/`). It was explicitly out of scope
for the shutdown and was verified untouched afterwards (`Up 4 days (healthy)`,
its model list unchanged). The same goes for every `hp-*` honeypot container
and for `hp-galah-llm-broker`, the other 11434 listener on the host.

## Configuration: set vs unset

All values live in `/var/pentagi/.env` on the host (mode `0600`, 244 keys) and
are **not** in this repo. The table records only whether a key was set in the
running `pentagi` container's environment, and — for the keys where the count
is genuinely useful when diagnosing a config drift — the character length of
the configured value. No value appears anywhere in this doc, and none was
written down to produce it.

### Set and non-empty

| Key | Chars | Note |
|---|---|---|
| `LLM_SERVER_URL` | 28 | `https`, public domain, no explicit port |
| `LLM_SERVER_KEY` | 73 | secret-bearing |
| `LLM_SERVER_MODEL` | 25 | secret-bearing |
| `OPEN_AI_SERVER_URL` | 28 | `https`, public domain, no explicit port |
| `OPEN_AI_KEY` | 73 | secret-bearing |
| `OLLAMA_SERVER_URL` | 29 | `http`, in-network service, port 11434 |
| `OLLAMA_SERVER_MODEL` | 9 | |
| `EMBEDDING_URL` | 29 | `http`, in-network service, port 11434 |
| `EMBEDDING_MODEL` | 16 | |
| `EMBEDDING_PROVIDER` | 6 | |
| `DATABASE_URL` | 124 | secret-bearing (carries DB credentials) |
| `GRAPHITI_ENABLED` | 4 | |
| `GRAPHITI_URL` | 20 | `http`, in-network service, port 8000 |
| `COOKIE_SIGNING_SALT` | 64 | secret-bearing |

### Unset (present in the environment with an empty value)

| Key | |
|---|---|
| `LLM_SERVER_PROVIDER` | no provider override — the generic OpenAI-compatible path is in use |
| `OLLAMA_SERVER_API_KEY` | ollama reachable with no auth |
| `EMBEDDING_KEY` | embedding reachable with no auth |
| `SEARXNG_URL` | SearXNG **not** in use, despite `SEARXNG_*` category settings being present |
| `TAVILY_API_KEY` | no Tavily |
| `ANTHROPIC_API_KEY` | no Anthropic |
| `PERPLEXITY_API_KEY` | no Perplexity |
| `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_BASE_URL` | tracing **not** wired up, even though `pentagi` was attached to `langfuse-network` |
| `OAUTH_GITHUB_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_ID` | no external SSO |
| `LICENSE_KEY` | community/unlicensed tier |
| `SERVER_SSL_CRT`, `SERVER_SSL_KEY` | no explicit keypair; TLS material comes from the `pentagi_pentagi-ssl` volume instead |
| `INSTALLATION_ID` | unset at capture |

The set-vs-unset split is the useful half of this table and it is worth
reading as a shape: **no search backend, no external LLM vendor key beyond the
one OpenAI-compatible endpoint, no tracing, no SSO, no licence.** The only
credentials present at all were the OpenAI-compatible key pair and the
Postgres/Neo4j/session secrets the stack generates for its own database.

### One real drift worth recording

`LLM_SERVER_URL` and `LLM_SERVER_MODEL` are **empty in `.env`** but non-empty
in the running container's environment, and the two disagree on length for
`LLM_SERVER_URL` (255 in `.env`, 28 in the container). `.env` also carries a
trailing block of `LLM_SERVER_*` / `OMNIROUTE_KEY` overrides appended after
the vendor sections it is meant to fill in, so later definitions win. In other
words **the container's environment is the record of what was actually
running; `.env` on disk had already moved on.** Anything reconstructing this
stack from `.env` alone would not reproduce the running configuration, which
is a second reason not to commit it.

## The shutdown, exactly as run

Run on `homeserver` as the `xore` user. In order:

```bash
# 1. the seven compose services — stop and remove, volumes and files untouched
cd /var/pentagi && docker compose \
  -f docker-compose.yml \
  -f docker-compose.override.yml \
  -f docker-compose-graphiti.yml \
  down

# 2. the vllm leftover + the three unmanaged terminals
docker stop pentagi-vllm pentagi-terminal-1 pentagi-terminal-2 pentagi-terminal-3

# 3. the stack's private network (declared external, so `down` left it behind
#    while pentagi-vllm still held an endpoint on it)
docker network rm pentagi-network

# 4. make the four survivors unable to auto-return
docker update --restart=no pentagi-vllm pentagi-terminal-1 pentagi-terminal-2 pentagi-terminal-3
```

No `-v` / `--volumes` flag anywhere: every volume listed above still exists.
No `rm` of any file: `/var/pentagi` is byte-for-byte as it was.

### Why `down` was not sufficient on its own

`restart: unless-stopped` restarts a container unless it was *manually*
stopped, so `down` (which removes the container) is already durable for the
seven services. Three things needed handling beyond it:

1. **The three terminals are invisible to compose** — no project label. They
   needed a direct `docker stop`, and because they came out at exit 137 under
   an `on-failure:5` policy, `docker update --restart=no` removes any doubt.
2. **`pentagi-vllm` is not in the current compose file**, so `down` skipped it
   entirely. It had exited on its own four days earlier, which means Docker
   had no manual-stop record for it and `unless-stopped` *would* have
   resurrected it on the next daemon restart. It is now stopped and pinned to
   `restart=no`.
3. **`pentagi-network` is declared `external: true`**, so `down` removed the
   two project-owned networks and left it. It needed the explicit
   `docker network rm`, which only succeeded once `pentagi-vllm` had let go of
   its endpoint.

The four surviving containers are left in place, exited, inert, and pinned to
`restart=no`. Nothing named `pentagi*` is running, and nothing can bring it
back without a deliberate `docker start`.

### Verification — from `docker ps`, not from the exit code

```
$ docker ps -a --filter name=pentagi
pentagi-terminal-3   vxcontrol/kali-linux      Exited (137) About a minute ago
pentagi-terminal-2   vxcontrol/kali-linux      Exited (137) About a minute ago
pentagi-terminal-1   vxcontrol/kali-linux      Exited (137) About a minute ago
pentagi-vllm         vllm/vllm-openai:nightly  Exited (0) 4 days ago

$ docker ps --filter name=pentagi --format '{{.Names}}'
NONE

$ docker inspect -f '{{.Name}} policy={{.HostConfig.RestartPolicy.Name}} restartcount={{.RestartCount}}' <each>
/pentagi-terminal-1  policy=no  restartcount=0
/pentagi-terminal-2  policy=no  restartcount=0
/pentagi-terminal-3  policy=no  restartcount=0
/pentagi-vllm        policy=no  restartcount=0

$ for n in pentagi-network langfuse-network observability-network; do ...; done
pentagi-network       absent
langfuse-network      absent
observability-network absent

$ docker volume ls | grep -i pentagi      # 11 volumes, unchanged
$ ls -1 /var/pentagi/docker-compose*.yml /var/pentagi/.env   # all six present
```

`restartcount=0` throughout: nothing was ever restarted by a policy during or
after the teardown.

### What was deliberately left alone

- **`ghidra-ollama-1`** — verified `Up 4 days (healthy)` after the shutdown,
  still serving `qwen3:14b` on 127.0.0.1:11434. Not PentAGI's; other work
  depends on it.
- **`hp-galah-llm-broker`** — the other 11434 listener, `Up 4 days (healthy)`.
- **Every `hp-*` honeypot container** and every other Arcane/dockge stack —
  92 containers running on the host afterwards, unchanged.
- **All 11 PentAGI volumes**, the ollama model store inside them, all compose
  files, `.env`, `docker-ssl/` and `.bak/`.

## If it ever has to come back

Everything needed is still on the host, so a restore is
`cd /var/pentagi && docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose-graphiti.yml up -d`
plus a `docker network create pentagi-network` first (external, so compose
will not create it), plus re-enabling `restart` on the four pinned
containers. Expect the `.env` drift above to bite: the on-disk file does not
match the configuration that was actually running, and the value of
`LLM_SERVER_URL` in it is not the one the stack was using. The compose files
and `.env` were deliberately left byte-identical rather than reconciled,
because reconciling them is a change nobody asked for and this doc is meant to
be a record, not a repair.
