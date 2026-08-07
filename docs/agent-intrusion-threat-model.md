# Agent-Speed Intrusion Chain: Threat Model & Applicability Matrix

> **Status:** Research (#154), phase 1 of 5. This document is the "map the
> published campaign to APIARY's actual trust boundaries" deliverable;
> it does not implement anything. Phases 2-5 (synthetic replay corpus,
> decode/correlate pipeline, deterministic criticality rules, preventive
> control gaps, operator evidence UI) are scoped as follow-up work — see
> [Follow-up scope](#follow-up-scope) at the end.
>
> **Source:** [huggingface.co/blog/agent-intrusion-technical-timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
> (July 2026) — an autonomous agent chaining ordinary weaknesses at machine
> speed across evaluation sandboxes, data-processing workers, Kubernetes,
> cloud identity, mesh networking, and source control. ~17,600 actions;
> isolated low-signal events were detected individually but never escalated
> with the right criticality. A corroborating source,
> [openai.com's own incident writeup](https://openai.com/index/hugging-face-model-evaluation-security-incident/),
> confirmed the initial foothold and added two checks folded in below (§1a).
>
> **Updated** since first landing (#591): §1a added (permitted cache/proxy
> trust boundaries, reference-artifact reachability); [Follow-up
> scope](#follow-up-scope) corrected to reflect that two of the four named
> follow-ups have since shipped (#592, and `llm_analysis.go`'s alert
> wiring) — checked against real repo state before starting phase 1
> (synthetic replay corpus) work, not assumed from this doc's original text.

## Method

For each of the nine areas #154 asked to cover, this maps to APIARY's
**actual** current architecture — verified against the real compose files,
Go/Python source, and docs in this tree, not assumed from what a "typical"
honeypot stack might do. Each entry records: what exists today, whether the
published campaign's technique applies here, and the evidence.

---

## 1. Evaluation/sandbox escape paths and reachable answer/reference artifacts

**Applies, partially — this repo's closest analogue is the malware
detonation sandbox, not an LLM eval harness.**

- `sandbox/windows/` (win11-sandbox) and the planned `cape-sandbox` (#314-322)
  are the actual "run untrusted code in a controlled environment" surfaces
  here — not an LLM code-eval sandbox, but the same escape-path shape: an
  untrusted binary/script runs inside a guest, and the question is what it
  can reach from there.
- `docs/honeypot-network-isolation.md` (§7/§11, the source #88 draws its own
  scope from) documents the isolation zones this already relies on:
  `virbr-sandbox` with no `<forward>` element (no route out), a Phase 0
  iptables DROP pair, and an `honeypot-sandbox-strict` nwfilter. **Untested
  by anything in this tree** — #88 exists precisely because no automated
  check confirms these invariants still hold after a config change.
- `docker-compose.sandbox.yml`'s INetSim/Zeek/Suricata/tcpdump containers use
  `network_mode: host` (three services, confirmed by grep) — a deliberate
  choice for full-spectrum traffic capture of the isolated sandbox network,
  but it means those specific containers are not themselves network-namespaced
  away from the host the way every honeypot sensor container is. #510 (open)
  already flags that these containers aren't reliably started/stopped per
  detonation, which is adjacent to, not the same as, this finding.
- No "reference/answer artifact" concept exists in this repo's design (unlike
  an LLM eval harness with a scored reference solution) — the nearest
  equivalent is the Ghidra/sandbox/GitHub-analysis result spools
  (`/var/lib/honeypot-ghidra/results`, etc.), which are mounted **read-only**
  into the dashboard (`docker-compose.dashboard.yml`, every `*-results` mount)
  specifically so a compromised guest or a malicious sample cannot forge a
  result by writing back into the directory the dashboard reads.

**Verdict:** the sandbox-escape shape applies; the "reachable answer
artifact" shape mostly does not (this repo has no evaluation-harness
component the campaign's original context assumed). The real open gap is
#88 (no automated proof the isolation invariants still hold) and #510 (the
network capture containers' lifecycle isn't tied to detonation lifecycle).

### 1a. Follow-up: permitted cache/registry proxies as a trust boundary

Per the corroborating primary source
([openai.com's incident writeup](https://openai.com/index/hugging-face-model-evaluation-security-incident/),
added to issue #154 after this doc's first pass): the campaign's own initial
foothold was a zero-day in a *package-registry cache proxy* — a component
everyone assumes is a passive mirror, not a trust boundary in its own right.
Two explicit checks that source asked to add here:

- **Do any package/module cache proxies exist in this repo's own build
  path, and if so, could a compromise of one become general egress?**
  Checked directly: no self-hosted package/module registry cache or proxy
  exists anywhere in this tree (grepped every Dockerfile and CI workflow for
  `GOPROXY`, a pip/npm registry-mirror config, an apt-cache-ng-style proxy,
  etc. — none found). Every build (`go build`, `npm install`, `pip install`)
  talks directly to the public upstream registry from GitHub Actions' own
  runner, not through an intermediary this repo operates. **Does not apply
  — by absence, not by a control**, the same "doesn't exist here" shape as
  item 4's cloud-metadata-service finding below. Worth stating explicitly so
  a future self-hosted proxy/mirror (e.g. for the self-hosted CI runner
  option `quality.yml` added) gets threat-modeled *as* a trust boundary from
  day one rather than assumed-safe by default.
- **Are evaluation answers/reference artifacts unreachable from the
  evaluated agent even after a sandbox or proxy compromise** (not just
  "not forgeable," which §1's own read-only-mount finding above already
  covers)? This is the sharper, distinct question: could a compromised
  sandbox guest, *during* its own detonation, read back any prior
  analysis/result data that would let it detect it's being evaluated and
  adapt? Checked directly against `docs/kvm-network-traffic-analysis.md`
  and `docker-compose.sandbox.yml`: the Ghidra/sandbox/GitHub-analysis
  result spools are host-side directories, written by the analysis pipeline
  **after** a detonation completes and the guest is torn down — nothing
  mounts them into the guest's own filesystem, and the guest's isolated
  network (§1 above: no `<forward>` element, INetSim answers every
  connection attempt itself) has no route to reach the host paths even if
  it tried. A compromised guest cannot read the results of its own or any
  prior run. **Applies as a check, and the existing isolation design already
  satisfies it** — this is a confirmation, not a newly found gap.

---

## 2. Untrusted structured-data processing

**Applies directly — this is the shape of a large fraction of this repo's
own code.**

- YARA rule/corpus loading (`scripts/check-yara-corpus.sh`, `analysis/yara/`)
  processes rule files against untrusted sample bytes. CI (`quality.yml`)
  already runs the corpus through the scanner's own base image on every
  change specifically because a bad rule takes the whole scanner down
  (confirmed: "yara(1) refuses to start on a corpus with one bad rule rather
  than skipping it").
- Every sensor's JSON log line is untrusted, attacker-controlled structured
  data by construction — `dashboard/classify.go` parses it. Escaping
  discipline here is already established: dashboard pages render event
  fields through `html/template` (auto-escaped), and `llm_analysis.go`
  (#150, just landed) explicitly re-derives this same reasoning for model
  output specifically because it is a second layer of untrusted free text on
  top of the underlying event.
- Archive/container-format processing: `analysis/es-results-importer/` and
  the Ghidra/sandbox result pipelines parse producer-written JSON, not
  archives directly — no code in this tree currently unpacks
  attacker-supplied ZIP/TAR/container images. This is a **currently-absent
  capability**, not a mitigated one; if a future sensor or the payload
  workbench ever adds archive extraction, that code needs its own bounds
  (size, depth, symlink/path-traversal) from day one — matching the pattern
  #154's own "Decoder is non-executing, bounded... records provenance"
  acceptance criterion already anticipates for phase 2.
- Template evaluation: no server-side template engine renders
  attacker-controlled strings anywhere in this tree (grepped for
  `text/template`/`html/template` `.Parse(` call sites — every one parses a
  fixed, repo-authored template string, never event data).

**Verdict:** applies broadly; the dashboard's existing escaping discipline
and #150's precedent are the right foundation for phase 2's decoder work.
Archive/container parsing is a gap only in the sense that nothing does it
yet — worth stating explicitly so it isn't added later without the same
bounding discipline.

---

## 3. Environment and `/proc/*/environ` secret exposure

**Partially mitigated already; inconsistent across services.**

- `dashboard/authorization.go`'s `secretFromEnvironment()` already supports
  a `<NAME>_FILE` indirection (read the secret from a file path named by
  `<NAME>_FILE`, falling back to the plain env var) for
  `AUTH_INTROSPECTION_TOKEN` — the file-based delivery pattern #154's
  acceptance criteria asks to extend already exists in exactly one place.
- Every other secret-shaped environment variable in this tree
  (`ARKIME_ADMIN_PASSWORD`, `ARKIME_PASSWORD_SECRET`, `GH_PAT` per
  `analysis/github/github.env.example`, VPS SSH keys in `deploy.yml`'s
  `secrets.VPS_SSH_KEY`) is delivered as a **plain environment variable**,
  not file-based — readable via `/proc/<pid>/environ` by anything with
  ptrace/procfs access to that container's PID namespace, and visible in
  `docker inspect`.
- GitHub Actions secrets (`deploy.yml`, `containers.yml`) are the CI-side
  equivalent: `VPS_SSH_KEY`/`VPS_HOST`/`VPS_USER`/`VPS_PORT` are consumed as
  `env:` on specific steps, GitHub's own masking prevents them appearing in
  logs, but they still exist as process environment for the step's lifetime.

**Verdict:** the file-based pattern exists but is applied to exactly one
secret. Extending `secretFromEnvironment`'s `<NAME>_FILE` convention to the
other secret-shaped env vars (or at minimum documenting which ones are
plain-env by conscious choice vs. oversight) is a concrete, scoped
follow-up — see [Follow-up scope](#follow-up-scope).

---

## 4. Metadata-service and RFC 1918/link-local reachability from workloads

**Not directly applicable — this repo has no cloud metadata service in its
threat surface, but the analogous "can a compromised sensor reach
internal-only services" question is real and already has partial answers.**

- No cloud provider metadata endpoint (`169.254.169.254`, GCP/Azure
  metadata) appears anywhere in this tree's runtime code (only mentioned in
  `docs/ip-reporting-plan.md`, in an unrelated context about IP geolocation
  services). The homeserver is bare-metal/self-hosted, not cloud VM-backed —
  the metadata-service SSRF vector the original campaign used does not exist
  here by construction, not by a control.
- The RFC 1918/internal-reachability analogue that *does* apply: every
  honeypot sensor container's own private Docker network (documented
  extensively across `docker-compose.*.yml` headers — e.g. dionaea's
  `dionaea_net`, tanner's `tanner_local`) is deliberately **not** `honeynet`,
  specifically so a compromised sensor cannot pivot to Elasticsearch,
  Kibana, or any other stack service. `docs/honeypot-network-isolation.md`
  is the authoritative source for this design.
- The one exception, by explicit design: services that need cross-stack
  reach (dashboard, es-results-importer) join `honeynet` and resolve
  Elasticsearch by service-name DNS — a deliberate, narrow allowlist, not an
  oversight (see `docker-compose.dashboard.yml`'s own header comment on
  this).
- No egress-filtering control currently prevents a compromised sensor
  container from reaching the *public* internet, only from reaching other
  stack services — #538 ("docs: make outbound network policy explicit") is
  the tracked issue for defining that policy, and it remains open.

**Verdict:** the metadata-service vector itself doesn't apply (no cloud
metadata surface exists). The internal-reachability principle it represents
is already substantially addressed by per-sensor private networks; the real
gap is outbound-to-internet egress policy, tracked separately in #538.

---

## 5. Credential lifetime, workload identity, and least-privilege boundaries

**Substantially addressed for the dashboard; inconsistent elsewhere.**

- The dashboard's own Docker-socket boundary is the strongest example in
  this tree: the dashboard container itself never mounts `/var/run/docker.sock`
  (`docker-compose.dashboard.yml`, grepped directly — absent). All
  Docker-lifecycle actions (start/stop/restart) go through
  `hp-services-adapter`, a separate container that is `cap_drop: [ALL]`,
  `read_only: true`, `network_mode: none`, and reachable only via an
  AF_UNIX socket the dashboard also holds — no TCP path exists to abuse it
  remotely even if the dashboard container itself were compromised.
- `hp-autoheal` is the one other service that does bind-mount the real
  `/var/run/docker.sock` (`docker-compose.utilities.yml`) — it watches
  containers by label daemon-wide and restarts unhealthy ones. This is a
  broad, standing grant (full Docker API access, not scoped to specific
  containers) held by a long-running service; workload-identity-scoped
  alternatives (e.g. a narrower label-filtered API surface) were not found
  in this tree.
- `tanner_docker` (`docker-compose.tanner.yml`) is `privileged: true` with
  its own `tmpfs /var/lib/docker` — explicitly isolated Docker-in-Docker on
  the private `tanner_local` network, not a bind mount of the host socket.
  This is a deliberate, already-documented exception (#88's own scope note
  says the future isolation audit "should assert it stays that shape rather
  than flag it").
- Credential *lifetime*: `AUTH_INTROSPECTION_TOKEN` is checked live on every
  privileged dashboard request (no long-lived session token cached
  server-side beyond the introspection call itself) — the closest thing this
  repo has to short-lived workload identity today.

**Verdict:** the dashboard/services-adapter split is a good existing
least-privilege pattern worth citing as the template for any future
privileged-access surface. `hp-autoheal`'s standing daemon-wide Docker
socket grant is the one credential-lifetime/least-privilege gap worth a
scoped look (whether its watch scope can be narrowed), separate from #88's
network-isolation focus.

---

## 6. Encoded/chunked C2 over ordinary web services, dead drops, raw sockets

**Applies to the honeypot's own captured traffic, not to this stack's own
services (which have no legitimate reason to originate arbitrary outbound
traffic in the first place).**

- Sensors like `http-honeypot`/`tanner` are the intended **capture** surface
  for exactly this technique — an attacker probing a honeypot is expected to
  attempt encoded C2/dead-drop patterns, and that's signal, not an incident.
  `dashboard/classify.go`'s handling of tanner's `post_data`/cookies (#578,
  landed) and Suricata's `payload_printable`/`http_body_printable` (#581,
  landed) are the current mechanisms for surfacing that content to an
  operator — neither currently *decodes* base64/gzip/chunked payloads
  automatically; an operator sees the raw captured bytes/text and would
  decode by hand today.
- The concern this campaign raises that *does* apply here: could a
  compromised **stack component** (not a honeypot sensor, which is
  supposed to be attacker-reachable) use encoded C2 over an ordinary
  outbound HTTP call to blend in? `github_analysis.go`'s
  `githubAnalysisPDFClient` (a 15s-timeout HTTP client fetching a specific,
  validated `raw.githubusercontent.com` URL) and the llm-worker's Ollama
  HTTP client are the only outbound HTTP call sites found in this tree
  outside the honeypot sensors themselves and CI. Both talk to a single,
  narrow, code-fixed destination — no general-purpose outbound HTTP client
  exists in any privileged dashboard/worker path today.
- No egress-filtering (network policy, allowlist) currently *enforces* that
  narrowness at the network layer — it is enforced only by the code not
  containing a general HTTP client. A future code change could add one
  without any control catching it. This is the same gap #538 already tracks.

**Verdict:** the honeypot's own sensors are the intended detection surface
for this exact technique (already partially wired, not decoded yet — phase 2
scope). The "could our own trusted code smuggle C2" question has no current
evidence of a problem, but also no network-layer control backing that up —
folds into #538.

---

## 7. Repeated recon, alternate egress, self-migration, machine-speed low-signal activity

**This is precisely the gap #154 opens with — "isolated low-signal events
were detected but not escalated with the right criticality" — and it
matches a real, already-partially-built mechanism in this repo.**

- `ml-worker`'s three unsupervised models (Isolation Forest, LSTM-AE, HBOS,
  delivered to the dashboard via `dashboard/ml_anomalies.go`, #64) are
  exactly the "statistical outlier across many low-signal events" detector
  this campaign's own postmortem says was missing at Hugging Face — but
  `ml_anomalies.go`'s own doc comment is explicit that its output is
  "statistical outliers, not confirmed attacks," scored per-event, not
  correlated into a *campaign*.
- `dashboard`'s existing campaign correlation
  (`campaignRow`/`clustersData`, cited throughout `store.go`/`main_test.go`)
  already clusters activity by shared fingerprint/ASN/CIDR across sensors —
  the closest existing analogue to "correlate low-signal events into one
  ordered timeline" phase 2 asks for, but it correlates by *infrastructure*
  identity (shared IP/ASN/fingerprint), not by *behavioral phase sequence*
  (recon → dropper → exfil → persistence) the way the campaign's own
  technical timeline is structured.
- No component in this repo currently escalates severity based on a
  *combination* of otherwise-individually-low-severity events crossing a
  trust boundary (phase 2/3's core ask) — `dashboard/alerts.go`'s alert
  manager fires on individual conditions crossing their own threshold
  (queue stalls, high-verdict samples, etc.), not on cross-signal
  combinations.

**Verdict:** the infrastructure (ml-worker anomaly scoring + dashboard
campaign clustering + `llm_analysis.go`'s new session-summary delivery,
#150) already provides three of the raw signal sources phase 2's
correlation engine would need to combine. The correlation-into-one-timeline
and combination-based severity escalation themselves do not exist yet —
this is phase 2/3's actual implementation gap, not something already
covered elsewhere.

---

## 8. Source-control/CI write paths and artifact digest/provenance verification

**Applies directly — this repo already has one deliberately narrow write
path from analysis back into source control, worth treating as the
reference implementation.**

- `analysis/github/` (#74) is the one place this repo's own automation
  writes back to a GitHub repository (publishing scanner samples/results).
  `quality.yml`'s own test step exists specifically because "the one
  property this whole feature depends on... `GITHUB_PUBLISH_ENABLED` unset
  must never reach `publish-sample.sh`" — a deterministic, CI-enforced gate
  on the one write-capable path, tested on every change regardless of
  whether `analysis/github/` itself changed.
- `GH_PAT` (the credential that write path uses) lives in
  `/etc/honeypot-github.env` on the host, read only by the root-owned host
  publisher script — the dashboard/worker side never holds it directly
  (per `dashboard/github_analysis.go`'s own doc comment: "the dashboard
  never writes one of these files, never calls git or the GitHub API, and
  never holds a `GH_PAT`").
- Artifact digest/provenance: container images built by `.github/workflows/containers.yml`
  are not currently pinned by digest anywhere this research found (compose
  files reference services by `build:` context, not a pinned upstream
  digest, for this repo's own images — vendored third-party dependencies
  like `github.com/nsmfoo/dicompot` *are* pinned by module version + go.sum
  hash, a different but related form of provenance pinning already in
  place for vendored code specifically).
- CI credential probing: `dependabot-auto-merge.yml` and `deploy.yml` are
  the workflows holding real secrets (`GITHUB_TOKEN`, `VPS_SSH_KEY`,
  production environment secrets). Both are scoped with `permissions:` at
  the top of the workflow file (least-privilege GitHub Actions token grants)
  — worth an explicit audit that every workflow's `permissions:` block is
  actually minimal, not just present, as a scoped follow-up.

**Verdict:** the `analysis/github/` publish gate is a strong existing
example of exactly the deterministic, CI-tested control phase 3 asks for
("Escalate independently of an LLM when... source-control token minting,
workflow/build-script changes"). Container image digest pinning is the one
concrete gap found here.

---

## 9. Alert correlation and severity escalation across sensors, container, host, and analysis-worker evidence

**Partially built, fragmented across several independent alert sources
rather than one correlated view — matches this campaign's own core
finding.**

- Current alert sources, confirmed independent of each other (each own
  `*Alerts` function in `dashboard/*.go`, all feeding the same
  `s.alerts`/`alertManager` sink but never cross-referencing each other's
  state): Suricata/sensor event alerts, `ghidraAlerts`, `githubAnalysisAlerts`,
  sandbox queue/verdict alerts, ML anomaly severity, and (as of #150) the
  new `llm-analysis` index's own severity field is not yet wired into
  `alerts.go` at all — it is currently browse-only via `/llm-analysis`.
- No single "this source_ip/session/sample crossed N independent trust
  boundaries in a Y-minute window" correlation exists — each alert source
  answers its own narrow question. This is exactly the shape the campaign's
  postmortem flags: individually-reasonable-severity signals from
  Elasticsearch/session-analysis/sandbox/container evidence never combine
  into one escalated verdict.
- `dashboard`'s campaign clustering (cited in §7 above) is the nearest
  existing cross-sensor correlation, but clusters by shared infrastructure
  identity for investigation, not by trust-boundary-crossing count for
  alerting.

**Verdict:** this is the clearest concrete gap this research surfaced. Wiring
`llm-analysis`'s severity into the existing alert sink is a small, immediate
follow-up; a genuine cross-source trust-boundary-crossing correlation engine
is squarely phase 3's scope, not something to build inside this research
pass.

---

## Applicability matrix

| # | Area | Applies to this repo? | Existing mitigation | Concrete gap found |
|---|---|---|---|---|
| 1 | Sandbox escape / reference artifacts | Partial (detonation sandbox, not eval harness) | Read-only result mounts; isolation zone design (docs) | #88 (untested invariants), #510 (capture container lifecycle) |
| 2 | Untrusted structured-data processing | Yes, broadly | `html/template` auto-escaping; CI YARA corpus gate | No archive/container-format parsing exists yet — must inherit this discipline when added |
| 3 | Env/`/proc/*/environ` secret exposure | Yes | `secretFromEnvironment`'s `_FILE` pattern (one use) | Pattern not applied to `ARKIME_*`, `GH_PAT`, VPS SSH key |
| 4 | Metadata-service / RFC 1918 reachability | No cloud metadata surface exists | Per-sensor private Docker networks | Outbound-to-internet egress policy (tracked in #538) |
| 5 | Credential lifetime / workload identity | Yes | dashboard/services-adapter split (strong pattern) | `hp-autoheal`'s standing daemon-wide docker.sock grant |
| 6 | Encoded/chunked C2 | Yes, as honeypot capture surface | Raw payload capture (tanner/Suricata); narrow fixed-destination outbound HTTP clients | No network-layer egress enforcement (folds into #538) |
| 7 | Repeated recon / low-signal escalation | Yes — core motivating gap | ml-worker anomaly scoring; dashboard campaign clustering | No behavioral-phase correlation or combination-based severity escalation |
| 8 | Source-control/CI write paths | Yes | `analysis/github/` publish gate (CI-tested); vendored-dep hash pinning | No image digest pinning for this repo's own built images |
| 9 | Cross-source alert correlation | Yes — core motivating gap | Multiple independent alert sources feed one sink | No trust-boundary-crossing correlation; `llm-analysis` severity not yet wired into alerts |

---

## Follow-up scope

Per #154's own acceptance criteria ("Isolation/egress/credential audits are
implemented or linked to scoped follow-up issues"), the concrete gaps above
route to:

- **#88** (existing, open) — automated isolation-invariant checks. Item 1's
  gap is already this issue's scope; no new issue needed.
- **#538** (existing, open) — outbound network egress policy. Items 4 and 6's
  gaps are already this issue's scope; no new issue needed.
- **New, scoped follow-ups named here** (not all filed as separate issues at
  once — this research doc's job was to identify them, not to fan out five
  new issues in one round). Status as of this update, not when first
  written:
  - ~~Audit/narrow `hp-autoheal`'s standing `docker.sock` grant (item 5).~~
    **Done** — #592, merged: replaced the raw bind mount with
    docker-socket-proxy scoped to `CONTAINERS`+`IMAGES`+`POST` only,
    verified end-to-end against a real unhealthy container.
  - ~~Wire `llm-analysis` severity into the existing dashboard alert sink
    (item 9's smallest, most immediate piece).~~ **Done** —
    `dashboard/llm_analysis.go`'s `llmAnalysisAlerts`, wired into
    `store.go`'s alert refresh and covered by dedicated tests
    (`llm_analysis_test.go`).
  - Extend `secretFromEnvironment`'s file-based delivery pattern to the
    other plain-env secrets (item 3). **Still open, and more involved than
    it first looked**: `ARKIME_PASSWORD_SECRET`/`ARKIME_ADMIN_PASSWORD`
    (`docker-compose.elk.yml`, `docker-compose.init.yml`) are consumed
    directly by Arkime's own third-party `docker.sh` entrypoint via its
    `ARKIME__*` env-var-to-config.ini convention — `secretFromEnvironment`
    is dashboard Go code and has no reach into a different container's
    entrypoint. Fixing this for real means either patching how the Arkime
    containers start (a wrapper that reads a file and exports the var right
    before exec, or writing the secret directly into the already
    host-mounted `config.ini` instead of passing it as an env var at all)
    — a real, scoped implementation task, not a one-line pattern reuse.
    `GH_PAT` is a host-side `.env` file consumed by a root-owned host
    script, not a container-namespace env var — the `/proc/*/environ`
    exposure shape this item is about doesn't actually apply to it the same
    way; worth leaving as-is rather than force-fitting the same fix.
  - Pin this repo's own built container images by digest, not just `build:`
    context (item 8). **Still open** — needs a decision on mechanism
    (digest-pin in `deploy.yml`'s pull step vs. Dependabot/Renovate-managed
    digest tracking) before implementation, not just a mechanical change.
- **Phases 2-5 of #154 itself** (synthetic replay corpus, decode/correlate
  pipeline, deterministic criticality rules, operator evidence UI) remain
  open, larger implementation work — items 2, 7, and 9's "no correlation/
  escalation engine exists yet" findings are exactly what phases 2 and 3
  would build. This document is the prerequisite research those phases
  depend on, not a replacement for them.
