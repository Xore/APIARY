# Research: GitSpawn — AI coding-agent `.git/config` `core.fsmonitor` RCE — APIARY pipeline exposure (#2891)

Checks whether this fleet's own CI pipeline, or any worker/script in the
repo, ever runs `git` against a directory whose `.git/` came from
attacker-influenced content rather than a controlled `clone`/`checkout` —
the specific precondition GitSpawn needs. Gathered 2026-09-03.

**Scope, per the issue and this batch's house rules:** analysis only. No
CI workflow was changed, no agent tooling config was touched.

## 1. The mechanism, restated precisely (matters for §2's test)

GitSpawn's primitive is **not** "a coding agent runs `git status`" in
general — every git checkout does that safely. It requires a **delivered,
not cloned** directory: a `.git/` tree that arrived via zip download, USB,
or file-sync, whose `.git/config` an attacker fully controls, containing a
`core.fsmonitor = <arbitrary command>` line. Git invokes that command
during ordinary index-refresh operations (`status`, `diff`, etc.) with no
separate execution prompt. A repository obtained through `git clone` or
`actions/checkout` gets its `.git/config` from the clone operation itself
— cloning a malicious *repository* does not let the attacker plant an
attacker-controlled *local* git config, since the clone writes its own
`.git/config` and does not copy one from the remote. The delivery vector
has to be a pre-built `.git/` directory handed to the agent as inert files.

## 2. Does anything in this fleet's CI or worker code do that?

**No — every git operation in the repo either goes through
`actions/checkout`, or operates on a clone this fleet's own script created
and controls, or is read-only against the repo's own checkout.** The
measurement below is at repo scope, over every tracked file, because an
absence claim is only as broad as the sweep that produced it.

### 2.1 CI workflows

```
$ grep -c "actions/checkout" .github/workflows/*.yml | grep -v ':0'
# every one of the 13 workflow files that run git-dependent jobs uses it
# (compose-drift-watch, ci-queue-watch, security, elastic-release-watch,
#  pages, image-security-scan, dependabot-auto-merge, containers,
#  dependency-review, disk-usage-watch, deploy (x2), diagnostics, quality)
$ grep -rn "archive/refs\|codeload.github.com\|\.zip\"" .github/workflows/*.yml
(no output)
```

`actions/checkout` performs a real `git clone`/`fetch` against GitHub's
API — it produces a `.git/` directory built by the runner's own git client,
not one unpacked from a downloaded archive.

### 2.2 Every git call site in the repo, not just the Python and Go ones

An earlier draft of this section rested on a grep restricted to
`--include="*.py" --include="*.go"` over `arcane/` and `analysis/`, which
returned exactly one hit. That is far narrower than the claim it was
supporting. Re-run unrestricted over every tracked file on `origin/main`:

```
$ git grep -lIE '(^|[^A-Za-z_-])git +(clone|status|diff|fetch|pull|checkout|ls-files|rev-parse|reset|init|add|log|remote|worktree)|exec\.Command\("git"|\["git"' origin/main -- . ':!*.md'
```

57 files, which sort into four groups (18 + 4 + 22 + 13 = 57). Every one
was checked individually:

| group | files | why it is not a GitSpawn carrier |
|---|---|---|
| **18 — `git clone` / `git init`+`fetch` of upstream source** | 12 Dockerfiles (`honeypot-cowrie`, `honeypot-beelzebub`, `honeypot-tanner` ×3, `honeypot-galah`, `honeypot-hellpot`, `honeypot-dicompot`, `honeypot-elasticpot`, `honeypot-mailoney`, `honeypot-sentrypeer`, `honeypot-init/snare`); `arcane/home/honeypot-payload-analysis/analysis/yara/sync-yara.sh:85-86` (an **external** rules repo); `scripts/install-homeserver.sh:1192` (`AUTH_THEME_REPO_URL`); `scripts/install-vps.sh:446` (`GIT_REPO_URL`); `scripts/sync-theme.sh`; `sandbox/windows_kimi/provision/40-fakenet.ps1:18` (`mandiant/flare-fakenet-ng`); `sandbox/windows/packer/pxe/prepare-pxe.sh:113` (`git init` + fetch of ipxe) | The `.git/config` is written by *our* git client during the clone. Cloning a hostile *remote* does not let that remote plant a local config — that is §1's whole point, and it holds however untrusted the remote is. `sync-yara.sh` and `40-fakenet.ps1` are the strongest cases here (genuinely third-party repos) and both are still clones. |
| **4 — git against a directory this fleet created and controls** | `analysis/github/collect-results.py:96-104`; `analysis/collect.sh:34` and `analysis/collect.sh:92-109`; `analysis/github/install-github-publisher.sh:137-143`; `analysis/github/publish-sample.sh:29-30` | All operate on `/opt/honeypot-samples`, which `collect.sh`'s own header (`:19`) documents as created by `git clone https://github.com/Xore/Honeypot`, and which `collect-results.py` `fetch`/`reset --hard`s against a hardcoded `origin`. Clone-derived and self-owned. |
| **22 — read-only, or index-refreshing, inside the repo's own checkout** | `scripts/check-doc-paths-exist.py`, `check-public-leaks.py`, `check-autoheal-labels.py`, `check-timestamp-utc.py`, `list-docker-base-images.py` (`git ls-files`); `scripts/promote-release.sh`, `scripts/homeserver-login-status.sh:164`, `scripts/backup-essentials.sh`, `safe-update.sh`, `factory-reset.sh`; `.github/workflows/quality.yml:456` and `:494` (`git diff --exit-code`); 7 `tests/docs/test_*.py`; 4 `analysis/github/tests/*.sh` | These run inside a checkout that `actions/checkout` or an operator's own clone produced. `quality.yml`'s `git diff` is the only one of the 22 that refreshes the index (and so would consult `core.fsmonitor`) — it does so in an `actions/checkout` tree whose config the runner's own git wrote. |
| **13 — not a git invocation at all** | 3 cowrie `honeyfs/**/.bash_history` decoy files; `sandbox/ghosts/vendor/**/v4-shims{,.min}.js`; `.gitignore`; `docs/autoinstall/homeserver-user-data.yaml`; `scripts/install-{homeserver,vps}.conf.example`; `cisco-asa-honeypot/ike.go`; `analysis/ghidra/docker-compose.ghidra.yml:213`, `auth-events-worker/docker-compose.yml:49-51` and `scripts/install-backup-essentials.sh:25` (all prose comments) | Decoy content, vendored JavaScript, config text and comments. None executes. |

### 2.3 The archive-extraction path, which does exist — and why it still is not a carrier

An earlier draft asserted *"there is no workflow anywhere in
`.github/workflows/` that downloads a repository as a zip/tarball and
extracts it."* That is true of the workflow YAML and **false of what CI
actually executes**: `containers.yml` builds Dockerfiles that do exactly
that, and this is the closest shape in the fleet to GitSpawn's delivery
vector, so it deserves the analysis rather than an absence claim.

```
$ git grep -nIE '(wget|curl)[^|]*\.(zip|tar\.gz|tgz)|unzip |tar (-)?x' origin/main -- '*Dockerfile*'
analysis/ghidra/service/Dockerfile:26,29        curl ghidra release .zip  -> unzip -d /opt
analysis/ghidra/statictools/Dockerfile:46,50    curl mandiant/capa-rules .tar.gz -> tar -xz
analysis/ghidra/statictools/Dockerfile:63,67    curl mandiant/capa .tar.gz       -> tar -xz
arcane/home/honeypot-canarytokens/canarytokens/Dockerfile:37,38
                                                wget github.com/thinkst/canarytokens/archive/${REF}.zip -> unzip
```

Three reasons none of them is a carrier, in increasing order of how much
they would have to change for that to stop being true:

1. **GitHub's archive endpoints do not ship `.git/` at all.** Verified on
   the actual artifact this fleet pins, not assumed:
   ```
   $ curl -sL -o ct.zip https://github.com/thinkst/canarytokens/archive/dd92bf29bd0f6d1b446fb41e3b8114c6fc7a6205.zip
   $ unzip -l ct.zip | wc -l
   2714
   $ unzip -l ct.zip | grep -c '\.git/'
   0
   ```
   The zip carries `.github/`, `.gitignore`, `.flake8` and so on, but no
   `.git/` directory and therefore no `.git/config`. The mandiant tarballs
   are GitHub *release* assets, which likewise contain no `.git/`.
2. **Nothing runs git in the extracted trees.** None of the four
   Dockerfiles contains a git invocation at any stage
   (`git show origin/main:<f> | grep -E '(^|[^A-Za-z_-])git( |$)'` → empty
   for all three of the repo-archive/tarball ones), and no runtime worker
   introspects `/opt/ghidra`, `/app/capa-*` or `/srv` as a git repository.
3. **The sources are pinned.** `CANARYTOKENS_REF` is a full 40-character
   commit SHA; the capa artifacts are version-pinned release assets. An
   attacker would need to control the upstream repository *and* have git
   run inside the extracted tree, and neither condition holds.

The only `.git/config` strings anywhere in the tree are decoy bait —
`arcane/home/honeypot-http/http-honeypot/main.go:7` lists `/.git/config`
among the paths the HTTP sensor baits scanners with. `core.fsmonitor`
appears nowhere in the repository outside this document.

## 3. Self-hosted runners — the one place this deserves a second look

`honeypot-ci` and `honeypot-home` are self-hosted runners (`quality.yml`,
`security.yml`, `ci-heartbeat.yml`, `deploy.yml`), meaning PR-triggered jobs
execute on infrastructure this fleet owns, not GitHub-hosted ephemeral
VMs. That raises the stakes of *any* RCE in CI (a compromised job persists
credential/network access to the runner host), but it does not change
whether GitSpawn's specific precondition exists — `actions/checkout` behaves
identically on a self-hosted runner, still performing a real clone rather
than unpacking a delivered `.git/`. No workflow here runs an AI coding
agent of any vendor against checked-out PR content at all — grepped
`.github/workflows/*.yml` for the major coding-agent vendors' names: zero
hits. The
only workflow matches for the word "agent" are this repo's own
`agent-intrusion-worker` honeypot-sensor test suite (an LLM-attacker decoy,
unrelated to coding-agent tooling).

## 4. Relevance to APIARY, re-assessed

- **Fleet CI/worker exposure**: none found (§2, §3). Nothing in this
  repository's automation is a GitSpawn carrier.
- **Sensor-variant idea** (issue's own suggestion: "an agent-facing sensor
  variant could serve a crafted repo/workspace"): a real, buildable
  decoy idea — bait a coding-agent-shaped client with a directory
  containing a `core.fsmonitor` canary and see if anything executes it —
  but this is **new decoy capability**, not a config or detection-query
  change achievable within a research row (same boundary #2861 and #2777
  drew). Not started here.
- **"Direct personal exposure"**: the issue's own body flags that AI
  coding-agent frameworks in general are the class of software GitSpawn
  targets, separate from whether APIARY's own repository content is a
  carrier. That is operational guidance for whoever runs a coding agent
  against delivered (non-cloned) content — outside this repo's own code or
  config, and not something a docs change in `docs/research/` fixes.

## 5. What I did not verify

- Did not independently confirm the CVE-2026-71963/-72718 identifiers or
  patch status against a primary vendor advisory — the issue's own
  citation (Manifold Security's writeup) is the only source checked, and
  this pass's time went to the fleet-exposure question, which doesn't
  depend on which specific agents are patched.
- Did not audit every third-party GitHub Action used across the thirteen
  workflow files for whether *it* might internally extract an archive and
  run git against it (e.g., a caching or artifact-restore action) —
  checked only this repo's own job steps.

## 6. Bottom line

**No exposure found.** GitSpawn's precondition — a delivered, not cloned,
`.git/` directory processed by git commands — does not occur anywhere in
this fleet's CI (`actions/checkout` everywhere; the four build-time archive
extractions that do exist ship no `.git/` and never have git run against
them — §2.3) or its worker code (every one of the 57 files carrying a git
call site is clone-derived, self-owned, or read-only — §2.2). This is a
disproved-for-this-fleet finding in the #2836 mold, with the caveat that
the vulnerability class is real and worth personal operational awareness
for whoever runs coding-agent tooling against content delivered outside a
`git clone` — a fact about agent operating practice, not about anything in
this repository.
