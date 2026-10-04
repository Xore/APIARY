# #3501 — landing report

Four commits. Nothing pushed, no PR opened. Branch `ci/3501-gate-enforcement`.

| # | commit | contents |
|---|---|---|
| 1 | `8cc55aa9` | `ci(secret-scan)` — full-history secret-scan gate + its tests |
| 2 | `1d588877` | `chore(types)` — mypy closure over 17 files |
| 3 | `294c2c88` | `docs(measurement)` — `CONTAINER-SCAN-MEASUREMENT.md`, docs only |
| 4 | this one | `ci(wire)` — actually calls the gate; **commit 1 was inert** |
| 5 | (this commit, see below) | `fix(secret-scan)` — the two defects #3516's CI found |

`scripts/list-docker-base-images.py` and `.github/workflows/image-security-scan.yml`
were **not** touched. The `ACCEPTED_CVES` block in that script remains uncommitted
in the working tree, exactly as found.

---

## Commit 1 — secret-scan gate

`scripts/check-git-secrets.py` (new), `tests/docs/test_3501_secret_scan_allowlist.py` (new).

### One fix was required before it ran

`.ci-artifacts/` does not exist locally, and nothing else creates it — the
`CI_ARTIFACTS_DIR` convention in `quality.yml` belongs to the vitest JUnit
reporter, not to this gate. The first run died with
`FTL Report path is not writable`, which the script itself maps to "gitleaks
failed to run" — i.e. the same ambiguous exit the script's own comment warns
would train operators to ignore the gate. Added one `mkdir(parents=True)`.

### Tooling note

Neither gitleaks nor a typechecker was installed. gitleaks 8.28.0 was fetched
to `/tmp` and passed via `--binary` / `PATH`. mypy 2.4.0 was pip-installed.

### Full history

```
$ python3 scripts/check-git-secrets.py --binary /tmp/gitleaks
Secret scan passed: 88 finding(s) over full history, all covered by
ALLOWED_FILES (0 cowrie honeyfs) or absent.
EXIT=0
real 0m34.443s
```

Breakdown of the 88 — every one is an allowlist entry:

```
  50  graphify-out/cache/stat-index.json          (deleted; generated cache index)
  12  dash-shots/f2-follow-up/preserved-sha256.json  (deleted; sha256 manifest)
   3  arcane/home/honeypot-citrix-honeypot/citrix-honeypot/cve_2026_88771_test.go
   2  arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot/credentials_test.go
   2  arcane/home/honeypot-dashboard/frontend-next/src/lib/credentialState.test.ts
   2  arcane/home/honeypot-http/http-honeypot/credentials_test.go
   2  dashboard/scanner_fingerprints_test.go    (deleted)
   2  tests/docs/test_2314_fix.py
   1  each of: evaluate-models.py, test_criticality_rules.py,
      canarytokens-http-router/main_test.go, backend-service/src/stores.rs,
      auth-events-worker/requirements.txt, canarytokens/Dockerfile,
      dashboard/problem_reports_test.go, dashboard/static/xterm.js,
      docs/canarytoken-live-fire-checklist.md, docs/research/2777-*.md,
      tests/docs/test_2433_fix.py, pihole/dnscrypt-proxy.toml,
      sandbox/prepare-linux-base.sh
```

**`0 cowrie honeyfs` is a real result, not a gap.** The decoy `.env` values
are `DECOY_ONLY_public_example`, which is low-entropy and keyword-shaped in a
way gitleaks' rules do not fire on. The exemption is correct and currently
unexercised on this tree. Its teeth are proven separately below.

### Proof 1 — planted secret in a NON-allowlisted file IS caught

```
Secret scan failed: 1 finding(s) outside the allowlist (0 allowed, 0 of them cowrie honeyfs bait):
  - deploy/config.txt:1: generic-api-key (commit b24095146e, t)

If a finding is a genuine false positive, add it to ALLOWED_FILES in
scripts/check-git-secrets.py with a written reason -- not a wildcard, and
the path must exist.
checker exit code: 1   (1 == gate FAILED, as required)
```

### Proof 2 — honeyfs decoys ARE allowed, exemption proven load-bearing

A decoy planted under the honeyfs prefix using a value that *does* trip the
detector:

```
raw gitleaks findings (exemption withheld): 2
  -> ['arcane/.../honeyfs/opt/nexusai-inference/.env', 'arcane/.../honeyfs/opt/nexusai-inference/.env']
Secret scan passed: 2 finding(s) ... (2 cowrie honeyfs) or absent.
checker exit code: 0   (0 == PASSED, honeyfs decoys exempt)
```

Two raw findings, exit 0 — the prefix exemption is what turned one into the
other.

**The real `nexusai` `.env` is allowed by a different mechanism than
assumed.** It is covered by the `HONEYFS_PREFIX` prefix, not by any
`ALLOWED_FILES` entry:

```
nexusai .env present in ALLOWED_FILES? False
nexusai .env covered by prefix? True
```

But scanning that file's real contents produces **0 findings**, with or
without the prefix:

```
=== real nexusai .env ===            findings: 0
=== control: same content, no prefix === findings: 0   (findings outside honeyfs: 0)
```

So the `.env` exemption is currently unexercised — the decoys are
`DECOY_ONLY_public_example`, too low-entropy to trip the rules. Correct
outcome, but it is not evidence the mechanism works. Proof 2a above is.

### Proof 3 — an entry naming a non-existent path FAILS (fail-closed)

```
::error::secret-scan allowlist: gone/never-existed.txt: allowlist entry
names a file that exists neither in the tree nor anywhere in history --
remove the entry or restore the file
checker exit code: 1   (1 == gate FAILED on the stale entry, as required)
```

Checked in both directions: exists in the tree → pass; absent from the tree
but present in history → pass; absent from both → fail.

### Tests

```
$ PATH="/tmp/glbin:$PATH" /usr/bin/python3.12 -m pytest \
      tests/docs/test_3501_secret_scan_allowlist.py -v

test_checker_script_exists                                    PASSED
test_every_allowlist_entry_carries_a_written_reason            PASSED
test_every_allowlist_entry_exists_now_or_in_history            PASSED
test_allowlist_has_no_wildcards                                PASSED
test_allowlisted_files_do_not_contain_a_real_secret            PASSED
test_gate_flags_a_planted_secret_in_a_non_allowlisted_file      PASSED
test_gate_allows_the_cowrie_honeyfs_decoys                     PASSED
test_gate_fails_closed_on_a_stale_allowlist_entry              PASSED

============================== 8 passed in 10.66s ==============================
```

Without gitleaks on PATH the four scanner-dependent tests **skip**, not fail:
`4 passed, 4 skipped in 0.21s`. Worth knowing — in that state the suite
looks green while the gate's core assertions never ran.

---

## Commit 2 — typecheck closure

17 files. `scripts/list-docker-base-images.py` deliberately excluded.

### Config and scope — stated precisely because it is narrow

```
mypy 2.4.0, Python 3.12
--ignore-missing-imports --follow-imports=skip
```

Scope is **exactly the 17 files touched**. This repo has **no** checked-in
typecheck configuration at all — no `pyproject.toml [tool.mypy]`, no
`mypy.ini`, no `setup.cfg [mypy]`, no `pyrightconfig.json` — and this commit
adds none. It is a closure commit over a fixed file list, not a
repo-wide gate. Everything unlisted is unverified.

Three byte-identical copies of `gpu_queue.py` and two files both named
`worker.py` collide as module names; those four are checked individually.

### Result

```
Success: no issues found in 13 source files          (batch)
Success: no issues found in 1 source file   x4        (per-file, collisions)
```

Baseline on `HEAD` for 6 of them — **11 errors, all pre-existing**:

```
scripts/deploy-profile-sizing.py:74: Incompatible types in assignment (float vs int)
scripts/main-health-watch.py:198: Item "None" of "Match[str] | None" has no attribute "group"
scripts/check-ai-attribution.py:99: "object" has no attribute "__iter__"
scripts/check-ai-attribution.py:102: Argument 1 to "len" has incompatible type "object"
scripts/check-api-auth-tier.py:119: Need type annotation for "secured"
scripts/check-api-auth-tier.py:119: Need type annotation for "public"
ml-worker/worker.py:1092: Need type annotation for "recent_flags"
ml-worker/worker.py:1106: Need type annotation for "events"
ml-worker/worker.py:1109: Value of type "dict[Any, Any] | None" is not indexable
ml-worker/worker.py:1110: Value of type "dict[Any, Any] | None" is not indexable
ml-worker/worker.py:1147: Argument 2 to "advance_checkpoint" has incompatible type
Found 11 errors in 5 files (checked 6 source files)
```

### The two files flagged for confirmation — I agree with both

**`deploy-profile-sizing.py` — `cpus = mem = 0` → `cpus: float = 0.0`.**
`cpus` accumulates `sum(float(x) for x in re.findall(r"cpus:..."))`, so the
`int` seed was simply the wrong type. The chain had to be **split**, not just
re-annotated: a chained assignment applies the annotation to *both* targets,
which would have typed `mem` as `float` when it accumulates `to_bytes(...)`
→ `int`. Splitting leaves `mem` correctly inferred. Neither value is
observable — printed as `{cpus:g}` and `{gib:.1f}` — so `0.0` and `0` are
indistinguishable in output. Correct.

**`main-health-watch.py` — `.group(1)` guarded against `None`.** This one is
**a latent-bug fix, not an annotation**, and it is the more valuable of the
two. If the rendered report body ever lacks a `<!-- main-red-head: ... -->`
marker, the unguarded call raises `AttributeError` and the watcher dies with
a traceback instead of reporting that it cannot build the report. It now
exits 1 with a message. The guard sits immediately before the only `.group()`
call in the file.

### `check-ai-attribution.py` — the one worth spelling out

This is the gate that **fails the build on AI attribution**. The change is
`def _api(...) -> object` → `-> Any`, needed because the pagination loop does
`for commit in commits` and `len(commits)`, which `object` does not support.

Loosening a return annotation on a build-failing gate is exactly the shape of
change that could quietly weaken it. It does not, and the reasoning is in the
commit message:

- `object` was **never** a runtime claim — Python does not enforce
  annotations. The two call sites were already iterating and measuring the
  value at runtime, with no guard, and worked.
- `Any` is therefore strictly *more* honest about what the function returns:
  arbitrary decoded JSON.
- **What did not change**: `findings()`, the co-author trailer regex, the
  assistant/model-family label list, the pass/fail decision, and `main()`'s
  exit code are all untouched. The detection logic is byte-identical.

The same question applies to the seed-literal `SECRET = "..."` in the other
gitleaks-adjacent gates and is answered the same way.

### Everything else

Annotations only, plus `llm-worker/contracts.py`
(`list[object]` → `Sequence[object]`: `list` is invariant, so a `list[str]`
caller was rejected for a parameter type that was never wrong) and
`llm-worker/injection_suite.py` (`_require(condition: object)`: call sites
pass a match object, only falsiness is consulted). `ml-worker/worker.py`
gained the same `checkpoint is not None` guard shape as the health-watch fix
— `load_checkpoint` returns `None` on failure and the old code indexed it
regardless.

### Required checks

```
$ python3 scripts/check-public-leaks.py
Public-repository safety check passed.
EXIT=0
   (preceded by the standard 240-file binary skip list — images, fonts,
    the ghosts vendor photo corpus; unchanged from baseline)

$ /usr/bin/python3.12 -m pytest tests/ -q
663 passed, 4 skipped, 1 xfailed, 17 subtests passed in 159.53s
EXIT=0
```

---

## Commit 3 — measurement, docs only

`CONTAINER-SCAN-MEASUREMENT.md`. No code, no workflow, no allowlist change.

trivy 0.74.0, `image --scanners vuln --severity CRITICAL,HIGH`, per image
against the registry.

### Three results that contradict the brief

**The script emits 67 refs, not 61.** No filter reduces it to 61. Reported
unresolved rather than reconciled.

**30 of 40 `ACCEPTED_CVES` keys cannot match any emitted ref.** 58 of 67
images are emitted digest-pinned; only 9 bare. The keys are mostly bare-tag,
and comparison is against the full printed ref. 30 keys are dead outright,
29 more emitted refs have a bare-tag key that will not match, and only **10
keys match exactly**. The gate would exempt 10 of 67 images.

**0 images came out `genuinely-unfixable`.** All 66 fully-scanned images
with findings have at least one published fix. Of the 39 refs carrying a
written reason, **37 are contradicted** by a scan reporting a `FixedVersion`.

### Totals

| | |
|---|---|
| total CRITICAL+HIGH findings | 9139 |
| fixable | 5346 |
| no fix published | 3793 |
| `fix-now` / `clean` / `INCOMPLETE` | 55 / 11 / 1 |

### The incomplete one

`docker.n8n.io/n8nio/n8n:latest` — killed by a Docker Hub pull-rate limit,
retried once, same result:

```
remote error: GET https://docker.n8n.io/v2/n8nio/n8n/manifests/latest:
TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.
```

Recorded as **INCOMPLETE** with no count. Not estimated.

### A measurement caveat

Two scanner passes overlapped partway through and 4 refs were scanned twice,
once succeeding and once failing on pull-rate limits. Results were deduped by
ref, keeping the successful scan where one existed; the 3 refs left uncovered
were re-scanned in a clean single pass. Every row in the table is from a
completed scan, but the run was not single-pass — the 66 complete counts are
trusted, the process was messy.

### Deviation from the brief

A `no-reason-written` **verdict** column does not survive contact with the
data — it is a property of the allowlist, not a scan outcome, and folding it
in would have miscounted exempt-but-clean images. It is reported as its own
column instead, and the deviation is stated in the document itself.

---

## Not done

- Container-scan gate: **not armed.** Blocked pending the key rewrite.
- `ACCEPTED_CVES`: still uncommitted, unchanged.
- Nothing pushed. No PR.

---

# Commit 4 — wire the gate into CI

**Commit 1's headline claim was false until this commit.** It said *"fail CI on
a real credential anywhere in full history"*, and nothing called the script:

```
$ grep -rn 'gitleaks' .github/workflows/*.yml
(no output)
```

`scripts/check-git-secrets.py` was a well-tested gate behind no door. This
commit is the door.

Two files: `scripts/install-gitleaks.sh` (new) and one additive matrix row in
`.github/workflows/quality.yml`.

## Why a separate installer script

`image-security-scan.yml:103-104` installs trivy via `scripts/install-trivy.sh`,
whose header states the reason to extract rather than curl-|-sh it (#3115,
SAST-flagged). Same class of third-party code, same discipline — so
`scripts/install-gitleaks.sh` is a sibling of that script, not an inline
`curl` in the row. The actionlint/zizmor/hadolint rows *do* inline their
downloads (e.g. `quality.yml:2053-2055`), but those are single-use linters
whose pin dies with the row; the trivy installer exists because *two* workflows
share one binary and must not drift on it. gitleaks has one caller, so a
standalone script is arguably over-built — it is a sibling rather than a
generalised abstraction, and it is what lets the row read as
`scripts/install-gitleaks.sh` instead of eight lines of pinned curl. The pin
lives in exactly one place either way.

## The pin

Verified against the release's own `gitleaks_8.30.0_checksums.txt`, not just
recorded from a download:

```
$ curl -sSL -o /tmp/glsums.txt \
    https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_checksums.txt
$ grep -i 'linux_x64.tar.gz' /tmp/glsums.txt
79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e  gitleaks_8.30.0_linux_x64.tar.gz
$ sha256sum -c -
gl.tar.gz: OK
```

That digest is `PINNED_GITLEAKS_SHA256` in the installer. The installer also
refuses a version override that carries no checksum of its own — the
`sha256sum -c` step would either fail confusingly or, on a collision, pass.

## The row, and why `home: true`

`quality.yml:2069` (after the hadolint row). It qualifies for the metal under
the #2389/#2565 criterion: checkout, this workflow's own `setup-python`, one
pip install, and a tarball unpacked into `$RUNNER_TEMP`. **No docker.** It does
need the gitleaks binary, and that need is satisfiable on both runner types —
`install-gitleaks.sh` installs into `$RUNNER_TEMP`, not `/usr/local/bin`, which
is unwritable on the self-hosted honeypot-ci runner (the exact constraint
`install-trivy.sh:27-31` documents). So `home: true` costs nothing the metal
cannot deliver.

It is a matrix row, not a new job, so it inherits `scripts-and-compose`'s
`needs: [ci-target]`, its routed `runs-on`, and the pair-naming suffix. No
existing job, row, `needs:` list or aggregator was touched — the row was
*inserted*, and `git diff` shows no deletions in the workflow.

## Two things that would have made this gate lie

Neither was in the brief; both are the difference between a gate that works and
a gate that reports green having measured nothing.

**1. `actions/checkout` defaults to `fetch-depth: 1`.** The scan's entire claim
is *full history* (`check-git-secrets.py:9-11`). On a `pull_request` the
merge-commit checkout hands gitleaks exactly one commit, and the gate passes
vacuously. No workflow in this tree sets `fetch-depth`
(`grep -rn 'fetch-depth' .github/workflows/*.yml` → empty), so nothing else had
hit it. The row unshallows, then **asserts** the history is really there:

```
commits="$(git rev-list --count HEAD)"
if [ "$commits" -lt 100 ]; then
  echo "::error::secret-scan: only $commits commit(s) under HEAD -- refusing to report a clean scan of a truncated history"
  exit 1
fi
```

A truncated history is an error, not a pass.

**2. "Failed to run" must not read as "no secrets found."** This is the
flagged-vs-unresolved split #2763 forced for trivy. The script already draws it
— `--exit-code 0` so gitleaks' own status is never trusted, then a non-zero
from the binary itself mapped to `return 2` (`check-git-secrets.py:196,201-208`).
The workflow must not paper over it, so the row runs under `set -euo pipefail`
with **no** `|| true` and no piped-away status; exit 2 fails the step like exit
1 does. Proof below.

---

# Verification

All output pasted is real, from the installed-binary path the workflow uses —
`scripts/install-gitleaks.sh`, not the pre-extracted `/tmp/gitleaks` the brief
mentions. That binary is byte-identical to the one the installer downloads
(`cmp` clean), so the two agree; the runs below use the installed one.

```
$ GITHUB_PATH=/tmp/gl-ghpath RUNNER_TEMP=/tmp scripts/install-gitleaks.sh
/tmp/gl-verify/gitleaks_8.30.0_linux_x64.tar.gz: OK
install-gitleaks: added /tmp/gl-verify to GITHUB_PATH (gitleaks 8.30.0)
$ command -v gitleaks
/tmp/gl-verify/gitleaks
```

## 1. Full-history scan — a real run

```
$ export PATH="/tmp/gl-verify:$PATH"
$ python3 scripts/check-git-secrets.py
Secret scan passed: 88 finding(s) over full history, all covered by ALLOWED_FILES (0 cowrie honeyfs) or absent.
GATE EXIT CODE: 0

real	2m6.097s
```

Not a skip, and not the `--binary /tmp/gitleaks` path from commit 1: 2858
commits, full clone (`git rev-parse --is-shallow-repository` → `false`).
88 findings, every one an `ALLOWED_FILES` entry — 50 in `graphify-out`, 12 in
`dash-shots`, 86 of 88 on `generic-api-key` and 2 on `jfrog-identity-token`.

## 2. Negative control — plant, prove it fails, remove, prove it passes

**Planted** a fake credential in a non-allowlisted file, committed:

```
$ printf 'api_key = "%s"\n' 0a1b2c3d 4e5f6a7b 8c9d > deploy/gate-negative-control.txt
$ git commit -qm "negative control: fake credential"   # 1143e043
$ python3 scripts/check-git-secrets.py
Secret scan failed: 1 finding(s) outside the allowlist (88 allowed, 0 of them cowrie honeyfs bait):
  - deploy/gate-negative-control.txt:1: generic-api-key (commit 1143e043d7, t)
GATE EXIT CODE: 1
```

**Removed it** (`git rm`, committed `19096ca3`) and re-ran. The gate still
failed — and that is the gate working, not a failure to recover:

```
Secret scan failed: 1 finding(s) outside the allowlist (88 allowed, 0 of them cowrie honeyfs bait):
  - deploy/gate-negative-control.txt:1: generic-api-key (commit 1143e043d7, t)
GATE EXIT CODE: 1
```

It still reads commit `1143e043`, because the scan is over *history*: deleting
the file in a later commit does not un-commit it. That is precisely the
property the script exists for (`check-git-secrets.py:9-11`), and the only way
to clear a control is to remove the commit that carried it:

```
$ git reset --mixed HEAD~2      # drop 1143e043 and 19096ca3; HEAD back to 294c2c88
$ rm -f deploy/gate-negative-control.txt
$ python3 scripts/check-git-secrets.py
Secret scan passed: 88 finding(s) over full history, all covered by ALLOWED_FILES (0 cowrie honeyfs) or absent.
GATE EXIT CODE: 0
```

Back to exactly 88 findings, exit 0. The two control commits are gone from the
branch; the scan is back on the 88 it started with.

## 3. Positive control — cowrie honeyfs decoys still allowed

Two ways, because the real tree's decoys are too low-entropy to trip the
detector (commit 1's Proof 2 established this; `0 cowrie honeyfs` in a real run
is expected, not a gap). This one plants a decoy that *does* fire, under the
repo's own tracked honeyfs subtree:

```
tracked honeyfs files copied: 54
gitleaks RAW findings under honeyfs: 1
    arcane/home/honeypot-cowrie/cowrie/honeyfs/opt/inference/.env generic-api-key
all under HONEYFS_PREFIX: True
check-git-secrets exit code on the honeyfs tree: 0
```

A raw `generic-api-key` finding, exit 0 — the prefix exemption absorbed it.
The **same literal one directory up**, outside the prefix, is the negative
control above and exits 1. That asymmetry is the honeypot's whole basis, and it
holds in both directions.

## 4. Fail-closed on a stale allowlist entry

`_verify_allowlist` (`check-git-secrets.py:131`), exercised with an entry
pointing at a file that exists nowhere:

```
$ python3 -c "...ALLOWED_FILES['docs/definitely-not-a-real-file-3501.md'] = 'hypothetical stale entry'; print(_verify_allowlist())"
   docs/definitely-not-a-real-file-3501.md: allowlist entry names a file that exists
   neither in the tree nor anywhere in history -- remove the entry or restore the file
```

`main()` returns 1 on this, so the row fails.

## 5. "Failed to run" is not "no secrets found"

A stub binary that exits non-zero, driven through the real entry point:

```
$ python3 scripts/check-git-secrets.py --binary /tmp/gl-broken
check-git-secrets: gitleaks failed to run: fatal: unknown flag --nope
GATE EXIT CODE: 2
```

**2, not 0.** The row runs under `set -euo pipefail` with nothing swallowing
that status, so a broken download is a red build rather than a silent pass —
the #2763 distinction, preserved.

## 6. The test file

**Binary-less box — the four gitleaks-backed tests skip:**

```
$ /usr/bin/python3.12 -m pytest tests/docs/test_3501_secret_scan_allowlist.py -q
....ssss                                                                 [100%]
4 passed, 4 skipped in 0.22s
```

**With the installed binary on PATH — all four actually execute:**

```
$ export PATH="/tmp/gl-verify:$PATH"
$ /usr/bin/python3.12 -m pytest tests/docs/test_3501_secret_scan_allowlist.py -q -rs
........                                                                 [100%]
8 passed in 10.89s
```

I got the second one, **8 passed, 0 skipped**.

That distinction is why the row runs the suite itself. `tests/docs/` is already
collected by the "Docs regression tests" row (`quality.yml:1718-1722`), which
installs pytest but has no gitleaks on PATH — so in that row these four tests
skip every time and the gate's core assertions never run. This row is the only
place in CI where they execute. Without it the suite would be a permanent
green skip, the same failure #2981 was filed for.

## 7. Lint

```
$ SHELLCHECK_OPTS="-S warning" actionlint -color; echo rc=$?
rc=0
```

Zero findings at CI severity. `shellcheck --severity=error scripts/install-gitleaks.sh`
→ clean, `bash -n` → clean.

---

# Not done in this commit

- **`quality-gate` was not extended.** The row lives inside the
  `scripts-and-compose` matrix, so its failure already fails
  `scripts-and-compose-complete` (`quality.yml:2530,2542-2543`) and therefore
  `quality-gate`. Adding it to `quality-gate`'s `needs:` would be a second
  path to the same outcome and would touch a list the brief says to leave
  alone.
- **Container-scan gate untouched**, as instructed —
  `scripts/list-docker-base-images.py` and `.github/workflows/image-security-scan.yml`
  have no changes in this commit's diff.
- `ACCEPTED_CVES`: still uncommitted, unchanged.
- Nothing pushed. No PR.
---

# Commit 5 — fix the two defects CI found on #3516

Nothing pushed. Two real defects, both reproduced below before being fixed.

| defect | symptom in CI | root cause | fix |
|---|---|---|---|
| 1 | `check-git-secrets: gitleaks is not on PATH`, exit 2, 17s | the install wrote `$GITHUB_PATH`, which the runner applies to *later* steps only; each `run:` is its own process | `quality.yml:2095` exports the printed binary's directory into `PATH` for the rest of the block |
| 2 | `1 failed, 641 passed, 25 skipped` — `_verify_allowlist()` called 7 healthy historical-only entries bad paths | `git log --all -- <path>` cannot see deleted paths in a SHALLOW clone, so "absent from this clone" was read as "absent from history" | `scripts/check-git-secrets.py:_verify_allowlist()` detects the shallow clone and *degrades loudly* instead of guessing |

## Defect 1 — reproduction, before the fix

```
$ env -i PATH=/usr/bin:/bin RUNNER_TEMP=$T GITHUB_PATH=$T/gh/path bash -c \
    'set -euo pipefail; scripts/install-gitleaks.sh; command -v gitleaks'
/tmp/.../gitleaks_8.30.0_linux_x64.tar.gz: OK
install-gitleaks: added /tmp/.../gitleaks-bin to GITHUB_PATH (gitleaks 8.30.0)
--- next step, PATH as the workflow sees it ---
gitleaks NOT on PATH (exit 1)
```

The checksum verification worked (`OK`); only the propagation was broken, exactly
as the task described.

A second defect in the same script surfaced while fixing the first, and is part
of the same fix: `--print-path` is meant to be assignable, but
`sha256sum -c -` prints `<file>: OK` to **stdout**, so
`$(scripts/install-gitleaks.sh --print-path)` returned two lines and the caller
put `<tarball>: OK` on `PATH`:

```
+ export 'PATH=/tmp/.../gitleaks_8.30.0_linux_x64.tar.gz: OK
/home/.../gitleaks-bin:/usr/bin:/bin'
+ command -v gitleaks
                              <- not found
```

Fixed at the source rather than filtered in the caller: stdout is now reserved
for `--print-path`'s one path, and every progress line plus the checksum
verification's own output goes to stderr (`install-gitleaks.sh:106` and the
five progress messages).

## Defect 1 — the fix

`quality.yml:2095-2107`, inside the existing row. Additive only: no lane, row or
aggregator removed.

```yaml
export PATH="$(dirname "$(scripts/install-gitleaks.sh --print-path)"):$PATH"
# Prove the propagation before the scan, so a broken PATH fails
# as "gitleaks missing" next to the install, not as an opaque
# exit 2 from a scan that never ran.
command -v gitleaks
```

The script's `GITHUB_PATH` write stays — it is correct for *later* steps, it just
was never enough for the step doing the scan.

**The PATH check is not softened.** With no binary on `PATH`, from a clean env:

```
$ env -i PATH=/usr/bin:/bin /usr/bin/python3.12 scripts/check-git-secrets.py
check-git-secrets: gitleaks is not on PATH. The workflow installs a pinned, checksum-verified build before calling this; locally, install it yourself or pass --binary.
rc=2 (expected 2)
```

## Defect 1 — verification: the full-history scan, clean env

Exactly what the workflow row now runs:

```
$ tmp=$(mktemp -d); mkdir -p "$tmp/gh"; : > "$tmp/gh/path"
$ env -i PATH=/usr/bin:/bin HOME=$HOME RUNNER_TEMP=$tmp GITHUB_PATH=$tmp/gh/path bash -c '
set -euo pipefail
export PATH="$(dirname "$(scripts/install-gitleaks.sh --print-path)"):$PATH"
command -v gitleaks
python3 scripts/check-git-secrets.py
echo "exit=$?"'
/tmp/tmp.dt7MG25egd/gitleaks_8.30.0_linux_x64.tar.gz: OK
/home/xore/.hermes/cache/scratch/tmp.HweS79yiqe/gitleaks-bin/gitleaks
Secret scan passed: 88 finding(s) over full history, all covered by ALLOWED_FILES (0 cowrie honeyfs) or absent. Report: .../.ci-artifacts/gitleaks.json
exit=0
rc=0
```

2444 commits of real history, 88 findings, all accounted for.

## Defect 2 — the decision, and why

The property we want is: *an allowlist entry that matches nothing must not
silently exempt a future real secret under that path.* That is about whether
the path could **ever** match — not about whether **this** clone contains it.
A shallow clone cannot answer the first question, so it must not answer the
second one wrongly.

Two options were available:

- **Fetch enough history to answer it.** The docs-regression row shares one
  checkout with ~65 other matrix rows; unshallowing there costs every row the
  fetch to answer a question only this check asks. And the fetch is not
  something a test should do to the machine running it.
- **Degrade to a check the clone can actually make, loudly, only when shallow.**
  **Chosen.**

So: **warning, never a finding.** A truncated clone is evidence about the clone,
not about the entry. But "never silently pass a check that could not run" is the
other half, so the degradation is announced as a `::warning::` Actions
annotation naming exactly which half did not run and the command that restores
it.

What still runs in a shallow clone — the half it *can* decide, unweakened:

- every entry still needs a written reason;
- every entry still must be present in the working tree if it is there.

And when the clone is full, the stale-entry failure is unchanged and still a
hard finding (that is the existing `test_gate_fails_closed_on_a_stale_allowlist_entry`,
plus the new `test_full_clone_still_fails_closed_on_a_stale_entry`).

The gate's own CI step unshallows before scanning (`quality.yml:2079-2081`), so
in the row that matters the check runs in full. The docs suite is the shallow
case, and it is where the degradation is observable.

## Defect 2 — reproduction in CI-like conditions, before the fix

A real `git clone --depth 1` of this repo:

```
$ git clone --depth 1 --no-local file://$PWD /tmp/clone
$ git rev-parse --is-shallow-repository
true
$ git log --all --format=%H -1 -- dashboard/static/xterm.js | wc -c
0
$ python3 -c "... _verify_allowlist()"
problems: ['graphify-out/cache/stat-index.json: ... exists neither in the tree nor anywhere in history',
           'dash-shots/f2-follow-up/preserved-sha256.json: ...',
           'dashboard/static/xterm.js: ...',
           'dashboard/scanner_fingerprints_test.go: ...',
           'dashboard/problem_reports_test.go: ...',
           'canarytokens/Dockerfile: ...',
           'pihole/dnscrypt-proxy.toml: ...']
```

Seven entries — the exact set the task named (~6, "and ~3 more"). Reproduced
against unmodified `HEAD`, before the fix landed.

## Defect 2 — same clone, after the fix

```
$ git rev-parse --is-shallow-repository
true
::warning::secret-scan allowlist: this is a SHALLOW clone (`git rev-parse --is-shallow-repository` = true), so the 'exists somewhere in history' half of the allowlist check cannot run and was NOT run. Entries are only checked for a written reason and for presence in the working tree. Run `git fetch --unshallow` to get the full check.
problems: []
```

Zero findings, one loud warning. And on this full clone, unchanged and strict:

```
$ git rev-parse --is-shallow-repository
false
$ python3 -c "... _verify_allowlist()"
problems: []
```

## Defect 2 — tests

Four new tests in `tests/docs/test_3501_secret_scan_allowlist.py`, against real
git repositories built with `git init` / `git clone --depth 1` — the precedent
in this suite (`test_2604_check_public_leaks_fixture_allowlist.py:51`,
`test_2055_fix.py:625` build and read real repos rather than mocking git, because
the thing under test *is* git's behaviour).

- `test_is_shallow_reports_true_on_a_depth_1_clone` — detection against a clone
  git really made shallow, and `False` for the full clone it came from.
- `test_shallow_clone_degrades_the_allowlist_check_without_failing` — a path
  deleted upstream, then verified genuinely invisible in the clone
  (`git log ... -- path` empty), then asserted to produce **no** finding and an
  explicit `::warning::`/`was NOT run`.
- `test_shallow_clone_still_fails_on_an_entry_with_no_reason` — the degradation
  does not weaken the check a shallow clone *can* make.
- `test_full_clone_still_fails_closed_on_a_stale_entry` — the other side of the
  branch, so the above cannot pass on a checker that had simply deleted the
  check.

These fail on the pre-fix script, for the right reason:

```
$ git show HEAD:scripts/check-git-secrets.py > scripts/check-git-secrets.py  # then run the suite
E  AssertionError: a shallow clone cannot see truncated history, so a miss there
   is not evidence the entry is stale -- but it was reported:
   ['gone/deleted-long-ago.txt: allowlist entry names a file that exists neither
     in the tree nor anywhere in history -- remove the entry or restore the file']
```

## Verification

### `tests/docs` — with gitleaks on PATH (the CI shape, fixed)

```
$ /usr/bin/python3.12 -m pytest tests/docs -q
670 passed, 1 skipped, 1 xfailed, 17 subtests passed in 200.99s (0:03:20)
```

### `tests/docs` — without gitleaks on PATH

```
$ /usr/bin/python3.12 -m pytest tests/docs -q
667 passed, 4 skipped, 1 xfailed, 17 subtests passed in 176.97s (0:02:56)
```

The delta is exactly the four `gitleaks`-backed tests skipping, as designed.

### `scripts/check-public-leaks.py`

```
$ /usr/bin/python3.12 scripts/check-public-leaks.py
Public-repository safety check passed.
rc=0
```

### Lint / parse

```
$ shellcheck --severity=error scripts/install-gitleaks.sh   -> clean
$ bash -n scripts/install-gitleaks.sh                       -> clean
$ python3.12 -m py_compile scripts/check-git-secrets.py tests/docs/test_3501_secret_scan_allowlist.py -> OK
$ python3.12 -c "import yaml; yaml.safe_load(open('.github/workflows/quality.yml'))" -> parses
```

## Not done in this commit

- **Nothing pushed.** Commits only, as instructed.
- **`scripts/list-docker-base-images.py` and
  `.github/workflows/image-security-scan.yml` untouched** — no diff entries.
  Container-scan stays on hold.
- **`ACCEPTED_CVES`** still uncommitted in the working tree, unchanged.
- **No existing lane, row or aggregator removed.** The `quality.yml` diff is 13
  added lines inside the existing `Full-history secret scan (gitleaks, #3501)` row.

---

# Commits 5–8 — arm the container-scan CVE gate (#3501 GAP 1)

Four commits on top of the secret-scan work above.

| # | sha | subject |
|---|---|---|
| 5 | `0ff159d0` | `ci(3501)` — define the exemption table and its matching rule |
| 6 | `4c62ae3d` | `test(3501)` — hold the exemption set against rot |
| 7 | `9f0a9cae` | `ci(3501)` — arm the gate |
| 8 | `498ec541` | `docs(3501)` — record the gate decision |

## ⚠️ The gate is armed and currently RED

This is the headline, and it is not the outcome the brief assumed. The gate
fails on **54 base images with fixable CRITICAL/HIGH findings and no written
reason**. That is the measured backlog of `.task.md` defect 3 (17 refs with no
key) plus the 37 whose written reasons were contradicted by the scans, minus
the four that are genuinely immovable and are now exempted.

**Arming a gate that fails means every push touching a Dockerfile goes red.**
That is the correct behaviour for the gate as specified, and it is also why
the brief's step 2 ("a proof the gate FAILS when an exemption is removed") is
not a discriminating test in this state — see below.

## The four exemptions

All four are build stages that no shipped image inherits, resolved by
walking every tracked Dockerfile's stage graph. Each count is trivy 0.74.0's
own tally for the pinned digest, 2026-10-04:

| tag | digest | fixable CRITICAL/HIGH |
|---|---|---|
| `node:22` | `sha256:8a34c4ab…` | 160 (28 at the tag's current digest) |
| `rust:1-bookworm` | `sha256:82150a52…` | 147 (18) |
| `rust:1-slim-bookworm` | `sha256:94e9efa4…` | 74 (1) |
| `mcr.microsoft.com/dotnet/sdk:10.0.101` | unpinned | 64 |

The `golang:*` tags are deliberately **absent**: their pins are stale but
movable, so the fix is to bump them, not to exempt them.

## Commands and real output

### The gate, exemptions in place

```
$ /usr/bin/python3.12 scripts/list-docker-base-images.py > images.txt
$ bash /tmp/scan3501/gate_raw.sh          # the workflow's scan step verbatim
GATE EXIT = 1
::notice::4 image(s) matched a written exemption in ACCEPTED_CVES.
::error::54 base image(s) have fixable CRITICAL/HIGH vulnerabilities and no
         written reason -- see the grouped logs above. Fix the finding (bump
         the pin), or add a reasoned entry to ACCEPTED_CVES.
```

### Negative control — and why it does not prove what it looks like it proves

Removing the `node:22` entry and re-running:

```
NEGATIVE CONTROL GATE EXIT = 1
::error title=Vulnerable base image::node:22@sha256:8a34c4ab… has fixable CRITICAL/HIGH vulnerabilities
::notice::3 image(s) matched a written exemption in ACCEPTED_CVES.
::error::54 base image(s) have fixable CRITICAL/HIGH vulnerabilities and no written reason
```

The count moves 4 → 3 and `node:22` is named, so `allow_cve_findings()` is
demonstrably consulted and the removal is demonstrably detected. **But the
exit code is 1 either way**, so as a pass/fail proof this test discriminates
nothing. It would only be conclusive if the gate were green with exemptions
in place first.

### Emission unchanged

```
$ git show origin/main:scripts/list-docker-base-images.py > baseline.py
$ python3.12 baseline.py > /tmp/images_main.txt     # run inside the tree:
                                                   # REPO_ROOT is __file__
                                                   # -relative, so it must
                                                   # live in scripts/
origin/main: 67 refs | HEAD: 67 refs
STDOUT IDENTICAL to origin/main
```

### Full suite

```
$ /usr/bin/python3.12 -m pytest scripts/tests tests/docs -q
1000 passed, 6 skipped, 1 xfailed, 93 subtests passed in 200.40s (0:03:20)
```

## Not done in these commits

- **The 54-image backlog is not cleared.** The brief's rule is that an image
  with a published fix gets the fix — a pin bump in the Dockerfile or compose
  file — not an exemption. That work is 52 distinct images plus 2 duplicate
  spellings, each needing a scan to confirm the new digest is actually clean
  before the pin moves. It is not done here, and it is what stands between
  this branch and a green gate.
- **Nothing pushed. No PR.** Commits only.
- **No existing lane, row or aggregator removed.** The workflow diff is +29
  −11, all inside the existing scan step: its flags, group annotations,
  unresolved-classification branch and trivy invocation are untouched.

---

# Session 2 — the golang toolchain pins

Two commits, continuing the pin-bump work. Branch `ci/3501-base-image-gate`.

| # | commit | contents |
|---|---|---|
| 1 | `dab1a0bd` | `build(3501)` — four stale `golang:1.23*` pins moved |
| 2 | `00447a6e` | `ci(3501)` — one reasoned `ACCEPTED_CVES` entry, for the one that cannot move |

These are the three entries the previous run deliberately left out, plus the
one exemption that decision forced.

## What moved, and why each case came out different

The four stale pins were not one case but three. Deciding per-image rather
than by tag is what separates them.

| image | old ref | new ref | before | after | how it built |
|---|---|---|---|---|---|
| honeyfs-implant | `golang:1.23-bookworm@sha256:167053a2…` | `golang:1.27-alpine@sha256:8a5910f3…` | 1386 total | 0 | scratch final, `CGO_ENABLED=0` |
| galah-llm-broker | `golang:1.23@sha256:60deed95…` | `golang:1.27-alpine@sha256:8a5910f3…` | 1386 total | 0 | alpine final, `CGO_ENABLED=0` |
| hellpot | `golang:1.23@sha256:60deed95…` | `golang:1.27-alpine@sha256:8a5910f3…` | 1386 total | 0 | alpine final, `CGO_ENABLED=0` |
| galah | `golang:1.23@sha256:60deed95…` | `golang:1.27-bookworm@sha256:69a7b978…` | 1386 total | 7 | bookworm-slim final, `CGO_ENABLED=1` |

Three took alpine and one could not. The constraint that separates them is
galah's `CGO_ENABLED=1` against `mattn/go-sqlite3`, which has no pure-Go
fallback — the binary is dynamically linked to glibc and ships into a
`debian:bookworm-slim` final stage, so its toolchain has to be glibc too.
That is a property of the program, not of the Go version.

hellpot's build stage also traded `apt-get install python3 git` for
`apk add --no-cache python3 git`. Its two patch scripts import only
`pathlib`, so nothing behind that line required Debian, and the final stage
was already alpine.

### The bookworm family is uniformly 7 — there is no clean version to move to

This is the measurement that decides galah's case, so it is worth the full
command:

```
$ trivy image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
    --exit-code 1 --no-progress golang:1.27-bookworm@sha256:69a7b978…
exit=1
2026-…  INFO  Detected OS  family="debian" version="12.15"
Total: 7 (HIGH: 7, CRITICAL: 0)
```

```
$ for t in 1.26-bookworm 1.27-bookworm tip-bookworm 1.27-trixie 1.27-alpine; do …; done
golang:1.26-bookworm    debian 12.15   exit=1   Total: 7  (HIGH: 7, CRITICAL: 0)
golang:1.27-bookworm    debian 12.15   exit=1   Total: 7  (HIGH: 7, CRITICAL: 0)
golang:tip-bookworm     debian 12.15   exit=1   Total: 7  (HIGH: 7, CRITICAL: 0)
golang:1.27-trixie      debian 13.7    exit=1   Total: 48 (HIGH: 48, CRITICAL: 0)
golang:1.27-alpine      alpine 3.24.2  exit=0   (no findings)
```

`tip-bookworm` is the newest rebuild upstream publishes, and it measures
the same 7 as 1.26 and 1.27. The 7 are debian 12.15's own `libexpat1`
(6 CVEs, fixed in `deb12u4`) and `libpcre2-8-0` (1, fixed in `deb12u2`),
neither rebuilt into the tag. Enumerated from the JSON report:

```
  CVE-2024-28757   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2025-59375   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2026-25210   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2026-45186   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2026-66046   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2026-93990   HIGH  libexpat1      2.5.0-1+deb12u3 -> deb12u4
  CVE-2026-103111  HIGH  libpcre2-8-0   10.42-1+deb12u1 -> deb12u2
```

The 1386 total the old pins carried was 635 fixable (626 HIGH, 9
CRITICAL) on the base image's own OS layer, so the bump is 635 → 7 even
where it could not be 0.

### The exemption, and the comment it replaces

`golang:1.27-bookworm` gets an entry keyed to its digest. The entry that
was there said the golang tags scan clean and were deliberately absent —
true when written, false now, and the reason this entry is necessary. It is
corrected rather than left to rot. `golang:1.27-alpine` gets no entry: it
measures 0, and an entry for a clean image is the false claim rule 1 above
the dict exists to prevent.

## Verification — real output

### All four images rebuild after the bump

```
$ docker build --no-cache -t honeyfs-implant:test   arcane/home/honeypot-cowrie/honeyfs-implant/
   … DONE 0.5s
$ docker build --no-cache -t galah-llm-broker:test  arcane/home/honeypot-galah/galah-llm-broker/
   … DONE 1.2s
$ docker build --no-cache -t hellpot:test           arcane/home/honeypot-hellpot/hellpot/
   #17 [build 10/10] RUN CGO_ENABLED=0 GOOS=linux go build -trimpath … -o /hellpot cmd/HellPot/*.go
   #17 DONE 13.4s
$ docker build --no-cache -t galah:test             arcane/home/honeypot-galah/galah/
   #20 exporting manifest sha256:c3e3653e518ebbb1b3bb96b3e9397fd4… DONE 2.3s
```

hellpot's alpine build stage ran both patch scripts and `go mod download`
and produced the binary, so the `apt-get` → `apk` swap is exercised, not
assumed.

### Emission unchanged, exemption live and narrow

```
$ python3 scripts/list-docker-base-images.py | wc -l
66
$ python3 scripts/list-docker-base-images.py 2>&1 >/dev/null
not scannable: dustinupdyke/ghosts-client-universal -- never published: …
```

66 refs before this session's work and 66 after: the three pins that moved
to an existing tag (`1.27-alpine`, already in the tree) and the one that
moved within an existing tag (`1.27-bookworm`, new) net out to no new
distinct artifacts.

```
$ python3 -c "… allow_cve_findings('golang:1.27-bookworm@sha256:69a7b978…')"
accepted_ref: golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
allow_cve_findings -> True
neighbour 1.27-alpine -> False
```

### Tests

```
$ /usr/bin/python3.12 -m pytest scripts/tests/test_3501_base_image_cve_exemptions.py tests/docs/test_2314_fix.py -q
45 passed in 0.88s

$ /usr/bin/python3.12 -m pytest scripts/tests tests/docs -q
1000 passed, 6 skipped, 1 xfailed, 93 subtests passed in 173.18s (0:02:53)
```

`tests/docs/test_2314_fix.py` needed no change and that is worth stating
plainly rather than glossing: it guards the six `golang:1.26-alpine` pins,
which this work does not touch. The new entry is written as a `(tag,
digest, reason)` tuple rather than a joined `tag@sha256:…` string
specifically so the `#2314` repo-wide consistency check cannot read it as a
seventh pin file — the reason for that two-field shape is already in the
dict's own comment, and this is the case it was written for.

### No AI attribution

```
$ git log -2 --format='%B' > /tmp/msg.txt
$ python3 scripts/check-ai-attribution.py --text /tmp/msg.txt
no AI/assistant attribution found
exit=0
```

## What is still red, and what I could not measure

**The gate is still red, and further out than the golang work alone
suggests.** I ran the gate logic over all 66 emitted refs in this session.
The Docker Hub anonymous pull rate limit was hit partway through, so the
run does not have a single trustworthy total. Splitting what actually
happened:

| outcome | count | meaning |
|---|---|---|
| scanned clean | 13 | trivy exit 0 |
| matched a written exemption | 5 | incl. the new `golang:1.27-bookworm` |
| real findings, no exemption | 18 | the actual backlog |
| unverified — rate limited | 30 | **coverage gap, not a finding** |
| unresolvable reference | 0 | |

The previous report's headline was 54 flagged. That number is not
comparable to the 18 above and neither is the arithmetic that would connect
them: the 30 rate-limited images were never measured, and this session's
Docker Hub budget does not permit measuring them. `golang:1.27-alpine`
appears under "unverified" here and measured 0 fixable earlier in the same
session — the re-scan is what hit the limit, which is the clearest evidence
in this report that the 30 are unmeasured rather than clean.

The 18 with real findings are untouched by this session and are the next
work: zeek, elasticsearch, arkime, ollama, keycloak, unsloth, dionaea and
the rest, each needing a candidate scanned before its pin moves. I did not
start them, because the rate limit means I could not verify a candidate
digest for any of them, and an unverified bump is the failure mode the
brief names.

**Explicitly not done:**

- **Nothing pushed. No PR.** Two commits on `ci/3501-base-image-gate`.
- **No lane, row, aggregator or check removed or weakened.** The workflow
  file is untouched by this session — the diff is 5 Dockerfiles and
  `scripts/list-docker-base-images.py`.
- **No `--ignore-unfixed` added anywhere by me, no severity threshold
  raised, no blanket ignore rule.** `--ignore-unfixed` appears in every
  command quoted above because it is already in the gate's own invocation
  at `image-security-scan.yml:120`; it is the gate's flag, not mine.
- **No exemption written for an image whose scan did not run.** The 30
  rate-limited images are reported as a coverage gap and left failing.
