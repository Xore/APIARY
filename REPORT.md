# #3501 — landing report

Four commits. Nothing pushed, no PR opened. Branch `ci/3501-gate-enforcement`.

| # | commit | contents |
|---|---|---|
| 1 | `8cc55aa9` | `ci(secret-scan)` — full-history secret-scan gate + its tests |
| 2 | `1d588877` | `chore(types)` — mypy closure over 17 files |
| 3 | `294c2c88` | `docs(measurement)` — `CONTAINER-SCAN-MEASUREMENT.md`, docs only |
| 4 | this one | `ci(wire)` — actually calls the gate; **commit 1 was inert** |

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