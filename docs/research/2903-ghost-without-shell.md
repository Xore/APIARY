# Research: Ghost Without Shell (arXiv:2606.28006) — cowrie session-mode signal this fleet currently discards (#2903)

Checks the paper's central claim — that session-length ranking discards the
majority of post-auth SSH signal, because most sessions are non-interactive
shell-fidelity verification rather than engagement — against what this
fleet's cowrie sensor actually logs and how the dashboard actually ranks
sessions today. Gathered 2026-09-03.

**Scope, per the issue and this batch's house rules:** analysis only. No
sensor config, worker, or dashboard query was changed.

## 1. Does this fleet's dashboard rank cowrie sessions by length today?

**Yes, directly — confirmed by reading the ranking metric's own source,
not inferred from the paper's general claim about "standard session
metrics."**

```rust
// arcane/home/honeypot-dashboard/backend-service/src/sensors.rs:615
"cowrie" => vec![("honeypot.duration_ms", "session time", "duration_ms")],
```

This is the sole per-session ranking/highlight metric the dashboard defines
for cowrie — a pure session-duration value, sourced from cowrie's own
`cowrie.log.closed` event. There is no mode tag, no verification-outcome
field, and no per-command signal anywhere in this list. The paper's
finding — that length-based ranking surfaces the wrong 1% and buries the
99% that is actually informative — applies to this fleet's current
dashboard exactly as described, not just to "standard" metrics in the
abstract.

## 2. What does cowrie already log that could answer the paper's proposed questions, without new sensor capability?

Cowrie is **built from pinned upstream source**, not pulled as an image —
`arcane/home/honeypot-cowrie/compose.yml:32` is `build: ./cowrie`, and
`arcane/home/honeypot-cowrie/cowrie/Dockerfile:23-31` shallow-fetches one
exact commit:

```
# #1488: pinned to v3.0.12 (ced855a) -- was an unpinned `--depth 1` HEAD clone
RUN git init -q /cowrie/cowrie-git && cd /cowrie/cowrie-git \
 && git remote add origin https://github.com/cowrie/cowrie \
 && git fetch -q --depth 1 origin ced855a5cda953eb4ad439d8ee8060afe4234fe4 \
 && git checkout -q FETCH_HEAD
```

That matters twice over: the eventid taxonomy below is **read from that
commit** rather than assumed from upstream documentation (§2.1), and the
repo carries a substantial *behavioural* overlay on top of it, not just
config — which is where this row's real finding turned out to be (§3).

Its JSON log shape is upstream's own, unmodified in structure by this
fleet's ingest pipeline — confirmed by reading the enrichment step that
touches it:

```
$ grep -n "eventid\|\"input\"\|command.input" \
    arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment/mod.rs
(no output)
```

`ip_enrichment/mod.rs` (the Rust successor to what `filebeat.yml`'s
comments still call "ip-enrichment-worker") never touches `eventid` or
`input` — its own header comment states its job is "field normalization
only, not IP resolution" for the fields it *does* touch (source-IP
attribution). Cowrie's raw event shape passes through unchanged, which
means the standard upstream cowrie eventids are already present in every
document Filebeat ships:

### 2.1 The eventid set, read at the pin rather than assumed

Checked out `ced855a` locally and enumerated every `cowrie.*` event string
in `src/`:

```
$ git grep -hoE '"cowrie\.[a-z_.]+"' src/ | tr -d '"' | sort -u
```

The session-relevant ones, with their emission counts:
`cowrie.command.input` (56 call sites), `cowrie.session.file_download` (40),
`cowrie.session.connect` (35), `cowrie.login.success` (32),
`cowrie.session.file_upload` (25), `cowrie.login.failed` (23),
`cowrie.session.closed` (19), `cowrie.log.closed` (16),
`cowrie.command.failed` (16), `cowrie.session.input` (14),
`cowrie.client.size` (9), `cowrie.session.params` (7),
`cowrie.command.success` (6). Nothing is pruned or renamed relative to
upstream's taxonomy, so §2's table below is not optimistic — it rests on
the pinned source.

**The mode discriminator is `cowrie.client.size`, and it is exact.** Read
from `src/cowrie/shell/session.py`: `getPty()` (`:90-98`) dispatches
`cowrie.client.size` with the terminal dimensions; `execCommand()`
(`:103-107`) — the non-interactive exec channel — dispatches nothing of
the kind and goes straight to `HoneyPotExecProtocol`. So *"session has a
`cowrie.client.size` event"* is a precise interactive/non-interactive tag
available in already-ingested data. `cowrie.session.params` is **not** a
discriminator despite looking like one: it is dispatched from
`HoneyPotBaseProtocol.connectionMade` (`shell/protocol.py:102`), the shared
parent of both the exec and interactive protocols.

| Paper's proposed addition | Computable from data already ingested? | Why |
|---|---|---|
| Per-session mode tag (non-interactive exec / interactive / file-transfer) | **Yes, at the ES-query/dashboard level** | Cowrie's own `eventid` values already distinguish these: `cowrie.command.input` for exec-channel non-interactive commands, `cowrie.session.file_download`/`file_upload` for transfers, and a session with any `cowrie.log.closed` but no matching PTY/interactive-shell path allocation for the rest. This is an aggregation change, not new sensor capability. |
| Verification-probe rate / "passed verification" boolean | **Partially, at the query level** | The paper's verification probes (base64 self-tests, exact-arithmetic checks, output round-trips) are detectable as **input patterns** — `cowrie.command.input`'s `input` field already carries the literal command text (e.g. `echo <b64> \| base64 -d`), so a regex/keyword classifier over already-ingested `input` values could flag the probe *attempt*. What it cannot determine is whether the probe *passed* — see next row. |
| Per-answer correctness score on command output | **No — this is a real gap, not a config toggle** | Cowrie's JSON logging does not include the shell's generated *output* text as structured data; only the raw TTY byte stream goes to the separate `cowrie-ttylog` binary recording, which `backend-service`'s own history confirms is content-addressed and has **no per-command, per-session correlation** (`es_importer.rs`'s comment on the retired per-recording attribution join, #1716: "the ttylog index... cannot answer 'who ran this' for a document thousands of different sessions produced"). Scoring "did the sensor return a plausible result" requires either parsing the ttylog stream and pairing it with the adjacent `command.input` event by timestamp (a real, nontrivial worker), or instrumenting cowrie's fake shell to log its own output structurally (a vendored-image change). Neither is a query change. |
| Alert on base64-decode / output-comparison behavior | **Partially, same basis as row 2** | The *attempt* (the input pattern) is visible today; whether it *worked* is the same gap as the row above. |

## 3. The sensor half: does this fleet survive the verification probes the paper describes?

The paper's whole premise is that attackers **verify shell fidelity before
engaging**, and that the recon commands they use for it (`uname` variants,
`lspci`, cpu/memory probes) are 41.59% of non-interactive volume. §1 and §2
measure the *reporting* layer. This section measures the *sensor*, because
this fleet has invested in exactly that surface and a row about fidelity
probes that never looks at it has answered half the question.

### 3.1 What the repo actually ships on top of cowrie

Not "config overlays". A persona:

- `cowrie/bin/gen-dynamic-txtcmds.py` — 400+ lines that generate, fresh on
  every container boot from one shared `SimState`, plausible output for
  `free`, `df`, `dd`, `ss`, `top`, `w`, `uptime`, `lscpu`, `last`,
  `lastlog`, plus `/proc/{version,cpuinfo,meminfo}`.
- 22 static `txtcmds/` entries — `bin/{df,dmesg,mount,netstat,ps,uname}`,
  `usr/bin/{free,id,klist,last,lastlog,lscpu,lspci,nmap,nvcc,nvidia-smi,top,uptime,w,wbinfo,who}`,
  `usr/sbin/smbstatus`.
- `fakefs/sys/class/dmi/id/{product_name,sys_vendor,board_name}`, bind-mounted
  read-only by `compose.yml:74-76`.

The persona is a machine called `gpu01`: 128 logical cores, ~503 GB RAM, 81
days of uptime, two NVIDIA A100 80GB cards in `lspci`, a populated
`nvidia-smi`, `nvcc`, and an `id` carrying a `nexusai\domain users` group.

### 3.2 Measured, not reasoned: a real session against the pinned image

Built the image from this repo's own `cowrie/` context (which pins
`ced855a`), ran it, and ran the paper's named verification commands over a
real SSH session. Two harness-only deviations, both stated: `auth_class` was
switched from `AuthRandom` to `UserDB` so the login was deterministic, and
`userdb.txt`'s line 3 needed its em-dash replaced to load at all (see §5 —
that is a defect in its own right, filed as #2927).

| probe | what the attacker gets | what the persona claims | why |
|---|---|---|---|
| `nproc` | **`2`** | 128 | there is **no `nproc` entry in the overlay**, so cowrie's own bundled `src/cowrie/data/txtcmds/usr/bin/nproc` — a static `2` — answers |
| `lscpu` | `CPU(s): 128` ✔ | 128 | overlay entry is reachable (no builtin `lscpu` shadows it) |
| `grep -c ^processor /proc/cpuinfo` | 128 ✔ | 128 | generated `/proc/cpuinfo` |
| `free -m` | **`Mem: 32336`** (≈31 GB) | ~503 GB | cowrie's **builtin** `free` shadows the generated `txtcmds/usr/bin/free`, and `commands/free.py`'s own comment says it reads *"real host memstats"* — so this reports the container host's actual RAM |
| `uptime` / `w` | **`up 0 min, load 0.00`** | up 81 days, load 2.72 | builtin `uptime`/`w` shadow the generated overlay entries; both report real container uptime |
| `lspci` | **AMD RS880 desktop chipset, no GPU** | two A100 80GB | builtin `lspci` shadows `txtcmds/usr/bin/lspci` |
| `id` | `uid=0(root) gid=0(root) groups=0(root)` | the `nexusai\domain users` line | builtin `id` shadows `txtcmds/usr/bin/id` |
| `who` | the attacker's own live session | a 2026-07-19 login from `10.10.0.52` | builtin `who` shadows `txtcmds/usr/bin/who` |
| `uname -a` | `Linux gpu01 5.15.0-119-generic … x86_64` ✔ | same | builtin `uname` also wins here, but reads `hostname`/`kernel_version` from `cowrie.cfg`, so it happens to agree |

### 3.3 Root cause, read from the producer

`src/cowrie/shell/protocol.py:194-199`, `getCommand()`:

```python
def getCommand(self, cmd, paths, cwd):
    if not cmd.strip():
        return None
    path = None
    if cmd in self.commands:          # <-- bare-name builtin wins here
        return self.commands[cmd]
    ...
    txtcmds_path = CowrieConfig.get("honeypot", "txtcmds_path", fallback="")
    if txtcmds_path:                  # <-- operator overlay only consulted after
```

A bare-name builtin is returned **before** the operator `txtcmds_path` is
consulted. Only a path-form invocation (`/usr/bin/free`) reaches the
overlay. Cross-checking the 220 registered builtin names at the pin against
the 22 overlay entries: **10 are shadowed** — `netstat`, `ps`, `uname`,
`free`, `id`, `last`, `lspci`, `uptime`, `w`, `who` — and 12 are reachable
(`df`, `dmesg`, `mount`, `klist`, `lastlog`, `lscpu`, `nmap`, `nvcc`,
`nvidia-smi`, `top`, `wbinfo`, `smbstatus`).

### 3.4 What this means for the paper's claim

The paper says attackers probe for fidelity and leave when it fails. On this
fleet a probe as cheap as `nproc; lscpu` returns **2 and 128 in the same
session**, and `free -m` reports the honeypot host's real memory. Those are
the failures the paper predicts an attacker screens on — which makes §1's
finding sharper, not weaker: ranking cowrie sessions by
`honeypot.duration_ms` will preferentially surface the sessions that *didn't*
screen us out, and bury the short non-interactive ones that did.

This is a live sensor defect rather than a research conclusion, so per this
batch's contract it is **filed as its own issue** rather than fixed here:
**#2926**.

## 4. Cross-check against this fleet's own numbers, not just the paper's

The paper's 99.23%-non-interactive figure came from an 11-honeypot,
15-day academic deployment (Frankfurt) — not this fleet. Whether the
*proportion* holds here is an empirical question this research row does
not answer: it would require running the eventid-based mode classifier
from §2's table row 1 against this fleet's own cowrie index, which is a
query/measurement exercise, not something inferable from reading code. Not
run here — flagged rather than assumed, per this batch's house rule 4
("read the producer," not the aggregation, but also don't extrapolate a
number this pass didn't measure).

## 5. What I did not verify

- Did not run the mode-classification query described in §2 against a
  live cowrie index to get this fleet's actual non-interactive/interactive/
  file-transfer split — §4 explains why this is a separate measurement
  step, not assumed equal to the paper's number.
- ~~Did not read cowrie's vendored source to confirm the exact set of
  `eventid` values it emits.~~ **Done — see §2.1.** An earlier draft
  deferred this on the false premise that cowrie is a pulled image with no
  source available. It is built from a pinned commit, so the eventid set and
  the interactive/non-interactive discriminator were read directly at
  `ced855a` and needed no live host.
- Did not check whether the paper's base64/arithmetic verification-probe
  *signatures* themselves are precise enough to avoid false positives
  against ordinary legitimate-looking recon commands already seen in this
  fleet's logs (e.g. a scanner's own base64 usage for payload delivery,
  unrelated to shell-fidelity checking) — building the actual classifier
  is out of scope here regardless.

## 6. Bottom line

**The paper's core claim reproduces structurally against this fleet's own
code, not just in the abstract**: cowrie's one dashboard ranking metric
(`honeypot.duration_ms`) is exactly the session-length signal the paper
says discards the majority of attacker behavior, and cowrie's raw logs
already carry two of the four proposed measurement fields (mode
classification, probe-attempt detection) without any new sensor
capability — this is dashboard/query work, not a decoy change. The fourth
(output correctness scoring) is a genuine gap requiring new capability
(ttylog-to-command correlation or shell-output instrumentation), correctly
distinguished from the others rather than lumped into one undifferentiated
ask.

**And the sensor half turned out to matter more than the reporting half.**
§3 measured a real session against the pinned image: the `gpu01` persona
contradicts itself on a two-command probe (`nproc` → 2, `lscpu` → 128), and
10 of the 22 `txtcmds/` overrides this repo ships are unreachable because
cowrie resolves bare-name builtins first. On a paper whose thesis is that
attackers screen on exactly these commands, that is the finding — filed as
**#2926**, with the `userdb.txt` encoding defect found alongside it as
**#2927**.

**Issues deliberately *not* filed:** the four reporting-layer capabilities in
§2's table. That is a decision, not an omission — §4's live-index measurement
should come first, because it establishes whether this fleet's own
non-interactive proportion resembles the paper's 99.23% and therefore whether
the mode tag is worth building. Filing four capability issues ahead of the
measurement that sizes them would be filing a wish list.

Nothing here changed a query, a worker, or cowrie's config, per this row's
own scope boundary — the fidelity defect was filed rather than fixed for
exactly that reason.
