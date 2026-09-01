# Research: Aurora ransomware + Cursor Agent vs APIARY's five proposed signatures (#2748)

Checks the Gambit Security disclosure against its own primary source, then
checks each of the issue's five proposed detection signatures against what
`honeypot-dionaea`'s SMB module, `honeypot-beelzebub`'s LDAP decoy, and
Cowrie's real captured session data actually do — including, per the batch's
own explicit warning, **measuring** signature 3's invented entropy threshold
against real sessions instead of taking it at face value. Gathered
2026-09-01.

**Scope, per the issue: assessment only.** None of the five signatures was
implemented. No YARA rules or ES queries were added to production.

## 1. What the source actually claims

Reached Gambit Security's own blog post directly (`gambit.security/blog-posts/
aurora-ransomware-targets-esxi-abuses-cursor-agent-for-exploitation`), plus a
WebSearch aggregate corroborating across The Hacker News, OODAloop,
Infosecurity Magazine, SC Media, Unite.AI, and gbhackers.

- **DCSync-restraint quote — corroborated with a correction.** The primary
  source's exact text is `"dcsync делать категорически нельзя"` ("dcsync is
  absolutely forbidden"), restated across at least five messages, with the
  operator instead asking for `"нам нужен только хеш DC"` (the DC machine
  hash only). The issue's quoted Russian (`"DCSync делывать категорически
  нельзя"`) has a transcription error — `делывать` is not the verb Gambit's
  post uses (`делать`) — worth noting since a future reader might grep for
  the exact string.
- **ESXi encryptor — fully corroborated**: sha256
  `a4af136d159a8eb96b54924fa80355ca52874913301300f55af7d67ae97edcfe`, ChaCha20
  + RSA-4096 key wrapping, ELF binary, the `-esxi` flag runs `esxcli vm
  process kill` to force-terminate VMs and release disk locks, then encrypts
  VM-specific extensions (`vmdk`/`vmx`/`vmsd`/`vmsn`/`nvram`/`vmem`/`vswp`/
  `log`) while skipping system volumes to preserve hypervisor boot.
- **Scope/dates — corroborated with an addition**: ten organizations,
  2026-04-08 to 2026-05-21, matching the issue. The primary post also
  describes a **second cluster** (eight victim organizations across six
  countries, CloudSEK's "more than 20 organisations across nine countries"
  in the WebSearch aggregate) that the issue doesn't mention — the campaign
  is larger than the issue's ten-organization framing states.
- **ADCS ESC1/ESC6/ESC8 specific variant numbers — could not confirm from
  the primary post.** Gambit's blog mentions the operator "running
  certificate attacks with Certipy" but does not itemize which ESC
  techniques were used. The issue's specific ESC1/ESC6/ESC8 attribution may
  come from a source I didn't reach (CloudSEK's own report, referenced but
  not fetched here) — flagging as unconfirmed rather than repeating it as
  established.
- **The 30-50% efficiency estimate — corroborated, but its status needs a
  correction.** The issue presents it as if derived from the technical
  analysis. It is instead a verbal estimate Eyal Sela gave to Reuters
  ("the AI probably made the attackers roughly 30 to 50 percent faster"),
  not a measured benchmark in Gambit's own write-up. Worth treating as an
  analyst's rough impression, not a rigorous efficiency metric, when citing
  it elsewhere.

## 2. What our sensors would see today

### Signature 1 — coercion primitives as a first-class Dionaea SMB event class

**More tractable than the issue's framing suggests, via an existing, proven
pattern — but with one unverified precondition.** Reading
`arcane/home/honeypot-dionaea/dionaea/smb_exploit_patch.py`'s own doc
comment: vendored dionaea's `smb.py` **already recognizes and fingerprints
three named exploit signatures** (CVE-2017-7494/Samba "is_known_pipename",
MS17-010 TRANS_NMPIPE_PEEK, DoublePulsar) purely from DCERPC bind/opnum
numbers it already parses — the comment states plainly that *before* this
patch, everything else was "raw DCERPC bind/opnum numbers" reaching only
Python's internal `logging` module, never Elasticsearch. The patch's own
shape (match an interface/opnum pattern → promote to a named
`dionaea.modules.python.smb.exploit` incident, latched once per connection
per #1775) is the exact template PetitPotam (`MS-EFSR` interface,
`EfsRpcOpenFileRaw`/`EfsRpcEncryptFileSrv` opnums) and PrinterBug (`MS-RPRN`
interface, `RpcRemoteFindFirstPrinterChangeNotificationEx`) detection would
follow — a fourth and fifth entry in an existing, working mechanism, not new
sensor infrastructure. **The precondition I could not verify from this
repo**: whether vendored dionaea's SMB module actually implements the
`lsarpc` (EFSR) and `spoolss` (RPRN) named-pipe interfaces at all — the
source lives in the vendored C build, not mirrored readably here, and I did
not pull and build it to check within this pass's budget. If either
interface isn't implemented, a real PetitPotam/PrinterBug tool would fail to
even open the pipe, and there would be nothing at the opnum layer to detect
regardless of adding the signature — this is the actual blocking question
for signature 1, not "does Dionaea support a coercion-primitive event
class," which per the pattern above it clearly already can.

### Signature 2 — ADCS ESC1/ESC6/ESC8 via decoy-LDAP responses

**Does not work as proposed, and the reason matters for what a real fix
would need.** Read `arcane/home/honeypot-beelzebub/beelzebub/configurations/
services/ldap-389.yaml` in full: it's Beelzebub's generic TCP strategy
configured with exactly two regex-matched raw-byte patterns — one for any
LDAP BindRequest PDU shape (`\x30.*\x60`), one for any SearchRequest PDU
shape (`\x30.*\x63`) — each answering with the **same fixed canned response**
regardless of what's actually being searched for (the bind response is
always the same success PDU; the search response is always the same empty
result). This decoy cannot distinguish a Certipy ADCS-template enumeration
query from any other LDAP search, and — more importantly for the issue's
proposed signature — **it never presents a fake vulnerable certificate
template for an attacker to find in the first place**, since every search
returns nothing. A real Certipy run against this decoy sees an empty result
and correctly concludes there's no ADCS here; there is no ESC1/ESC6/ESC8
surface to abuse or observe. Confirmed via `internal/protocols/strategies/TCP/tcp.go`
that the underlying strategy does log a `CommandRaw` field (hex-escaped raw
bytes) for every matched connection regardless of response — so a Certipy
query's raw BER-encoded filter *is* captured as an opaque byte blob today,
recoverable by manual decode after the fact, but there is no live
classification, and — the harder problem — no bait content to make an
attacker's engagement meaningful in the first place. Building this
signature for real needs a BER/LDAP filter parser and fabricated
certificate-template attributes, not a log-classification rule; a much
larger lift than the issue's "monitor... responses" framing implies.

### Signature 3 — per-turn entropy profile, measured against real data

**The specific number is unsupported by anything in our own telemetry, and
measuring it surfaced a second, more basic problem: we have no confirmed
agent-driven session to calibrate the *direction* of the signal against
either.** Pulled 2,000 real `cowrie.command.input` events (186 distinct
sessions) from the homeserver, concatenated each session's command text,
windowed it into 100-character chunks (a token-count proxy — this pipeline
has no tokenizer instrumented on captured text), and computed Shannon
entropy per window exactly as the issue specifies:

```
sessions with >70% of windows below 3.0 bits/char: 0 / 186
overall average across sessions: 4.485 bits/char
lowest average entropy seen in any single session: 4.169 bits/char
```

This was then re-run over a **25× larger slice** — 50,000
`cowrie.command.input` events, 4,517 sessions, 31,495 full 100-character
windows — to check the result was not an artefact of a 2,000-event sample:

```
windows below 3.0 bits/char:            0 / 31,495
sessions with any window below 3.0:     0 / 4,517
sessions with >70% of windows below 3.0: 0 / 4,517
overall average across sessions:        4.496 bits/char
lowest average entropy in any session:  4.113 bits/char
```

**No window in either sample fell below 3.0 bits/char**, let alone the
proposed 70%-of-windows threshold. This is automated botnet
dropper/scanner traffic — highly repetitive, scripted shell one-liners —
and even that sits above 4.1 bits/char throughout.

Stated precisely, because the distinction matters for anyone re-running
this: across 50,000 command-input events the threshold never fired *on the
logged command text*, which is the string a detector built from this
signature would actually see. That is a large sample, not the whole
corpus, and it is one measurement method. A separate re-measurement during
review reported 77 low-entropy windows attributed to binary-echo dropper
traffic; it did not reproduce here at 25× the sample size, and the most
likely reason is a methodological difference rather than a sampling one —
decoding a payload's `\xNN` escapes into real bytes before measuring turns
a run of NULs into genuinely low entropy, whereas measuring the logged
text (as here) does not. Anyone proposing to *implement* this signature
should settle that question first, because it decides whether the
signature has a false-positive class at all.

On the evidence measured, `alert below 3.0 bits/char` has never fired on
this fleet. That could mean
either "we've never yet captured an Aurora-style agent session" (plausible;
this is a narrow, targeted human-operator campaign against ~10-20 named
enterprises, not something that shows up in broad internet-facing honeypot
scanning) or "the threshold is simply too low to ever discriminate anything
in real shell-command text" — and there is no way to tell which from data
we don't have. Labeling this explicitly as a **hypothesis, not a measured
threshold**: nothing here confirms *or* refutes that agent-driven sessions
would actually score lower than the human/botnet baseline above — the
opposite is at least as plausible a hypothesis (structured, flag-heavy
agent-issued commands could score *lower* entropy than human typing full of
natural-language variance and typo-correction, but scripted botnet
one-liners already sit near the ceiling of the 8-bit/char space for ASCII
shell syntax, so it's not obvious agent output would sit meaningfully
lower). This is exactly the kind of unlabelled invented threshold the
batch's own instructions warn against; measuring it didn't validate it, it
showed the number has no grounding in anything we've captured.

### Signature 4 — operator-restraint canary (`DC01`/`ADCS-ROOT`/`ENTCA`)

**Partially already exists.** `ldap-389.yaml:17` sets `serverName:
"dc01.nexusai.local"` — the LDAP decoy already presents itself as a domain
controller named `dc01`, satisfying half of this signature's naming ask
without any new work. What doesn't exist: an actual **touch-detection**
mechanism distinguishing "an attacker enumerated `dc01` as one target among
many" from "an attacker deliberately targeted `dc01`/`adcs-root`/`entca`
while avoiding others" — that requires either multiple decoy hosts of
varying apparent value with differential logging, or session-level
correlation across which named targets a given source IP touched versus
skipped. Neither exists today; this is a real, not-yet-built idea, and
unlike signatures 1-3 it doesn't have an existing pattern to extend from.

### Signature 5 — ESXi encryptor hash + `-esxi` flag as a Cowrie canary

**No existing "command-pattern canary catalog" to extend.** Grepped this
repo for any dedicated known-bad-command/hash matching mechanism in the
Cowrie stack (canary lists, IOC catalogs, signature files) and found none —
Cowrie here runs as a stock fake shell with no such classification layer.
Dionaea's exploit-signature pattern (§ signature 1) is the nearest analog in
this fleet, but it operates on parsed DCERPC opnums, not shell text.
Adding a static string/hash match (`a4af136d159...`, `-esxi`) against
Cowrie's `cowrie.command.input` event stream would be a small, standalone
addition (an ES ingest-pipeline rule or a small script tagging matching
events) rather than an extension of anything that exists — cheap, but net
new, not "add an entry."

## 3. Which of the issue's premises survive

| premise | verdict |
|---|---|
| Campaign facts (DCSync restraint, ESXi encryptor hash/algorithm/flag behavior, 10-org/date-range core cluster) | **confirmed**, with the exact restraint quote's transcription corrected and a second, larger victim cluster added |
| ESC1/ESC6/ESC8 specific ADCS technique attribution | **unconfirmed from the primary source** reachable here |
| 30-50% efficiency gain as a measured benchmark | **corrected** — it's Eyal Sela's verbal estimate to Reuters, not a metric derived in Gambit's technical write-up |
| "Dionaea captures the surface traffic but does not currently surface coercion primitives as a detection class" | **true today, but a proven, cheap extension path already exists** (three working analogs); real blocker is unverified interface support, not missing infrastructure |
| "APIARY does not surface [ADCS template patterns] as canary credential misuses" | **true, and structurally can't with the current LDAP decoy** — it has no query-parsing or bait-content capability at all, a bigger lift than "surface" implies |
| "Agent-driven sessions have a narrower per-window entropy, alert below 3.0 bits/char" | **unsupported by any measurement against our own data** — measured 0/186 real sessions below threshold; the threshold and even the signal's direction are unvalidated hypotheses |
| Operator-restraint canary naming (`DC01` etc.) | **partially already deployed** (the LDAP decoy's own hostname), touch-differential detection itself does not exist |

## 4. The gap, costed

- **Signature 1**: cheap **if** the RPC interfaces exist in vendored
  dionaea (unverified here) — same shape as an existing, working pattern,
  likely a half-day to a day once the interface question is settled.
- **Signature 2**: expensive — needs an LDAP filter parser and fabricated
  ADCS bait content, not a logging rule. Multi-day, and arguably a
  standalone LDAP-decoy redesign rather than an ADCS-specific feature.
- **Signature 3**: **do not ship the numeric threshold as-is.** If pursued
  at all, needs either (a) a labeled-dataset calibration exercise once a
  real or synthetic agent-driven session sample exists, or (b) explicit
  framing as an unvalidated research probe, not a production alert.
- **Signature 4**: cheap for the naming half (already partly done); the
  differential-touch detection half needs new session-correlation logic,
  not costed further here since it wasn't specified precisely enough to
  size.
- **Signature 5**: cheap, standalone, no existing infrastructure to build
  on but nothing complex needed either — a static-string/hash match against
  one event stream.

## 5. Recommendation

**None of the five should ship as specified.** Two (1, 5) are cheap and
sound in principle, pending one unverified precondition for #1. Two (2, 4)
are underspecified relative to what they'd actually require (a real LDAP
protocol implementation; a session-correlation mechanism that doesn't
exist). One (3) should not ship at all in its current form — the specific
threshold has zero grounding in this fleet's own data, and this research
pass's measurement is itself the evidence, not a hunch. If a follow-up
implementation issue is filed, it should split these five apart rather than
track them as one unit, since their cost and readiness vary by an order of
magnitude.

**Follow-up issues**: none filed. Recommend, if this work continues, a
narrow follow-up scoped only to signature 1 (with the dionaea RPC-interface
question answered first) and signature 5 (mechanically simple) — signatures
2-4 need more design work than a code issue, and signature 3 needs data
that doesn't exist yet.

## What I could not verify

- Whether vendored dionaea's SMB module implements the `lsarpc`/`spoolss`
  DCERPC interfaces PetitPotam/PrinterBug actually call — the source lives
  in the vendored C build, not readable from this repo without pulling and
  building it, which this pass's budget didn't extend to.
- The ESC1/ESC6/ESC8 specific attribution — not found in the one primary
  source reached (Gambit's own blog); may exist in CloudSEK's report, not
  independently fetched here.
- Did not attempt to obtain or synthesize a real or realistic agent-driven
  session sample to test signature 3's *directional* hypothesis (agent
  sessions lower-entropy than human) — only tested the threshold against
  what this fleet has actually captured, which by definition contains no
  confirmed agent-driven sessions to compare against.
