# #3364 — CVE-2026-48842: Roundcube pre-auth SQLi in `virtuser_query`, and what the http-honeypot classifier actually sees

Scope: the APIARY `http-honeypot` payload classifier's coverage of
CVE-2026-48842, as implemented, plus the one evasion path that survived
implementation and the parser fix that closed it. Written 2026-09-29 against
`origin/main` at `43061f27`.

The issue's STATUS block is stale. The detector is **shipped** — #3420 added
the class, #3441 closed a case-folding gap in it, #3464 moved it into its own
file. This document is the research deliverable #3364 asked for, not a new
detector.

## Finding

**CVE-2026-48842** is a pre-authentication SQL injection in Roundcube Webmail's
`virtuser_query` plugin. The value the plugin is handed is escaped with
`preg_replace()`, and a backslash inside the value defeats that escape: a
backslash immediately before the quote turns the escape into a second
backslash and the quote closes the string literal anyway. CVSS **8.1**.

**Exploitation is confirmed in the wild, and the technique is not published.**
The Canadian Centre for Cyber Security's advisory **AV26-503 (2026-09-21)**
reports the CVE as exploited and has published no exploitation detail. The
shape below therefore comes from the advisory's description of the root cause
and from Roundcube's own dispatch, **not from a capture of this fleet being
attacked**. That distinction is load-bearing and is carried through every claim
below.

What follows is the part of the CVE that reaches the sensor as bytes: Roundcube
addresses its own requests with a small set of dispatch parameters, and
`?_task=login` *is* the login form, so both the form and a plugin endpoint
(`?_action=plugin.<name>`) are reachable with no session and no credential.
That is the pre-auth half of the CVE.

## Why this matters for APIARY

The fleet serves no webmail UI, and this is deliberate. A bait path for this
CVE would never match, because in a real attack the path is whatever endpoint
the *target's* dispatch resolves — the same reasoning #2919 and #3309 each
recorded for their own cases. So the class matches on the request's own
structure, and a genuine probe against a real Roundcube instance is a request
this sensor would see arriving on port 80/443 with no preceding session.

The cost of matching on bytes is that the bytes have to be parsed the way the
*target* parses them, not the way Go does. That is where the evasion was, and
it is in the code because the class is in the code.

## Coverage as implemented

Class `roundcube-virtuser-query-sqli`, in
`arcane/home/honeypot-http/http-honeypot/classify_roundcube.go`, dispatched
first in `classify.go:73` — ahead of the generic `sqli` case, because a
Roundcube probe is often both at once and this class is the one that can say
which CVE it was and that no session was needed to reach it.

It is a two-part test, and both parts are required because each alone is
ordinary traffic:

1. **The gate** (`classify_roundcube.go:79`–`92`): one of Roundcube's dispatch
   parameters present as a *key* (`_task`, `_action`, or the plugin named
   outright as `virtuser_query`/`virtuser`), or the plugin named as a *value*
   (`virtuser_query`, `plugin.virtuser_query`). Compared whole and
   case-insensitively, never by substring.
2. **The payload** (`roundcubeSQLPayload`, `classify_roundcube.go:126`): a
   value carrying a SQL metacharacter sequence — tautologies, `union select`,
   `information_schema`, `sleep(`/`benchmark(`/`waitfor delay`, or
   `extractvalue(`/`updatexml(` — **or** the CVE's own root-cause pair,
   backslash-quote plus a metacharacter in the same value
   (`pregReplaceEscapeBypass`, `classify_roundcube.go:162`).

Both halves are matched case-insensitively; the generic `sqli` case is not,
which is exactly the gap #3441 closed after a measured uppercase `UNION SELECT`
went unlabelled on both GET and POST.

**What the tests pin, and what they deliberately refuse.** The boundary cases
in `roundcube_sqli_test.go` are the ones that decide whether the class is
usable rather than noisy, because mail addresses contain apostrophes and this
classifier is the thing reading them: a real Roundcube login, an apostrophe in
a mail address (`o'brien@example.com`), a backslash with no SQL metacharacter
(a Windows path, a JSON escape, a regex), a bare quote with no metacharacter,
and plugin enumeration with no payload. SQLi with no Roundcube shape keeps
`sqli`, and a payload in a query string with no Roundcube shape stays
unlabelled. `classify_order_3464_test.go` additionally pins that this class
still beats `sqli` on the same bytes — a precedence the dispatch order owns.

**The parser, and the fix this document records.** Until this branch, the class
parsed its parameters with `url.ParseQuery` behind a
`if err != nil && len(values) == 0 { continue }` guard. That guard is the
whole bug, and it is the *other* three classes' bug too.

Since Go 1.17, `url.ParseQuery` **rejects and drops any pair containing a
semicolon**, and returns a non-nil map of the pairs that had none. So the
guard does not fire — there *are* values left — and the case keeps reading a
truncated map in which the attacker's own parameter is simply absent:

```
q="_user=x&;_action=login%27+OR+1%3D1--"
  err=invalid semicolon separator in query
  url.Values{"_user":[]string{"x"}}
```

`err != nil`, `len(values) == 1`. Parsing continues, and `_action=login' OR
1=1--` is invisible to the sensor.

This is a real evasion path rather than a theoretical one, because **the
targeted application is PHP, whose only query separator is `&`**. The payload
reaches Roundcube in full while the sensor cannot see it. The same applies to
the guard's other silent case: a value that will not decode
(`%zzadmin' or 1=1--`) makes `url.ParseQuery` return an *empty* map, the guard
fires, and a deliberately broken escape deletes the sensor's own evidence.

**The fix: reuse the parser this codebase already has.** `formValues`
(`classify_wordpress.go:50`), added by #3449 for exactly this reason in both
WordPress cases, splits on `&`, then on the first `=`, unescapes each side, and
**keeps an undecodable side as-is rather than dropping it**. No new parser, no
new abstraction, no new file. All four call sites now use it, so this is one
root cause retired rather than four bugs left.

**New behaviour, stated plainly.** After the fix:

- A Roundcube dispatch parameter whose value contains a literal `;` is now
  read. `_task=login&_user=admin%5C%27;or+1%3D1--` is classified; before, the
  `_user` pair was dropped and the request was unlabelled.
- A value with a deliberately broken escape is now read rather than discarded.
- `odata-double-encode-probe` (`classify_odata.go`) likewise now sees an OData
  option whose own value carries a `;`, and now sees a genuine residual escape
  that a broken escape ahead of it was hiding. This changed one existing
  expectation, `$filter=Year%zz%2520eq`, from unlabelled to
  `odata-double-encode-probe`; the justification is in
  `odata_double_encode_test.go` at the pin. The *rule* did not change — a
  malformed escape is still not a residual escape, pinned separately on a value
  whose only escape is broken — but which requests reach the rule did, and they
  were previously not reaching it because the parser had deleted them.
- **No false-positive surface was widened in the ways that matter.** A `;` in
  front of a key is *not* that key: `;_action` is not a Roundcube dispatch
  parameter, and `;$filter` is not an OData system option. A semicolon with no
  payload behind it stays unlabelled, which is ordinary traffic — `;` is a
  `Content-Type` parameter, a matrix parameter, and a very common typo. Every
  one of these negatives is asserted, not asserted-in-a-comment.
- `qualifyingODataRequest` (`laundering.go:740`, #3447's layer C) now sees an
  OData option separated by a `;`. Its value-consistency gate is unchanged and
  still runs on the value it is shown, so a wider parser did not become a wider
  over-match: `$top=10;$filter=Year%20eq%202026` still does not qualify, because
  `$top` wants a bounded integer and gets a fragment.

`classify_order_3464_test.go` — the deliberate dispatch-order regression gate —
**passes unmodified.** It is not in this branch's diff.

## Known gaps

- **Coverage against the fleet corpus is unmeasured, and #3364 marks it
  unmeasured.** The live corpus (the `honeypot-v2-*` indices) is not reachable
  from a branch. What is measured is the corpus that *is* on `main`: the pinned
  30-day real-traffic fixture from #1888, mirrored entry-for-entry in
  `roundcube_coverage_3364_test.go`. Over it, the class claims **0** entries
  and #3364's naive pre-gate signature claims **0**, both asserted rather than
  logged; over the CVE's own published shapes it catches **9/9**. This is a
  fixture, not the fleet, and it says nothing about recall against real
  Roundcube exploitation.
- **No capture of this fleet being attacked exists.** Every positive follows
  the advisory's description of the root cause plus Roundcube's own dispatch.
  AV26-503 reports exploitation but publishes no technique, so a scanner that
  exploits this CVE in a shape neither the advisory nor the product's dispatch
  suggests would be missed. That gap is upstream's, not this classifier's, and
  it is not closable from here.
- **A value-level `;` is now read; a key-level one is deliberately still not.**
  `;_action=login&_user=…` is refused, because the target's parser does not
  strip the `;` either — the parameter the target sees is not `_action`. The
  class reports what the target would act on, not what the attacker meant.
- **Not reachable at all:** the issue's third proposed shape — a webmail/plugin
  path segment from a source with no prior session in the correlation window.
  This sensor keeps no session state and consults no backend, so it is
  structurally unimplementable in-request, as #3447's own file argues for the
  analogous question.
- **The gate is Roundcube-shaped, so a bare SQLi against a webmail client that
  is not Roundcube is somebody else's class or nobody's.** Widening to cover it
  would be a second generic detection mechanism rather than this CVE.
- **The `teamcity-agent-deserialization` call site was changed for consistency
  and is measured to gain nothing.** Its call-name test compares a value to a
  fixed list as a whole string, so a `;` makes a different value rather than
  recovering a dropped one, and the target's parser reaches the same verdict.
  That is pinned as a measured negative, not assumed — the value of the swap
  there is retiring one root cause, not coverage.
- **No live detection rate is claimed.** Nothing was deployed; this change is
  repo-only. An Arcane build + redeploy is needed before any of it can appear in
  Elasticsearch, and the first real hit must be verified on a document indexed
  after that deploy.
- **No traffic was sent anywhere.** All fixtures are inert strings in unit
  tests. No exploitation, no docker, no Elasticsearch, no model load.

## Severity

**CVE severity: CVSS 8.1** (from the advisory, as recorded in the class's own
doc comment). Known exploited in the wild per AV26-503, 2026-09-21, with no
published technique.

**APIARY exposure: none, by design.** This fleet does not run Roundcube, so
there is nothing to exploit. The value of the class is detection quality —
telling an analyst that a probe aimed at a pre-auth webmail SQLi arrived, and
distinguishing it from the ordinary mail-shaped traffic the classifier would
otherwise have to treat as an attack. The pre-fix gap was a false negative in
a decoy's detection surface, not a vulnerability in the decoy.

## References

- GitHub issue **#3364** — this research request; the source of the CVE id,
  the "actively exploited" claim, and the honest note that the coverage gap is
  unmeasured. Its STATUS block is stale and this document supersedes it.
- PRs **#3420** (the class), **#3441** (case-folding gap), **#3449**
  (`formValues`, for the same root cause in the WordPress cases), **#3464**
  (one file per CVE, dispatch order pinned).
- Canadian Centre for Cyber Security advisory **AV26-503, 2026-09-21** — cited
  as the source for "exploited in the wild" and for the absence of published
  exploitation detail. Cited here as recorded in
  `classify_roundcube.go:14`; **not independently re-fetched for this
  document**, so treat the advisory's own text as second-hand here.
- **#2919**, **#3309** — the "match the request's bytes, not a bait path"
  reasoning this class follows, and **#1888** — the pinned 30-day real-traffic
  corpus the measurement runs against.
- Code: `classify_roundcube.go`, `classify.go:73`, `classify_wordpress.go:50`
  (`formValues`), `classify_odata.go`, `classify_teamcity.go`,
  `laundering.go:740`; tests `roundcube_sqli_test.go`,
  `roundcube_coverage_3364_test.go`, `classify_order_3464_test.go`,
  `form_values_semicolon_3364_test.go`.

No Kibana field names, dashboards, or index patterns are asserted anywhere in
this document: this change adds none, and the only field the classes write is
the existing `payload_class`.

## Veracity note

- **CVSS 8.1, the CVSS identifier, the exploitability claim and the advisory
  id/date are transcribed from the issue body and from the class's own doc
  comment, not from memory and not from a fresh fetch.** No build number,
  fixed version, or affected-version range is claimed, because no source
  consulted for this document states one.
- **No capture exists.** Every payload shape is derived from the advisory's
  description of the root cause plus Roundcube's dispatch parameters. Nothing
  here is presented as observed traffic.
- **The corpus numbers (0 claims, 9/9 published shapes) are measured against a
  pinned fixture, re-runnable via `roundcube_coverage_3364_test.go`.** They are
  not a fleet measurement and must not be quoted as one. #3364's own
  "unmeasured" marking is carried forward deliberately.
- **The parser behaviour quoted in the Finding** was reproduced directly against
  this toolchain (`go1.26.7`) before and after the fix, and the failing-test
  run against unmodified `main` is recorded in the branch's commit history.
- **`teamcity-agent-deserialization` gaining nothing is a measured claim** from
  `form_values_semicolon_3364_test.go`, not an inference from reading the code.
