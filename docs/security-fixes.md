# Code scanning

Open CodeQL alerts are tracked in
[#80](https://github.com/Xore/honeypot-stack/issues/80) and in the
[Security tab](https://github.com/Xore/honeypot-stack/security/code-scanning),
which is authoritative. This file is not a list of alerts — a snapshot of
scanner output goes stale the moment anyone commits.

Earlier revisions of this document were exactly that snapshot: seventeen alerts
captured on 2026-07-26, with a fix recipe for each. By 2026-07-30 twelve of the
seventeen had ceased to exist, because the files holding them had been deleted
— `vps/forward-auth/` moved to `Xore/auth-backend`, `analysis/scan_samples.py`
was removed, and `dashboard/static/hp-adminlte.js` was replaced by
`Xore/theme`. The document went on describing all seventeen as open. Meanwhile
three genuinely new alerts had appeared and it mentioned none of them.

The lesson is worth keeping, since it generalises past CodeQL: **do not mirror
a live system's state into a markdown file.** Link to the system.

## How to handle an alert

1. Read the flagged code before reading the suggested fix. CodeQL reports a
   dataflow path, not a verdict; it cannot see a guard in a different function
   and it does not know what `ServeMux` normalised before the handler ran.
2. Decide: real defect, or false positive.
3. If real, fix it **and** add a test that fails without the fix. An alert that
   disappears because the code moved is not a resolved alert.
4. If false, dismiss it in the Security tab with the reasoning written out.
   Leaving an error-severity alert open and unexplained is the worst outcome —
   it teaches the next reader that open alerts are normal, and the real one
   after it gets the same shrug.
5. Record the disposition in the issue, not here.

## A defect can be real without being exploitable

`sandboxArtifactFile` in `dashboard/sandbox.go` is the working example. Its
`filepath.Join` is reached only after the handler has checked that the request
path exactly equals a server-derived URL, so there is no live traversal. It is
still worth fixing, because the property that makes it safe is enforced three
frames away, is partly an accident of `ServeMux`, and is asserted by no test.
The next caller added to that function inherits none of it.

Fix the join, not the handler. Safety that has to be argued from context is
safety that will be lost during a refactor nobody thinks is risky.
