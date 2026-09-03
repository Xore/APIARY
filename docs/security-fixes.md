# Code scanning

Open CodeQL alerts are tracked in
[#80](https://github.com/Xore/APIARY/issues/80) and in the
[Security tab](https://github.com/Xore/APIARY/security/code-scanning),
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

`sandboxArtifactFile` in `dashboard/sandbox.go` was the working example (removed
by #764, see below). Its `filepath.Join` was reached only after the handler had
checked that the request path exactly equalled a server-derived URL, so there
was no live traversal. It was still worth fixing, because the property that
made it safe was enforced three frames away, was partly an accident of
`ServeMux`, and was asserted by no test. The next caller added to that
function would have inherited none of it.

Fix the join, not the handler. Safety that has to be argued from context is
safety that will be lost during a refactor nobody thinks is risky.

`ghidra.go`'s equivalent (`ReportPDF`/`CallGraphSVG` re-validated as bare
filenames before a `filepath.Join`) went further still: #638/#763/#764 moved
every one of these disk-backed artifact routes onto Elasticsearch, so there is
no join left to defend in any of them — the safest fix for "the join's safety
depends on context three frames away" is often removing the join.
