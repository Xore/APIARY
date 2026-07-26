# Security Fix Guide — CodeQL Alerts

> Generated from 17 open code-scanning alerts on 2026-07-26.  
> All alerts are **error** severity unless marked ⚠️ (warning).

---

## Table of Contents

| # | Severity | Rule | File | Line |
|---|----------|------|------|------|
| [17](#17-tarslip--pytar-slip) | 🔴 error | `py/tarslip` | `analysis/scan_samples.py` | 169 |
| [16](#16-clear-text-logging--pyclear-text-logging-sensitive-data) | 🔴 error | `py/clear-text-logging-sensitive-data` | `analysis/scan_samples.py` | 745 |
| [15–12](#15-12-log-injection--golog-injection-maingoL953) | 🔴 error | `go/log-injection` | `vps/forward-auth/main.go` | 953 (×4) |
| [11](#11-log-injection--golog-injection-maingoL758) | 🔴 error | `go/log-injection` | `vps/forward-auth/main.go` | 758 |
| [10](#10-log-injection--golog-injection-notifygoL64) | 🔴 error | `go/log-injection` | `vps/forward-auth/notify.go` | 64 |
| [9](#9-log-injection--golog-injection-notifygoL58) | 🔴 error | `go/log-injection` | `vps/forward-auth/notify.go` | 58 |
| [8](#8-log-injection--golog-injection-notifygoL51) | 🔴 error | `go/log-injection` | `vps/forward-auth/notify.go` | 51 |
| [7](#7-unvalidated-url-redirect--gounvalidated-url-redirection-⚠️-warning) | ⚠️ warning | `go/unvalidated-url-redirection` | `vps/forward-auth/main.go` | 680 |
| [6](#6-reflected-xss--goreflected-xss-pagegoL80) | 🔴 error | `go/reflected-xss` | `vps/forward-auth/page.go` | 80 |
| [5](#5-reflected-xss--goreflected-xss-pagegoL31) | 🔴 error | `go/reflected-xss` | `vps/forward-auth/page.go` | 31 |
| [4](#4-path-injection--gopath-injection-sandboxgoL365) | 🔴 error | `go/path-injection` | `dashboard/sandbox.go` | 365 |
| [3](#3-path-injection--gopath-injection-sandboxgoL360) | 🔴 error | `go/path-injection` | `dashboard/sandbox.go` | 360 |
| [2](#2-xss-through-dom--jsxss-through-dom-⚠️-warning) | ⚠️ warning | `js/xss-through-dom` | `dashboard/static/hp-adminlte.js` | 218 |
| [1](#1-overly-permissive-file--pyoverly-permissive-file-⚠️-warning) | ⚠️ warning | `py/overly-permissive-file` | `sandbox/status-export.py` | 67 |

---

## #17 — Tarslip / `py/tar-slip`

**File:** `analysis/scan_samples.py` · **Line:** 169  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/17

### What it is
A tar archive is extracted without sanitising member paths. An attacker who controls the archive content can write files outside the intended extraction directory ("zip slip" / path traversal via tar).

### How to fix

**Step 1** — Locate the `tarfile.open` / `extractall` call near line 169.

**Step 2** — Replace unsafe extraction with a safe helper that rejects absolute paths and `../` traversals:

```python
import tarfile, os

def safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    dest = os.path.realpath(dest)
    for member in tar.getmembers():
        member_path = os.path.realpath(os.path.join(dest, member.name))
        if not member_path.startswith(dest + os.sep):
            raise ValueError(f"Attempted path traversal in tar: {member.name}")
    tar.extractall(dest)

# Usage — replace: tar.extractall(dest_dir)
# With:
with tarfile.open(archive_path) as tar:
    safe_extract(tar, dest_dir)
```

**Step 3** — If using Python ≥ 3.12, use the built-in `filter='data'` argument instead:

```python
with tarfile.open(archive_path) as tar:
    tar.extractall(dest_dir, filter='data')
```

---

## #16 — Clear-text logging / `py/clear-text-logging-sensitive-data`

**File:** `analysis/scan_samples.py` · **Line:** 745  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/16

### What it is
Sensitive data (passwords, tokens, keys, credentials) is being passed to a logging call unredacted, so it ends up in log files or stdout in plain text.

### How to fix

**Step 1** — Identify the variable logged around line 745 (likely a password, API key, or token).

**Step 2** — Never log the raw value. Options:

```python
import logging

# Option A — omit the value entirely
logging.info("Operation completed for user %s", username)

# Option B — redact it
logging.debug("Config loaded, secret=%s", "***REDACTED***")

# Option C — log only a safe fingerprint (last 4 chars)
logging.debug("Token fingerprint: ...%s", token[-4:] if token else "(none)")
```

**Step 3** — Audit all other `logging.*` / `print()` calls in the file for the same pattern.

---

## #15–12 — Log Injection / `go/log-injection` (main.go:953 ×4)

**File:** `vps/forward-auth/main.go` · **Line:** 953  
**Alerts:** https://github.com/Xore/honeypot-stack/security/code-scanning/15  
https://github.com/Xore/honeypot-stack/security/code-scanning/14  
https://github.com/Xore/honeypot-stack/security/code-scanning/13  
https://github.com/Xore/honeypot-stack/security/code-scanning/12

### What it is
User-controlled input (e.g. a header, form field, or URL parameter) flows into a `log.Printf` / `slog` call without sanitisation. An attacker can inject newlines to forge log entries or poison structured log parsers.

### How to fix

**Step 1** — Line 953 is inside `main()`, near the startup `log.Info("forward-auth starting", ...)` block. The four alerts likely map to fields sourced from config values that themselves derive from environment variables (`AUTH_HOST`, `COOKIE_DOMAIN`, `WEBHOOK_URL`, `AUDIT_LOG`).

**Step 2** — Strip newlines from any user/env-controlled string before logging:

```go
// sanitizeLog removes characters that can forge log lines.
func sanitizeLog(s string) string {
    return strings.NewReplacer("\n", "\\n", "\r", "\\r", "\t", "\\t").Replace(s)
}
```

**Step 3** — Apply it to every config field used in the startup log line:

```go
log.Info("forward-auth starting",
    "listen",          sanitizeLog(cfg.listen),
    "auth_host",       sanitizeLog(cfg.authHost),
    "cookie_domain",   sanitizeLog(cfg.cookieDom),
    "audit_log",       sanitizeLog(cfg.auditLog),
    "webhook",         cfg.webhookURL != "",   // boolean — safe
    "metrics",         cfg.metricsToken != "", // boolean — safe
    // ... other fields
)
```

> `slog` structured fields are less dangerous than `fmt.Sprintf` since values are quoted by the JSON handler, but CodeQL still flags them because the *value* is tainted. The `sanitizeLog` wrapper is the cleanest suppression.

---

## #11 — Log Injection / `go/log-injection` (main.go:758)

**File:** `vps/forward-auth/main.go` · **Line:** 758  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/11

### What it is
Same category as #15–12. Line 758 is in the `admin` handler area — likely logging a user-supplied value such as a username or action string.

### How to fix

Apply the same `sanitizeLog()` helper from #15–12:

```go
// Before
s.log.Info("admin action", "action", r.PostForm.Get("action"), "user", cl.user)

// After
s.log.Info("admin action",
    "action", sanitizeLog(r.PostForm.Get("action")),
    "user",   sanitizeLog(cl.user),
)
```

---

## #10 — Log Injection / `go/log-injection` (notify.go:64)

**File:** `vps/forward-auth/notify.go` · **Line:** 64  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/10

### What it is
The `notifier.send()` function logs the webhook response status. The `event` parameter that reaches line 64 is caller-supplied and could contain newlines.

### How to fix

In `notify.go`, sanitise the `event` string in the warn call:

```go
// Line ~64 — before
n.log.Warn("webhook rejected", "event", event, "status", resp.StatusCode)

// After
n.log.Warn("webhook rejected", "event", sanitizeLog(event), "status", resp.StatusCode)
```

Add the `sanitizeLog` helper to `notify.go` or move it to a shared `util.go`.

---

## #9 — Log Injection / `go/log-injection` (notify.go:58)

**File:** `vps/forward-auth/notify.go` · **Line:** 58  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/9

### How to fix

Line 58 is the `webhook failed` warn path:

```go
// Before
n.log.Warn("webhook failed", "event", event, "error", err)

// After
n.log.Warn("webhook failed", "event", sanitizeLog(event), "error", err)
```

---

## #8 — Log Injection / `go/log-injection` (notify.go:51)

**File:** `vps/forward-auth/notify.go` · **Line:** 51  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/8

### How to fix

Line 51 is the `webhook dropped` warn path:

```go
// Before
n.log.Warn("webhook dropped", "event", event)

// After
n.log.Warn("webhook dropped", "event", sanitizeLog(event))
```

---

## #7 — Unvalidated URL Redirect / `go/unvalidated-url-redirection` ⚠️ Warning

**File:** `vps/forward-auth/main.go` · **Line:** 680  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/7

### What it is
The `rd` (redirect) query parameter reaches an `http.Redirect` call at line 680 inside the `login` GET handler before `safeRedirect` is applied, or possibly through a code path that bypasses it.

### How to fix

**Step 1** — Check that *every* redirect in `login()` and `verify()` goes through `s.cfg.safeRedirect()`.

**Step 2** — The `safeRedirect` function already exists and is correct. Ensure it is called before the redirect — **never** after:

```go
// Unsafe pattern to find and remove:
http.Redirect(w, r, r.URL.Query().Get("rd"), http.StatusFound)

// Safe — already present in the codebase, verify it covers line 680:
http.Redirect(w, r, s.cfg.safeRedirect(r.URL.Query().Get("rd")), http.StatusFound)
```

**Step 3** — The `safeRedirect` function validates scheme (`https` only) and host suffix against `cookieDomain`. Confirm the fallback (`/_auth/ok`) is hit for any unexpected input.

> CodeQL may flag this as a false-positive if `safeRedirect` already wraps all paths. In that case, mark the alert as "false positive" in the Security tab after verifying.

---

## #6 — Reflected XSS / `go/reflected-xss` (page.go:80)

**File:** `vps/forward-auth/page.go` · **Line:** 80  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/6

### What it is
User-controlled data reaches `w.Write` / `io.WriteString` without HTML-encoding, allowing script injection in the browser.

### How to fix

Line 80 is in `renderForbidden`. The `host` variable comes from an HTTP header and must be escaped:

```go
// page.go — renderForbidden (already correct in current code, verify):
func (s *server) renderForbidden(w http.ResponseWriter, host string) {
    page := strings.ReplaceAll(forbiddenPage, "{{HOST}}", htmlEscape(host)) // ✅ already escaped
    _, _ = w.Write([]byte(page))
}
```

If `htmlEscape` is **not** applied at line 80, add it. The `htmlEscape` helper is defined later in the same file — ensure it covers `&`, `<`, `>`, `"`, and `'`.

---

## #5 — Reflected XSS / `go/reflected-xss` (page.go:31)

**File:** `vps/forward-auth/page.go` · **Line:** 31  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/5

### What it is
Same category. Line 31 is inside `renderLogin` — likely the `rd` redirect URL or `errMsg` flowing unescaped into the HTML template.

### How to fix

Verify that all template replacements in `renderLogin` use `htmlEscape`:

```go
page = strings.ReplaceAll(page, "{{RD}}",    htmlEscape(rd))     // ✅ must be escaped
page = strings.ReplaceAll(page, "{{ERROR}}",  errHTML)            // errHTML already wraps in htmlEscape
page = strings.ReplaceAll(page, "{{FT}}",    s.cfg.issueForm())   // HMAC output — safe
```

If any replacement omits `htmlEscape`, add it. Pay special attention to `rd` which is attacker-controlled.

---

## #4 — Path Injection / `go/path-injection` (sandbox.go:365)

**File:** `dashboard/sandbox.go` · **Line:** 365  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/4

### What it is
A user-controlled path segment (the `name` variable in `serveSandboxExport`) is joined onto a base directory using `filepath.Join` without verifying the result stays inside the sandbox results directory.

### How to fix

**Step 1** — After constructing the path, use `filepath.Clean` + prefix check to confirm it is still inside the results directory:

```go
func safeJoin(base, name string) (string, error) {
    base = filepath.Clean(base)
    joined := filepath.Clean(filepath.Join(base, name))
    if !strings.HasPrefix(joined, base+string(os.PathSeparator)) {
        return "", fmt.Errorf("path traversal detected: %q", name)
    }
    return joined, nil
}
```

**Step 2** — Replace the unsafe join in `serveSandboxExport` (~line 365):

```go
// Before
path := filepath.Join(sandboxResultsDir(), name)

// After
path, err := safeJoin(sandboxResultsDir(), name)
if err != nil {
    http.NotFound(w, r)
    return
}
```

---

## #3 — Path Injection / `go/path-injection` (sandbox.go:360)

**File:** `dashboard/sandbox.go` · **Line:** 360  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/3

### How to fix

Same fix as #4. Line 360 is a few lines earlier in the same function, likely the `os.Lstat` call:

```go
// Before
info, err := os.Lstat(filepath.Join(sandboxResultsDir(), name))

// After
safePath, err := safeJoin(sandboxResultsDir(), name)
if err != nil {
    http.NotFound(w, r)
    return
}
info, err := os.Lstat(safePath)
```

Add the `safeJoin` helper once to `sandbox.go` and reuse it for both calls.

---

## #2 — XSS Through DOM / `js/xss-through-dom` ⚠️ Warning

**File:** `dashboard/static/hp-adminlte.js` · **Line:** 218  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/2

### What it is
A value read from the DOM (e.g. `innerHTML`, `document.write`, or an `href`/`src` set from `location.hash` / `location.search`) flows into a sink that renders HTML without sanitisation.

### How to fix

**Step 1** — Open `hp-adminlte.js` and find line 218. Look for patterns like:

```js
element.innerHTML = someVar;           // dangerous
document.write(userControlled);        // dangerous
location.href = unsanitizedUrl;        // dangerous
```

**Step 2** — Replace with safe alternatives:

```js
// Instead of innerHTML, use textContent for plain text:
element.textContent = someVar;

// If HTML is truly needed, sanitise first (DOMPurify):
element.innerHTML = DOMPurify.sanitize(someVar);

// For URL sinks, validate before assigning:
const url = new URL(someVar, location.origin);
if (url.origin === location.origin) {
    location.href = url.toString();
}
```

**Step 3** — Since `hp-adminlte.js` is a vendored/bundled file, check if there is a newer version of AdminLTE that patches this, and update the vendor file.

---

## #1 — Overly Permissive File / `py/overly-permissive-file` ⚠️ Warning

**File:** `sandbox/status-export.py` · **Line:** 67  
**Alert:** https://github.com/Xore/honeypot-stack/security/code-scanning/1

### What it is
A file or directory is created with permissions that are too broad (e.g. `0o777`, `0o666`), allowing other users on the system to read or write sensitive files.

### How to fix

**Step 1** — Find the `os.chmod`, `open(..., mode=...)`, `os.makedirs(..., mode=...)`, or `os.mkdir` call near line 67.

**Step 2** — Replace overly permissive modes:

```python
# Before — world-writable or world-readable
os.makedirs(output_dir, mode=0o777, exist_ok=True)
with open(output_file, "w", opener=lambda p, f: os.open(p, f, 0o666)) as f:
    ...

# After — owner read/write only, or owner+group
os.makedirs(output_dir, mode=0o750, exist_ok=True)
with open(output_file, "w", opener=lambda p, f: os.open(p, f, 0o640)) as f:
    ...
```

**Step 3** — Set the `umask` at the top of the script to prevent accidental over-permissive creation elsewhere:

```python
import os
os.umask(0o027)  # files max 0o640, dirs max 0o750
```

---

## Verification

After applying all fixes, re-run CodeQL locally to confirm resolution:

```bash
# Re-trigger via GitHub Actions
git add -A && git commit -m "fix: resolve CodeQL security alerts" && git push

# Or run CodeQL CLI locally
codeql database create ./codeql-db --language=go
codeql database analyze ./codeql-db --format=sarif-latest --output=results.sarif \
  codeql/go-queries:codeql-suites/go-security-extended.qls
```

All 17 alerts should disappear from https://github.com/Xore/honeypot-stack/security/code-scanning once the fixes are merged to `main`.
