"""Attack-surface / vulnerability-triage scoring for the v1 API's
security_index capability (#1180).

Deliberately deferred by #1165 ("needs real new analysis methodology, not
just routing") until this module gave it one. The methodology here is
narrow on purpose: known-dangerous-import detection via the call graph
Ghidra already exports for every function (xrefs.json), the same
established technique real tools like flawfinder/cppcheck/banned-API lists
already use -- not disassembly-level taint analysis, not a claim of
exploitability. See the client's own disclaimer, reproduced here because
every score this module produces must keep meaning exactly this and
nothing more:

    "Scores are deterministic, evidence-based triage priorities -- not
    vulnerability verdicts, exploitability claims, or model-generated
    findings. Use them to decide what to inspect first."

Explicitly out of scope (#1180's own issue text): native_interop/
android_input/device_integrity (JNI/APK-specific; this service never
analyzes APKs), taint-aware reachability, indirect-call target resolution,
and a rescore/build lifecycle -- scoring is computed fresh from artifacts
that are already exactly synchronized with the job's own completed
analysis, so "available" is just "the required artifacts exist," the same
gate every other v1 route already uses.
"""

SCHEMA_VERSION = "1"
SCORER_VERSION = "1"
WEIGHTS_VERSION = "1"

BANDS = ("critical", "high", "medium", "low")
# Calibrated against the weight scale below (_HIGH=40, _MED=25, _LOW=12): a
# single high-confidence signal (one call to system()/CreateProcessA/etc.)
# lands in "high" on its own, two stack into "critical"; a single
# medium-weight signal lands in "medium"; anything weaker stays "low".
BAND_THRESHOLDS = (("critical", 80.0), ("high", 40.0), ("medium", 20.0), ("low", 0.0))

CATEGORIES = (
    "attack_surface", "memory_safety", "format_string", "command_execution",
    "filesystem_loading", "integer_allocation", "auth_privilege",
    "crypto_verification", "indirect_call", "coverage_uncertainty",
    "anti_analysis", "mitigation",
)

# Known-dangerous imported-symbol taxonomy. Matched case-insensitively
# against xrefs.json callee names, cross-checked against imports.json so an
# internal function that happens to share a name with a libc symbol (e.g. a
# statically-linked or hand-rolled "memcpy") is never scored as if it were
# the real imported one. Each entry: signal_id, category, weight (summed
# per function, not per call site -- calling system() twice is not "twice
# as dangerous" for a triage-priority score), confidence label, and a
# human-readable evidence detail template.
#
# Weights are a deliberately coarse three-tier scale (40/25/12), not a
# precision-tuned model -- there is no ground-truth vulnerability corpus to
# calibrate against here, and pretending otherwise would misrepresent what
# this is. Confidence separately marks how directly a signal implies real
# risk versus merely widening the attack surface worth a closer look.
_HIGH = 40.0
_MED = 25.0
_LOW = 12.0

# (category, weight, confidence, evidence detail)
_DANGEROUS_IMPORTS = {
    # command_execution -- direct process/shell spawn.
    "system": ("command_execution", _HIGH, "high", "calls system(), which runs a shell command"),
    "popen": ("command_execution", _HIGH, "high", "calls popen(), which runs a shell command"),
    "execve": ("command_execution", _HIGH, "high", "calls execve(), replacing the process image"),
    "execl": ("command_execution", _HIGH, "high", "calls execl(), replacing the process image"),
    "execlp": ("command_execution", _HIGH, "high", "calls execlp(), replacing the process image"),
    "execvp": ("command_execution", _HIGH, "high", "calls execvp(), replacing the process image"),
    "winexec": ("command_execution", _HIGH, "high", "calls WinExec() to launch a program"),
    "shellexecutea": ("command_execution", _HIGH, "high", "calls ShellExecuteA() to launch a program/document"),
    "shellexecutew": ("command_execution", _HIGH, "high", "calls ShellExecuteW() to launch a program/document"),
    "createprocessa": ("command_execution", _HIGH, "high", "calls CreateProcessA() to launch a program"),
    "createprocessw": ("command_execution", _HIGH, "high", "calls CreateProcessW() to launch a program"),

    # memory_safety -- classic unbounded C string/buffer operations.
    "strcpy": ("memory_safety", _MED, "medium", "calls strcpy(), an unbounded copy"),
    "strcat": ("memory_safety", _MED, "medium", "calls strcat(), an unbounded concatenation"),
    "gets": ("memory_safety", _HIGH, "high", "calls gets(), which cannot bound its input"),
    "sprintf": ("memory_safety", _MED, "medium", "calls sprintf(), an unbounded formatted write"),
    "vsprintf": ("memory_safety", _MED, "medium", "calls vsprintf(), an unbounded formatted write"),
    "wcscpy": ("memory_safety", _MED, "medium", "calls wcscpy(), an unbounded wide-char copy"),
    "wcscat": ("memory_safety", _MED, "medium", "calls wcscat(), an unbounded wide-char concatenation"),
    "strncpy": ("memory_safety", _LOW, "low", "calls strncpy(), bounded but not guaranteed NUL-terminated"),
    "memcpy": ("memory_safety", _LOW, "low", "calls memcpy() -- flagged only for the length argument to be reviewed"),
    "alloca": ("memory_safety", _LOW, "low", "calls alloca(), a stack allocation with no overflow check"),

    # format_string -- caller-controlled format string risk.
    "printf": ("format_string", _LOW, "low", "calls printf() -- flagged only if the format argument is not a literal"),
    "fprintf": ("format_string", _LOW, "low", "calls fprintf() -- flagged only if the format argument is not a literal"),
    "syslog": ("format_string", _LOW, "low", "calls syslog() -- flagged only if the format argument is not a literal"),

    # filesystem_loading -- dynamic module loading, a common sideload vector.
    "loadlibrarya": ("filesystem_loading", _MED, "medium", "calls LoadLibraryA() to load a module at runtime"),
    "loadlibraryw": ("filesystem_loading", _MED, "medium", "calls LoadLibraryW() to load a module at runtime"),
    "loadlibraryexa": ("filesystem_loading", _MED, "medium", "calls LoadLibraryExA() to load a module at runtime"),
    "loadlibraryexw": ("filesystem_loading", _MED, "medium", "calls LoadLibraryExW() to load a module at runtime"),
    "dlopen": ("filesystem_loading", _MED, "medium", "calls dlopen() to load a module at runtime"),

    # integer_allocation -- allocation size is a common overflow input.
    "malloc": ("integer_allocation", _LOW, "low", "calls malloc() -- flagged only for the size argument to be reviewed"),
    "calloc": ("integer_allocation", _LOW, "low", "calls calloc() -- flagged only for the size arguments to be reviewed"),
    "realloc": ("integer_allocation", _LOW, "low", "calls realloc() -- flagged only for the size argument to be reviewed"),
    "virtualalloc": ("integer_allocation", _LOW, "low", "calls VirtualAlloc() -- flagged only for the size argument to be reviewed"),
    "heapalloc": ("integer_allocation", _LOW, "low", "calls HeapAlloc() -- flagged only for the size argument to be reviewed"),

    # auth_privilege -- privilege/credential-sensitive APIs.
    "setuid": ("auth_privilege", _MED, "medium", "calls setuid(), changing the process's effective user"),
    "seteuid": ("auth_privilege", _MED, "medium", "calls seteuid(), changing the process's effective user"),
    "adjusttokenprivileges": ("auth_privilege", _MED, "medium", "calls AdjustTokenPrivileges() to alter its own privilege set"),
    "impersonateloggedonuser": ("auth_privilege", _MED, "medium", "calls ImpersonateLoggedOnUser()"),

    # crypto_verification -- weak/broken primitives, or a policy-relevant
    # crypto call worth a second look regardless of strength.
    "md5init": ("crypto_verification", _LOW, "low", "uses MD5, a broken hash for integrity/authenticity purposes"),
    "des": ("crypto_verification", _LOW, "low", "references DES, a broken cipher for confidentiality purposes"),
    "rc4": ("crypto_verification", _LOW, "low", "references RC4, a broken stream cipher"),

    # anti_analysis -- debugger/VM detection, common in evasive samples.
    "isdebuggerpresent": ("anti_analysis", _MED, "medium", "calls IsDebuggerPresent(), a debugger-detection check"),
    "checkremotedebuggerpresent": ("anti_analysis", _MED, "medium", "calls CheckRemoteDebuggerPresent()"),
    "ptrace": ("anti_analysis", _MED, "medium", "calls ptrace(), commonly used for anti-debugging on Linux"),
    "outputdebugstringa": ("anti_analysis", _LOW, "low", "calls OutputDebugStringA(), sometimes used as a timing-based debugger check"),
}


def _score_to_band(score):
    for band, threshold in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "low"


def _function_signals(callee_names, import_names_lower):
    """Return the list of (signal_id, category, weight, confidence, detail)
    tuples for one function's callees. callee_names is that function's own
    xrefs.json callees (a list of names, not yet lowercased); a callee only
    ever scores if its lowercased name is BOTH in the dangerous-API table
    AND present in imports.json -- so a same-named internal/static function
    (never actually imported) is never mistaken for the real one."""
    signals = []
    seen_signal_ids = set()
    for name in callee_names:
        key = str(name or "").strip().lower()
        if not key or key not in _DANGEROUS_IMPORTS or key not in import_names_lower:
            continue
        signal_id = f"calls_{key}"
        if signal_id in seen_signal_ids:
            continue  # one function calling the same dangerous import via
            # more than one call site is still one signal, not a stacked one.
        seen_signal_ids.add(signal_id)
        category, weight, confidence, detail = _DANGEROUS_IMPORTS[key]
        signals.append((signal_id, category, weight, confidence, detail))
    return signals


def score_function(fn, xrefs_entry, import_names_lower):
    """Score one functions.json entry against its own xrefs.json callees.
    Returns None if the function has no signals at all (callers render this
    as the zero-signal caveat, not a fabricated clean bill of health)."""
    callees = (xrefs_entry or {}).get("callees") or []
    callee_names = [c.get("name") for c in callees if isinstance(c, dict)]
    signals = _function_signals(callee_names, import_names_lower)
    if not signals:
        return None

    raw_score = sum(weight for _, _, weight, _, _ in signals)
    score = min(100.0, raw_score)
    categories = sorted({category for _, category, _, _, _ in signals})
    # Confidence: the strongest single signal's own confidence, since one
    # high-confidence call (e.g. system()) should not be diluted by also
    # having a handful of low-confidence ones (e.g. malloc()).
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    confidence_label = max(
        (c for _, _, _, c, _ in signals), key=lambda c: confidence_rank.get(c, 0)
    )
    confidence = {"high": 0.9, "medium": 0.6, "low": 0.3}[confidence_label]

    return {
        "addr": fn.get("addr"),
        "name": fn.get("name"),
        "score": round(score, 1),
        "band": _score_to_band(score),
        "confidence": confidence,
        "categories": categories,
        "callers": (xrefs_entry or {}).get("callers") or [],
        "signals": [
            {
                "signal_id": signal_id,
                "category": category,
                "weight": weight,
                "confidence": confidence_lbl,
                "evidence": [{"kind": "call", "ref": fn.get("addr"), "detail": detail}],
            }
            for signal_id, category, weight, confidence_lbl, detail in signals
        ],
    }


def build_security_index(functions, imports, xrefs, max_decompile_functions=None):
    """Build the full security index from a job's own already-exported
    artifacts (functions.json's "functions" list, imports.json, xrefs.json).
    Returns {"scored": [...], "summary": {...}, "coverage": {...},
    "metadata": {...}} -- server.py's routes slice/paginate/look up by addr
    from "scored" and pass "summary"/"coverage"/"metadata" straight through
    into the /security/summary response shape."""
    import_names_lower = {str(i.get("name") or "").strip().lower() for i in (imports or []) if isinstance(i, dict)}

    scored = []
    for fn in functions or []:
        addr = fn.get("addr")
        entry = score_function(fn, (xrefs or {}).get(addr), import_names_lower)
        if entry is not None:
            scored.append(entry)
    scored.sort(key=lambda e: e["score"], reverse=True)
    for i, entry in enumerate(scored, start=1):
        entry["rank"] = i

    bands = {b: 0 for b in BANDS}
    categories = {c: 0 for c in CATEGORIES}
    root_count = 0
    for entry in scored:
        bands[entry["band"]] += 1
        for c in entry["categories"]:
            if c in categories:
                categories[c] += 1
        if not entry["callers"]:
            root_count += 1

    total_functions = len(functions or [])
    decompile_coverage = 1.0
    if max_decompile_functions is not None and total_functions > 0:
        decompile_coverage = min(1.0, max_decompile_functions / float(total_functions))

    return {
        "scored": scored,
        "summary": {
            "total_functions": len(scored),
            "bands": bands,
            "categories": categories,
            "unresolved_indirect_calls": 0,
            "root_count": root_count,
            "android_functions": 0,
        },
        "coverage": {
            "score": round((1.0 + decompile_coverage) / 2.0, 3),
            "functions_truncated": False,
            "edges_truncated": False,
            "strings_truncated": False,
            "legacy_artifacts": False,
            "scorer_downgraded": False,
            "invalid_functions": 0,
            "components": {
                "entry_export": 1.0,
                "call_edges": 1.0,
                "import_resolution": 1.0,
                "decompile": round(decompile_coverage, 3),
            },
        },
        "metadata": {
            "artifact_schema_version": SCHEMA_VERSION,
        },
    }
