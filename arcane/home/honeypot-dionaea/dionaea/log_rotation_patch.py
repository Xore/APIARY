#!/usr/bin/env python3
"""Give dionaea's log_json/log_incident FileHandler self-rotation (#1389).

Both ihandlers' FileHandler opens its target path once with `open(path,
"a")` and keeps writing to that one file descriptor forever -- confirmed
live against the vendored source in both files, no signal handling, no
reopen hook, nothing. dionaea.json and dionaea_incident.json grew to
3.86GB/multi-GB on the live homeserver as a direct result (#120 already
found and documented this exact gap when it rotated every other sensor's
raw JSON; these two were explicitly left out because of it).

ip-enrichment-worker's own tailer (tail.go's readNewLines) already treats
a file that's shorter than its last-read offset as a fresh generation and
resumes from 0 -- the same rename-based-rotation tolerance Filebeat's
inode-tracking harvester and cowrie's own CowrieDailyLogFile rely on
elsewhere in this repo -- and Filebeat itself never tails these raw files
directly (only the enriched copies under /logs/enriched, which
ip-enrichment-worker's own OUTPUT_MAX_BYTES rotation now covers, see
rotate.go). So closing, renaming aside, and reopening at the same path
here is lossless for every downstream reader with zero additional
coordination needed.

Same shape as ftp_patch.py/printer_patch.py/etc.: exact-match string
replacement with a marker for idempotency, applied at Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: FileHandler self-rotation patch (#1389)"
TARGETS = [
    Path("/opt/dionaea/lib/dionaea/python/dionaea/log_json.py"),
    Path("/opt/dionaea/lib/dionaea/python/dionaea/log_incident.py"),
]

OLD_IMPORT = "from urllib.parse import urlparse"
NEW_IMPORT = "from urllib.parse import urlparse\nimport os  # --- {marker} ---".format(marker=MARKER)

OLD_CLASS = '''class FileHandler(object):
    handle_schemes = ["file"]

    def __init__(self, url):
        self.url = url
        url = urlparse(url)
        try:
            self.fp = open(url.path, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", url.path, e.strerror)

    def submit(self, data):
        data = json.dumps(data)
        self.fp.write(data)
        self.fp.write("\\n")
        self.fp.flush()'''

NEW_CLASS = '''class FileHandler(object):
    handle_schemes = ["file"]

    def __init__(self, url):
        self.url = url
        url = urlparse(url)
        self.path = url.path
        # --- {marker} ---
        # max_bytes=0 disables rotation, same "0 means unbounded" contract
        # as every other self-rotating writer in this repo (e.g.
        # multipot/main.go's newLogger).
        self.max_bytes = int(os.environ.get("DIONAEA_LOG_MAX_BYTES", "67108864"))
        try:
            self.fp = open(self.path, "a")
        except OSError as e:
            raise LoaderError("Unable to open file %s Error message '%s'", url.path, e.strerror)
        try:
            self.size = os.path.getsize(self.path)
        except OSError:
            self.size = 0

    def _rotate(self):
        # Close, rename aside with a timestamp suffix, reopen fresh at the
        # original path -- the same pattern multipot/main.go's logger.rotate()
        # and ip-enrichment-worker/rotate.go's outputWriter.rotate() already
        # use for exactly this reason (#120, #1389).
        try:
            self.fp.close()
        except OSError:
            pass
        import time
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        # A small max_bytes rotates more than once within the same
        # wall-clock second -- confirmed live while testing this. Without a
        # collision check the second os.rename() silently replaces the
        # first rotated file, losing everything in it.
        target = self.path + "." + stamp
        if os.path.exists(target):
            n = 2
            while os.path.exists(target + "." + str(n)):
                n += 1
            target = target + "." + str(n)
        try:
            os.rename(self.path, target)
        except OSError:
            pass
        self.fp = open(self.path, "a")
        self.size = 0
        # --- end {marker} ---

    def submit(self, data):
        if self.max_bytes > 0 and self.size >= self.max_bytes:
            self._rotate()
        data = json.dumps(data)
        line = data + "\\n"
        self.fp.write(line)
        self.fp.flush()
        self.size += len(line.encode("utf-8"))'''.format(marker=MARKER)

def apply_patch(target: Path) -> str:
    """Patch one target file in place; returns a one-line status message.

    Factored out of the module-level loop below so dionaea/tests/
    test_log_rotation_patch.py can exercise it directly against fixture
    copies instead of only against a live container's real files.
    """
    text = target.read_text()
    if MARKER in text:
        return f"log_rotation_patch: {target} already patched, skipping"
    if text.count(OLD_CLASS) != 1:
        raise SystemExit(f"log_rotation_patch: expected exactly one occurrence of FileHandler in {target}, refusing to patch blind")
    if text.count(OLD_IMPORT) != 1:
        raise SystemExit(f"log_rotation_patch: expected exactly one occurrence of the urlparse import in {target}, refusing to patch blind")
    text = text.replace(OLD_IMPORT, NEW_IMPORT, 1)
    text = text.replace(OLD_CLASS, NEW_CLASS, 1)
    target.write_text(text)
    return f"log_rotation_patch: added self-rotation to FileHandler in {target}"


if __name__ == "__main__":
    for target in TARGETS:
        print(apply_patch(target))
