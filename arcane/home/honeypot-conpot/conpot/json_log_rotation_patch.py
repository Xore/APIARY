#!/usr/bin/env python3
"""Give conpot's JsonLogger self-rotation (#2892).

conpot.json is written by conpot/core/loggers/json_log.py's JsonLogger,
which `open(filename, "a")`s once at construction and keeps writing to that
one file descriptor forever -- confirmed live against the vendored source
at /usr/lib/python3.12/site-packages/conpot/core/loggers/json_log.py in the
pinned dtagdevsec/conpot:24.04.1 image, same shape as the FileHandler gap
dionaea/log_rotation_patch.py (#1389) closed. Only conpot.log rotates
today (log-maintenance.sh's own copytruncate loop); conpot.json has neither
half of the #120 contract. All six conpot personas (conpot, conpot-s7-1200,
conpot-s7-1500, conpot-iec104, conpot-guardian, conpot-kamstrup) share this
one vendored source tree, so one patch covers all six ledger rows.

Same shape as dionaea/log_rotation_patch.py and mailoney/json_log_patch.py:
exact-match string replacement with a marker for idempotency, applied at
Docker build time, close/rename/reopen at CONPOT_JSON_LOG_MAX_BYTES (0
disables, matching the "0 means unbounded" contract every other
self-rotating writer in this repo uses).
"""
from pathlib import Path

MARKER = "honeypot-stack: JsonLogger self-rotation patch (#2892)"
TARGET = Path("/usr/lib/python3.12/site-packages/conpot/core/loggers/json_log.py")

OLD_IMPORT = """import json
from .helpers import json_default"""
NEW_IMPORT = """import json
import os  # --- {marker} ---
from .helpers import json_default""".format(marker=MARKER)

OLD_CLASS = '''class JsonLogger(object):
    def __init__(self, filename, sensorid, public_ip):
        self.fileHandle = open(filename, "a")
        self.sensorid = sensorid
        self.public_ip = public_ip

    def log(self, event):
        if self.public_ip is not None:
            dst_ip = self.public_ip
        else:
            dst_ip = None
        data = {
            "timestamp": event["timestamp"].isoformat(),
            "sensorid": self.sensorid,
            "id": event["id"],
            "src_ip": event["remote"][0],
            "src_port": event["remote"][1],
            "dst_ip": event["local"][0],
            "dst_port": event["local"][1],
            "public_ip": dst_ip,
            "data_type": event["data_type"],
            "request": event["data"].get("request"),
            "response": event["data"].get("response"),
            "event_type": event["data"].get("type"),
        }

        json.dump(data, self.fileHandle, default=json_default)
        self.fileHandle.write("\\n")
        self.fileHandle.flush()'''

NEW_CLASS = '''class JsonLogger(object):
    def __init__(self, filename, sensorid, public_ip):
        # --- __MARKER__ ---
        self.path = filename
        self.max_bytes = int(os.environ.get("CONPOT_JSON_LOG_MAX_BYTES", "67108864"))
        self.fileHandle = open(filename, "a")
        try:
            self.size = os.path.getsize(filename)
        except OSError:
            self.size = 0
        self.sensorid = sensorid
        self.public_ip = public_ip

    def _rotate(self):
        # Close, rename aside with a timestamp suffix, reopen fresh at the
        # original path -- the same pattern dionaea/log_rotation_patch.py
        # and mailoney/json_log_patch.py already use (#1389, #2196).
        try:
            self.fileHandle.close()
        except OSError:
            pass
        import time
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
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
        self.fileHandle = open(self.path, "a")
        self.size = 0
        # --- end __MARKER__ ---

    def log(self, event):
        if self.public_ip is not None:
            dst_ip = self.public_ip
        else:
            dst_ip = None
        data = {
            "timestamp": event["timestamp"].isoformat(),
            "sensorid": self.sensorid,
            "id": event["id"],
            "src_ip": event["remote"][0],
            "src_port": event["remote"][1],
            "dst_ip": event["local"][0],
            "dst_port": event["local"][1],
            "public_ip": dst_ip,
            "data_type": event["data_type"],
            "request": event["data"].get("request"),
            "response": event["data"].get("response"),
            "event_type": event["data"].get("type"),
        }

        if self.max_bytes > 0 and self.size >= self.max_bytes:
            self._rotate()
        line = json.dumps(data, default=json_default)
        self.fileHandle.write(line)
        self.fileHandle.write("\\n")
        self.fileHandle.flush()
        self.size += len(line.encode("utf-8")) + 1'''.replace("__MARKER__", MARKER)


def apply_patch(target: Path) -> str:
    """Patch the target file in place; returns a one-line status message.

    Factored out of the module-level call below so
    tests/test_json_log_rotation_patch.py can exercise it directly against
    a fixture copy instead of only against a live container's real file.
    """
    text = target.read_text()
    if MARKER in text:
        return f"json_log_rotation_patch: {target} already patched, skipping"
    if text.count(OLD_CLASS) != 1:
        raise SystemExit(f"json_log_rotation_patch: expected exactly one occurrence of JsonLogger in {target}, refusing to patch blind")
    if text.count(OLD_IMPORT) != 1:
        raise SystemExit(f"json_log_rotation_patch: expected exactly one occurrence of the json_default import in {target}, refusing to patch blind")
    text = text.replace(OLD_IMPORT, NEW_IMPORT, 1)
    text = text.replace(OLD_CLASS, NEW_CLASS, 1)
    target.write_text(text)
    return f"json_log_rotation_patch: added self-rotation to JsonLogger in {target}"


if __name__ == "__main__":
    print(apply_patch(TARGET))
