#!/usr/bin/env python3
"""Build SNARE's content-addressed page store from the fictional persona."""
import hashlib
import json
from pathlib import Path

host = "portal.meridian.example"
source = Path("/tmp/persona/index.html")
destination = Path("/opt/persona-pages") / host
content = source.read_bytes()
digest = hashlib.md5(content).hexdigest()  # SNARE's on-disk format uses MD5 names.
destination.mkdir(parents=True, exist_ok=True)
(destination / digest).write_bytes(content)
response = {"hash": digest, "headers": [{"Content-Type": "text/html; charset=utf-8"}, {"Server": "nginx/1.22.1"}, {"X-Frame-Options": "SAMEORIGIN"}, {"Referrer-Policy": "strict-origin-when-cross-origin"}]}
(destination / "meta.json").write_text(json.dumps({"/": response, "/index.html": response, "/status_404": response}), encoding="utf-8")
