#!/usr/bin/env python3
"""Fix dionaea's FTP handler never reporting a completed STOR upload (#621).

ftp.py's ftp_STOR() accepts file uploads and writes them to disk via
self.dtp.recv_file(file), but the completion path in FTPDataCon's
handle_disconnect() -- the only place a 'recv_file'-mode transfer is ever
recognized as finished, since handle_io_in() just appends bytes with no
end-of-transfer detection of its own -- only closes the file and replies
txfr_complete_ok. No incident is fired at all: no dionaea.download.offer,
no dionaea.download.complete, no hash. Compare to tftp.py's own download
completion, which fires exactly one dionaea.download.complete incident
(url/path/con) and lets store.py's storehandler take it from there (MD5
hash, dedup via hardlink into download.dir, the .hash/.unique/.again
follow-up incidents) -- FTP uploads got none of that.

Practical effect: an attacker uploading a malware sample to the FTP
honeypot (classic anonymous-FTP dropbox scenario) was captured on disk but
produced zero telemetry -- no JSON log line, no ES document, no dashboard
payload-inventory entry, no hash for cross-referencing against
sandbox/Ghidra/GitHub-analysis indices.

This patch adds the same dionaea.download.complete incident TFTP already
fires, in the same place (right after the file is closed, before the
existing txfr_complete_ok reply) -- giving FTP uploads the same hash and
tracking treatment SMB/TFTP downloads already get, through the exact same
storehandler path, no new ihandler needed.
"""
from pathlib import Path

MARKER = "honeypot-stack: FTP STOR download.complete patch (#621)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/ftp.py")

OLD = """            if self.mode == 'recv_file' and self.file:
                self.file.close()
                self.ctrl.reply("txfr_complete_ok")"""

NEW = """            if self.mode == 'recv_file' and self.file:
                self.file.close()
                # --- {marker} ---
                # See #621: SMB/TFTP downloads both fire
                # dionaea.download.complete here and let store.py's
                # storehandler do the hashing/dedup; FTP uploads never
                # did, so a STOR'd sample was captured on disk with zero
                # telemetry -- no hash, no ES document, no way to
                # cross-reference it against sandbox/Ghidra/GitHub-analysis.
                icd = incident("dionaea.download.complete")
                icd.url = "ftp://%s/%s" % (self.ctrl.remote.host, os.path.basename(self.file.name))
                icd.path = self.file.name
                icd.con = self.ctrl
                icd.report()
                # --- end {marker} ---
                self.ctrl.reply("txfr_complete_ok")""".format(marker=MARKER)

text = TARGET.read_text()
if MARKER in text:
    print(f"ftp_patch: {TARGET} already patched, skipping")
else:
    if text.count(OLD) != 1:
        raise SystemExit("ftp_patch: expected exactly one occurrence of the recv_file disconnect handler, refusing to patch blind")
    text = text.replace(OLD, NEW, 1)
    TARGET.write_text(text)
    print(f"ftp_patch: added dionaea.download.complete incident for STOR uploads in {TARGET}")
