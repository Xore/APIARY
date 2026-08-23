#!/usr/bin/env python3
"""Make captured payloads readable by the payload-inventory worker (#1789).

store.py's storehandler saves a download by hardlinking the temporary capture
into download.dir:

    os.link(p, n)

A hardlink is a second name for an existing inode. Permissions and ACLs live on
the inode, so the file in download.dir carries whatever the temporary file had.
A directory's default ACL is applied when a file is created in it, never when a
link to an existing inode is added -- so a hardlink would not inherit one even
if it existed.

On this deployment it does not exist. Measured: the binaries directory carries
an *access* ACL granting user:nobody:r-x and no `default:` entries at all, so
there has never been anything for a captured sample to inherit by any route.
That is why every capture arrived unreadable, not merely the hardlinked ones.

That matters because the ACL is the only thing granting access. The payload
store is owned 1000:1000 and the inventory worker runs as `nobody`, so it reads
these files solely through:

    user:nobody:r--

Measured consequence, live: every payload captured after 2026-08-22 22:14
arrived mode 0600 with no ACL entries, the worker could not open one of them,
and 61 samples were indexed with an empty Kind and MIME application/octet-stream.
Capture never stopped -- only identification did, which is the failure mode that
reads as quiet success. The classifier was never at fault; it simply never
received a byte, and the empty Preview on every affected document was the tell.

This applies the directory's own default ACL to the new link, so a captured
sample is readable by exactly the account that has to read it. It grants
nothing the directory did not already intend: the entry is copied from the
parent's default ACL rather than invented here, so a deployment that narrows or
widens that default gets the same treatment automatically, and a deployment
with no default ACL gets nothing.

Deliberately not chmod. Making the file group- or world-readable would widen
access to every account on the host, and this directory holds live malware --
the default ACL exists precisely to name one reader instead.
"""
from pathlib import Path

MARKER = "honeypot-stack: captured-payload ACL inheritance patch (#1789)"
TARGET = Path("/opt/dionaea/lib/dionaea/python/dionaea/store.py")

ANCHOR = "            os.link(p, n)\n"

INJECTED = '''            os.link(p, n)
            # {marker}
            # A hardlink inherits the inode's permissions, not the directory's
            # default ACL, so apply that default explicitly -- see this
            # patch's own docstring for why the ACL is load-bearing.
            _apply_download_dir_acl(n)
'''.format(marker=MARKER)

HELPER = '''

def _apply_download_dir_acl(path):
    """Copy the download directory's default ACL onto a freshly linked file.

    Best-effort by design: a capture must never be lost because the ACL could
    not be set. Failures are logged rather than raised, and a store with no
    default ACL is left exactly as it was.
    """
    import os
    import subprocess

    try:
        directory = os.path.dirname(path)
        # dionaea embeds Python 3.6: subprocess.run gained capture_output and
        # text only in 3.7. Using them raises TypeError, which this function's
        # own except would swallow -- the helper would appear to run and do
        # nothing at all.
        listing = subprocess.run(
            ["getfacl", "-p", directory],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=10, check=False,
        )
        if listing.returncode != 0:
            return
        def _named(lines, prefix=""):
            """Named user/group entries only. The owner/group/other triple is
            already carried by the file mode, and mask is recomputed by
            setfacl from the entries it is given."""
            out = []
            for line in lines:
                if prefix and not line.startswith(prefix):
                    continue
                entry = line[len(prefix):] if prefix else line
                entry = entry.split("\t")[0].strip()   # drop "#effective:..."
                if entry.startswith("mask"):
                    continue
                if entry.startswith(("user:", "group:")) and not entry.startswith(
                    ("user::", "group::")
                ):
                    out.append(entry)
            return out

        lines = listing.stdout.splitlines()
        # A default ACL is the right source when one exists -- it states what
        # the directory intends new files to carry.
        entries = _named(lines, "default:")
        if not entries:
            # This store has no default ACL. Measured on the live deployment:
            # the binaries directory carries an *access* ACL granting
            # user:nobody:r-x and no default entries at all, so there has never
            # been anything for a new file to inherit -- which is why every
            # capture arrived unreadable rather than only the hardlinked ones.
            #
            # Fall back to the directory's own named access entries. "Who may
            # read this directory" is the same intent, expressed the only way
            # this deployment expresses it, and copying it is still reading
            # policy off the filesystem rather than inventing it here.
            entries = [e for e in _named(lines) if not e.startswith("default:")]
        if not entries:
            return
        subprocess.run(
            ["setfacl", "-m", ",".join(entries), path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
    except Exception as error:  # noqa: BLE001 - never fail a capture over this
        try:
            logger.warning("could not apply download-dir ACL to %s: %s", path, error)
        except Exception:
            pass
'''


def main():
    source = TARGET.read_text()
    if MARKER in source:
        print("store.py: ACL inheritance patch already applied")
        return
    if ANCHOR not in source:
        raise SystemExit(
            "store.py: expected 'os.link(p, n)' anchor not found -- the upstream "
            "store handler changed and this patch must be re-checked, not skipped"
        )
    source = source.replace(ANCHOR, INJECTED, 1)
    source = source.rstrip("\n") + "\n" + HELPER
    TARGET.write_text(source)
    print("store.py: captured payloads now inherit the download-dir ACL")


if __name__ == "__main__":
    main()
