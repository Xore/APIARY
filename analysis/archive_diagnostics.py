#!/usr/bin/env python3
"""Archive old sandbox diagnostics.zip files into the row-aware chunk
store (#528), reclaiming disk space for procmon.csv specifically -- the
one artifact record-aware chunking demonstrably helps with (~90%
recovery across unrelated runs on the same golden image, vs <1% from
generic byte-CDC; see analysis/tests/test_cdc_dedup_prototype.py and
analysis/procmon_cdc_store.py's own module docstring for the research
this builds on).

## Scope: cold storage only, never the live-served path

export_result.py's write_diagnostics_bundle() produces {job}.diagnostics.zip
in the results directory, and dashboard/sandbox.go serves that file
straight from disk via http.ServeContent -- no Python (or any) hook in
that path. This module is deliberately NOT wired into either of those:
archive_one() only ever operates on zips this script is explicitly
pointed at (typically gated by mtime age, see find_archivable()), the
same "cold data only" posture dedupe-payloads.py's own bistreams
retention-pruning already uses.

Archiving a zip makes it no longer a complete, directly-openable file:
procmon.csv inside it is replaced with a small JSON stub
(procmon.csv.dedup-manifest-ref) pointing at the chunk store instead of
containing real bytes. This is a real, disclosed trade-off: an archived
zip downloaded from the dashboard would be missing procmon.csv until
rehydrated. It's only meant to apply to zips already past an archival
age threshold that operationally are not the ones actively pulled from
the dashboard's hot path -- run archive_one()/main() against fresh zips
at your own risk, this module does not defend against that itself.

rehydrate_one() reverses archive_one() exactly, verified by SHA-256
against the value recorded at archive time -- for whenever an operator
or tool needs the real procmon.csv content back for an archived run.
Its failures reach the operator the same way archive failures do (#1988):
a JSON {"path", "error"} line and a non-zero exit instead of a traceback.
A truncated stub, a stub missing its keys, or a manifest no longer in
the store is an expected maintenance-time condition, and machine-
parseable output is what keeps the maintenance log greppable.

main()'s archive summary distinguishes what actually happened per zip
(#1988): zips_processed counts archives written, zips_skipped the
no-ops (already archived / no member / empty) -- counting skips as work
used to make every cycle's log overstate its own progress.

## Verify-before-destroy discipline

archive_one() reconstructs from the chunk store and compares against the
original bytes before touching the zip at all, matching
dedupe-payloads.py's own inode-check-before-hardlink discipline: a
destructive step never runs on an unverified assumption. The same
discipline covers its own bookkeeping (#1987): any failure between
store_bytes() and the final atomic replace releases the manifest it just
committed (abandoned manifests hold chunk refcounts up permanently), and
the rewrite re-checks that its second read of the zip still matches the
members verification saw -- a file changed in between must abort, never
promote a half-old half-new archive.
"""

import argparse
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from procmon_cdc_store import RowChunkStore  # noqa: E402

STUB_SUFFIX = ".dedup-manifest-ref"
TARGET_MEMBER = "procmon.csv"


def _stub_name(member: str) -> str:
    return member + STUB_SUFFIX


def archive_one(zip_path: Path, store: RowChunkStore) -> dict:
    """Replace `procmon.csv` inside zip_path with a small manifest-ref
    stub, after storing its content in `store` and verifying the
    reconstruction is byte-exact. Raises rather than touching the zip if
    verification fails or if a required precondition isn't met."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        # Check "already archived" first: once archived, procmon.csv is
        # itself gone (replaced by the stub), so checking for its absence
        # before checking for the stub's presence would misreport every
        # already-archived zip as "no procmon.csv member" instead.
        if _stub_name(TARGET_MEMBER) in names:
            return {"path": str(zip_path), "skipped": "already archived"}
        if TARGET_MEMBER not in names:
            return {"path": str(zip_path), "skipped": "no procmon.csv member"}
        original = zf.read(TARGET_MEMBER)
        # Per-member fingerprint of the verified view (#1987): the
        # rewrite pass below re-reads the zip through a second open, and
        # its copied members must be these exact bytes.
        first_view = {i.filename: (i.file_size, i.CRC) for i in zf.infolist()}

    if not original:
        return {"path": str(zip_path), "skipped": "procmon.csv empty"}

    manifest_id = store.store_bytes(original)

    # From here until tmp_path.replace() succeeds, every failure must
    # release what store_bytes() just committed (#1987): an abandoned
    # manifest holds every chunk's refcount up permanently --
    # compact_pack() only reclaims refcount<=0 chunks -- so stats()
    # would report leaked capacity as live forever.
    tmp_path = zip_path.with_name(zip_path.name + ".archiving.tmp")
    replaced = False
    try:
        reconstructed = store.reconstruct(manifest_id)
        if reconstructed != original:
            # Should be unreachable if store_bytes()/reconstruct() are
            # correct, but this is exactly the class of bug that must
            # never reach a destructive step unverified -- the finally
            # below releases what was just stored rather than leaving a
            # manifest nothing points to.
            raise RuntimeError(
                f"{zip_path}: chunk-store round-trip did not match the original "
                f"procmon.csv bytes -- refusing to touch the zip"
            )

        stub = json.dumps({
            "manifest_id": manifest_id,
            "original_size": len(original),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "archived_at": datetime.now(timezone.utc).isoformat(),
        }).encode()

        with zipfile.ZipFile(zip_path, "r") as src, \
                zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as dst:
            # This is a second, separate read of the zip; the verified
            # bytes came from the first one (#1987). If the file changed
            # between the two opens, copying from here would promote a
            # mixture -- surviving members from the new version while the
            # stub pins old procmon.csv bytes in the store, losing the
            # new content outright. Refuse instead; cold-only posture or
            # not, concurrent modification is exactly what round-trip
            # verification claims to defend against.
            if src.namelist() != names:
                raise RuntimeError(
                    f"{zip_path}: zip changed between the verification read "
                    f"and the rewrite read -- refusing to archive a mixture"
                )
            for info in src.infolist():
                if info.filename == TARGET_MEMBER:
                    # Replaced by the stub below, never copied.
                    continue
                if (info.file_size, info.CRC) != first_view[info.filename]:
                    raise RuntimeError(
                        f"{zip_path}: member {info.filename} changed between "
                        f"the verification read and the rewrite read -- "
                        f"refusing to archive a mixture"
                    )
                dst.writestr(info, src.read(info.filename))
            dst.writestr(_stub_name(TARGET_MEMBER), stub)

        before_size = zip_path.stat().st_size
        tmp_path.replace(zip_path)
        replaced = True
    finally:
        if not replaced:
            store.release_manifest(manifest_id)
            tmp_path.unlink(missing_ok=True)
    after_size = zip_path.stat().st_size

    return {
        "path": str(zip_path),
        "manifest_id": manifest_id,
        "bytes_before": before_size,
        "bytes_after": after_size,
        "bytes_reclaimed": before_size - after_size,
    }


def rehydrate_one(zip_path: Path, store: RowChunkStore) -> dict:
    """Reverse archive_one(): read the stub, reconstruct procmon.csv from
    the chunk store, verify it against the hash recorded at archive time,
    and rewrite the zip with real bytes back in place of the stub."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        if _stub_name(TARGET_MEMBER) not in names:
            return {"path": str(zip_path), "skipped": "not archived"}
        stub = json.loads(zf.read(_stub_name(TARGET_MEMBER)))

    data = store.reconstruct(stub["manifest_id"])
    if hashlib.sha256(data).hexdigest() != stub["original_sha256"]:
        raise RuntimeError(
            f"{zip_path}: reconstructed procmon.csv does not match the "
            f"hash recorded at archive time -- chunk store may be "
            f"corrupt, refusing to write a silently-wrong file"
        )

    tmp_path = zip_path.with_name(zip_path.name + ".rehydrating.tmp")
    with zipfile.ZipFile(zip_path, "r") as src, \
            zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            if info.filename == _stub_name(TARGET_MEMBER):
                continue
            dst.writestr(info, src.read(info.filename))
        dst.writestr(TARGET_MEMBER, data)
    tmp_path.replace(zip_path)
    return {"path": str(zip_path), "rehydrated_bytes": len(data)}


def find_archivable(results_dir: Path, after_days: int, now=None):
    """Yield *.diagnostics.zip files under results_dir older than
    after_days, by mtime -- same directory-scan-plus-age-cutoff shape as
    dedupe-payloads.py's own prune_old_directories(), except gating on a
    file's mtime rather than a directory name parsed as a date (sandbox
    results aren't named by date the way Dionaea's bistreams/ are)."""
    if not results_dir.exists():
        return
    now = now or datetime.now(timezone.utc)
    cutoff = now.timestamp() - after_days * 86400
    for path in sorted(results_dir.glob("*.diagnostics.zip")):
        try:
            if path.stat().st_mtime < cutoff:
                yield path
        except OSError:
            continue


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["archive", "rehydrate", "status"])
    ap.add_argument(
        "--results-dir", type=Path,
        default=Path(os.environ.get("SANDBOX_RESULTS_DIR", "/results")),
    )
    ap.add_argument(
        "--store-dir", type=Path,
        default=Path(os.environ.get("CDC_STORE_DIR", "/state/procmon-cdc-store")),
    )
    ap.add_argument(
        "--after-days", type=int,
        default=int(os.environ.get(
            "RESULTS_ARCHIVE_AFTER_DAYS", os.environ.get("HONEYPOT_RETENTION_DAYS", "30")
        )),
    )
    ap.add_argument("--zip", type=Path, help="operate on exactly this zip (rehydrate)")
    args = ap.parse_args()

    with RowChunkStore(args.store_dir) as store:
        if args.command == "archive":
            total_reclaimed = 0
            archived = 0
            skipped = 0
            errored = 0
            for zip_path in find_archivable(args.results_dir, args.after_days):
                try:
                    result = archive_one(zip_path, store)
                except Exception as exc:
                    print(json.dumps({"path": str(zip_path), "error": str(exc)}))
                    errored += 1
                    continue
                print(json.dumps(result))
                total_reclaimed += result.get("bytes_reclaimed", 0)
                # #1988: skips are no-ops, not work done -- counting them
                # in zips_processed made every cycle's log overstate its
                # own progress.
                if "skipped" in result:
                    skipped += 1
                else:
                    archived += 1
            compacted = store.compact_all()
            print(json.dumps({
                "summary": True,
                "zips_processed": archived,
                "zips_skipped": skipped,
                "zips_errored": errored,
                "bytes_reclaimed": total_reclaimed,
                "packs_compacted": len(compacted),
            }))
        elif args.command == "rehydrate":
            if not args.zip:
                ap.error("--zip is required for rehydrate")
            try:
                print(json.dumps(rehydrate_one(args.zip, store)))
            except Exception as exc:
                # Same structured shape as archive's error lines (#1988):
                # a truncated stub (json.loads), a stub missing keys
                # (KeyError), or a manifest absent from the store all dump
                # a traceback today. The exit must be non-zero so a
                # calling script notices; the JSON line keeps the output
                # parseable like every other path through this command.
                print(json.dumps({"path": str(args.zip), "error": str(exc)}))
                return 1
        elif args.command == "status":
            print(json.dumps(store.stats(), indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
