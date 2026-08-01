"""
Shared model-lifecycle helpers (#65): version retention and metadata,
used identically by IsoForestModel and LSTMAEModel so the "last N versions,
metadata sidecar per accepted version" contract is one implementation, not
two independently-maintained copies.

The acceptance gate itself (holdout evaluation, anomaly-rate comparison)
lives in each model class, not here -- what counts as a valid holdout split
and how to score it is model-specific; only what happens to a file on disk
after a version is accepted is shared.

See docs/ml-worker-plan.md §11 for the full design and the reasoning behind
each constant below.
"""
import glob
import json
import os
import re

MAX_RETAINED_VERSIONS = 3


def prune_old_versions(model_dir: str, prefix: str, keep: int = MAX_RETAINED_VERSIONS) -> None:
    """Delete every `{prefix}_{timestamp}.*` file in model_dir except the
    newest `keep` (by the timestamp embedded in the filename, not mtime --
    a restored/copied file's mtime is not trustworthy, the name ml-worker
    itself wrote is). Also deletes each pruned version's `.meta.json`
    sidecar, if present. Never touches whatever `current_{prefix}` points
    to elsewhere by construction: promotion always keeps the newest version,
    and the newest version is never the one pruned.
    """
    pattern = re.compile(re.escape(prefix) + r"_(\d+)\.")
    versions = {}
    for path in glob.glob(os.path.join(model_dir, f"{prefix}_*")):
        m = pattern.search(os.path.basename(path))
        if not m:
            continue
        versions.setdefault(int(m.group(1)), []).append(path)

    for ts in sorted(versions.keys(), reverse=True)[keep:]:
        for path in versions[ts]:
            try:
                os.remove(path)
            except OSError:
                pass


def write_version_metadata(model_dir: str, prefix: str, ts: int, meta: dict) -> None:
    """Write the evidence for one accepted version next to its model
    file(s) -- survives independent of Elasticsearch retention, so
    "why is this the active model" is answerable even if ml-worker-metrics
    has rolled over."""
    path = os.path.join(model_dir, f"{prefix}_{ts}.meta.json")
    try:
        with open(path, "w") as f:
            json.dump(meta, f, indent=2, default=str)
    except OSError:
        pass
