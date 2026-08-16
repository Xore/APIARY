#!/usr/bin/env python3
"""Sync a honeyfs overlay into Cowrie's fake-filesystem index (fs.pickle).

Cowrie decides what `ls` shows from fs.pickle, and what `cat` returns from the
honeyfs directory. Dropping files into honeyfs alone is not enough — the path
must also exist in fs.pickle, with A_REALFILE pointing at the honeyfs file.

This script walks the honeyfs overlay and, for every directory and file, makes
sure a matching node exists in fs.pickle (creating parents as needed), fixes the
file size, and sets A_REALFILE so the real content is served. Existing nodes are
updated in place; nothing is deleted.

If fs.pickle does not exist yet (fresh clone, cowrie has never run), the script
bootstraps a minimal root node and writes a new pickle file.

Usage:  sync-fs.py <fs.pickle> <honeyfs-dir>
"""

import os
import pickle
import sys
import time

# fs.pickle node layout (from Cowrie src/cowrie/shell/fs.py)
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

CTIME = time.mktime((2024, 6, 30, 3, 12, 0, 0, 0, 0))


def owner_for(path):
    """Guess a plausible uid/gid from the path."""
    if path.startswith("/home/deploy") or path.startswith("/opt/nexusai-inference"):
        return 1000, 1000
    if path.startswith("/home/mwagner"):
        return 1001, 1001
    if path.startswith("/home/svc-backup"):
        return 1002, 1002
    return 0, 0


def mode_for(name, is_dir):
    if is_dir:
        return 0o40755
    if name in ("shadow",):
        return 0o100640
    if name in (".env", "authorized_keys", "id_rsa") or name.endswith(".key"):
        return 0o100600
    if name == ".bash_history":
        return 0o100600
    return 0o100644


def find_child(node, name):
    for child in node[A_CONTENTS]:
        if child[A_NAME] == name:
            return child
    return None


def ensure(root, path, is_dir, size, realfile):
    """Ensure a node exists at `path`; return it."""
    parts = [p for p in path.split("/") if p]
    node = root
    acc = ""
    for i, name in enumerate(parts):
        acc += "/" + name
        last = i == len(parts) - 1
        child = find_child(node, name)
        make_dir = is_dir or not last
        if child is None:
            uid, gid = owner_for(acc)
            child = [
                name,
                T_DIR if make_dir else T_FILE,
                uid,
                gid,
                4096 if make_dir else size,
                mode_for(name, make_dir),
                CTIME,
                [] if make_dir else None,
                None,
                None if make_dir else realfile,
            ]
            node[A_CONTENTS].append(child)
        elif last and not is_dir:
            child[A_TYPE] = T_FILE
            child[A_SIZE] = size
            child[A_REALFILE] = realfile
            if child[A_CONTENTS] is None:
                child[A_CONTENTS] = None
        node = child
    return node


def bootstrap_root():
    """Return a minimal fs.pickle root node (cowrie root directory)."""
    return [
        "/",       # A_NAME
        T_DIR,     # A_TYPE
        0,         # A_UID
        0,         # A_GID
        4096,      # A_SIZE
        0o40755,   # A_MODE
        CTIME,     # A_CTIME
        [],        # A_CONTENTS
        None,      # A_TARGET
        None,      # A_REALFILE
    ]


def seed_cpu_frequency(honeyfs):
    """Create a coherent 128-thread EPYC cpufreq tree before indexing honeyfs."""
    for cpu in range(128):
        base = os.path.join(honeyfs, "sys", "devices", "system", "cpu", f"cpu{cpu}", "cpufreq")
        os.makedirs(base, exist_ok=True)
        values = {
            "scaling_cur_freq": str(2245000 + (cpu % 16) * 12500),
            "cpuinfo_cur_freq": str(2245000 + (cpu % 16) * 12500),
            "scaling_min_freq": "1500000",
            "scaling_max_freq": "2250000",
            "cpuinfo_min_freq": "1500000",
            "cpuinfo_max_freq": "2250000",
            "scaling_governor": "schedutil",
            "scaling_available_governors": "conservative ondemand userspace powersave performance schedutil",
        }
        for name, value in values.items():
            with open(os.path.join(base, name), "w", encoding="ascii") as fh:
                fh.write(value + "\n")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: sync-fs.py <fs.pickle> <honeyfs-dir>")
    fs_path, honeyfs = sys.argv[1], os.path.abspath(sys.argv[2])
    seed_cpu_frequency(honeyfs)

    # Load existing pickle or bootstrap a fresh root if the file doesn't exist yet.
    if os.path.exists(fs_path):
        with open(fs_path, "rb") as fh:
            root = pickle.load(fh)
        if root[A_CONTENTS] is None:
            root[A_CONTENTS] = []
        # Back up the original once.
        backup = fs_path + ".orig"
        if not os.path.exists(backup):
            with open(backup, "wb") as fh:
                pickle.dump(root, fh)
    else:
        print(f"sync-fs: {fs_path} not found — bootstrapping a new root node")
        os.makedirs(os.path.dirname(fs_path), exist_ok=True)
        root = bootstrap_root()

    added = 0
    for dirpath, dirnames, filenames in os.walk(honeyfs):
        rel = "/" + os.path.relpath(dirpath, honeyfs).replace(os.sep, "/")
        if rel == "/.":
            rel = "/"
        for d in sorted(dirnames):
            ensure(root, (rel.rstrip("/") + "/" + d), True, 4096, None)
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            vpath = (rel.rstrip("/") + "/" + f)
            realfile = os.path.join(honeyfs, os.path.relpath(full, honeyfs))
            ensure(root, vpath, False, os.path.getsize(full), realfile)
            added += 1

    with open(fs_path, "wb") as fh:
        pickle.dump(root, fh)
    print(f"sync-fs: merged {added} honeyfs files into {fs_path}")


if __name__ == "__main__":
    main()
