#!/usr/bin/env python3
"""Build-time patch adding self-rotation to sentrypeer's JSON writer (#2892).

Same close/rename/reopen contract as
arcane/home/honeypot-beelzebub/beelzebub/json_log_rotation_patch.py,
arcane/home/honeypot-conpot/conpot/json_log_rotation_patch.py and
arcane/home/honeypot-galah/galah/json_log_rotation_patch.py: rotate the live
file aside with a timestamp suffix once it exceeds a size threshold, then
reopen fresh at the original path, so log-maintenance.sh's pruner has
digit-suffixed generations to age out (#120).

Two JSON writers exist upstream, C (src/json_logger.c) and Rust
(sentrypeer_rust/src/json_logger.rs::json_log_bad_actor_rs), selected at
runtime by sentrypeer_config->new_mode. This Dockerfile installs
rust/cargo/rust-bindgen and never passes --disable-rust to ./configure, so
configure.ac auto-sets HAVE_RUST=1 -- confirmed directly against
src/conf.c, which sets self->new_mode = true under #if HAVE_RUST != 0
(confirmed too against tests/unit_tests/test_json_logger.c, which dispatches
on new_mode == true the same way). sentrypeer_rust/src/cli.rs's -N flag can
clear new_mode back to false, but this image's CMD never passes -N -- and it
would not matter if it did: under HAVE_RUST != 0, src/bad_actor.c compiles
the C writer's call site out entirely (#else), so json_log_bad_actor_rs() is
the only reachable JSON writer either way. src/bad_actor.c::bad_actor_log()
therefore always takes the json_log_bad_actor_rs() branch in this image; the
plain C writer is dead code here. Patching only the C file would leave the
actual unbounded-growth bug (#2892: 94MB and growing) completely unfixed, so
this patches the Rust writer instead -- the vendored source is still
C-family/compiled-at-build, same "must be C, not interpreted" shape the
task called for, just the half of it that this build actually executes.

sentrypeer_rust/Cargo.toml already depends on chrono (used elsewhere in the
crate, see lib.rs's `use chrono::Utc;`), so the timestamp suffix reuses that
instead of adding a dependency.
"""
import sys

PATH = "sentrypeer_rust/src/json_logger.rs"
MARKER = "// #2892 json_log_rotation_patch: added self-rotation"

OLD_IMPORTS = """use crate::cli;
use libc::c_char;
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};"""

NEW_IMPORTS = """use crate::cli;
use chrono::Utc;
use libc::c_char;
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;"""

OLD_FUNC = """#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn json_log_bad_actor_rs(
    sentrypeer_c_config: *const sentrypeer_config,
    bad_actor_event: *const bad_actor,
) -> i32 {
    let log_file_name = unsafe {
        CStr::from_ptr((*sentrypeer_c_config).json_log_file)
            .to_str()
            .unwrap()
    };

    let json = unsafe { bad_actor_to_json_rs(sentrypeer_c_config, bad_actor_event) };
    let json_str = unsafe { CStr::from_ptr(json).to_str().unwrap() };

    let json_log_file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file_name)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Could not open JSON log file: {e}");
            return libc::EXIT_FAILURE;
        }
    };

    let mut buf = BufWriter::new(json_log_file);
    let json_str = format!("{json_str}\\n");

    match buf.write_all(json_str.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to JSON log file: {e}");
            return libc::EXIT_FAILURE;
        }
    }

    libc::EXIT_SUCCESS
}"""

NEW_FUNC = """fn json_log_max_bytes() -> u64 {
    std::env::var("SENTRYPEER_JSON_LOG_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(67_108_864)
}

// #2892 json_log_rotation_patch: added self-rotation. Close/rename/reopen
// once json_log_max_bytes() is exceeded ("0" disables), same contract as
// the other sensors' writers (#120). json_log_bad_actor_rs() already opens
// a fresh handle per call, so "reopen" falls out of the existing
// OpenOptions::new().create(true) below once the live path is renamed
// aside -- no persistent handle to track across calls, unlike the Go/Python
// writers this pattern is modelled on.
fn rotate_json_log_if_needed(log_file_name: &str) {
    let max_bytes = json_log_max_bytes();
    if max_bytes == 0 {
        return;
    }

    let size = match std::fs::metadata(log_file_name) {
        Ok(meta) => meta.len(),
        Err(_) => return,
    };
    if size < max_bytes {
        return;
    }

    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    let mut rotated = format!("{log_file_name}.{stamp}");
    let mut generation = 2;
    while Path::new(&rotated).exists() {
        rotated = format!("{log_file_name}.{stamp}.{generation}");
        generation += 1;
    }

    if let Err(e) = std::fs::rename(log_file_name, &rotated) {
        eprintln!("Could not rotate JSON log file: {e}");
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn json_log_bad_actor_rs(
    sentrypeer_c_config: *const sentrypeer_config,
    bad_actor_event: *const bad_actor,
) -> i32 {
    let log_file_name = unsafe {
        CStr::from_ptr((*sentrypeer_c_config).json_log_file)
            .to_str()
            .unwrap()
    };

    let json = unsafe { bad_actor_to_json_rs(sentrypeer_c_config, bad_actor_event) };
    let json_str = unsafe { CStr::from_ptr(json).to_str().unwrap() };

    rotate_json_log_if_needed(log_file_name);

    let json_log_file = match OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file_name)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Could not open JSON log file: {e}");
            return libc::EXIT_FAILURE;
        }
    };

    let mut buf = BufWriter::new(json_log_file);
    let json_str = format!("{json_str}\\n");

    match buf.write_all(json_str.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to JSON log file: {e}");
            return libc::EXIT_FAILURE;
        }
    }

    libc::EXIT_SUCCESS
}"""


def apply_patch(path=PATH):
    with open(path) as f:
        text = f.read()

    if MARKER in text:
        return f"{path}: already patched, skipping"

    for old, name in ((OLD_IMPORTS, "imports"), (OLD_FUNC, "json_log_bad_actor_rs")):
        count = text.count(old)
        if count != 1:
            print(
                f"{path}: expected exactly 1 match for the {name} block, found {count}",
                file=sys.stderr,
            )
            sys.exit(1)

    text = text.replace(OLD_IMPORTS, NEW_IMPORTS).replace(OLD_FUNC, NEW_FUNC)

    with open(path, "w") as f:
        f.write(text)

    return f"{path}: patched (added self-rotation)"


if __name__ == "__main__":
    print(apply_patch())
