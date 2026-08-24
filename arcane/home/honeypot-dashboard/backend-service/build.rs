// Stamp the binary with when it was compiled.
//
// Without this there is no way to tell which build is running, and the
// obvious substitute does not work: grepping the shipped binary for a string
// introduced by a recent change looks decisive and is not. The release
// profile merges and splits string literals, so a literal present in a debug
// build can be absent from a release build of the identical source --
// verified both ways while chasing #1836, where a perfectly good deploy was
// diagnosed as a stale one, twice, on the strength of a grep that could
// never have succeeded.
//
// A compile timestamp answers the question that actually gets asked after a
// deploy: is the running binary newer than the merge? Git metadata would say
// more, but the Docker build context is the crate directory alone and
// carries no .git, so it cannot be read where it would need to be.
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Re-run whenever the crate changes, so the stamp cannot go stale while
    // the code moves underneath it.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=APIARY_BUILD_EPOCH={epoch}");
}
