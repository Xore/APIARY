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
// carries no .git, so it cannot be read where it would need to be -- it has
// to be handed in as a build arg (GIT_SHA) instead, which is what #3315 added
// once a timestamp stopped being enough to answer "which code is this?".
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Re-run whenever the crate changes, so the stamp cannot go stale while
    // the code moves underneath it.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    // ...and whenever GIT_SHA changes, which is the case this did not cover
    // before #3315. cargo caches a build script's output by its inputs, and an
    // environment variable is not one of them unless it is declared here: a
    // rebuild of an identical tree with a different GIT_SHA would otherwise
    // reuse the previous revision's compiled-in value and report itself as
    // that revision. That is the "green, healthy, running the old code" shape
    // this stamp exists to end, reproduced by the stamp itself.
    println!("cargo:rerun-if-env-changed=GIT_SHA");

    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=APIARY_BUILD_EPOCH={epoch}");

    // Only the first whitespace-delimited token survives, and only because the
    // cargo directive protocol is newline-separated: a GIT_SHA carrying a
    // newline would otherwise inject arbitrary directives (extra
    // rustc-envs, a rerun-if-changed pointing anywhere) into this build.
    // Whether what came out is a plausible object name is decided by
    // main.rs's normalize_revision, which is a plain function and therefore
    // unit-testable; this is only the transport.
    let sha = std::env::var("GIT_SHA")
        .ok()
        .and_then(|value| value.split_whitespace().next().map(str::to_string))
        .unwrap_or_default();
    println!("cargo:rustc-env=APIARY_GIT_SHA={sha}");
}
