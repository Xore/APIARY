//! Prints the /api contract to stdout, so the committed copy is a build
//! artifact rather than something edited by hand:
//!
//! ```text
//! cargo run --bin openapi > openapi.json
//! ```
//!
//! #3325's drift tests (`src/openapi.rs`) fail when `openapi.json` and
//! this output disagree, and `quality.yml` runs the same command as a
//! `diff`, so the file cannot fall behind the router. The write is
//! deliberately *not* done here -- a generator that rewrites its own
//! tracked file in passing is one `cargo run` away from silently
//! accepting a contract nobody reviewed.

fn main() {
    let document = apiary_backend::openapi::document();
    match serde_json::to_string_pretty(&document) {
        Ok(rendered) => println!("{rendered}"),
        // A `serde_json::Value` this module built in-process always
        // serializes; failing here would mean the module is broken, and
        // a panic says that louder than an io error would.
        Err(error) => panic!("the contract did not serialize: {error}"),
    }
}
