//! The library half of the crate.
//!
//! The binary (`src/main.rs`) is the service: 80-odd handler modules, the
//! router, and the #2183 boot gate. None of that needs to be a library,
//! and making it one would be a large refactor with no payoff.
//!
//! What *does* need to be reachable from a second target is
//! [`openapi`] -- the machine-readable /api contract (#3325) and the
//! drift tests that keep it honest. Those run from `cargo test` and from
//! the `openapi` generator binary (`src/bin/openapi.rs`), which is why
//! the module lives here rather than in `main.rs`: a second binary cannot
//! see a first binary's modules.

pub mod openapi;
