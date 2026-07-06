//! clipveil — secret detection library.
//!
//! The binary (`src/main.rs`) is a thin CLI/agent wrapper around this. Keeping
//! detection in a library is what lets `tests/` exercise it directly.

pub mod agent_plan;
pub mod config;
pub mod detect;
