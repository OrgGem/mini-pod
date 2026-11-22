#![forbid(unsafe_code)]
//! Layer 4 daemon library interface exposing composition root modules (`config`, `mcp`, `server`).

pub mod config;
mod doctor;
pub mod mcp;
pub mod server;
mod spawn_registry;
