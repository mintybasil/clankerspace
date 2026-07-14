//! ae-proxy — MITM egress proxy for agent environments.
//!
//! Library crate exposing the proxy's internal modules for reuse by the
//! integration PoC and other consumers.

pub mod certs;
pub mod proxy;
pub mod session;
pub mod stream;
pub mod vault;
