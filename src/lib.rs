//! ae-poc library — shared modules for the ae-poc and vm-manager binaries.
//!
//! This crate library exposes the internal modules so that the `vm-manager`
//! binary can reuse the `vm_manager` module without duplicating code.

pub mod certs;
pub mod proxy;
pub mod session;
pub mod stream;
pub mod vault;
pub mod vm_manager;
