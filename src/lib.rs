//#![deny(warnings)]

//! # Slauth
//!
//! Auth utils for MFA algorithms

/// Module for hotp algorithms
pub mod oath;

#[cfg(feature = "u2f")]
pub mod u2f;