use std::io::Read;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

pub mod error;
pub mod proto;
pub mod client;

#[cfg(feature = "u2f-server")]
pub mod server;