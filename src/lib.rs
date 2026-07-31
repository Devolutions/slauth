#![deny(warnings)]

//! # Slauth
//!
//! Auth utils for MFA algorithms

extern crate core;

/// Module for hotp algorithms
pub mod oath;

#[cfg(feature = "u2f")]
pub mod u2f;

#[cfg(feature = "webauthn")]
pub mod webauthn;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub mod base64;

#[cfg(feature = "native-bindings")]
pub mod strings {
    use std::{
        ffi::{CStr, CString},
        os::raw::c_char,
    };

    /// # Safety
    /// Needed to cast string in FFY context
    pub unsafe fn c_char_to_string_checked(cchar: *const c_char) -> Option<String> {
        let c_str = CStr::from_ptr(cchar);
        match c_str.to_str() {
            Ok(string) => Some(string.to_string()),
            Err(_) => None,
        }
    }

    /// # Safety
    /// Needed to cast string in FFY context
    pub unsafe fn c_char_to_string(cchar: *const c_char) -> String {
        let c_str = CStr::from_ptr(cchar);
        let r_str = c_str.to_str().unwrap_or("");
        r_str.to_string()
    }

    pub fn string_to_c_char(r_string: String) -> *mut c_char {
        CString::new(r_string)
            .expect("Converting a string into a c_char should not fail")
            .into_raw()
    }

    /// Reclaims any `char*` returned by this crate's native bindings. They all originate from
    /// `CString::into_raw`, so the caller's `free` is a different allocator and must not be used. The
    /// buffer is wiped first because some of these strings carry private key material.
    ///
    /// # Safety
    /// The pointer must have been produced by this crate and must not be used afterwards.
    #[no_mangle]
    pub unsafe extern "C" fn slauth_string_free(s: *mut c_char) {
        if s.is_null() {
            return;
        }

        let mut bytes = CString::from_raw(s).into_bytes_with_nul();
        for byte in bytes.iter_mut() {
            std::ptr::write_volatile(byte, 0);
        }

        // Keep the wipe from being optimized away now that the buffer is about to be released.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// # Safety
    /// Needed to cast string in FFY context
    pub unsafe fn mut_c_char_to_string(cchar: *mut c_char) -> String {
        let c_string = if cchar.is_null() {
            CString::from_vec_unchecked(vec![])
        } else {
            CString::from_raw(cchar)
        };
        let c_str = c_string.as_c_str();
        let r_str = c_str.to_str().unwrap_or_default();
        r_str.to_string()
    }
}
