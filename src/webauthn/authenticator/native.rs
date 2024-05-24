#[cfg(target_os = "ios")]
mod ios {
    use crate::{
        strings,
        webauthn::{
            authenticator::WebauthnAuthenticator,
            proto::raw_message::{CoseAlgorithmIdentifier, Message},
        },
    };
    use std::{
        ffi::{c_int, c_uchar, CString},
        os::raw::c_char,
        ptr::null_mut,
    };
    use uuid::Uuid;

    pub struct AuthenticatorResponse {
        pub private_key_response: String,
        pub attestation_object: Vec<u8>,
    }

    #[repr(C)]
    pub struct Buffer {
        data: *mut u8,
        len: usize,
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_private_key_from_response(res: *mut AuthenticatorResponse) -> *mut c_char {
        if res.is_null() {
            return null_mut();
        }

        let cstring = CString::new((*res).private_key_response.clone());
        match cstring {
            Ok(cstring) => cstring.into_raw(),
            Err(_) => null_mut(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_attestation_object_from_response(res: *mut AuthenticatorResponse) -> Buffer {
        if res.is_null() {
            return Buffer { data: null_mut(), len: 0 };
        }

        Buffer {
            data: (*res).attestation_object.as_mut_ptr(),
            len: (*res).attestation_object.len(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn response_free(res: *mut AuthenticatorResponse) {
        let _ = Box::from_raw(res);
    }

    #[no_mangle]
    pub unsafe extern "C" fn generate_credential_creation_response(
        aaguid: *const c_char,
        credential_id: *const c_uchar,
        credential_id_length: usize,
        rp_id: *const c_char,
        attestation_flags: u8,
        cose_algorithm_identifiers: *const c_int,
        cose_algorithm_identifiers_length: usize,
    ) -> *mut AuthenticatorResponse {
        let aaguid_str = strings::c_char_to_string(aaguid);
        let aaguid = Uuid::parse_str(aaguid_str.as_str());
        if aaguid.is_err() {
            return null_mut();
        }

        let rp_id_str = strings::c_char_to_string(rp_id);

        let credential_id: Vec<u8> = std::slice::from_raw_parts(credential_id, credential_id_length).into();
        let algorithms_raw: Vec<i32> = std::slice::from_raw_parts(cose_algorithm_identifiers, cose_algorithm_identifiers_length).into();
        let alg = WebauthnAuthenticator::find_best_supported_algorithm(
            algorithms_raw
                .into_iter()
                .map(CoseAlgorithmIdentifier::from)
                .collect::<Vec<CoseAlgorithmIdentifier>>()
                .as_slice(),
        );
        if alg.is_err() {
            return null_mut();
        }

        let attestation_object = WebauthnAuthenticator::generate_attestation_object(
            alg.expect("Checked above"),
            aaguid.expect("Checked above"),
            &credential_id,
            rp_id_str.as_str(),
            u8::from_be(attestation_flags),
        );

        if attestation_object.is_err() {
            return null_mut();
        }

        let (attestation_object, private_key, _) = attestation_object.expect("Checked above");
        let attestation_object_bytes = attestation_object.to_bytes();
        if attestation_object_bytes.is_err() {
            return null_mut();
        }

        Box::into_raw(Box::new(AuthenticatorResponse {
            private_key_response: private_key,
            attestation_object: attestation_object_bytes.expect("Checked above"),
        }))
    }
}
