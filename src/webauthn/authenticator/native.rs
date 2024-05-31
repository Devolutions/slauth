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

    pub struct AuthenticatorCreationResponse {
        pub private_key_response: String,
        pub attestation_object: Vec<u8>,
    }

    pub struct AuthenticatorRequestResponse {
        pub auth_data_bytes: Vec<u8>,
        pub signature: Vec<u8>,
    }

    #[repr(C)]
    pub struct Buffer {
        data: *mut u8,
        len: usize,
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_private_key_from_response(res: *mut AuthenticatorCreationResponse) -> *mut c_char {
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
    pub unsafe extern "C" fn get_attestation_object_from_response(res: *mut AuthenticatorCreationResponse) -> Buffer {
        if res.is_null() {
            return Buffer { data: null_mut(), len: 0 };
        }

        Buffer {
            data: (*res).attestation_object.as_mut_ptr(),
            len: (*res).attestation_object.len(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn response_free(res: *mut AuthenticatorCreationResponse) {
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
    ) -> *mut AuthenticatorCreationResponse {
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

        Box::into_raw(Box::new(AuthenticatorCreationResponse {
            private_key_response: private_key,
            attestation_object: attestation_object_bytes.expect("Checked above"),
        }))
    }

    #[no_mangle]
    pub unsafe extern "C" fn generate_credential_request_response(
        rp_id: *const c_char,
        private_key: *const c_char,
        attestation_flags: u8,
        client_data_hash: *const c_uchar,
        client_data_hash_length: usize,
    ) -> *mut AuthenticatorRequestResponse {
        let rp_id_str = strings::c_char_to_string(rp_id);
        let private_key = strings::c_char_to_string(private_key);
        let client_data_hash: Vec<u8> = std::slice::from_raw_parts(client_data_hash, client_data_hash_length).into();

        let auth_data = WebauthnAuthenticator::generate_authenticator_data(rp_id_str.as_str(), u8::from_be(attestation_flags), None);

        if auth_data.is_err() {
            return null_mut();
        }

        let auth_data_bytes = auth_data.expect("Checked above").to_vec();
        if auth_data_bytes.is_err() {
            return null_mut();
        }
        let auth_data_bytes = auth_data_bytes.expect("Checked above");

        let signature = WebauthnAuthenticator::generate_signature(auth_data_bytes.as_slice(), client_data_hash.as_slice(), private_key);

        if signature.is_err() {
            return null_mut();
        }

        Box::into_raw(Box::new(AuthenticatorRequestResponse {
            auth_data_bytes,
            signature: signature.expect("Checked above"),
        }))
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_auth_data_from_response(res: *mut AuthenticatorRequestResponse) -> Buffer {
        if res.is_null() {
            return Buffer { data: null_mut(), len: 0 };
        }

        Buffer {
            data: (*res).auth_data_bytes.as_mut_ptr(),
            len: (*res).auth_data_bytes.len(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_signature_from_response(res: *mut AuthenticatorRequestResponse) -> Buffer {
        if res.is_null() {
            return Buffer { data: null_mut(), len: 0 };
        }

        Buffer {
            data: (*res).signature.as_mut_ptr(),
            len: (*res).signature.len(),
        }
    }
}

#[cfg(target_os = "android")]
pub mod android {
    use crate::{
        strings,
        webauthn::{
            authenticator::{responses::AuthenticatorCredentialCreationResponse, WebauthnAuthenticator},
            proto::web_message::{
                PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRaw, PublicKeyCredentialRequestOptions,
            },
        },
    };
    use std::{
        ffi::{c_uchar, CString},
        os::raw::c_char,
        ptr::null_mut,
    };
    use uuid::Uuid;

    #[no_mangle]
    pub unsafe extern "C" fn generate_credential_creation_response(
        aaguid: *const c_char,
        credential_id: *const c_uchar,
        credential_id_length: usize,
        request_json: *const c_char,
        origin: *const c_char,
        attestation_flags: u8,
    ) -> *mut AuthenticatorCredentialCreationResponse {
        let aaguid_str = strings::c_char_to_string(aaguid);
        let aaguid = Uuid::parse_str(aaguid_str.as_str());
        if aaguid.is_err() {
            return null_mut();
        }
        let credential_id: Vec<u8> = std::slice::from_raw_parts(credential_id, credential_id_length).into();

        let options: Result<PublicKeyCredentialCreationOptions, serde_json::Error> =
            serde_json::from_str(strings::c_char_to_string(request_json).as_str());

        if options.is_err() {
            return null_mut();
        }

        let origin_str = if origin.is_null() {
            None
        } else {
            Some(strings::c_char_to_string(origin))
        };
        let options = options.expect("Checked above");
        let response = WebauthnAuthenticator::generate_credential_creation_response(
            options,
            aaguid.expect("Checked above"),
            credential_id,
            origin_str,
            attestation_flags,
        );

        if response.is_err() {
            return null_mut();
        }

        Box::into_raw(Box::new(response.expect("Checked above")))
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_private_key_from_response(res: *mut AuthenticatorCredentialCreationResponse) -> *mut c_char {
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
    pub unsafe extern "C" fn get_json_from_creation_response(res: *mut AuthenticatorCredentialCreationResponse) -> *mut c_char {
        if res.is_null() {
            return null_mut();
        }

        let public_key_credential = PublicKeyCredential::from((*res).credential_response.clone());
        let json = serde_json::to_string(&public_key_credential);

        if json.is_err() {
            return null_mut();
        }

        let cstring = CString::new(json.expect("Checked above"));
        match cstring {
            Ok(cstring) => cstring.into_raw(),
            Err(_) => null_mut(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn get_json_from_request_response(res: *mut PublicKeyCredentialRaw) -> *mut c_char {
        if res.is_null() {
            return null_mut();
        }

        let public_key_credential = PublicKeyCredential::from((*res).clone());
        let json = serde_json::to_string(&public_key_credential);

        if json.is_err() {
            return null_mut();
        }

        let cstring = CString::new(json.expect("Checked above"));
        match cstring {
            Ok(cstring) => cstring.into_raw(),
            Err(_) => null_mut(),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn generate_credential_request_response(
        credential_id: *const c_uchar,
        credential_id_length: usize,
        request_json: *const c_char,
        origin: *const c_char,
        attestation_flags: u8,
        user_handle: *const c_uchar,
        user_handle_length: usize,
        private_key: *const c_char,
    ) -> *mut PublicKeyCredentialRaw {
        let credential_id: Vec<u8> = std::slice::from_raw_parts(credential_id, credential_id_length).into();
        let user_handle: Option<Vec<u8>> = if user_handle.is_null() {
            None
        } else {
            Some(std::slice::from_raw_parts(user_handle, user_handle_length).into())
        };

        let options: Result<PublicKeyCredentialRequestOptions, serde_json::Error> =
            serde_json::from_str(strings::c_char_to_string(request_json).as_str());

        let private_key = strings::c_char_to_string(private_key);

        if options.is_err() {
            return null_mut();
        }

        let origin_str = if origin.is_null() {
            None
        } else {
            Some(strings::c_char_to_string(origin))
        };
        let options = options.expect("Checked above");
        let response = WebauthnAuthenticator::generate_credential_request_response(
            credential_id,
            attestation_flags,
            options,
            origin_str,
            user_handle,
            private_key,
        );

        if response.is_err() {
            return null_mut();
        }

        Box::into_raw(Box::new(response.expect("Checked above")))
    }

    #[no_mangle]
    pub unsafe extern "C" fn response_free(res: *mut AuthenticatorCredentialCreationResponse) {
        let _ = Box::from_raw(res);
    }
}
