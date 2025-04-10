pub mod token;

pub struct SigningKey {
    pub key_handle: String,
    pub private_key: Vec<u8>,
}

#[allow(clippy::module_inception)]
pub mod client {
    use sha2::{Digest, Sha256};

    use crate::base64::*;
    use crate::u2f::{
        client::{token, SigningKey},
        error::Error,
        proto::{
            constants::{MAX_RESPONSE_LEN_EXTENDED, U2F_AUTHENTICATE, U2F_AUTH_DONT_ENFORCE, U2F_REGISTER, U2F_V2_VERSION_STR},
            raw_message::{
                self,
                apdu::{ApduFrame, Request as RawRequest},
                Message as RawMessageTrait,
            },
            web_message::{
                ClientData, ClientDataType, ClientError, Request, Response, U2fRegisterResponse, U2fRequest, U2fRequestType,
                U2fResponse as WebResponse, U2fResponseType, U2fSignResponse,
            },
        },
    };

    impl U2fRequest {
        pub(crate) fn register(
            &self,
            origin: String,
            attestation_cert: &[u8],
            attestation_key: &[u8],
        ) -> Result<(Response, SigningKey), Error> {
            let U2fRequest { app_id, data, .. } = self;

            let origin = app_id.as_ref().cloned().unwrap_or(origin);
            let mut hasher = Sha256::new();

            hasher.update(&origin);

            let application_parameter = hasher.finalize_reset();

            match data {
                Request::Register(reg) => {
                    let reg_req = reg
                        .register_requests
                        .iter()
                        .find(|r| r.version.eq(U2F_V2_VERSION_STR))
                        .ok_or_else(|| Error::Registration("At least one Registration request V2 must be used".to_string()))?;

                    let client_data = ClientData {
                        typ: ClientDataType::Registration,
                        challenge: reg_req.challenge.clone(),
                        origin,
                        cid_pubkey: None,
                    };

                    let client_data_str = serde_json::to_string(&client_data)?;

                    hasher.update(&client_data_str);

                    let challenge_param = hasher.finalize_reset();

                    let mut data = Vec::with_capacity(64);

                    data.extend_from_slice(challenge_param.as_slice());
                    data.extend_from_slice(application_parameter.as_slice());

                    let raw_req = RawRequest {
                        class_byte: 0x00,
                        command_mode: U2F_REGISTER,
                        param_1: 0,
                        param_2: 0,
                        data_len: Some(64),
                        data: Some(data),
                        max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED),
                    };

                    let (raw_rsp, signing_key) = raw_message::RegisterRequest::from_apdu(raw_req).and_then(|reg| {
                        token::register(reg, attestation_cert, attestation_key)
                            .and_then(|(rsp, sign)| rsp.into_apdu().map(move |r| (r, sign)))
                    })?;

                    let mut raw_rsp_byte = Vec::new();

                    let _ = raw_rsp.write_to(&mut raw_rsp_byte);

                    Ok((
                        Response::Register(U2fRegisterResponse {
                            version: U2F_V2_VERSION_STR.to_string(),
                            client_data: BASE64_URLSAFE_NOPAD.encode(&client_data_str),
                            registration_data: BASE64_URLSAFE_NOPAD.encode(&raw_rsp_byte),
                        }),
                        signing_key,
                    ))
                }

                Request::Sign(_sign) => Err(Error::Other("Unexpected Sign request during registration".to_string())),
            }
        }

        pub(crate) fn sign(&self, signing_key: &SigningKey, origin: String, counter: u32, user_presence: bool) -> Result<Response, Error> {
            let U2fRequest { app_id, data, .. } = self;

            let origin = app_id.as_ref().cloned().unwrap_or(origin);
            let mut hasher = Sha256::new();

            hasher.update(&origin);

            let application_parameter = hasher.finalize_reset();

            match data {
                Request::Register(_reg) => Err(Error::Other("Unexpected Register request while signing".to_string())),

                Request::Sign(sign) => {
                    let client_data = ClientData {
                        typ: ClientDataType::Authentication,
                        challenge: sign.challenge.clone(),
                        origin,
                        cid_pubkey: None,
                    };

                    let client_data_str = serde_json::to_string(&client_data)?;

                    hasher.update(&client_data_str);

                    let challenge_param = hasher.finalize_reset();

                    let mut data = Vec::new();

                    data.extend_from_slice(challenge_param.as_slice());
                    data.extend_from_slice(application_parameter.as_slice());
                    data.push(signing_key.key_handle.len() as u8);
                    data.extend_from_slice(signing_key.key_handle.as_bytes());

                    let data_len = Some(data.len());

                    let raw_req = RawRequest {
                        class_byte: 0x00,
                        command_mode: U2F_AUTHENTICATE,
                        param_1: U2F_AUTH_DONT_ENFORCE,
                        param_2: 0,
                        data_len,
                        data: Some(data),
                        max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED),
                    };

                    let raw_rsp = raw_message::AuthenticateRequest::from_apdu(raw_req)
                        .and_then(|auth| token::sign(auth, signing_key, counter, user_presence).and_then(|rsp| rsp.into_apdu()))?;

                    let mut raw_rsp_byte = Vec::new();

                    let _ = raw_rsp.write_to(&mut raw_rsp_byte);

                    Ok(Response::Sign(U2fSignResponse {
                        key_handle: signing_key.key_handle.clone(),
                        signature_data: BASE64_URLSAFE_NOPAD.encode(&raw_rsp_byte),
                        client_data: BASE64_URLSAFE_NOPAD.encode(&client_data_str),
                    }))
                }
            }
        }
    }

    #[cfg(feature = "native-bindings")]
    mod native_bindings {
        use std::{
            os::raw::{c_char, c_uchar, c_ulong, c_ulonglong},
            ptr::null_mut,
        };

        use crate::{strings, u2f::client::SigningKey};

        use super::*;
        use crate::u2f::proto::web_message::U2fRequest;

        pub struct ClientWebResponse {
            rsp: WebResponse,
            signing_key: Option<SigningKey>,
        }

        pub type WebRequest = U2fRequest;

        #[no_mangle]
        pub unsafe extern "C" fn web_request_from_json(req: *const c_char) -> *mut WebRequest {
            serde_json::from_str::<WebRequest>(&strings::c_char_to_string(req))
                .map_err(|e| println!("Unable to create web request from json: {}", e))
                .map(|r| Box::into_raw(Box::new(r)))
                .unwrap_or_else(|_| null_mut())
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_free(req: *mut WebRequest) {
            let _ = Box::from_raw(req);
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_is_register(req: *mut WebRequest) -> bool {
            let req = &*req;
            if let U2fRequestType::Register = req.req_type {
                return true;
            }
            false
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_is_sign(req: *mut WebRequest) -> bool {
            let req = &*req;
            if let U2fRequestType::Sign = req.req_type {
                return true;
            }
            false
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_origin(req: *mut WebRequest) -> *mut c_char {
            let req = &*req;
            req.app_id
                .as_ref()
                .map(|s| strings::string_to_c_char(s.to_owned()))
                .unwrap_or_else(null_mut)
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_timeout(req: *mut WebRequest) -> c_ulonglong {
            let req = &*req;
            req.timeout_seconds.unwrap_or(60)
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_key_handle(req: *mut WebRequest, origin: *const c_char) -> *mut c_char {
            let req = &*req;
            let origin = strings::c_char_to_string(origin);
            if let Request::Sign(sign) = &req.data {
                sign.registered_keys
                    .iter()
                    .find_map(|k| {
                        if let Some(application) = &k.app_id {
                            if application == &origin {
                                return Some(k.key_handle.clone());
                            }
                        }

                        None
                    })
                    .map(strings::string_to_c_char)
                    .unwrap_or_else(null_mut)
            } else {
                null_mut()
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_sign(
            req: *mut WebRequest,
            signing_key: *mut SigningKey,
            origin: *const c_char,
            counter: c_ulong,
            user_presence: bool,
        ) -> *mut ClientWebResponse {
            let req = &*req;
            let signing_key = &*signing_key;
            let default_origin = strings::c_char_to_string_checked(origin).unwrap_or_default();

            let request_id = req.request_id;

            let web_response = match req.sign(signing_key, default_origin, counter as u32, user_presence) {
                Ok(response_data) => WebResponse {
                    rsp_type: U2fResponseType::from(&req.req_type),
                    request_id,
                    response_data,
                },
                Err(e) => match e {
                    Error::Registration(e) => WebResponse {
                        rsp_type: U2fResponseType::Register,
                        request_id,
                        response_data: Response::Error(ClientError::bad_request(Some(e))),
                    },

                    Error::Sign(e) => WebResponse {
                        rsp_type: U2fResponseType::Sign,
                        request_id,
                        response_data: Response::Error(ClientError::bad_request(Some(e))),
                    },

                    e => WebResponse {
                        rsp_type: U2fResponseType::from(&req.req_type),
                        request_id,
                        response_data: Response::Error(ClientError::other_error(Some(e.to_string()))),
                    },
                },
            };

            Box::into_raw(Box::new(ClientWebResponse {
                rsp: web_response,
                signing_key: None,
            }))
        }

        #[no_mangle]
        pub unsafe extern "C" fn web_request_register(
            req: *mut WebRequest,
            origin: *const c_char,
            attestation_cert: *const c_uchar,
            attestation_cert_len: c_ulonglong,
            attestation_key: *const c_uchar,
            attestation_key_len: c_ulonglong,
        ) -> *mut ClientWebResponse {
            let req = &*req;

            let attestation_cert = std::slice::from_raw_parts(attestation_cert, attestation_cert_len as usize);
            let attestation_key = std::slice::from_raw_parts(attestation_key, attestation_key_len as usize);

            let default_origin = strings::c_char_to_string_checked(origin).unwrap_or_default();

            let request_id = req.request_id;
            let mut signing_key = None;
            let web_response = match req.register(default_origin, attestation_cert, attestation_key) {
                Ok((response_data, s_k)) => {
                    signing_key = Some(s_k);
                    WebResponse {
                        rsp_type: U2fResponseType::from(&req.req_type),
                        request_id,
                        response_data,
                    }
                }
                Err(e) => match e {
                    Error::Registration(e) => WebResponse {
                        rsp_type: U2fResponseType::Register,
                        request_id,
                        response_data: Response::Error(ClientError::bad_request(Some(e))),
                    },

                    Error::Sign(e) => WebResponse {
                        rsp_type: U2fResponseType::Sign,
                        request_id,
                        response_data: Response::Error(ClientError::bad_request(Some(e))),
                    },

                    e => WebResponse {
                        rsp_type: U2fResponseType::from(&req.req_type),
                        request_id,
                        response_data: Response::Error(ClientError::other_error(Some(e.to_string()))),
                    },
                },
            };

            Box::into_raw(Box::new(ClientWebResponse {
                rsp: web_response,
                signing_key,
            }))
        }

        #[no_mangle]
        pub unsafe extern "C" fn client_web_response_free(rsp: *mut ClientWebResponse) {
            let _ = Box::from_raw(rsp);
        }

        #[no_mangle]
        pub unsafe extern "C" fn client_web_response_to_json(rsp: *mut ClientWebResponse) -> *mut c_char {
            let rsp = &*rsp;
            strings::string_to_c_char(
                serde_json::to_string(&rsp.rsp)
                    .unwrap_or_else(|_| r#"{"type": "u2f_register_response", "responseData" : {"errorCode" : 1}}"#.to_string()),
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn client_web_response_signing_key(rsp: *mut ClientWebResponse) -> *mut SigningKey {
            let rsp = &mut *rsp;
            rsp.signing_key.take().map(|s| Box::into_raw(Box::new(s))).unwrap_or_else(null_mut)
        }

        #[no_mangle]
        pub unsafe extern "C" fn signing_key_free(s: *mut SigningKey) {
            let _ = Box::from_raw(s);
        }

        #[no_mangle]
        pub unsafe extern "C" fn signing_key_to_string(s: *mut SigningKey) -> *mut c_char {
            let SigningKey { key_handle, private_key } = &*s;

            strings::string_to_c_char(format!("{}.{}", key_handle, BASE64_URLSAFE_NOPAD.encode(private_key)))
        }

        #[no_mangle]
        pub unsafe extern "C" fn signing_key_get_key_handle(s: *mut SigningKey) -> *mut c_char {
            let s = &*s;
            strings::string_to_c_char(s.key_handle.clone())
        }

        #[no_mangle]
        pub unsafe extern "C" fn signing_key_from_string(s: *const c_char) -> *mut SigningKey {
            strings::c_char_to_string_checked(s)
                .and_then(|s| {
                    let mut parts = s.split('.');
                    let l = parts.next().and_then(|key_handle| parts.next().map(|b64| (key_handle, b64)));

                    l.and_then(|(k, b64)| BASE64_URLSAFE_NOPAD.decode(b64).ok().map(|b64_v| (k.to_string(), b64_v)))
                })
                .map(|(key_handle, key)| {
                    Box::into_raw(Box::new(SigningKey {
                        key_handle,
                        private_key: key,
                    }))
                })
                .unwrap_or_else(null_mut)
        }
    }
}
