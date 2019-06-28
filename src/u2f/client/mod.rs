pub mod token;

pub mod client {
    use crate::u2f::error::Error;
    use crate::u2f::proto::raw_message::apdu::{Request as RawRequest, Response as RawResponse, ApduFrame};
    use crate::u2f::proto::web_message::{U2fRequest as WebRequest, U2fResponse as WebResponse, Request, ClientData, ClientDataType, Response, U2fResponseType, ClientError, ErrorCode, U2fRequestType, U2fRegisterResponse, U2fSignResponse};
    use crate::u2f::client::token::{U2FSToken, KeyStore, PresenceValidator};
    use std::sync::Arc;
    use crate::u2f::proto::constants::{U2F_V2_VERSION_STR, U2F_REGISTER, U2F_AUTHENTICATE, MAX_RESPONSE_LEN_EXTENDED, U2F_AUTH_ENFORCE, U2F_AUTH_DONT_ENFORCE, U2F_SW_NO_ERROR};
    use sha2::{Sha256, Digest};

    #[derive(Clone)]
    pub struct LocalClient {
        default_origin: String,
        s_token: Arc<U2FSToken>
    }

    impl LocalClient {
        pub fn new(origin: &str, store: impl KeyStore + 'static, p_v: impl PresenceValidator + 'static, counter: u32) -> LocalClient {
            LocalClient {
                default_origin: origin.to_string(),
                s_token: Arc::new(U2FSToken {
                    store: Box::new(store),
                    presence_validator: Box::new(p_v),
                    counter: std::sync::atomic::AtomicU32::new(counter),
                })
            }
        }

        fn handle_web_request(&self, req: &WebRequest, enforce_user: bool) -> Result<Response, Error> {
            let WebRequest {
                req_type,
                app_id,
                timeout_seconds,
                request_id,
                data,
            } = req;

            let origin = app_id.as_ref().map(|a| a.clone()).unwrap_or_else(|| self.default_origin.clone());
            let mut hasher = Sha256::new();

            hasher.input(&origin);

            let application_parameter = hasher.result_reset();

            match data {
                Request::Register(reg) => {
                    let reg_req = reg.register_requests.iter().find(|r| r.version.eq(U2F_V2_VERSION_STR)).ok_or_else(|| Error::Registration("At least one Registration request V2 must be used".to_string()))?;

                    let client_data = ClientData {
                        typ: ClientDataType::Registration,
                        challenge: reg_req.challenge.clone(),
                        origin,
                        cid_pubkey: None
                    };

                    let client_data_str = serde_json::to_string(&client_data)?;

                    hasher.input(&client_data_str);

                    let challenge_param = hasher.result_reset();

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
                        max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED)
                    };

                    let raw_rsp = self.s_token.handle_apdu_request(raw_req);

                    let mut raw_rsp_byte = Vec::new();

                    raw_rsp.write_to(&mut raw_rsp_byte);

                    Ok(Response::Register(U2fRegisterResponse {
                        version: U2F_V2_VERSION_STR.to_string(),
                        client_data: base64::encode_config(&client_data_str, base64::URL_SAFE_NO_PAD),
                        registration_data: base64::encode_config(&raw_rsp_byte, base64::URL_SAFE_NO_PAD),
                    }))
                },

                Request::Sign(sign) => {

                    let key_handle = sign.registered_keys.iter().find_map(|k| {
                        if let Some(application) = &k.app_id {
                            if application == &origin {
                                return Some(k.key_handle.clone())
                            }
                        }

                        None
                    }).ok_or_else(|| Error::Sign("At least one registed key must match the origin".to_string()))?;

                    let client_data = ClientData {
                        typ: ClientDataType::Authentication,
                        challenge: sign.challenge.clone(),
                        origin,
                        cid_pubkey: None
                    };

                    let client_data_str = serde_json::to_string(&client_data)?;

                    hasher.input(&client_data_str);

                    let challenge_param = hasher.result_reset();

                    let mut data = Vec::new();

                    data.extend_from_slice(challenge_param.as_slice());
                    data.extend_from_slice(application_parameter.as_slice());
                    data.push(key_handle.len() as u8);
                    data.extend_from_slice(key_handle.as_bytes());

                    let data_len = Some(data.len());

                    let raw_req = RawRequest {
                        class_byte: 0x00,
                        command_mode: U2F_AUTHENTICATE,
                        param_1: if enforce_user {U2F_AUTH_ENFORCE} else {U2F_AUTH_DONT_ENFORCE},
                        param_2: 0,
                        data_len,
                        data: Some(data),
                        max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED)
                    };

                    let raw_rsp = self.s_token.handle_apdu_request(raw_req);

                    let mut raw_rsp_byte = Vec::new();

                    raw_rsp.write_to(&mut raw_rsp_byte);

                    Ok(Response::Sign(U2fSignResponse {
                        key_handle,
                        signature_data: base64::encode_config(&raw_rsp_byte, base64::URL_SAFE_NO_PAD),
                        client_data: base64::encode_config(&client_data_str, base64::URL_SAFE_NO_PAD)
                    }))
                },
            }
        }

        pub fn handle(&self, json_req: &str, enforce_user: bool) -> String {
            let web_response = match serde_json::from_str::<WebRequest>(json_req) {
                Ok(req) => {
                    let request_id = req.request_id.clone();
                    match self.handle_web_request(&req, enforce_user) {
                        Ok(response_data) => {
                            WebResponse {
                                rsp_type: req.req_type.into(),
                                request_id,
                                response_data,
                            }
                        }
                        Err(e) => {
                            match e {
                                Error::Registration(e) => {
                                    WebResponse {
                                        rsp_type: U2fResponseType::Register,
                                        request_id,
                                        response_data: Response::Error(ClientError::bad_request(Some(e)))
                                    }
                                }

                                Error::Sign(e) => {
                                    WebResponse {
                                        rsp_type: U2fResponseType::Sign,
                                        request_id,
                                        response_data: Response::Error(ClientError::bad_request(Some(e)))
                                    }
                                }

                                e => {
                                    WebResponse {
                                        rsp_type: req.req_type.into(),
                                        request_id,
                                        response_data: Response::Error(ClientError::other_error(Some(e.to_string())))
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    WebResponse {
                        rsp_type: U2fResponseType::Register,
                        request_id: None,
                        response_data: Response::Error(ClientError::bad_request(Some("Request is unintelligible".to_string())))
                    }
                }
            };

            serde_json::to_string(&web_response).unwrap_or_else(|_e| r#"{"type": "u2f_register_response", "responseData" : {"errorCode" : 1}}"#.to_string())
        }
    }

    #[cfg(feature = "native-bindings")]
    mod native_bindings {
        use std::os::raw::{c_char, c_ulong};
        use std::ptr::null_mut;

        use super::*;
        use crate::oath::strings;
    }
}