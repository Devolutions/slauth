pub fn main() {
    #[cfg(feature = "webauthn-server")]
    {
        use saphir::{BasicController, Method, Middleware, RequestContinuation, Server, SyncRequest, SyncResponse};
        use serde_json::json;
        use slauth::webauthn::{
            error::{CredentialError as CredE, Error::CredentialError},
            proto::{
                constants::WEBAUTHN_CHALLENGE_LENGTH,
                raw_message::CredentialPublicKey,
                web_message::{PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions},
            },
            server::{CredentialCreationBuilder, CredentialCreationVerifier, CredentialRequestBuilder, CredentialRequestVerifier},
        };
        use std::{collections::HashMap, str::FromStr, sync::RwLock};
        use uuid::Uuid;

        let server = Server::builder();

        let server = server
            .configure_middlewares(|stack| stack.apply(CorsMiddleware::new(), vec!["/"], None))
            .configure_router(|router| {
                let basic_test_cont = BasicController::new("/webauthn", TestControllerContext::new());

                basic_test_cont.add(Method::GET, "/register", TestControllerContext::register_request);

                basic_test_cont.add(Method::POST, "/register", TestControllerContext::complete_register);

                basic_test_cont.add(Method::GET, "/sign", TestControllerContext::sign_request);

                basic_test_cont.add(Method::POST, "/sign", TestControllerContext::complete_sign);

                router.add(basic_test_cont)
            })
            .configure_listener(|listener_config| listener_config.set_uri("http://0.0.0.0:12345"))
            .build();

        if let Err(e) = server.run() {
            println!("{:?}", e);
            assert!(false);
        }

        struct TestControllerContext {
            creds: RwLock<HashMap<String, (CredentialPublicKey, u32)>>,
            reg_contexts: RwLock<HashMap<String, PublicKeyCredentialCreationOptions>>,
            sign_contexts: RwLock<HashMap<String, PublicKeyCredentialRequestOptions>>,
        }

        impl TestControllerContext {
            pub fn new() -> Self {
                TestControllerContext {
                    creds: RwLock::new(HashMap::new()),
                    reg_contexts: RwLock::new(HashMap::new()),
                    sign_contexts: RwLock::new(HashMap::new()),
                }
            }

            pub fn register_request(&self, _req: &SyncRequest, res: &mut SyncResponse) {
                let uuid = base64::encode_config(
                    Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                        .expect("should be ok")
                        .as_bytes(),
                    base64::URL_SAFE_NO_PAD,
                );
                let builder = CredentialCreationBuilder::new()
                    .challenge(gen_challenge(WEBAUTHN_CHALLENGE_LENGTH))
                    .user(uuid.clone(), "lfauvel@devolutions.net".to_string(), "Luc Fauvel".to_string(), None)
                    .rp("localhost".to_string(), None, Some("localhost".to_string()))
                    .build();

                match builder {
                    Ok(pubkey) => {
                        if let Ok(mut contexts) = self.reg_contexts.write() {
                            contexts.insert(uuid, pubkey.clone());
                        }
                        res.status(200)
                            .body(serde_json::to_vec(&json!({ "publicKey": pubkey })).expect("This is valid json"))
                            .header("Content-Type", "application/json");
                    }
                    Err(e) => {
                        dbg!(e);
                    }
                }
            }

            pub fn complete_register(&self, req: &SyncRequest, _res: &mut SyncResponse) {
                let value = serde_json::from_str::<PublicKeyCredential>(&String::from_utf8(req.body().clone()).unwrap());
                let uuid = base64::encode_config(
                    Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                        .expect("should be ok")
                        .as_bytes(),
                    base64::URL_SAFE_NO_PAD,
                );
                if let Ok(cred) = value {
                    if let Some(context) = self.reg_contexts.read().expect("should be ok").get(&uuid) {
                        let mut verifier = CredentialCreationVerifier::new(cred.clone(), context.clone(), "http://localhost");
                        if let Ok(result) = verifier.verify() {
                            self.creds.write().unwrap().insert(cred.id, (result.public_key, result.sign_count));
                        }
                    }
                }
            }

            pub fn sign_request(&self, _req: &SyncRequest, res: &mut SyncResponse) {
                let mut builder = CredentialRequestBuilder::new()
                    .rp("localhost".to_string())
                    .challenge(gen_challenge(WEBAUTHN_CHALLENGE_LENGTH));
                let uuid = base64::encode_config(
                    Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                        .expect("should be ok")
                        .as_bytes(),
                    base64::URL_SAFE_NO_PAD,
                );
                for (cred, _) in self.creds.read().unwrap().iter() {
                    builder = builder.allow_credential(cred.clone());
                }
                match builder.build() {
                    Ok(pubkey) => {
                        self.sign_contexts.write().unwrap().insert(uuid, pubkey.clone());
                        res.status(200)
                            .body(serde_json::to_vec(&json!({ "publicKey": pubkey })).expect("This is valid json"))
                            .header("Content-Type", "application/json");
                    }
                    Err(e) => {
                        dbg!(e);
                    }
                }
            }

            pub fn complete_sign(&self, req: &SyncRequest, res: &mut SyncResponse) {
                let value = serde_json::from_str::<PublicKeyCredential>(&String::from_utf8(req.body().clone()).unwrap());
                let uuid = base64::encode_config(
                    Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                        .expect("should be ok")
                        .as_bytes(),
                    base64::URL_SAFE_NO_PAD,
                );
                let result = if let Ok(cred) = value {
                    if let Some(context) = self.sign_contexts.read().expect("should be ok").get(&uuid) {
                        if let Some((cred_pub, sign_count)) = self.creds.read().unwrap().get(&cred.id) {
                            let mut verifier = CredentialRequestVerifier::new(
                                cred.clone(),
                                cred_pub.clone(),
                                context.clone(),
                                "http://localhost",
                                uuid.as_str(),
                                sign_count.clone(),
                            );
                            match verifier.verify() {
                                Ok(res) => Ok((cred_pub.clone(), res.sign_count)),

                                Err(e) => Err(e),
                            }
                        } else {
                            Err(CredentialError(CredE::Other("Credential not found".to_string())))
                        }
                    } else {
                        Err(CredentialError(CredE::Other("Context not found".to_string())))
                    }
                } else {
                    Err(CredentialError(CredE::Other(
                        "Public key credential could not be parsed".to_string(),
                    )))
                };

                match result {
                    Ok((cred_pub, sign_count)) => {
                        self.creds.write().unwrap().insert(uuid, (cred_pub.clone(), sign_count));
                        res.status(200).body("it works".to_string());
                    }

                    Err(e) => {
                        res.status(500).body(e.to_string());
                    }
                }
            }
        }

        pub struct CorsMiddleware {}

        impl CorsMiddleware {
            pub fn new() -> Self {
                CorsMiddleware {}
            }
        }

        impl Middleware for CorsMiddleware {
            fn resolve(&self, req: &mut SyncRequest, res: &mut SyncResponse) -> RequestContinuation {
                let headers = req.headers_map();
                if let Some(Ok(origin)) = headers.get("Origin").map(|c| c.to_str()) {
                    res.header("Access-Control-Allow-Origin", origin);
                } else {
                    res.header("Access-Control-Allow-Origin", "*");
                }

                res.header("Access-Control-Expose-Headers", "Auth-ID, WWW-Authenticate, auth-id, www-authenticate, authorization, Authorization, Origin, origin, Set-Cookie, set-cookie, Cookie, cookie");

                if req.uri().path().contains("/auth") {
                    res.header("Access-Control-Allow-Credentials", "true");
                }

                if req.method() == Method::OPTIONS.as_ref() {
                    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                    res.header("Access-Control-Allow-Headers", "Auth-ID, WWW-Authenticate, auth-id, www-authenticate, authorization, Authorization, Origin, origin, Set-Cookie, set-cookie, Cookie, cookie, Code");
                    return RequestContinuation::Stop;
                }

                return RequestContinuation::Continue;
            }
        }

        pub fn gen_challenge(len: usize) -> String {
            use rand::{thread_rng, Rng};

            let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            let mut rng = thread_rng();
            let value = (0..len).map(|_| *rng.choose(charset.as_ref()).unwrap() as u8).collect::<Vec<u8>>();
            base64::encode_config(value.as_slice(), base64::URL_SAFE_NO_PAD)
        }
    }
}
