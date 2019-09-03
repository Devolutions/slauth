use crate::webauthn::proto::raw_message::{AttestationObject, Message};
use std::collections::HashMap;
use crate::webauthn::proto::web_message::PublicKeyCredentialCreationOptions;

pub mod proto;
pub mod server;
pub mod error;

#[test]
pub fn web_test() {
    use crate::webauthn::server::{CredentialCreationBuilder, CredentialRequestBuilder};
    use uuid::Uuid;
    use std::str::FromStr;
    use serde_json::json;
    use saphir::{Server, BasicController, Method, SyncRequest, SyncResponse, Middleware, RequestContinuation};
    use crate::webauthn::proto::constants::WEBAUTHN_CHALLENGE_LENGTH;
    use std::sync::RwLock;
    use crate::webauthn::proto::web_message::PublicKeyCredential;

    let server = Server::builder();

    let server = server
        .configure_middlewares(|stack| {
            stack.apply(CorsMiddleware::new(), vec!("/"), None)
        })
        .configure_router(|router| {
            let basic_test_cont = BasicController::new("/webauthn", TestControllerContext::new());

            basic_test_cont.add(Method::GET, "/register", TestControllerContext::register_request);

            basic_test_cont.add(Method::POST, "/register", TestControllerContext::complete_register);

            basic_test_cont.add(Method::GET, "/sign", TestControllerContext::sign_request);

            router.add(basic_test_cont)
        })
        .configure_listener(|listener_config| {
            listener_config.set_uri("http://0.0.0.0:12345")
        })
        .build();

    if let Err(e) = server.run() {
        println!("{:?}", e);
        assert!(false);
    }

    struct TestControllerContext {
        creds: RwLock<Vec<String>>,
        contexts: RwLock<HashMap<String, PublicKeyCredentialCreationOptions>>,
    }

    impl TestControllerContext {
        pub fn new() -> Self {
            TestControllerContext {
                creds: RwLock::new(Vec::new()),
                contexts: RwLock::new(HashMap::new())
            }
        }

        pub fn register_request(&self, _req: &SyncRequest, res: &mut SyncResponse) {
            let uuid = base64::encode_config(Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7").expect("should be ok").as_bytes(), base64::URL_SAFE_NO_PAD);
            let builder = CredentialCreationBuilder::new().challenge(gen_challenge(WEBAUTHN_CHALLENGE_LENGTH)
            ).user(
                uuid.clone(),
                "lfauvel@devolutions.net".to_string(),
                "Luc Fauvel".to_string(),
                None
            ).rp(
                "localhost".to_string(),
                None,
                Some("localhost".to_string()),
            ).build();

            match builder {
                Ok(pubkey) => {
                    if let Ok(mut contexts) = self.contexts.write() {
                        contexts.insert(uuid, pubkey.clone());
                    }
                    res.status(200).body(serde_json::to_vec(&json!({
                "publicKey": pubkey
            })).expect("This is valid json")).header("Content-Type", "application/json");
                },
                Err(e) => { dbg!(e); }
            }
        }

        pub fn complete_register(&self, req: &SyncRequest, _res: &mut SyncResponse) {
            let value = serde_json::from_str::<PublicKeyCredential>(&String::from_utf8(req.body().clone()).unwrap());
            if let Ok(cred) = dbg!(value) {
                if let Some(att) = cred.response {
                    let _value = AttestationObject::from_base64(&att.attestation_object);
                }
                self.creds.write().unwrap().push(cred.id);
            }
        }

        pub fn sign_request(&self, _req: &SyncRequest, res: &mut SyncResponse) {
            let mut builder = CredentialRequestBuilder::new().rp("localhost".to_string()).challenge(gen_challenge(WEBAUTHN_CHALLENGE_LENGTH));
            for cred in self.creds.read().unwrap().iter() {
                builder = builder.allow_credential(cred.clone());
            }
            match builder.build() {
                Ok(pubkey) => {
                    res.status(200).body(serde_json::to_vec(&json!({
                "publicKey": pubkey
            })).expect("This is valid json")).header("Content-Type", "application/json");
                },
                Err(e) => { dbg!(e); },
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
        let value = (0..len).map(|_|
            { *rng.choose(charset.as_ref()).unwrap() as u8 }
        ).collect::<Vec<u8>>();
        base64::encode_config(value.as_slice(), base64::URL_SAFE_NO_PAD)
    }
}