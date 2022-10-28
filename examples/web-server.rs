use rand::seq::IteratorRandom;
use saphir::prelude::*;
use serde_json::{json, Value};
use slauth::webauthn::{
    error::{CredentialError as CredE, Error::CredentialError},
    proto::{
        constants::WEBAUTHN_CHALLENGE_LENGTH,
        raw_message::CredentialPublicKey,
        web_message::{PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions},
    },
    server::{CredentialCreationBuilder, CredentialCreationVerifier, CredentialRequestBuilder, CredentialRequestVerifier},
};
use std::{collections::HashMap, sync::RwLock};
use uuid::Uuid;

struct TestController {
    creds: RwLock<HashMap<String, (CredentialPublicKey, u32)>>,
    reg_contexts: RwLock<HashMap<String, PublicKeyCredentialCreationOptions>>,
    sign_contexts: RwLock<HashMap<String, PublicKeyCredentialRequestOptions>>,
}

impl TestController {
    pub fn new() -> Self {
        TestController {
            creds: RwLock::new(HashMap::new()),
            reg_contexts: RwLock::new(HashMap::new()),
            sign_contexts: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Debug)]
enum TestError {
    Slauth(slauth::webauthn::error::Error),
    Internal,
}

impl From<slauth::webauthn::error::Error> for TestError {
    fn from(e: slauth::webauthn::error::Error) -> Self {
        TestError::Slauth(e)
    }
}

impl Responder for TestError {
    fn respond_with_builder(self, builder: Builder, _ctx: &HttpContext) -> Builder {
        match self {
            TestError::Slauth(_) => builder.status(500),
            TestError::Internal => builder.status(500),
        }
    }
}

#[controller(name = "webauthn")]
impl TestController {
    #[get("/register")]
    async fn register_request(&self) -> Result<Json<Value>, TestError> {
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
                Ok(Json(json!({ "publicKey": pubkey })))
            }
            Err(e) => {
                dbg!(e);
                Err(TestError::Internal)
            }
        }
    }

    #[post("/register")]
    async fn complete_register(&self, cred: Json<PublicKeyCredential>) -> () {
        let cred = cred.into_inner();
        let uuid = base64::encode_config(
            Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                .expect("should be ok")
                .as_bytes(),
            base64::URL_SAFE_NO_PAD,
        );
        if let Some(context) = self.reg_contexts.read().expect("should be ok").get(&uuid) {
            let mut verifier = CredentialCreationVerifier::new(cred.clone(), context.clone(), "http://localhost");
            if let Ok(result) = verifier.verify() {
                self.creds.write().unwrap().insert(cred.id, (result.public_key, result.sign_count));
            }
        }
    }

    #[get("/sign")]
    async fn sign_request(&self) -> Result<Json<Value>, TestError> {
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
                Ok(Json(json!({ "publicKey": pubkey })))
            }
            Err(e) => {
                dbg!(e);
                Err(TestError::Internal)
            }
        }
    }

    #[post("/sign")]
    async fn complete_sign(&self, req: Json<PublicKeyCredential>) -> Result<(u16, String), TestError> {
        let cred = req.into_inner();
        let uuid = base64::encode_config(
            Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")
                .expect("should be ok")
                .as_bytes(),
            base64::URL_SAFE_NO_PAD,
        );

        let ctx_lock = self
            .sign_contexts
            .read()
            .map_err(|_| CredentialError(CredE::Other("Synchronization error".to_string())))?;
        let context = ctx_lock
            .get(&uuid)
            .ok_or(CredentialError(CredE::Other("Context not found".to_string())))?;

        let creds_lock = self
            .creds
            .read()
            .map_err(|_| CredentialError(CredE::Other("Synchronization error".to_string())))?;
        let (cred_pub, sign_count) = creds_lock
            .get(&cred.id)
            .ok_or(CredentialError(CredE::Other("Credential not found".to_string())))?;

        let mut verifier = CredentialRequestVerifier::new(
            cred,
            cred_pub.clone(),
            context.clone(),
            "http://localhost",
            uuid.as_str(),
            *sign_count,
        );
        let res = verifier.verify()?;
        self.creds.write().unwrap().insert(uuid, (cred_pub.clone(), res.sign_count));
        Ok((200, "it works".to_string()))
    }
}

pub struct CorsMiddleware;

impl CorsMiddleware {
    pub fn new() -> Self {
        CorsMiddleware {}
    }
}

#[middleware]
impl CorsMiddleware {
    // fn resolve(&self, req: &mut SyncRequest, res: &mut SyncResponse) -> RequestContinuation {
    async fn next(&self, mut ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
        let req = ctx.state.request_unchecked();
        let headers = req.headers().clone();
        let is_auth = req.uri().path().contains("/auth");

        if req.method() == Method::OPTIONS.as_ref() {
            ctx.after(Builder::new()
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
                .header("Access-Control-Allow-Headers", "Auth-ID, WWW-Authenticate, auth-id, www-authenticate, authorization, Authorization, Origin, origin, Set-Cookie, set-cookie, Cookie, cookie, Code, Content-Type, content-type")
                .status(StatusCode::NO_CONTENT)
                .build()?);
        } else {
            ctx = chain.next(ctx).await?;
        }

        let res = ctx.state.response_unchecked_mut();
        let res_headers = res.headers_mut();

        if let Some(Ok(origin)) = headers.get("Origin").map(|c| c.to_str()) {
            res_headers.insert("Access-Control-Allow-Origin", origin.parse()?);
        } else {
            res_headers.insert("Access-Control-Allow-Origin", "*".parse()?);
        }

        res_headers.insert("Access-Control-Expose-Headers", "Auth-ID, WWW-Authenticate, auth-id, www-authenticate, authorization, Authorization, Origin, origin, Set-Cookie, set-cookie, Cookie, cookie".parse()?);

        if is_auth {
            res_headers.insert("Access-Control-Allow-Credentials", "true".parse()?);
        }

        Ok(ctx)
    }
}

#[tokio::main]
async fn main() -> Result<(), SaphirError> {
    let server = Server::builder()
        .configure_middlewares(|stack| stack.apply(CorsMiddleware::new(), vec!["/"], None))
        .configure_router(|router| router.controller(TestController::new()))
        .configure_listener(|listener_config| listener_config.interface("0.0.0.0:12345"))
        .build();

    server.run().await
}

pub fn gen_challenge(len: usize) -> String {
    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut rng = rand::thread_rng();
    let value = (0..len)
        .map(|_| charset.chars().choose(&mut rng).unwrap() as u8)
        .collect::<Vec<u8>>();
    base64::encode_config(value.as_slice(), base64::URL_SAFE_NO_PAD)
}
