pub mod proto;
pub mod server;
pub mod error;

#[macro_use]
extern crate saphir;

use saphir::*;
use std::sync::RwLock;
use crate::webauthn::proto::web_message::PublicKeyCredentialCreationOptions;
use crate::webauthn::server::CredentialCreationBuilder;
use uuid::Uuid;
use std::str::FromStr;

#[test]
pub fn web_test() {
    let server = Server::builder();

    if let Err(e) = server
        .configure_router(|router| {
            let basic_test_cont = BasicController::new("/user", TestControllerContext::new());

            basic_test_cont.add_with_guards(Method::POST, "/", BodyGuard.into(), TestControllerContext::create);

            basic_test_cont.add(Method::GET, "/<user-id>", UserControllerContext::read);

            basic_test_cont.add(Method::GET, "/<user-id>/<claim#r(^(firstname)|(lastname)$)>", TestControllerContext::read);

            basic_test_cont.add(Method::PUT, "/<user-id>", UserControllerContext::update);

            basic_test_cont.add(Method::DELETE, "/<user-id#r(^[0-9]*$)>", UserControllerContext::delete);

            router.add(basic_test_cont)

        })
        .configure_listener(|listener_config| {
            listener_config.set_uri("http://0.0.0.0:12345");
        })
        .build() {
    }
}


struct TestControllerContext {
    keys: RwLock<Vec<()>>
}

impl TestControllerContext {
    pub fn new() -> Self {
        TestControllerContext {
            keys: RwLock::new(Vec::new()),
        }
    }

    pub fn register_request(&self, req: &SyncRequest, res: &mut SyncResponse) {
        let uuid = Uuid::from_str("e1aea4d6-d2ee-4218-9f1c-5ccddadaa1a7")?;
        let builder = CredentialCreationBuilder::new().user(
            *uuid.as_bytes(),
            "lfauvel@devolutions.net".to_string(),
            "Luc Fauvel".to_string(),
            None
        ).rp(
            "login.devolutions.net".to_string(),
            None,
        ).build();
    }
}