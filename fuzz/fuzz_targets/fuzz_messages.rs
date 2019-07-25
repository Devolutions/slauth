#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate slauth;

use slauth::u2f::proto::raw_message::{Message, AuthenticateRequest, AuthenticateResponse, RegisterRequest, 
    RegisterResponse, VersionRequest, VersionResponse};
use slauth::u2f::proto::raw_message::apdu::{ApduFrame, Request, Response};

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = Request::read_from(data) {
        let _ = AuthenticateRequest::from_apdu(req.clone());
        let _ = RegisterRequest::from_apdu(req.clone());
        let _ = VersionRequest::from_apdu(req);
    };

    if let Ok(rsp) = Response::read_from(data) {
        let _ = AuthenticateResponse::from_apdu(rsp.clone());
        let _ = RegisterResponse::from_apdu(rsp.clone());
        let _ = VersionResponse::from_apdu(rsp);
    };

});
