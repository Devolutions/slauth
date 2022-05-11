pub mod client;
pub mod error;
pub mod proto;

#[cfg(feature = "u2f-server")]
pub mod server;

#[test]
fn test() {
    use crate::u2f::proto::web_message::{Response, U2fRequest};
    use server::*;
    const ATT_PKEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzgUSoDttmryF0C+ck4GppKwssha7ngah0dfezfTBzDOhRANCAATXk8CelRQjNuArEPpEW40yOOX9wPTq8pEG2XRf8KI3NzeKBOHWpxzTRAgKABBTF28dKf4NpJGSL+Qj04nyWQ8a";
    const ATT_CERT: &str = "MIICODCCAd6gAwIBAgIJAKsa9WC9HvEuMAoGCCqGSM49BAMCMFoxDzANBgNVBAMMBlNsYXV0aDELMAkGA1UEBhMCQ0ExDzANBgNVBAgMBlF1ZWJlYzETMBEGA1UEBwwKTGF2YWx0cm91ZTEUMBIGA1UECgwLRGV2b2x1dGlvbnMwHhcNMTkwNzAyMTgwMTUyWhcNMzEwNjI5MTgwMTUyWjBaMQ8wDQYDVQQDDAZTbGF1dGgxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIDAZRdWViZWMxEzARBgNVBAcMCkxhdmFsdHJvdWUxFDASBgNVBAoMC0Rldm9sdXRpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE15PAnpUUIzbgKxD6RFuNMjjl/cD06vKRBtl0X/CiNzc3igTh1qcc00QICgAQUxdvHSn+DaSRki/kI9OJ8lkPGqOBjDCBiTAdBgNVHQ4EFgQU7iZ4JceUHOuWoMymFGm+ZBUmwwgwHwYDVR0jBBgwFoAU7iZ4JceUHOuWoMymFGm+ZBUmwwgwDgYDVR0PAQH/BAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAVBgNVHREEDjAMggpzbGF1dGgub3JnMAoGCCqGSM49BAMCA0gAMEUCIEdjPFNsund4FXs/1HpK4AXWQ0asfY6ERhNlg29VGS6pAiEAx8f2lrlVV1tASWbC/edTgH9JsCbANuXW/9FZcWHGl2E=";
    const APP_ID: &str = "https://example.com/login/";

    let server_request = U2fRequestBuilder::register()
        .app_id(APP_ID.to_string())
        .challenge("1234567".to_string())
        .timeout_sec(81)
        .build()
        .expect("Unable to build U2fRequest register");

    let json_req = serde_json::to_string(&server_request).expect("Unable to serialize request"); //r#"{"appId":"http://localhost:4242","registerRequests":[{"challenge":"UzAxNE0yMTBWM1JDYzA1a1JqWndRUT09","version":"U2F_V2"}],"registeredKeys":[],"requestId":1,"timeoutSeconds":300,"type":"u2f_register_request"}"#;

    let web_req = serde_json::from_str::<U2fRequest>(&json_req).expect("Unable to deserialize req");

    let origin = web_req.app_id.as_ref().expect("Missing origin");

    let (rsp, signing_key) = web_req
        .register(
            origin.to_string(),
            base64::decode(ATT_CERT).unwrap().as_slice(),
            base64::decode(ATT_PKEY).unwrap().as_slice(),
        )
        .expect("Unable to register");

    let registration_rsp = if let Response::Register(reg) = rsp { reg } else { panic!() };

    let registration = registration_rsp.get_registration().expect("Unable to verify registration response");

    let server_sign_request = U2fRequestBuilder::sign()
        .app_id(APP_ID.to_string())
        .challenge("987654321".to_string())
        .timeout_sec(82)
        .registered_keys(vec![registration.get_registered_key()])
        .build()
        .expect("Unable to build U2fRequest Sign");

    let json_sign_req = serde_json::to_string(&server_sign_request).expect("Unable to serialize request");

    let web_sign_req = serde_json::from_str::<U2fRequest>(&json_sign_req).expect("Unable to deserialize req");

    let origin = web_sign_req.app_id.as_ref().expect("Missing origin");

    let rsp = web_sign_req
        .sign(&signing_key, origin.to_string(), 1, true)
        .expect("Unable to sign");

    let sign_rsp = if let Response::Sign(sig) = rsp { sig } else { panic!() };

    assert!(sign_rsp
        .validate_signature(registration.pub_key.as_slice())
        .expect("Unable to validate signature"));
}
