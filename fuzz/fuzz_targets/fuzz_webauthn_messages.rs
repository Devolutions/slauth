#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate slauth;

fuzz_target!(|data: &[u8]| {
    let _ = AttestationObject::from_bytes(data);
    let _ = AuthenticatorData::from_vec(data.to_vec());
});
