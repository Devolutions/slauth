#[cfg(feature = "webauthn")]
pub mod authenticator;
#[cfg(feature = "webauthn")]
pub mod error;
#[cfg(feature = "webauthn")]
pub mod proto;

#[cfg(feature = "webauthn-server")]
pub mod server;
