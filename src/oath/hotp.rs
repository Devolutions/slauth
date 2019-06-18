use super::*;

pub const HOTP_DEFAULT_COUNTER_VALUE: u64 = 0;
pub const HOTP_DEFAULT_RESYNC_VALUE: u16 = 2;

pub struct HOTPBuilder {
    alg: Option<HashesAlgorithm>,
    counter: Option<u64>,
    resync: Option<u16>,
    digits: Option<usize>,
    secret: Option<Vec<u8>>,
}

impl HOTPBuilder {
    pub fn new() -> Self {
        HOTPBuilder {
            alg: None,
            counter: None,
            resync: None,
            digits: None,
            secret: None,
        }
    }

    pub fn algorithm(mut self, alg: HashesAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    pub fn counter(mut self, c: u64) -> Self {
        self.counter = Some(c);
        self
    }

    pub fn re_sync_parameter(mut self, s: u16) -> Self {
        self.resync = Some(s);
        self
    }

    pub fn digits(mut self, d: usize) -> Self {
        self.digits = Some(d);
        self
    }

    pub fn secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    pub fn build(self) -> HOTPContext {
        let HOTPBuilder {
            alg,
            counter,
            resync,
            digits,
            secret
        } = self;

        let alg = alg.unwrap_or_else(|| OTP_DEFAULT_ALG_VALUE);
        let secret = secret.unwrap_or_else(|| vec![]);
        let secret_key = alg.to_mac_hash_key(secret.as_slice());

        HOTPContext {
            alg,
            counter: counter.unwrap_or_else(|| HOTP_DEFAULT_COUNTER_VALUE),
            resync: resync.unwrap_or_else(|| HOTP_DEFAULT_RESYNC_VALUE),
            digits: digits.unwrap_or_else(|| OTP_DEFAULT_DIGITS_VALUE),
            secret,
            secret_key,
        }
    }
}

pub struct HOTPContext {
    alg: HashesAlgorithm,
    counter: u64,
    resync: u16,
    digits: usize,
    secret: Vec<u8>,
    secret_key: MacHashKey,
}

impl HOTPContext {
    /// Create a new HOTP builder
    pub fn builder() -> HOTPBuilder {
        HOTPBuilder::new()
    }

    /// Generate the current HOTP code corresponding to the counter value
    pub fn gen(&self) -> String {
        self.gen_at(self.counter)
    }

    /// Increment the inner counter value
    pub fn inc(&mut self) -> &mut Self {
        self.counter += 1;
        self
    }

    /// Check if a code equal the current value at the counter
    pub fn validate_current(&self, value: &str) -> bool {
        if value.len() != self.digits {
            return false;
        }

        self.gen().as_str().eq(value)
    }

    /// Check if a code is valid, if yes icrements the counter, if not begins the resync procedure.
    /// The counter won't be altered if the value is invalidated.
    pub fn verify(&mut self, value: &str) -> bool {
        if value.len() != self.digits {
            return false;
        }

        for i in self.counter..(self.counter + self.resync as u64) {
            if self.gen_at(i).as_str().eq(value) {
                self.counter += i - self.counter + 1;
                return true;
            }
        }

        false
    }

    fn gen_at(&self, c: u64) -> String {
        let c_b_e = c.to_be_bytes();

        let hs_sig = self.secret_key.sign(&c_b_e[..]).expect("This should not happen since HMAC can take key of any size").into_vec();
        let s_bits = dt(hs_sig.as_ref());

        let s_num = s_bits % (10 as u32).pow(self.digits as u32);

        format!("{:0>6}", s_num)
    }
}

impl OtpAuth for HOTPContext {
    fn to_uri(&self, label: Option<&str>, issuer: Option<&str>) -> String {
        let mut uri = format!("otpauth://hotp/{}?secret={}&algorithm={}&digits={}&counter={}",
                              label.unwrap_or_else(|| "slauth"),
                              base32::encode(base32::Alphabet::RFC4648 { padding: false }, self.secret.as_slice()),
                              self.alg.to_string(),
                              self.digits,
                              self.counter
        );

        if let Some(iss) = issuer {
            uri.push_str("&issuer=");
            uri.push_str(iss);
        }

        uri
    }

    fn from_uri(uri: &str) -> Result<Self, String> where Self: Sized {
        let mut uri_it = uri.split("://");

        uri_it.next().filter(|scheme| scheme.eq(&"otpauth")).ok_or_else(|| { "Otpauth uri is malformed".to_string() })?;

        let type_label_it_opt = uri_it.next().map(|type_label_param| type_label_param.split('/'));

        if let Some(mut type_label_it) = type_label_it_opt {
            type_label_it.next().filter(|otp_type| otp_type.eq(&"hotp")).ok_or_else(|| { "Otpauth uri is malformed, bad type".to_string() })?;

            let param_it_opt = type_label_it.next().and_then(|label_param| label_param.split('?').last().map(|s| s.split('&')));

            param_it_opt.ok_or_else(|| { "Otpauth uri is malformed, missing parameters".to_string() })
                .and_then(|param_it| {
                    let mut secret = Vec::<u8>::new();
                    let mut counter = std::u64::MAX;
                    let mut alg = OTP_DEFAULT_ALG_VALUE;
                    let mut digits = OTP_DEFAULT_DIGITS_VALUE;

                    for s_param in param_it {
                        let mut s_param_it = s_param.split('=');

                        match s_param_it.next() {
                            Some("secret") => {
                                secret = s_param_it.next().and_then(|s| {
                                    dbg!(base32::decode(base32::Alphabet::RFC4648 { padding: false }, s))
                                }).ok_or_else(|| { "Otpauth uri is malformed, missing secret value".to_string() })?;
                                continue;
                            }
                            Some("algorithm") => {
                                alg = match s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing algorithm value".to_string() })? {
                                    "SHA256" => HashesAlgorithm::SHA256,
                                    "SHA512" => HashesAlgorithm::SHA512,
                                    _ => HashesAlgorithm::SHA1,
                                };
                                continue;
                            }
                            Some("digits") => {
                                digits = s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing digits value".to_string() })?.parse::<usize>().map_err(|_| "Otpauth uri is malformed, bad digits value".to_string())?;
                                continue;
                            }
                            Some("counter") => {
                                counter = s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing counter value".to_string() })?.parse::<u64>().map_err(|_| "Otpauth uri is malformed, bad counter value".to_string())?;
                                continue;
                            }
                            _ => {}
                        }
                    }

                    if secret.is_empty() || counter == std::u64::MAX {
                        return Err("Otpauth uri is malformed".to_string());
                    }

                    let secret_key = alg.to_mac_hash_key(secret.as_slice());

                    Ok(HOTPContext {
                        alg,
                        counter,
                        resync: HOTP_DEFAULT_RESYNC_VALUE,
                        digits,
                        secret,
                        secret_key,
                    })
                })
        } else {
            Err("Otpauth uri is malformed, missing parts".to_string())
        }
    }
}

#[cfg(feature = "native-bindings")]
mod native_bindings {
    use std::os::raw::c_char;
    use std::ptr::null_mut;

    use super::*;

    #[no_mangle]
    pub unsafe extern fn hotp_from_uri(uri: *const c_char) -> *mut HOTPContext {
        let uri_str = strings::c_char_to_string(uri);
        Box::into_raw(HOTPContext::from_uri(&uri_str).map(|h| Box::new(h)).unwrap_or_else(|_| Box::from_raw(null_mut())))
    }

    #[no_mangle]
    pub unsafe extern fn hotp_free(hotp: *mut HOTPContext) {
        let _ = Box::from_raw(hotp);
    }

    #[no_mangle]
    pub unsafe extern fn hotp_to_uri(hotp: *mut HOTPContext, label: *const c_char, issuer: *const c_char) -> *mut c_char {
        let hotp = &*hotp;
        let label = strings::c_char_to_string(label);
        let label_opt = if label.len() > 0 {Some(label.as_str())} else {None};
        let issuer = strings::c_char_to_string(issuer);
        let issuer_opt = if issuer.len() > 0 {Some(issuer.as_str())} else {None};
        strings::string_to_c_char(hotp.to_uri(label_opt, issuer_opt))
    }

    #[no_mangle]
    pub unsafe extern fn hotp_gen(hotp: *mut HOTPContext) -> *mut c_char {
        let hotp = &*hotp;
        strings::string_to_c_char(hotp.gen())
    }

    #[no_mangle]
    pub unsafe extern fn hotp_inc(hotp: *mut HOTPContext) {
        let hotp = &mut *hotp;
        hotp.inc();
    }

    #[no_mangle]
    pub unsafe extern fn hotp_verify(hotp: *mut HOTPContext, code: *const c_char) -> bool {
        let hotp = &mut *hotp;
        let value = strings::c_char_to_string(code);
        hotp.verify(&value)
    }

    #[no_mangle]
    pub unsafe extern fn hotp_validate_current(hotp: *mut HOTPContext, code: *const c_char) -> bool {
        let hotp = &*hotp;
        let value = strings::c_char_to_string(code);
        hotp.validate_current(&value)
    }
}

#[test]
fn hotp_from_uri() {
    const MK_ULTRA: &'static str = "patate";

    let server = HOTPBuilder::new().counter(102).re_sync_parameter(3).secret(MK_ULTRA.as_bytes()).build();

    let uri = server.to_uri(Some("Lucid:test@devolutions.net"), Some("Lucid"));

    let client = HOTPContext::from_uri(uri.as_ref()).expect("oh no");

    assert!(server.validate_current(client.gen().as_str()));
}

#[test]
fn hotp_multiple() {
    const MK_ULTRA: &'static str = "patate";

    let mut server = HOTPBuilder::new().counter(102).re_sync_parameter(3).secret(MK_ULTRA.as_bytes()).build();

    let uri = server.to_uri(Some("Lucid:test@devolutions.net"), Some("Lucid"));

    let mut client = HOTPContext::from_uri(uri.as_ref()).expect("oh no");

    assert!(server.verify(client.gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
}

#[test]
fn hotp_multiple_resync() {
    const MK_ULTRA: &'static str = "patate";

    let mut server = HOTPBuilder::new().counter(102).re_sync_parameter(3).secret(MK_ULTRA.as_bytes()).build();

    let uri = server.to_uri(Some("Lucid:test@devolutions.net"), Some("Lucid"));

    let mut client = HOTPContext::from_uri(uri.as_ref()).expect("oh no");

    assert!(server.verify(client.gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
    assert!(server.verify(client.inc().inc().gen().as_str()));
    assert!(server.verify(client.inc().gen().as_str()));
    assert!(server.verify(client.inc().inc().inc().gen().as_str()));
}