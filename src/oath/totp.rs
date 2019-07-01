use time::now_utc;

use super::*;

pub const TOTP_DEFAULT_PERIOD_VALUE: u64 = 30;
pub const TOTP_DEFAULT_BACK_RESYNC_VALUE: u64 = 1;
pub const TOTP_DEFAULT_FORWARD_RESYNC_VALUE: u64 = 1;

pub struct TOTPBuilder {
    alg: Option<HashesAlgorithm>,
    period: Option<u64>,
    backward_resync: Option<u64>,
    forward_resync: Option<u64>,
    initial_time: Option<u64>,
    digits: Option<usize>,
    secret: Option<Vec<u8>>,

}

impl TOTPBuilder {
    pub fn new() -> Self {
        TOTPBuilder {
            alg: None,
            period: None,
            backward_resync: None,
            forward_resync: None,
            initial_time: None,
            digits: None,
            secret: None,
        }
    }

    pub fn algorithm(mut self, alg: HashesAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    pub fn period(mut self, p: u64) -> Self {
        self.period = Some(p);
        self
    }

    pub fn re_sync_parameter(mut self, backward: u64, forward: u64) -> Self {
        self.backward_resync = Some(backward);
        self.forward_resync = Some(forward);
        self
    }

    pub fn digits(mut self, d: usize) -> Self {
        self.digits = Some(d);
        self
    }

    pub fn initial_time(mut self, t: u64) -> Self {
        self.initial_time = Some(t);
        self
    }

    pub fn secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    pub fn build(self) -> TOTPContext {
        let TOTPBuilder {
            alg,
            period,
            backward_resync,
            forward_resync,
            digits,
            secret,
            initial_time
        } = self;

        let alg = alg.unwrap_or_else(|| OTP_DEFAULT_ALG_VALUE);
        let secret = secret.unwrap_or_else(|| vec![]);
        let secret_key = alg.to_mac_hash_key(secret.as_slice());

        TOTPContext {
            alg,
            period: period.unwrap_or_else(|| TOTP_DEFAULT_PERIOD_VALUE),
            backward_resync: backward_resync.unwrap_or_else(|| TOTP_DEFAULT_BACK_RESYNC_VALUE),
            forward_resync: forward_resync.unwrap_or_else(|| TOTP_DEFAULT_FORWARD_RESYNC_VALUE),
            digits: digits.unwrap_or_else(|| OTP_DEFAULT_DIGITS_VALUE),
            secret,
            secret_key,
            initial_time: initial_time.unwrap_or_else(|| 0),
            clock_drift: 0
        }
    }
}

pub struct TOTPContext {
    alg: HashesAlgorithm,
    period: u64,
    backward_resync: u64,
    forward_resync: u64,
    initial_time: u64,
    clock_drift: i64,
    digits: usize,
    secret: Vec<u8>,
    secret_key: MacHashKey,
}

impl TOTPContext {
    /// Create a new HOTP builder
    pub fn builder() -> TOTPBuilder {
        TOTPBuilder::new()
    }

    /// Generate the current TOTP code corresponding to the counter value
    pub fn gen(&self) -> String {
        self.gen_with(0)

    }

    /// Generate the current TOTP code corresponding to the counter value
    /// Note that elapsed represent the time between the actual time you want in to be generated for and now.
    /// E.g. if you want a code valid exactly 68 sec ago, elapsed value would be 68
    pub fn gen_with(&self, elapsed: u64) -> String {
        let mut counter = ((now_utc().to_timespec().sec as u64 - elapsed - self.initial_time) / self.period) as u64;

        match self.clock_drift {
            d if d > 0 => counter += d.abs() as u64,
            d if d < 0 => counter -= d.abs() as u64,
            _ => {},
        }

        self.gen_at(counter)
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

        let mut counter = ((now_utc().to_timespec().sec as u64 - self.initial_time) / self.period) as u64;

        match self.clock_drift {
            d if d > 0 => counter += d.abs() as u64,
            d if d < 0 => counter -= d.abs() as u64,
            _ => {},
        }

        for i in (counter - self.backward_resync)..(counter + self.forward_resync) {
            if self.gen_at(i).as_str().eq(value) {
                match i {
                    i if i > counter => {
                        let drift = (i - counter) as i64;
                        self.clock_drift += drift;
                    },
                    i if i < counter => {
                        let drift = (counter - i) as i64;
                        self.clock_drift -= drift;
                    },
                    _ => {},
                }
                return true;
            }
        }

        false
    }

    fn gen_at(&self, t: u64) -> String {
        let c_b_e = t.to_be_bytes();

        let hs_sig = self.secret_key.sign(&c_b_e[..]).expect("This should not happen since HMAC can take key of any size").into_vec();
        let s_bits = dt(hs_sig.as_ref());

        let s_num = s_bits % (10 as u32).pow(self.digits as u32);

        format!("{:0>6}", s_num)
    }
}

impl OtpAuth for TOTPContext {
    fn to_uri(&self, label: Option<&str>, issuer: Option<&str>) -> String {
        let mut uri = format!("otpauth://totp/{}?secret={}&algorithm={}&digits={}&period={}",
                              label.unwrap_or_else(|| "slauth"),
                              base32::encode(base32::Alphabet::RFC4648 { padding: false }, self.secret.as_slice()),
                              self.alg.to_string(),
                              self.digits,
                              self.period
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
            type_label_it.next().filter(|otp_type| otp_type.eq(&"totp")).ok_or_else(|| { "Otpauth uri is malformed, bad type".to_string() })?;

            let param_it_opt = type_label_it.next().and_then(|label_param| label_param.split('?').last().map(|s| s.split('&')));

            param_it_opt.ok_or_else(|| { "Otpauth uri is malformed, missing parameters".to_string() })
                .and_then(|param_it| {
                    let mut secret = Vec::<u8>::new();
                    let mut period = TOTP_DEFAULT_PERIOD_VALUE;
                    let mut alg = OTP_DEFAULT_ALG_VALUE;
                    let mut digits = OTP_DEFAULT_DIGITS_VALUE;

                    for s_param in param_it {
                        let mut s_param_it = s_param.split('=');

                        match s_param_it.next() {
                            Some("secret") => {
                                secret = s_param_it.next().and_then(|s| base32::decode(base32::Alphabet::RFC4648 {padding: false}, s)).ok_or_else(|| { "Otpauth uri is malformed, missing secret value".to_string() })?;
                                continue
                            }
                            Some("algorithm") => {
                                alg = match s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing algorithm value".to_string() })? {
                                    "SHA256" => HashesAlgorithm::SHA256,
                                    "SHA512" => HashesAlgorithm::SHA512,
                                    _ => HashesAlgorithm::SHA1,
                                };
                                continue
                            }
                            Some("digits") => {
                                digits = s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing digits value".to_string() })?.parse::<usize>().map_err(|_| "Otpauth uri is malformed, bad digits value".to_string())?;
                                continue
                            }
                            Some("period") => {
                                period = s_param_it.next().ok_or_else(|| { "Otpauth uri is malformed, missing period value".to_string() })?.parse::<u64>().map_err(|_| "Otpauth uri is malformed, bad period value".to_string())?;
                                continue
                            }
                            _ => {}
                        }
                    }

                    if secret.is_empty() {
                        return Err("Otpauth uri is malformed".to_string());
                    }

                    let secret_key = alg.to_mac_hash_key(secret.as_slice());

                    Ok(TOTPContext {
                        alg,
                        period,
                        digits,
                        secret,
                        secret_key,
                        backward_resync: TOTP_DEFAULT_BACK_RESYNC_VALUE,
                        forward_resync: TOTP_DEFAULT_FORWARD_RESYNC_VALUE,
                        initial_time: 0,
                        clock_drift: 0
                    })
                })
        } else {
            Err("Otpauth uri is malformed, missing parts".to_string())
        }
    }
}

#[cfg(feature = "native-bindings")]
mod native_bindings {
    use std::os::raw::{c_char, c_ulong};
    use std::ptr::null_mut;
    use crate::strings;

    use super::*;

    #[no_mangle]
    pub unsafe extern fn totp_from_uri(uri: *const c_char) -> *mut TOTPContext {
        let uri_str = strings::c_char_to_string(uri);
        Box::into_raw(TOTPContext::from_uri(&uri_str).map(|h| Box::new(h)).unwrap_or_else(|_| Box::from_raw(null_mut())))
    }

    #[no_mangle]
    pub unsafe extern fn totp_free(totp: *mut TOTPContext) {
        let _ = Box::from_raw(totp);
    }

    #[no_mangle]
    pub unsafe extern fn totp_to_uri(totp: *mut TOTPContext, label: *const c_char, issuer: *const c_char) -> *mut c_char {
        let totp = &*totp;
        let label = strings::c_char_to_string(label);
        let label_opt = if label.len() > 0 {Some(label.as_str())} else {None};
        let issuer = strings::c_char_to_string(issuer);
        let issuer_opt = if issuer.len() > 0 {Some(issuer.as_str())} else {None};
        strings::string_to_c_char(totp.to_uri(label_opt, issuer_opt))
    }

    #[no_mangle]
    pub unsafe extern fn totp_gen(totp: *mut TOTPContext) -> *mut c_char {
        let totp = &*totp;
        strings::string_to_c_char(totp.gen())
    }

    #[no_mangle]
    pub unsafe extern fn totp_gen_with(totp: *mut TOTPContext, elapsed: c_ulong) -> *mut c_char {
        let totp = &*totp;
        strings::string_to_c_char(totp.gen_with(elapsed as u64))
    }

    #[no_mangle]
    pub unsafe extern fn totp_verify(totp: *mut TOTPContext, code: *const c_char) -> bool {
        let totp = &mut *totp;
        let value = strings::c_char_to_string(code);
        totp.verify(&value)
    }

    #[no_mangle]
    pub unsafe extern fn totp_validate_current(totp: *mut TOTPContext, code: *const c_char) -> bool {
        let totp = &*totp;
        let value = strings::c_char_to_string(code);
        totp.validate_current(&value)
    }
}

#[test]
fn test_multiple() {
    const MK_ULTRA: &'static str = "patate";

    let mut server = TOTPContext::builder().period(5).secret(MK_ULTRA.as_bytes()).build();

    let client = TOTPContext::from_uri(server.to_uri(None, None).as_str()).unwrap();

    for _ in 0..10 {
        use std::thread::sleep;
        use std::time::Duration;
        assert!(server.verify(&client.gen()));
        sleep(Duration::from_secs(5));
    }
}

#[test]
fn test_clock_drifting() {
    const MK_ULTRA: &'static str = "patate";

    let mut server = TOTPContext::builder().period(5).secret(MK_ULTRA.as_bytes()).re_sync_parameter(3, 3).build();

    let client = TOTPContext::from_uri(server.to_uri(None, None).as_str()).unwrap();

    for _ in 0..10 {
        let client_code = client.gen();
        use std::thread::sleep;
        use std::time::Duration;
        sleep(Duration::from_secs(6));
        dbg!(&server.clock_drift);
        assert!(server.verify(&client_code));
    }
}

#[test]
fn test_gen_with() {
    let totp = TOTPContext::from_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example").unwrap();

    let code1 = totp.gen();

    std::thread::sleep(std::time::Duration::from_secs(31));

    let code2 = totp.gen_with(31);

    assert_eq!(code1, code2);
}