use std::io::{Cursor, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::u2f::constants::*;
use crate::u2f::error::Error;
use crate::u2f::message::apdu::{ApduFrame, Request, Response};

pub struct RegisterRequest {
    challenge: [u8; 32],
    application: [u8; 32],
}

pub struct RegisterResponse {
    reserved: u8,
    user_public_key: [u8; 65],
    key_handle_lenght: u8,
    attestation_cert: Vec<u8>,
    signature: Vec<u8>,
}

pub struct AuthenticateRequest {
    control: u8,
    challenge: [u8; 32],
    application: [u8; 32],
    key_h_len: u8,
    key_handle: Vec<u8>,
}

pub struct AuthenticateResponse {
    user_presence: u8,
    counter: u32,
    signature: Vec<u8>,
}

pub struct VersionRequest {}

pub struct VersionResponse {
    version: String,
}

pub trait Message {
    type Apdu: ApduFrame;
    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized;
    fn into_apdu(self) -> Result<Self::Apdu, Error>;
}

impl Message for RegisterRequest {
    type Apdu = Request;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.command_mode != REGISTER_COMMAND_CODE {
            return Err(Error::UnexpectedApdu(format!("Expecting Register Command Mode, got {}", apdu.command_mode)));
        }

        if apdu.data_len.filter(|l| *l == 64).is_none() {
            return Err(Error::MalformedApdu);
        }

        apdu.data.ok_or(Error::MalformedApdu).and_then(|data| {
            let mut cursor = Cursor::new(data);

            let mut challenge = [0u8; 32];

            cursor.read_exact(&mut challenge)?;

            let mut application = [0u8; 32];

            cursor.read_exact(&mut application)?;

            Ok(RegisterRequest {
                challenge,
                application,
            })
        })
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        let RegisterRequest {
            challenge,
            application,
        } = self;

        let mut data = Vec::new();

        data.extend_from_slice(&challenge);
        data.extend_from_slice(&application);

        Ok(Request {
            class_byte: 0,
            command_mode: REGISTER_COMMAND_CODE,
            param_1: 0,
            param_2: 0,
            data_len: Some(64),
            data: Some(data),
            max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED),
        })
    }
}

impl Message for RegisterResponse {
    type Apdu = Response;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.status != SW_NO_ERROR {
            return Err(apdu.status.into());
        }

        apdu.data.ok_or(Error::MalformedApdu).and_then(|data| {
            let data_len = data.len();
            let mut cursor = Cursor::new(data);
            let reserved = cursor.read_u8()?;

            let mut user_public_key = [0u8; 65];
            cursor.read_exact(&mut user_public_key)?;

            let key_handle_lenght = cursor.read_u8()?;

            let mut attestation_cert = vec![0u8; key_handle_lenght as usize];
            cursor.read_exact(&mut attestation_cert[..])?;

            let mut signature = vec![0u8; data_len - cursor.position() as usize];
            cursor.read_exact(&mut signature[..])?;

            Ok(RegisterResponse {
                reserved,
                user_public_key,
                key_handle_lenght,
                attestation_cert,
                signature,
            })
        })
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        let RegisterResponse {
            reserved,
            user_public_key,
            key_handle_lenght,
            attestation_cert,
            signature,
        } = self;

        let mut data = Vec::new();

        data.write_u8(reserved)?;
        data.write_all(&user_public_key)?;
        data.write_u8(key_handle_lenght)?;
        data.write_all(&attestation_cert)?;
        data.write_all(&signature)?;

        Ok(Response {
            data: Some(data),
            status: SW_NO_ERROR,
        })
    }
}

impl Message for AuthenticateRequest {
    type Apdu = Request;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.command_mode != AUTHENTICATE_COMMAND_CODE {
            return Err(Error::UnexpectedApdu(format!("Expecting Version Command Mode, got {}", apdu.command_mode)));
        }

        let control = apdu.param_1;

        match control {
            AUTHENTICATE_CHECK_ONLY | AUTHENTICATE_ENFORCE_PRESENCE | AUTHENTICATE_DONT_ENFORCE_PRESENCE => {}
            _ => {return Err(Error::MalformedApdu);}
        }


        apdu.data.ok_or(Error::MalformedApdu).and_then(move |data| {
            let mut cursor = Cursor::new(data);

            let mut challenge = [0u8; 32];
            cursor.read_exact(&mut challenge)?;

            let mut application = [0u8; 32];
            cursor.read_exact(&mut application)?;

            let key_h_len = cursor.read_u8()?;
            let mut key_handle = vec![0u8; key_h_len as usize];
            cursor.read_exact(&mut key_handle[..])?;

            Ok(AuthenticateRequest {
                control,
                challenge,
                application,
                key_h_len,
                key_handle
            })
        })
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        let AuthenticateRequest {
            control,
            challenge,
            application,
            key_h_len,
            key_handle
        } = self;

        let mut data = Vec::new();

        data.write_all(&challenge)?;
        data.write_all(&application)?;

        data.write_u8(key_h_len)?;
        data.write_all(&key_handle)?;

        let data_len = data.len();

        Ok(Request {
            class_byte: 0,
            command_mode: AUTHENTICATE_COMMAND_CODE,
            param_1: control,
            param_2: 0,
            data_len: Some(data_len),
            data: Some(data),
            max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED)
        })
    }
}

impl Message for AuthenticateResponse {
    type Apdu = Response;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.status != SW_NO_ERROR {
            return Err(apdu.status.into());
        }

        apdu.data.ok_or(Error::MalformedApdu).and_then(|data| {
            let data_len = data.len();
            let mut cursor = Cursor::new(data);

            let user_presence = cursor.read_u8()?;
            let counter = cursor.read_u32::<BigEndian>()?;

            let mut signature = vec![0u8; data_len - cursor.position() as usize];
            cursor.read_exact(&mut signature[..])?;

            Ok(AuthenticateResponse {
                user_presence,
                counter,
                signature,
            })
        })
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        let AuthenticateResponse {
            user_presence,
            counter,
            mut signature,
        } = self;

        let mut data = Vec::new();

        data.write_u8(user_presence)?;

        data.write_u32::<BigEndian>(counter)?;

        data.append(&mut signature);

        Ok(Response {
            data: Some(data),
            status: SW_NO_ERROR
        })
    }
}

impl Message for VersionRequest {
    type Apdu = Request;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.command_mode != VERSION_COMMAND_CODE {
            return Err(Error::UnexpectedApdu(format!("Expecting Version Command Mode, got {}", apdu.command_mode)));
        }

        Ok(VersionRequest {})
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        Ok(Request {
            class_byte: 0,
            command_mode: VERSION_COMMAND_CODE,
            param_1: 0,
            param_2: 0,
            data_len: None,
            data: None,
            max_rsp_len: Some(MAX_RESPONSE_LEN_EXTENDED),
        })
    }
}

impl Message for VersionResponse {
    type Apdu = Response;

    fn from_apdu(apdu: Self::Apdu) -> Result<Self, Error> where Self: Sized {
        if apdu.status != SW_NO_ERROR {
            return Err(apdu.status.into());
        }

        apdu.data.ok_or(Error::MalformedApdu).and_then(|data| {
            Ok(VersionResponse {
                version: String::from_utf8(data).map_err(|e| Error::UnexpectedApdu(format!("Got error while parsing version string: {:?}", e)))?
            })
        })
    }

    fn into_apdu(self) -> Result<Self::Apdu, Error> {
        Ok(Response {
            data: Some(self.version.as_bytes().to_vec()),
            status: SW_NO_ERROR
        })
    }
}

pub mod apdu {
    use std::io::{Cursor, Read, Write};

    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

    use crate::u2f::constants::{MAX_RESPONSE_LEN_EXTENDED, MAX_RESPONSE_LEN_SHORT};
    use crate::u2f::error::Error;

    pub trait ApduFrame {
        fn read_from(slice: &[u8]) -> Result<Self, Error>
            where
                Self: Sized;
        fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error>;
        fn get_frame_size(&self) -> usize;
    }

    pub struct Request {
        pub class_byte: u8,
        pub command_mode: u8,
        pub param_1: u8,
        pub param_2: u8,
        pub data_len: Option<usize>,
        pub data: Option<Vec<u8>>,
        pub max_rsp_len: Option<usize>,
    }

    impl ApduFrame for Request {
        fn read_from(slice: &[u8]) -> Result<Self, Error>
            where
                Self: Sized {
            let slice_len = slice.len();
            let mut reader = Cursor::new(slice);
            let class_byte = reader.read_u8()?;
            let command_mode = reader.read_u8()?;
            let param_1 = reader.read_u8()?;
            let param_2 = reader.read_u8()?;

            let mut data_len = None;
            let mut data = None;
            let mut max_rsp_len = None;

            // Try to figure out if this is short of extended encoding
            // assuming this slice where b1 to b4 may not be present
            //
            //              +--+--+--+--+--+--+--+--+
            //              |cl|in|p1|p2|b1|b2|b3|b4|
            //              +--+--+--+--+--+--+--+--+
            // (0) if b1 don't exists --> L_c N_c and L_e are omitted
            // (1) if b2 don't exists --> b1 is L_e, L_c is omitted
            //     if b2 exists --> check 2 more bytes
            //          if b3 don't exists -> Short Enc
            // (2)          if b1 = 0x01 --> b1 is L_c, data is b2, L_e is omitted
            //          if b3 exists
            //              if b4 don't exists
            // (3)              if b1 is 0x00 --> Extended enc, L_e is BE(b2, b3), L_c is omitted
            // (4)              if b1 is 0x01 --> b1 is L_c, data is b2, L_e is b3
            //              if b4 exists
            // (5)              if b1 is 0x00 --> extended encoding
            // (6)              if b1 is not 0x00 --> short encoding
            {
                let remaining_len = slice_len - reader.position() as usize;

                match remaining_len {
                    1 => {
                        // (1)
                        let l_e = reader.read_u8()?;
                        if l_e == 0x00 {
                            max_rsp_len = Some(MAX_RESPONSE_LEN_SHORT)
                        } else {
                            max_rsp_len = Some(l_e as usize)
                        };
                    }
                    2 => {
                        // (2)
                        let l_c = reader.read_u8()?;
                        if l_c != 0x01 {
                            return Err(Error::MalformedApdu);
                        }
                        data_len = Some(l_c as usize);
                        let mut data_vec = vec![0u8; l_c as usize];
                        reader.read_exact(&mut data_vec[..])?;
                        data = Some(data_vec);
                    }
                    3 => {
                        let b_1 = reader.read_u8()?;
                        if b_1 == 0x00 {
                            // (3)
                            let l_e = reader.read_u16::<BigEndian>()?;
                            if l_e == 0x0000 {
                                max_rsp_len = Some(MAX_RESPONSE_LEN_EXTENDED);
                            } else {
                                max_rsp_len = Some(l_e as usize);
                            }
                        } else if b_1 == 0x01 {
                            // (4)
                            let mut data_vec = vec![0u8; b_1 as usize];
                            reader.read_exact(&mut data_vec[..])?;
                            data_len = Some(b_1 as usize);
                            data = Some(data_vec);
                            let l_e = reader.read_u8()?;
                            if l_e == 0x00 {
                                max_rsp_len = Some(MAX_RESPONSE_LEN_SHORT)
                            } else {
                                max_rsp_len = Some(l_e as usize)
                            };
                        } else {
                            return Err(Error::MalformedApdu);
                        }
                    }
                    len if len > 3 => {
                        let b_1 = reader.read_u8()?;
                        if b_1 == 0x00 {
                            // (5)
                            let l_c = reader.read_u16::<BigEndian>()?;
                            let mut data_vec = vec![0u8; l_c as usize];
                            reader.read_exact(&mut data_vec[..])?;
                            let l_e = reader.read_u16::<BigEndian>()?;
                            data_len = Some(l_c as usize);
                            data = Some(data_vec);
                            if l_e == 0x0000 {
                                max_rsp_len = Some(MAX_RESPONSE_LEN_EXTENDED);
                            } else {
                                max_rsp_len = Some(l_e as usize);
                            }
                        } else {
                            // (6)
                            let mut data_vec = vec![0u8; b_1 as usize];
                            reader.read_exact(&mut data_vec[..])?;
                            data_len = Some(b_1 as usize);
                            data = Some(data_vec);
                            let l_e = reader.read_u8()?;
                            if l_e == 0x00 {
                                max_rsp_len = Some(MAX_RESPONSE_LEN_SHORT)
                            } else {
                                max_rsp_len = Some(l_e as usize)
                            };
                        }
                    }
                    _ => {}
                }
            }

            Ok(Request {
                class_byte,
                command_mode,
                param_1,
                param_2,
                data_len,
                data,
                max_rsp_len,
            })
        }

        fn write_to<W: Write + WriteBytesExt>(self, writer: &mut W) -> Result<(), Error> {
            let Request {
                class_byte,
                command_mode,
                param_1,
                param_2,
                data_len,
                data,
                max_rsp_len
            } = self;

            let _ = writer.write_u8(class_byte)?;
            let _ = writer.write_u8(command_mode)?;
            let _ = writer.write_u8(param_1)?;
            let _ = writer.write_u8(param_2)?;

            let mut l_e_offset = true;

            if let Some((data_len, mut data)) = data_len.and_then(|l| data.and_then(move |d| Some((l, d)))) {
                l_e_offset = false;
                let _ = writer.write_u8(0x00)?;
                let _ = writer.write_u16::<BigEndian>(data_len as u16)?;
                let _ = writer.write_all(&mut data[..])?;
            }

            if let Some(max_len) = max_rsp_len {
                if l_e_offset {
                    let _ = writer.write_u8(0x00)?;
                }

                if max_len == MAX_RESPONSE_LEN_EXTENDED {
                    let _ = writer.write_u16::<BigEndian>(0x0000)?;
                } else {
                    let _ = writer.write_u16::<BigEndian>(max_len as u16)?;
                }
            }

            Ok(())
        }

        fn get_frame_size(&self) -> usize {
            let mut len = 4;
            let mut need_offset = false;

            if let Some(ref data_len) = self.data_len {
                if *data_len > 0 {
                    len += data_len + 2; // len of the request data + 2 byte for the extended encoding of the length
                    need_offset = true;
                }
            }

            if let Some(ref max_rsp_len) = self.max_rsp_len {
                if *max_rsp_len > 0 {
                    len += 2;
                    need_offset = true;
                }
            }

            if need_offset {
                len += 1;
            }

            len
        }
    }

    pub struct Response {
        pub data: Option<Vec<u8>>,
        pub status: u16,
    }

    impl ApduFrame for Response {
        fn read_from(slice: &[u8]) -> Result<Self, Error> where
            Self: Sized {
            let slice_len = slice.len();


            let rsp_data = &slice[0..slice_len - 2];

            let status = (&slice[slice_len - 2..slice_len]).read_u16::<BigEndian>()?;

            let data = if rsp_data.len() > 0 {
                Some(rsp_data.to_vec())
            } else {
                None
            };

            Ok(Response {
                data,
                status,
            })
        }

        fn write_to<W: Write + WriteBytesExt>(self, writer: &mut W) -> Result<(), Error> {
            let Response {
                data,
                status,
            } = self;

            if let Some(mut data) = data {
                let _ = writer.write_all(&mut data[..])?;
            }

            Ok(writer.write_u16::<BigEndian>(status)?)
        }

        fn get_frame_size(&self) -> usize {
            let mut len = 2; // status bytes
            if let Some(ref data) = self.data {
                len += data.len();
            }
            len
        }
    }
}

pub trait MessageFrame {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error>
        where
            Self: Sized;
    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error>;
    fn get_size(&self) -> usize;
}