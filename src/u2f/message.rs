use std::any::TypeId;
use std::cmp::Ordering;
use std::io::{Error, ErrorKind, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::u2f::constants::*;

pub struct Request<T = Vec<u8>> {
    header: AdpuHeader,
    data_len: Option<Lenght>,
    data: Option<T>,
    max_rsp_len: Option<Lenght>,
}

impl<T> Request<T> {
    pub fn map<F, U>(self, map: F) -> Request<U> where F: FnOnce(Option<T>) -> Option<U> {
        let Request {
            header,
            data_len,
            data,
            max_rsp_len,
        } = self;

        let data_u = map(data);

        Request {
            header,
            data_len,
            data: data_u,
            max_rsp_len,
        }
    }
}

impl Request<Vec<u8>> {
    fn into<T: MessageFrame + 'static>(self) -> Result<Request<T>, Error> {
        let Request {
            header,
            data_len,
            data,
            max_rsp_len,
        } = self;

        let data_u = data.map(|data_vec| T::read_from(&mut data_vec.as_slice())).transpose()?;

        Ok(Request::<T> {
            header,
            data_len,
            data: data_u,
            max_rsp_len,
        })
    }

    pub fn into_register(self) -> Result<Request<Register>, Error> {
        self.into()
    }

    pub fn into_authenticate(self) -> Result<Request<Authenticate>, Error> {
        self.into()
    }

    pub fn into_version(self) -> Result<Request<Version>, Error> {
        self.into()
    }

    pub fn into_vendor<T: MessageFrame + 'static>(self) -> Result<Request<T>, Error> {
        self.into()
    }
}

impl<T> MessageFrame for Request<T> where T: MessageFrame + 'static {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        let header = AdpuHeader::read_from(reader)?;

        let type_id = TypeId::of::<T>();

        match header.command_mode {
            REGISTER_COMMAND_CODE => { if type_id != TypeId::of::<Register>() { return Err(Error::from(ErrorKind::InvalidData)); } }
            AUTHENTICATE_COMMAND_CODE => { if type_id != TypeId::of::<Authenticate>() { return Err(Error::from(ErrorKind::InvalidData)); } }
            VERSION_COMMAND_CODE => { if type_id != TypeId::of::<Version>() { return Err(Error::from(ErrorKind::InvalidData)); } }
            _ => {}
        }

        let data_len = match Lenght::read_from(reader) {
            Ok(l) => Some(l),
            Err(e) => { if e.kind() == ErrorKind::UnexpectedEof { None } else { return Err(e); } }
        };

        let data = data_len.as_ref().and_then(|data_len| {
            if data_len > &0u8 {
                Some(T::read_from(reader))
            } else {
                None
            }
        }).transpose()?;

        let max_rsp_len = match Lenght::read_from(reader) {
            Ok(l) => Some(l),
            Err(e) => { if e.kind() == ErrorKind::UnexpectedEof { None } else { return Err(e); } }
        };

        Ok(Request {
            header,
            data_len,
            data,
            max_rsp_len,
        })
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let Request {
            header,
            data_len,
            data,
            max_rsp_len,
        } = self;

        header.write_to(writer)?;
        if let Some(l) = data_len {
            l.write_to(writer)?;
        }

        if let Some(d) = data {
            d.write_to(writer)?;
        }

        if let Some(l) = max_rsp_len {
            l.write_to(writer)?;
        }

        Ok(())
    }

    fn get_size(&self) -> usize {
        self.header.get_size()
            + self.data_len.as_ref().map(|t| t.get_size()).unwrap_or_else(|| 0)
            + self.data.as_ref().map(|t| t.get_size()).unwrap_or_else(|| 0)
            + self.max_rsp_len.as_ref().map(|t| t.get_size()).unwrap_or_else(|| 0)
    }
}

impl MessageFrame for Request<Vec<u8>> {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        let header = AdpuHeader::read_from(reader)?;

        let data_len = match Lenght::read_from(reader) {
            Ok(l) => Some(l),
            Err(e) => { if e.kind() == ErrorKind::UnexpectedEof { None } else { return Err(e); } }
        };

        let data = data_len.as_ref().and_then(|data_len| {
            if data_len > &0u8 {
                let mut data = vec![0u8; data_len.usize()];
                Some(reader.read_exact(&mut data[..]).map(move |_| data))
            } else {
                None
            }
        }).transpose()?;

        let max_rsp_len = match Lenght::read_from(reader) {
            Ok(l) => Some(l),
            Err(e) => { if e.kind() == ErrorKind::UnexpectedEof { None } else { return Err(e); } }
        };

        Ok(Request {
            header,
            data_len,
            data,
            max_rsp_len,
        })
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let Request {
            header,
            data_len,
            data,
            max_rsp_len,
        } = self;

        header.write_to(writer)?;
        if let Some(l) = data_len {
            l.write_to(writer)?;
        }

        if let Some(mut d) = data {
            writer.write_all(&mut d)?;
        }

        if let Some(l) = max_rsp_len {
            l.write_to(writer)?;
        }

        Ok(())
    }

    fn get_size(&self) -> usize {
        self.header.get_size()
            + self.data_len.as_ref().map(|t| t.get_size()).unwrap_or_else(|| 0)
            + self.data.as_ref().map(|t| t.len()).unwrap_or_else(|| 0)
            + self.max_rsp_len.as_ref().map(|t| t.get_size()).unwrap_or_else(|| 0)
    }
}

impl<T> Request<T> where T: MessageFrame + 'static {}

pub struct AdpuHeader {
    class_byte: u8,
    command_mode: u8,
    param_1: u8,
    param_2: u8,
}

impl MessageFrame for AdpuHeader {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        let class_byte = reader.read_u8()?;
        let command_mode = reader.read_u8()?;
        let param_1 = reader.read_u8()?;
        let param_2 = reader.read_u8()?;

        match command_mode {
            REGISTER_COMMAND_CODE => { if param_1 != 0 || param_2 != 0 { return Err(Error::from(ErrorKind::InvalidData)); } }
            AUTHENTICATE_COMMAND_CODE => {
                let p1 = param_1 == AUTHENTICATE_CHECK_ONLY || param_1 == AUTHENTICATE_ENFORCE_PRESENCE || param_1 == AUTHENTICATE_DONT_ENFORCE_PRESENCE;
                if !p1 || param_2 != 0 { return Err(Error::from(ErrorKind::InvalidData)); }
            }
            VERSION_COMMAND_CODE => { if param_1 != 0 || param_2 != 0 { return Err(Error::from(ErrorKind::InvalidData)); } }
            ins => {
                if ins <= VENDOR_FIRST_COMMAND_CODE || ins >= VENDOR_LAST_COMMAND_CODE {
                    return Err(Error::from(ErrorKind::InvalidData));
                }
            }
        }

        Ok(AdpuHeader {
            class_byte,
            command_mode,
            param_1,
            param_2,
        })
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let AdpuHeader {
            class_byte: _class_byte,
            command_mode,
            param_1,
            param_2
        } = self;
        // Class byte shall be 0
        writer.write_u8(0)?;
        writer.write_u8(command_mode)?;
        writer.write_u8(param_1)?;
        writer.write_u8(param_2)
    }

    fn get_size(&self) -> usize {
        4
    }
}

pub struct Register {
    challenge: [u8; 32],
    application: [u8; 32],
}

impl MessageFrame for Register {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        let mut challenge = [0; 32];
        reader.read_exact(&mut challenge)?;

        let mut application = [0; 32];
        reader.read_exact(&mut application)?;

        Ok(Register {
            challenge,
            application,
        })
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let Register {
            mut challenge,
            mut application,
        } = self;
        writer.write_all(&mut challenge)?;
        writer.write_all(&mut application)
    }

    fn get_size(&self) -> usize {
        REGISTER_REQUEST_DATA_LEN
    }
}

pub struct Authenticate {
    control: u8,
    challenge: [u8; 32],
    application: [u8; 32],
    key_h_len: u8,
    key_handle: Vec<u8>,
}

impl MessageFrame for Authenticate {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        let control = reader.read_u8()?;
        let mut challenge = [0; 32];
        reader.read_exact(&mut challenge)?;

        let mut application = [0; 32];
        reader.read_exact(&mut application)?;

        let key_h_len = reader.read_u8()?;

        let mut key_handle = vec![0; key_h_len as usize];
        reader.read_exact(&mut key_handle[..])?;

        Ok(Authenticate {
            control,
            challenge,
            application,
            key_h_len,
            key_handle,
        })
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        let Authenticate {
            control,
            mut challenge,
            mut application,
            key_h_len,
            mut key_handle,
        } = self;

        writer.write_u8(control)?;

        writer.write_all(&mut challenge)?;
        writer.write_all(&mut application)?;

        writer.write_u8(key_h_len)?;

        writer.write_all(&mut key_handle)
    }

    fn get_size(&self) -> usize {
        AUTHENTICATE_REQUEST_DATA_FIXED_LEN + self.key_handle.len()
    }
}

pub struct Version {}

impl MessageFrame for Version {
    fn read_from<R: Read>(_reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        Ok(Version {})
    }

    fn write_to<W: Write>(self, _writer: &mut W) -> Result<(), Error> {
        Ok(())
    }

    fn get_size(&self) -> usize {
        0
    }
}

pub enum Lenght {
    Short(u8),
    Extended(u16),
}

impl Lenght {
    fn usize(&self) -> usize {
        match self {
            Lenght::Short(ref len) => len.clone() as usize,
            Lenght::Extended(ref len) => len.clone() as usize,
        }
    }
}

impl PartialEq<u8> for Lenght {
    fn eq(&self, other: &u8) -> bool {
        match self {
            Lenght::Short(ref len) => len.eq(other),
            Lenght::Extended(ref len) => (len.clone() as u8).eq(other),
        }
    }
}

impl PartialEq<u16> for Lenght {
    fn eq(&self, other: &u16) -> bool {
        match self {
            Lenght::Short(ref len) => (len.clone() as u16).eq(other),
            Lenght::Extended(ref len) => len.eq(other),
        }
    }
}

impl PartialOrd<u8> for Lenght {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> {
        match self {
            Lenght::Short(ref len) => len.partial_cmp(other),
            Lenght::Extended(ref len) => (len.clone() as u8).partial_cmp(other),
        }
    }
}

impl PartialOrd<u16> for Lenght {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> {
        match self {
            Lenght::Short(ref len) => (len.clone() as u16).partial_cmp(other),
            Lenght::Extended(ref len) => len.partial_cmp(other),
        }
    }
}

impl MessageFrame for Lenght {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error> where
        Self: Sized {
        // ATM only extended Length encoding is read with the following assumption L_c is present
        let _zero_byte = reader.read_u8()?;
        let len = reader.read_u16::<BigEndian>()?;

        Ok(Lenght::Extended(len))
    }

    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error> {
        match self {
            Lenght::Short(len) => {
                writer.write_u8(len)
            }
            Lenght::Extended(len) => {
                // zero_byte
                writer.write_u8(0)?;
                writer.write_u16::<BigEndian>(len)
            }
        }
    }

    fn get_size(&self) -> usize {
        match self {
            Lenght::Short(_) => 1,
            Lenght::Extended(_) => 3,
        }
    }
}

pub trait MessageFrame {
    #[inline]
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, Error>
        where
            Self: Sized;
    #[inline]
    fn write_to<W: Write>(self, writer: &mut W) -> Result<(), Error>;
    #[inline]
    fn get_size(&self) -> usize;
}