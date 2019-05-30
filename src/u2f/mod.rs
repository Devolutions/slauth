use std::io::Read;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Weak};
use parking_lot::Mutex;

pub mod constants;
pub mod error;
pub mod raw_message;
pub mod hid_proto;

//#[test]
//fn test_mozilla_auth() {
//    use std::io::{Read, Write, Error, Cursor};
//    use sha2::{Sha256, Digest};
//    use authenticator::u2fprotocol::*;
//    use authenticator::u2ftypes::*;
//    use authenticator::consts::{HID_RPT_SIZE, INIT_DATA_SIZE, CONT_DATA_SIZE, TYPE_MASK, TYPE_INIT};
//    use std::cmp;
//
//    pub fn io_err(msg: &str) -> Error {
//        Error::new(std::io::ErrorKind::Other, msg)
//    }
//
//    type ClientStream = Arc<HidStream>;
//
//    struct HidStream {
//        cid: u32,
//        seq: u8,
//        data: Option<Vec<u8>>,
//        shared: Weak<Mutex<DeviceInner>>,
//    }
//
//    impl HidStream {
//        pub fn new(cid: u32, shared: Weak<Mutex<DeviceInner>>) -> Self {
//            HidStream {
//                cid,
//                seq: 0,
//                data: None,
//                shared
//            }
//        }
//    }
//
//    impl U2FDevice for HidStream {
//        fn get_cid(&self) -> &[u8; 4] {
////            &self.cid.to_le_bytes()
//            unimplemented!()
//        }
//
//        fn set_cid(&mut self, cid: [u8; 4]) {
//            unimplemented!()
//        }
//    }
//
//    struct DeviceInner {
//        current_channel_id: AtomicU32,
//        streams: HashMap<u32, ClientStream>,
//    }
//
//    impl DeviceInner {
//        pub fn new() -> Self {
//            DeviceInner {
//                current_channel_id: AtomicU32::new(1),
//                streams: HashMap::new(),
//            }
//        }
//    }
//
//    struct MockDevice {
//        inner: Arc<Mutex<DeviceInner>>,
//    }
//
//    impl MockDevice {
//        pub fn new() -> Self {
//            MockDevice {
//                inner: Arc::new(Mutex::new(DeviceInner::new()))
//            }
//        }
//
//        pub fn get_stream(&self) -> ClientStream {
//            let weak = Arc::downgrade(&self.inner);
//
//            let mut inner = self.inner.lock();
//
//            let cid = inner.current_channel_id.fetch_add(1, SeqCst);
//
//            let h_s = Arc::new(HidStream::new(cid, weak));
//
//            inner.streams.insert(cid, h_s.clone());
//
//            h_s
//        }
//    }
//
//    impl Read for MockDevice {
//        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
//            unimplemented!();
////            let mut cursor = Cursor::new(&mut self.response_data);
////            cursor.read(buf)
//        }
//    }
//
//    impl Write for MockDevice {
//        fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
//            unimplemented!()
////            let buf_len = buf.len();
////            let mut cursor = Cursor::new(buf);
////
//////            while cursor.position() < buf_len {
//////
//////            }
////
////            let mut frame = [0u8; HID_RPT_SIZE];
////            let count = cursor.read(&mut frame)?;
////
////            if count != HID_RPT_SIZE {
////                return Err(io_err("invalid init packet"));
////            }
////
////            if self.get_cid() != &frame[..4] {
////                return Err(io_err("invalid channel id"));
////            }
////
////            if (frame[4] & TYPE_MASK) == TYPE_INIT {
////                let cap = (frame[5] as usize) << 8 | (frame[6] as usize);
////                self.request_data = Vec::with_capacity(cap);
////
////                let len = cmp::min(cap, INIT_DATA_SIZE);
////                self.request_data.extend_from_slice(&frame[7..7 + len]);
////            } else {
////
////            }
////
////            let mut sequence = 0u8;
////
////            while self.request_data.len() < self.request_data.capacity() {
////                let max = self.request_data.capacity() - self.request_data.len();
////
////                let mut frame = [0u8; HID_RPT_SIZE];
////                let count = cursor.read(&mut frame)?;
////
////                if count != HID_RPT_SIZE {
////                    break;
////                }
////
////                if self.get_cid() != &frame[..4] {
////                    return Err(io_err("invalid channel id"));
////                }
////
////                if sequence != frame[4] {
////                    return Err(io_err("invalid sequence number"));
////                }
////
////                let max = cmp::min(max, CONT_DATA_SIZE);
////                self.request_data.extend_from_slice(&frame[5..5 + max]);
////
////                sequence += 1;
////            }
////
////            Ok(cursor.position() as usize)
//        }
//
//        fn flush(&mut self) -> Result<(), Error> {
//            Ok(())
//        }
//    }
//
//    let challenge_str = format!(
//        "{}{}",
//        r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70","#,
//        r#" "version": "U2F_V2", "appId": "https://login.devolutions.net"}"#
//    );
//
//    dbg!(&challenge_str);
//
//    let mut challenge = Sha256::default();
//    challenge.input(challenge_str.as_bytes());
//    let chall_bytes = challenge.result().to_vec();
//
//    let mut application = Sha256::default();
//    application.input(b"https://login.devolutions.net");
//    let app_bytes = application.result().to_vec();
//
//    let mut device = MockDevice::new();
//
////    dbg!(u2f_register(&mut device, &chall_bytes, &app_bytes));
////    dbg!(&device.request_data.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>());
//}