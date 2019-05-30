use std::time::Duration;

pub mod hid_const {
    // From : Common U2F HID transport header - Review Draft
    // 2014-10-08

    // Size of HID reports

    pub const HID_RPT_SIZE: usize = 64;      // Default size of raw HID report

    // Frame layout - command- and continuation frames

    pub const CID_BROADCAST: u32 = 0xffffffff; // Broadcast channel id
    pub const CID_BROADCAST_SLICE: [u8;4] = [0xff,0xff,0xff,0xff]; // Broadcast channel id

    pub const TYPE_MASK: u8 = 0x80; // Frame type mask
    pub const TYPE_INIT: u8 = 0x80; // Initial frame identifier
    pub const TYPE_CONT: u8 = 0x00; // Continuation frame identifier

    // HID usage- and usage-page definitions

    pub const FIDO_USAGE_PAGE: u16 = 0xf1d0; // FIDO alliance HID usage page
    pub const FIDO_USAGE_U2FHID: u8 = 0x01; // U2FHID usage for top-level collection
    pub const FIDO_USAGE_DATA_IN: u8 = 0x20; // Raw IN data report
    pub const FIDO_USAGE_DATA_OUT: u8 = 0x21; // Raw OUT data report

    // General constants

    pub const U2FHID_IF_VERSION: usize = 2; // Current interface implementation version
    pub const U2FHID_TRANS_TIMEOUT: usize = 3000; // Default message timeout in ms

    // U2FHID native commands

    pub const U2FHID_PING: u8 = (TYPE_INIT | 0x01); // Echo data through local processor only
    pub const U2FHID_MSG : u8 = (TYPE_INIT | 0x03); // Send U2F message frame
    pub const U2FHID_LOCK: u8 = (TYPE_INIT | 0x04); // Send lock channel command
    pub const U2FHID_INIT: u8 = (TYPE_INIT | 0x06); // Channel initialization
    pub const U2FHID_WINK: u8 = (TYPE_INIT | 0x08); // Send device identification wink
    pub const U2FHID_SYNC: u8 = (TYPE_INIT | 0x3c); // Protocol resync command
    pub const U2FHID_ERROR: u8 = (TYPE_INIT | 0x3f); // Error response

    pub const U2FHID_VENDOR_FIRST: u8 = (TYPE_INIT | 0x40); // First vendor defined command
    pub const U2FHID_VENDOR_LAST: u8 = (TYPE_INIT | 0x7f); // Last vendor defined command

    // U2FHID_INIT command defines

    pub const INIT_NONCE_SIZE: usize = 8; // Size of channel initialization challenge
    pub const CAPFLAG_WINK: u8 = 0x01; // Device supports WINK command

    // Low-level error codes. Return as negatives.

    pub const ERR_NONE: u8 = 0x00; // No error
    pub const ERR_INVALID_CMD: u8 = 0x01; // Invalid command
    pub const ERR_INVALID_PAR: u8 = 0x02; // Invalid parameter
    pub const ERR_INVALID_LEN: u8 = 0x03; // Invalid message length
    pub const ERR_INVALID_SEQ: u8 = 0x04; // Invalid message sequencing
    pub const ERR_MSG_TIMEOUT: u8 = 0x05; // Message has timed out
    pub const ERR_CHANNEL_BUSY: u8 = 0x06; // Channel busy
    pub const ERR_LOCK_REQUIRED: u8 = 0x0a; // Command requires channel lock
    pub const ERR_SYNC_FAIL: u8 = 0x0b; // SYNC command failed
    pub const ERR_OTHER: u8 = 0x7f; // Other unspecified error
}

pub mod hid_type {
    use crate::u2f::hid_proto::hid_const::*;

    pub enum Packet {
        Init {
            cmd: u8, // Frame type - b7 defines type
            bcnth: u8, // Message byte count - high part
            bcntl: u8, // Message byte count - low part
            data: [u8; HID_RPT_SIZE - 7], // Data payload
        },
        Cont {
            seq: u8, // Frame type - b7 defines type
            data: [u8; HID_RPT_SIZE - 5], // Data payload
        }
    }

    pub struct U2fHidFrame {
        cid: u32, // Channel identifier
        packet: Packet
    }

    impl U2fHidFrame {
        #[inline]
        pub fn frame_type(&self) -> u8 {
            match self.packet {
                Packet::Init {cmd, bcnth:_, bcntl:_, data:_} => cmd & TYPE_MASK,
                Packet::Cont {seq, data:_} => seq & TYPE_MASK,
            }
        }

        #[inline]
        pub fn frame_cmd(&self) -> Option<u8> {
            match self.packet {
                Packet::Init {cmd, bcnth:_, bcntl:_, data:_} => Some(cmd & !TYPE_MASK),
                _ => None,
            }
        }

        #[inline]
        pub fn frame_seq(&self) -> Option<u8> {
            match self.packet {
                Packet::Cont {seq, data:_} => Some(seq & !TYPE_MASK),
                _ => None,
            }
        }

        #[inline]
        pub fn msg_len(&self) -> Option<u16> {
            match self.packet {
                Packet::Init {cmd: _, bcnth, bcntl, data:_} => Some(bcnth as u16 * 256 + bcntl as u16),
                _ => None,
            }
        }
    }

    pub struct U2fHidInitReq {
        nonce: [u8; INIT_NONCE_SIZE], // Client application nonce
    }

    pub struct U2fHidInitRsp {
        nonce: [u8; INIT_NONCE_SIZE], // Client application nonce
        cid: u32,// Client application nonce
        interface_version: u8,// Channel identifier
        major_version: u8,// Interface version
        minor_version: u8,// Major version number
        build_version: u8,// Minor version number
        cap_flags: u8,// Build version number
    }

    // U2FHID_SYNC command defines

    pub struct U2fHidSyncReq {
        nonce: u8, // Client application nonce
    }

    pub struct U2fHidSyncRsp {
        nonce: u8, // Client application nonce
    }
}

pub trait KeyStore {
    fn load_key(&self, handle: &str) -> &[u8];
    fn save_key(&self, handle: String, key: Vec<u8>) -> bool;
}

pub trait PresenceValidator {
    fn check_user_presence(&self, timeout: Duration) -> bool;
}

pub struct VirtualHidToken {
    attestation_cert: Vec<u8>,
    attestation_key: Vec<u8>,
    store: Box<KeyStore>,
    check_user_presence_cb: Box<PresenceValidator>,
}