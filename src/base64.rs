pub use base64::Engine as _;
use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(true)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);

const CONFIG_NO_PAD: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(false)
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
pub const BASE64_URLSAFE_NOPAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG_NO_PAD);
