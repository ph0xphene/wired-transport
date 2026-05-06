use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageFormat, RgbaImage};
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256StarStar;
use thiserror::Error;

use crate::dsss::SignalReport;
use crate::{crypto, dsss, ecc, jpeg_dct};

pub(crate) const MAGIC: &[u8; 4] = b"WTR1";
pub(crate) const VERSION: u8 = 1;
pub(crate) const HEADER_LEN: usize = 64;
const HEADER_AUTH_LEN: usize = 44;
const HEADER_TAG_OFFSET: usize = 44;
const HEADER_TAG_LEN: usize = 16;
pub(crate) const HEADER_REPEAT: usize = 31;
pub(crate) const MIN_PAYLOAD_REPEAT: usize = 1;
pub(crate) const MAX_PAYLOAD_REPEAT: usize = 31;
pub(crate) const PUBLIC_HEADER_SEED: [u8; 32] = [
    0x57, 0x49, 0x52, 0x45, 0x44, 0x2d, 0x48, 0x44, 0x52, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, 0x31,
    0x6c, 0x37, 0x2d, 0x73, 0x74, 0x65, 0x67, 0x6f, 0x2d, 0x6d, 0x61, 0x70, 0x2d, 0x76, 0x31, 0x00,
];

#[derive(Clone, Copy, Debug)]
pub struct StegoConfig {
    /// Fraction of total ECC shards that may be lost or corrupted.
    pub recovery_rate: f32,
    /// Number of physical LSB positions used for each encoded payload bit.
    pub bit_repetition: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageContainer {
    Png,
    Jpeg,
}

impl ImageContainer {
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
        }
    }
}

#[derive(Debug)]
pub struct EncodedImage {
    pub bytes: Vec<u8>,
    pub container: ImageContainer,
}

#[derive(Debug)]
pub struct ExtractedData {
    pub data: Vec<u8>,
    pub signal: SignalReport,
}

#[derive(Debug)]
pub struct StressTestReport {
    pub attacked: EncodedImage,
    pub decoded: Vec<u8>,
    pub success: bool,
    pub signal: SignalReport,
}

impl Default for StegoConfig {
    fn default() -> Self {
        Self {
            recovery_rate: 0.25,
            bit_repetition: 15,
        }
    }
}

#[derive(Debug, Error)]
pub enum StegoError {
    #[error("cover image does not have enough RGB capacity")]
    Capacity,
    #[error("invalid or missing wired-transport header")]
    InvalidHeader,
    #[error("unsupported image container")]
    UnsupportedContainer,
    #[error("image codec error: {0}")]
    Image(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("ecc error: {0}")]
    Ecc(#[from] ecc::EccError),
}

pub struct Encoder;

impl Encoder {
    pub fn inject_bytes(input: &[u8], data: &[u8], key: &[u8]) -> Result<EncodedImage, StegoError> {
        Self::inject_bytes_with_config(input, data, key, StegoConfig::default())
    }

    pub fn inject_bytes_with_config(
        input: &[u8],
        data: &[u8],
        key: &[u8],
        config: StegoConfig,
    ) -> Result<EncodedImage, StegoError> {
        match detect_container(input)? {
            ImageContainer::Png => {
                let image = image::load_from_memory_with_format(input, ImageFormat::Png)
                    .map_err(|err| StegoError::Image(err.to_string()))?;
                let encoded = Self::inject_with_config(image, data, key, config)?;
                Ok(EncodedImage {
                    bytes: encode_png(&encoded)?,
                    container: ImageContainer::Png,
                })
            }
            ImageContainer::Jpeg => {
                let image = image::load_from_memory_with_format(input, ImageFormat::Jpeg)
                    .map_err(|err| StegoError::Image(err.to_string()))?;
                let encoded = jpeg_dct::inject_with_config(image, data, key, config)?;
                Ok(EncodedImage {
                    bytes: encode_jpeg(&encoded, 92)?,
                    container: ImageContainer::Jpeg,
                })
            }
        }
    }

    pub fn inject(
        image: DynamicImage,
        data: &[u8],
        key: &[u8],
    ) -> Result<DynamicImage, StegoError> {
        Self::inject_with_config(image, data, key, StegoConfig::default())
    }

    pub fn inject_with_config(
        image: DynamicImage,
        data: &[u8],
        key: &[u8],
        config: StegoConfig,
    ) -> Result<DynamicImage, StegoError> {
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let encrypted = crypto::encrypt(data, key, &salt, &nonce)?;
        let ecc_packet = ecc::encode(&encrypted, config.recovery_rate)?;
        let bit_repetition = config
            .bit_repetition
            .clamp(MIN_PAYLOAD_REPEAT, MAX_PAYLOAD_REPEAT);
        let header = build_header(
            ecc_packet.len() as u64,
            bit_repetition as u8,
            config.recovery_rate,
            &salt,
            &nonce,
        );

        let mut rgba = image.to_rgba8();
        let capacity = lsb_capacity(&rgba);
        let header_slots = HEADER_LEN * 8 * HEADER_REPEAT;
        let payload_slots = ecc_packet.len() * 8 * bit_repetition;
        if header_slots + payload_slots > capacity {
            return Err(StegoError::Capacity);
        }

        let header_indices = mapping_indices(capacity, header_slots, PUBLIC_HEADER_SEED, None)?;
        write_repeated_bits(
            &mut rgba,
            &header_indices,
            &bytes_to_bits(&header),
            HEADER_REPEAT,
        );

        let reserved = reserved_mask(capacity, &header_indices);
        let payload_seed = crypto::mapping_seed(key, &salt);
        let payload_indices =
            mapping_indices(capacity, payload_slots, payload_seed, Some(&reserved))?;
        write_repeated_bits(
            &mut rgba,
            &payload_indices,
            &bytes_to_bits(&ecc_packet),
            bit_repetition,
        );

        Ok(DynamicImage::ImageRgba8(rgba))
    }
}

pub struct Decoder;

impl Decoder {
    pub fn extract_bytes(input: &[u8], key: &[u8]) -> Result<Vec<u8>, StegoError> {
        Ok(Self::extract_bytes_with_report(input, key)?.data)
    }

    pub fn extract_bytes_with_report(
        input: &[u8],
        key: &[u8],
    ) -> Result<ExtractedData, StegoError> {
        match detect_container(input)? {
            ImageContainer::Png => {
                let image = image::load_from_memory_with_format(input, ImageFormat::Png)
                    .map_err(|err| StegoError::Image(err.to_string()))?;
                Ok(ExtractedData {
                    data: Self::extract(image, key)?,
                    signal: SignalReport::default(),
                })
            }
            ImageContainer::Jpeg => {
                let image = image::load_from_memory_with_format(input, ImageFormat::Jpeg)
                    .map_err(|err| StegoError::Image(err.to_string()))?;
                let report = jpeg_dct::extract_with_report(image, key)?;
                Ok(ExtractedData {
                    data: report.data,
                    signal: report.metrics,
                })
            }
        }
    }

    pub fn extract(image: DynamicImage, key: &[u8]) -> Result<Vec<u8>, StegoError> {
        let rgba = image.to_rgba8();
        let capacity = lsb_capacity(&rgba);
        let header_slots = HEADER_LEN * 8 * HEADER_REPEAT;
        if header_slots > capacity {
            return Err(StegoError::Capacity);
        }

        let header_indices = mapping_indices(capacity, header_slots, PUBLIC_HEADER_SEED, None)?;
        let header_bits = read_repeated_bits(&rgba, &header_indices, HEADER_LEN * 8, HEADER_REPEAT);
        let header = bits_to_bytes(&header_bits);
        let parsed = parse_header(&header)?;

        let payload_slots = parsed.packet_len * 8 * parsed.bit_repetition;
        if header_slots + payload_slots > capacity {
            return Err(StegoError::Capacity);
        }

        let reserved = reserved_mask(capacity, &header_indices);
        let payload_seed = crypto::mapping_seed(key, &parsed.salt);
        let payload_indices =
            mapping_indices(capacity, payload_slots, payload_seed, Some(&reserved))?;
        let payload_bits = read_repeated_bits(
            &rgba,
            &payload_indices,
            parsed.packet_len * 8,
            parsed.bit_repetition,
        );
        let packet = bits_to_bytes(&payload_bits);
        let encrypted = ecc::decode(&packet)?;
        let plain = crypto::decrypt(&encrypted, key, &parsed.salt, &parsed.nonce)?;

        Ok(plain)
    }
}

#[derive(Debug)]
pub(crate) struct ParsedHeader {
    pub(crate) packet_len: usize,
    pub(crate) bit_repetition: usize,
    pub(crate) salt: [u8; crypto::SALT_LEN],
    pub(crate) nonce: [u8; crypto::NONCE_LEN],
}

pub(crate) fn build_header(
    packet_len: u64,
    bit_repetition: u8,
    recovery_rate: f32,
    salt: &[u8; crypto::SALT_LEN],
    nonce: &[u8; crypto::NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = bit_repetition;
    let recovery_bps = (recovery_rate.clamp(0.0, 1.0) * 10_000.0).round() as u16;
    header[6..8].copy_from_slice(&recovery_bps.to_be_bytes());
    header[8..16].copy_from_slice(&packet_len.to_be_bytes());
    header[16..32].copy_from_slice(salt);
    header[32..44].copy_from_slice(nonce);
    let tag = crypto::digest16(&[b"wired-transport header v1", &header[..HEADER_AUTH_LEN]]);
    header[HEADER_TAG_OFFSET..HEADER_TAG_OFFSET + HEADER_TAG_LEN].copy_from_slice(&tag);
    header
}

pub(crate) fn parse_header(header: &[u8]) -> Result<ParsedHeader, StegoError> {
    if header.len() != HEADER_LEN || &header[..4] != MAGIC || header[4] != VERSION {
        return Err(StegoError::InvalidHeader);
    }

    let expected = crypto::digest16(&[b"wired-transport header v1", &header[..HEADER_AUTH_LEN]]);
    let actual = &header[HEADER_TAG_OFFSET..HEADER_TAG_OFFSET + HEADER_TAG_LEN];
    if expected.as_slice() != actual {
        return Err(StegoError::InvalidHeader);
    }

    let bit_repetition = header[5] as usize;
    if !(MIN_PAYLOAD_REPEAT..=MAX_PAYLOAD_REPEAT).contains(&bit_repetition) {
        return Err(StegoError::InvalidHeader);
    }

    let packet_len = u64::from_be_bytes(header[8..16].try_into().unwrap()) as usize;
    if packet_len == 0 {
        return Err(StegoError::InvalidHeader);
    }

    let mut salt = [0u8; crypto::SALT_LEN];
    salt.copy_from_slice(&header[16..32]);
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&header[32..44]);

    Ok(ParsedHeader {
        packet_len,
        bit_repetition,
        salt,
        nonce,
    })
}

fn lsb_capacity(image: &RgbaImage) -> usize {
    image.width() as usize * image.height() as usize * 3
}

pub(crate) fn mapping_indices(
    capacity: usize,
    count: usize,
    seed: [u8; 32],
    reserved: Option<&[bool]>,
) -> Result<Vec<usize>, StegoError> {
    let mut indices: Vec<usize> = match reserved {
        Some(mask) => (0..capacity).filter(|idx| !mask[*idx]).collect(),
        None => (0..capacity).collect(),
    };

    if count > indices.len() {
        return Err(StegoError::Capacity);
    }

    let mut rng = Xoshiro256StarStar::from_seed(seed);
    for i in (1..indices.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        indices.swap(i, j);
    }
    indices.truncate(count);
    Ok(indices)
}

pub(crate) fn reserved_mask(capacity: usize, indices: &[usize]) -> Vec<bool> {
    let mut reserved = vec![false; capacity];
    for idx in indices {
        reserved[*idx] = true;
    }
    reserved
}

fn write_repeated_bits(image: &mut RgbaImage, indices: &[usize], bits: &[u8], repeat: usize) {
    for (bit_idx, bit) in bits.iter().enumerate() {
        for copy in 0..repeat {
            write_lsb(image, indices[bit_idx * repeat + copy], *bit);
        }
    }
}

fn read_repeated_bits(
    image: &RgbaImage,
    indices: &[usize],
    bit_count: usize,
    repeat: usize,
) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bit_count);
    for bit_idx in 0..bit_count {
        let mut ones = 0usize;
        for copy in 0..repeat {
            ones += read_lsb(image, indices[bit_idx * repeat + copy]) as usize;
        }
        bits.push((ones * 2 >= repeat) as u8);
    }
    bits
}

fn write_lsb(image: &mut RgbaImage, index: usize, bit: u8) {
    let pixel_index = index / 3;
    let channel = index % 3;
    let x = (pixel_index % image.width() as usize) as u32;
    let y = (pixel_index / image.width() as usize) as u32;
    let pixel = image.get_pixel_mut(x, y);
    pixel.0[channel] = (pixel.0[channel] & 0xfe) | (bit & 1);
}

fn read_lsb(image: &RgbaImage, index: usize) -> u8 {
    let pixel_index = index / 3;
    let channel = index % 3;
    let x = (pixel_index % image.width() as usize) as u32;
    let y = (pixel_index / image.width() as usize) as u32;
    image.get_pixel(x, y).0[channel] & 1
}

pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits
}

pub(crate) fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(bits.len().div_ceil(8));
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for bit in chunk {
            byte = (byte << 1) | (bit & 1);
        }
        if chunk.len() < 8 {
            byte <<= 8 - chunk.len();
        }
        bytes.push(byte);
    }
    bytes
}

pub(crate) fn encode_payload(
    data: &[u8],
    key: &[u8],
    config: StegoConfig,
) -> Result<
    (
        Vec<u8>,
        [u8; crypto::SALT_LEN],
        [u8; crypto::NONCE_LEN],
        usize,
    ),
    StegoError,
> {
    let salt = crypto::random_salt()?;
    let nonce = crypto::random_nonce()?;
    let encrypted = crypto::encrypt(data, key, &salt, &nonce)?;
    let ecc_packet = ecc::encode(&encrypted, config.recovery_rate)?;
    let bit_repetition = config
        .bit_repetition
        .clamp(MIN_PAYLOAD_REPEAT, MAX_PAYLOAD_REPEAT);

    Ok((ecc_packet, salt, nonce, bit_repetition))
}

pub(crate) fn decode_payload(
    packet: &[u8],
    key: &[u8],
    salt: &[u8; crypto::SALT_LEN],
    nonce: &[u8; crypto::NONCE_LEN],
) -> Result<Vec<u8>, StegoError> {
    let encrypted = ecc::decode(packet)?;
    Ok(crypto::decrypt(&encrypted, key, salt, nonce)?)
}

fn detect_container(input: &[u8]) -> Result<ImageContainer, StegoError> {
    if input.starts_with(b"\x89PNG\r\n\x1a\n") {
        Ok(ImageContainer::Png)
    } else if input.starts_with(&[0xff, 0xd8, 0xff]) {
        Ok(ImageContainer::Jpeg)
    } else {
        Err(StegoError::UnsupportedContainer)
    }
}

fn encode_png(image: &DynamicImage) -> Result<Vec<u8>, StegoError> {
    let mut out = Cursor::new(Vec::new());
    image
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|err| StegoError::Image(err.to_string()))?;
    Ok(out.into_inner())
}

fn encode_jpeg(image: &DynamicImage, quality: u8) -> Result<Vec<u8>, StegoError> {
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
    encoder
        .encode_image(image)
        .map_err(|err| StegoError::Image(err.to_string()))?;
    Ok(out)
}

pub fn simulate_attack(input: &[u8], quality: u8) -> Result<EncodedImage, StegoError> {
    let image = image::load_from_memory(input).map_err(|err| StegoError::Image(err.to_string()))?;
    Ok(EncodedImage {
        bytes: encode_jpeg(&image, quality)?,
        container: ImageContainer::Jpeg,
    })
}

pub fn stress_test(
    input: &[u8],
    payload: &[u8],
    key: &[u8],
    quality: u8,
    config: StegoConfig,
) -> Result<StressTestReport, StegoError> {
    let carrier =
        image::load_from_memory(input).map_err(|err| StegoError::Image(err.to_string()))?;
    let injected = jpeg_dct::inject_with_report(carrier, payload, key, config)?;
    let encoded = encode_jpeg(&injected.image, 92)?;
    let attacked = simulate_attack(&encoded, quality)?;
    let attacked_image = image::load_from_memory_with_format(&attacked.bytes, ImageFormat::Jpeg)
        .map_err(|err| StegoError::Image(err.to_string()))?;
    let extracted = jpeg_dct::extract_with_report(attacked_image, key)?;
    let raw_ber = dsss::bit_error_rate(&injected.packet_bits, &extracted.packet_bits);
    let mut signal = extracted.metrics;
    signal.raw_ber = raw_ber;
    signal.psnr_db = injected.psnr_db;
    let success = extracted.data == payload;

    Ok(StressTestReport {
        attacked,
        decoded: extracted.data,
        success,
        signal,
    })
}

#[cfg(test)]
mod tests {
    use image::codecs::jpeg::JpegEncoder;
    use image::{ImageBuffer, Rgba};
    use image::{Rgb, RgbImage};
    use rand::seq::SliceRandom;
    use rand::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn round_trips_payload_through_pixels() {
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_pixel(
            256,
            256,
            Rgba([0x22, 0x33, 0x44, 0xff]),
        ));
        let key = b"test-key";
        let payload = b"classified transit manifest".repeat(8);

        let encoded = Encoder::inject(image, &payload, key).unwrap();
        let decoded = Decoder::extract(encoded, key).unwrap();

        assert_eq!(decoded, payload);
    }

    #[test]
    fn recovers_after_random_lsb_noise_on_twenty_percent_pixels() {
        let image = DynamicImage::ImageRgba8(ImageBuffer::from_pixel(
            512,
            512,
            Rgba([0x22, 0x33, 0x44, 0xff]),
        ));
        let key = b"test-key";
        let payload = b"resilient manifest".repeat(6);

        let encoded = Encoder::inject(image, &payload, key).unwrap();
        let mut noisy = encoded.to_rgba8();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let pixel_count = (noisy.width() * noisy.height()) as usize;
        let mut pixels: Vec<usize> = (0..pixel_count).collect();
        pixels.shuffle(&mut rng);

        for pixel_idx in pixels.into_iter().take(pixel_count / 5) {
            let x = (pixel_idx % noisy.width() as usize) as u32;
            let y = (pixel_idx / noisy.width() as usize) as u32;
            let pixel = noisy.get_pixel_mut(x, y);
            for channel in 0..3 {
                pixel.0[channel] = (pixel.0[channel] & 0xfe) | ((rng.next_u32() as u8) & 1);
            }
        }

        let decoded = Decoder::extract(DynamicImage::ImageRgba8(noisy), key).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn stress_test_reports_dsss_metrics_at_quality_50() {
        let carrier = DynamicImage::ImageRgb8(RgbImage::from_fn(512, 512, |x, y| {
            let base = 96 + ((x + y) % 64) as u8;
            Rgb([
                base,
                base.saturating_add(((x / 8) % 16) as u8),
                base.saturating_sub(((y / 8) % 16) as u8),
            ])
        }));
        let mut input = Vec::new();
        JpegEncoder::new_with_quality(&mut input, 92)
            .encode_image(&carrier)
            .unwrap();

        let report = stress_test(
            &input,
            b"dsss adversarial payload",
            b"stress-key",
            50,
            StegoConfig {
                recovery_rate: 0.25,
                bit_repetition: 16,
            },
        )
        .unwrap();

        assert!(report.success);
        assert!(report.signal.average_correlation_peak > 1.0);
        assert!(report.signal.raw_ber.unwrap() < 0.25);
        assert!(report.signal.psnr_db.unwrap().is_finite());
    }
}
