use image::{DynamicImage, RgbImage};

use crate::dsss::{DsssConfig, SignalReport};
use crate::stego_engine::{
    bits_to_bytes, build_header, bytes_to_bits, decode_payload, encode_payload, mapping_indices,
    parse_header, reserved_mask, StegoConfig, StegoError, HEADER_LEN, MAX_PAYLOAD_REPEAT,
    PUBLIC_HEADER_SEED,
};
use crate::{crypto, dsss};

const BLOCK: usize = 8;
const JPEG_RECOVERY_QUALITY: u8 = 75;
const MID_ZIGZAG_START: usize = 5;
const MID_ZIGZAG_END: usize = 50;
const HEADER_CHIPS_PER_SYMBOL: usize = 32;
const MIN_PAYLOAD_CHIPS_PER_SYMBOL: usize = 16;
const DSSS_GAIN: i32 = 2;

const LUMA_Q50: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

pub fn inject_with_config(
    image: DynamicImage,
    data: &[u8],
    key: &[u8],
    config: StegoConfig,
) -> Result<DynamicImage, StegoError> {
    Ok(inject_with_report(image, data, key, config)?.image)
}

pub fn inject_with_report(
    image: DynamicImage,
    data: &[u8],
    key: &[u8],
    config: StegoConfig,
) -> Result<JpegInjectReport, StegoError> {
    let (ecc_packet, salt, nonce, bit_repetition) = encode_payload(data, key, config)?;
    let payload_chips = bit_repetition
        .max(MIN_PAYLOAD_CHIPS_PER_SYMBOL)
        .min(MAX_PAYLOAD_REPEAT);
    let header = build_header(
        ecc_packet.len() as u64,
        payload_chips as u8,
        config.recovery_rate,
        &salt,
        &nonce,
    );

    let original_rgb = image.to_rgb8();
    let mut rgb = original_rgb.clone();
    let layout = Layout::new(rgb.width() as usize, rgb.height() as usize)?;
    let capacity = layout.capacity();
    let header_bits = bytes_to_bits(&header);
    let payload_bits = bytes_to_bits(&ecc_packet);
    let header_slots = header_bits.len() * HEADER_CHIPS_PER_SYMBOL;
    let payload_slots = payload_bits.len() * payload_chips;
    if header_slots + payload_slots > capacity {
        return Err(StegoError::Capacity);
    }

    let quant = luminance_quant_table(JPEG_RECOVERY_QUALITY);
    let mut coeffs = quantized_luma_coefficients(&rgb, &layout, &quant);
    let original_coeffs = coeffs.clone();

    let header_indices = mapping_indices(capacity, header_slots, PUBLIC_HEADER_SEED, None)?;
    dsss::spread_bits(
        &mut coeffs,
        coeff_positions(),
        &header_indices,
        &header_bits,
        dsss_seed(PUBLIC_HEADER_SEED, b"header-pn"),
        DsssConfig {
            chips_per_symbol: HEADER_CHIPS_PER_SYMBOL,
            gain: DSSS_GAIN,
            threshold: 0.0,
        },
    );

    let reserved = reserved_mask(capacity, &header_indices);
    let payload_seed = crypto::mapping_seed(key, &salt);
    let payload_indices = mapping_indices(capacity, payload_slots, payload_seed, Some(&reserved))?;
    dsss::spread_bits(
        &mut coeffs,
        coeff_positions(),
        &payload_indices,
        &payload_bits,
        dsss_seed(payload_seed, b"payload-pn"),
        DsssConfig {
            chips_per_symbol: payload_chips,
            gain: DSSS_GAIN,
            threshold: 0.0,
        },
    );

    apply_coefficients_to_luma(&mut rgb, &layout, &original_coeffs, &coeffs, &quant);
    let psnr_db = dsss::psnr_rgb(&original_rgb, &rgb);
    Ok(JpegInjectReport {
        image: DynamicImage::ImageRgb8(rgb),
        packet_bits: payload_bits,
        psnr_db,
    })
}

pub fn extract(image: DynamicImage, key: &[u8]) -> Result<Vec<u8>, StegoError> {
    Ok(extract_with_report(image, key)?.data)
}

pub fn extract_with_report(
    image: DynamicImage,
    key: &[u8],
) -> Result<JpegExtractReport, StegoError> {
    let rgb = image.to_rgb8();
    let layout = Layout::new(rgb.width() as usize, rgb.height() as usize)?;
    let capacity = layout.capacity();
    let header_bit_count = HEADER_LEN * 8;
    let header_slots = header_bit_count * HEADER_CHIPS_PER_SYMBOL;
    if header_slots > capacity {
        return Err(StegoError::Capacity);
    }

    let quant = luminance_quant_table(JPEG_RECOVERY_QUALITY);
    let coeffs = quantized_luma_coefficients(&rgb, &layout, &quant);
    let header_indices = mapping_indices(capacity, header_slots, PUBLIC_HEADER_SEED, None)?;
    let header_readout = dsss::correlate_bits(
        &coeffs,
        coeff_positions(),
        &header_indices,
        header_bit_count,
        dsss_seed(PUBLIC_HEADER_SEED, b"header-pn"),
        DsssConfig {
            chips_per_symbol: HEADER_CHIPS_PER_SYMBOL,
            gain: DSSS_GAIN,
            threshold: 0.0,
        },
    );
    let header = bits_to_bytes(&header_readout.bits);
    let parsed = parse_header(&header)?;

    let payload_bit_count = parsed.packet_len * 8;
    let payload_slots = payload_bit_count * parsed.bit_repetition;
    if header_slots + payload_slots > capacity {
        return Err(StegoError::Capacity);
    }

    let reserved = reserved_mask(capacity, &header_indices);
    let payload_seed = crypto::mapping_seed(key, &parsed.salt);
    let payload_indices = mapping_indices(capacity, payload_slots, payload_seed, Some(&reserved))?;
    let payload_readout = dsss::correlate_bits(
        &coeffs,
        coeff_positions(),
        &payload_indices,
        payload_bit_count,
        dsss_seed(payload_seed, b"payload-pn"),
        DsssConfig {
            chips_per_symbol: parsed.bit_repetition,
            gain: DSSS_GAIN,
            threshold: 0.0,
        },
    );
    let packet = bits_to_bytes(&payload_readout.bits);

    let data = decode_payload(&packet, key, &parsed.salt, &parsed.nonce)?;
    let metrics = dsss::signal_report(&payload_readout.correlations, None, None);

    Ok(JpegExtractReport {
        data,
        packet_bits: payload_readout.bits,
        metrics,
    })
}

#[derive(Debug)]
pub struct JpegInjectReport {
    pub image: DynamicImage,
    pub packet_bits: Vec<u8>,
    pub psnr_db: Option<f32>,
}

#[derive(Debug)]
pub struct JpegExtractReport {
    pub data: Vec<u8>,
    pub packet_bits: Vec<u8>,
    pub metrics: SignalReport,
}

struct Layout {
    width: usize,
    block_cols: usize,
    block_rows: usize,
}

impl Layout {
    fn new(width: usize, height: usize) -> Result<Self, StegoError> {
        let block_cols = width / BLOCK;
        let block_rows = height / BLOCK;
        if block_cols == 0 || block_rows == 0 {
            return Err(StegoError::Capacity);
        }
        Ok(Self {
            width,
            block_cols,
            block_rows,
        })
    }

    fn block_count(&self) -> usize {
        self.block_cols * self.block_rows
    }

    fn capacity(&self) -> usize {
        self.block_count() * coeff_positions().len()
    }
}

fn coeff_positions() -> &'static [usize] {
    &ZIGZAG[MID_ZIGZAG_START..MID_ZIGZAG_END]
}

fn quantized_luma_coefficients(
    image: &RgbImage,
    layout: &Layout,
    quant: &[f32; 64],
) -> Vec<[i32; 64]> {
    let mut coeffs = Vec::with_capacity(layout.block_count());
    for block_y in 0..layout.block_rows {
        for block_x in 0..layout.block_cols {
            let block = luma_block(image, layout, block_x, block_y);
            let dct = fdct(&block);
            let mut quantized = [0i32; 64];
            for idx in 0..64 {
                quantized[idx] = (dct[idx] / quant[idx]).round() as i32;
            }
            coeffs.push(quantized);
        }
    }
    coeffs
}

fn apply_coefficients_to_luma(
    image: &mut RgbImage,
    layout: &Layout,
    original_coeffs: &[[i32; 64]],
    modified_coeffs: &[[i32; 64]],
    quant: &[f32; 64],
) {
    for block_y in 0..layout.block_rows {
        for block_x in 0..layout.block_cols {
            let block_idx = block_y * layout.block_cols + block_x;
            let mut original_dequantized = [0f32; 64];
            let mut modified_dequantized = [0f32; 64];
            for idx in 0..64 {
                original_dequantized[idx] = original_coeffs[block_idx][idx] as f32 * quant[idx];
                modified_dequantized[idx] = modified_coeffs[block_idx][idx] as f32 * quant[idx];
            }
            let original = idct(&original_dequantized);
            let modified = idct(&modified_dequantized);

            for y in 0..BLOCK {
                for x in 0..BLOCK {
                    let px = (block_x * BLOCK + x) as u32;
                    let py = (block_y * BLOCK + y) as u32;
                    let pixel = image.get_pixel_mut(px, py);
                    let old_y = rgb_to_luma(pixel.0) as f32;
                    let delta = modified[y * BLOCK + x] - original[y * BLOCK + x];
                    let new_y = (old_y + delta).clamp(0.0, 255.0);
                    pixel.0 = replace_luma(pixel.0, new_y);
                }
            }
        }
    }
}

fn luma_block(image: &RgbImage, layout: &Layout, block_x: usize, block_y: usize) -> [f32; 64] {
    let mut block = [0f32; 64];
    for y in 0..BLOCK {
        for x in 0..BLOCK {
            let px = (block_x * BLOCK + x) as u32;
            let py = (block_y * BLOCK + y) as u32;
            let rgb = image.get_pixel(px, py).0;
            debug_assert!((px as usize) < layout.width);
            block[y * BLOCK + x] = rgb_to_luma(rgb) as f32 - 128.0;
        }
    }
    block
}

fn rgb_to_luma(rgb: [u8; 3]) -> u8 {
    (0.299 * rgb[0] as f32 + 0.587 * rgb[1] as f32 + 0.114 * rgb[2] as f32)
        .round()
        .clamp(0.0, 255.0) as u8
}

fn replace_luma(rgb: [u8; 3], new_y: f32) -> [u8; 3] {
    let old_y = rgb_to_luma(rgb) as f32;
    let cb = (rgb[2] as f32 - old_y) * 0.564 + 128.0;
    let cr = (rgb[0] as f32 - old_y) * 0.713 + 128.0;
    [
        (new_y + 1.403 * (cr - 128.0)).round().clamp(0.0, 255.0) as u8,
        (new_y - 0.344 * (cb - 128.0) - 0.714 * (cr - 128.0))
            .round()
            .clamp(0.0, 255.0) as u8,
        (new_y + 1.773 * (cb - 128.0)).round().clamp(0.0, 255.0) as u8,
    ]
}

fn fdct(block: &[f32; 64]) -> [f32; 64] {
    let mut out = [0f32; 64];
    for v in 0..BLOCK {
        for u in 0..BLOCK {
            let mut sum = 0.0;
            for y in 0..BLOCK {
                for x in 0..BLOCK {
                    sum += block[y * BLOCK + x] * dct_basis(x, u) * dct_basis(y, v);
                }
            }
            out[v * BLOCK + u] = 0.25 * dct_scale(u) * dct_scale(v) * sum;
        }
    }
    out
}

fn idct(coeffs: &[f32; 64]) -> [f32; 64] {
    let mut out = [0f32; 64];
    for y in 0..BLOCK {
        for x in 0..BLOCK {
            let mut sum = 0.0;
            for v in 0..BLOCK {
                for u in 0..BLOCK {
                    sum += dct_scale(u)
                        * dct_scale(v)
                        * coeffs[v * BLOCK + u]
                        * dct_basis(x, u)
                        * dct_basis(y, v);
                }
            }
            out[y * BLOCK + x] = 0.25 * sum;
        }
    }
    out
}

fn dct_scale(freq: usize) -> f32 {
    if freq == 0 {
        std::f32::consts::FRAC_1_SQRT_2
    } else {
        1.0
    }
}

fn dct_basis(sample: usize, freq: usize) -> f32 {
    (((2 * sample + 1) as f32 * freq as f32 * std::f32::consts::PI) / 16.0).cos()
}

fn luminance_quant_table(quality: u8) -> [f32; 64] {
    let quality = quality.clamp(1, 100) as u32;
    let scale = if quality < 50 {
        5000 / quality
    } else {
        200 - quality * 2
    };

    let mut out = [0f32; 64];
    for (idx, base) in LUMA_Q50.iter().enumerate() {
        let value = ((*base as u32 * scale + 50) / 100).clamp(1, 255);
        out[idx] = value as f32;
    }
    out
}

fn dsss_seed(mut seed: [u8; 32], domain: &[u8]) -> [u8; 32] {
    for (idx, byte) in seed.iter_mut().enumerate() {
        *byte ^= domain[idx % domain.len()].wrapping_add(idx as u8);
    }
    seed
}

#[cfg(test)]
mod tests {
    use image::codecs::jpeg::JpegEncoder;
    use image::{ImageBuffer, ImageFormat, Rgb};

    use super::*;

    #[test]
    fn jpeg_dsss_survives_quality_50_round_trip() {
        let carrier = DynamicImage::ImageRgb8(ImageBuffer::from_fn(512, 512, |x, y| {
            let base = 96 + ((x + y) % 64) as u8;
            Rgb([
                base,
                base.saturating_add(((x / 8) % 16) as u8),
                base.saturating_sub(((y / 8) % 16) as u8),
            ])
        }));
        let payload = b"jpeg dct manifest";
        let key = b"jpeg-key";

        let encoded = inject_with_config(carrier, payload, key, StegoConfig::default()).unwrap();
        assert_eq!(extract(encoded.clone(), key).unwrap(), payload);
        let recompressed = recompress_jpeg(&encoded, 50);
        let decoded_image =
            image::load_from_memory_with_format(&recompressed, ImageFormat::Jpeg).unwrap();
        let decoded = extract(decoded_image, key).unwrap();

        assert_eq!(decoded, payload);
    }

    fn recompress_jpeg(image: &DynamicImage, quality: u8) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
        encoder.encode_image(image).unwrap();
        out
    }
}
