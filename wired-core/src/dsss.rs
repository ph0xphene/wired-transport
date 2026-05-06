use image::RgbImage;
use rand_core::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256StarStar;

#[derive(Clone, Copy, Debug)]
pub struct DsssConfig {
    pub chips_per_symbol: usize,
    pub gain: i32,
    pub threshold: f32,
}

#[derive(Clone, Debug, Default)]
pub struct DsssReadout {
    pub bits: Vec<u8>,
    pub correlations: Vec<f32>,
}

#[derive(Clone, Debug, Default)]
pub struct SignalReport {
    pub average_correlation_peak: f32,
    pub raw_ber: Option<f32>,
    pub psnr_db: Option<f32>,
    pub symbols: usize,
}

#[derive(Clone, Debug)]
pub struct DsssMetrics {
    pub report: SignalReport,
    pub correlations: Vec<f32>,
}

impl Default for DsssConfig {
    fn default() -> Self {
        Self {
            chips_per_symbol: 16,
            gain: 18,
            threshold: 0.0,
        }
    }
}

pub fn spread_bits(
    coeffs: &mut [[i32; 64]],
    coeff_positions: &[usize],
    indices: &[usize],
    bits: &[u8],
    seed: [u8; 32],
    config: DsssConfig,
) {
    let mut pn = PnSequence::new(seed);
    for (symbol_idx, bit) in bits.iter().enumerate() {
        let sign = if *bit == 0 { -1 } else { 1 };
        for chip_idx in 0..config.chips_per_symbol {
            let slot = indices[symbol_idx * config.chips_per_symbol + chip_idx];
            let (block_idx, coeff_idx) = slot_to_coeff(coeff_positions, slot);
            let chip = pn.next_chip();
            coeffs[block_idx][coeff_idx] += sign * config.gain * chip;
        }
    }
}

pub fn correlate_bits(
    coeffs: &[[i32; 64]],
    coeff_positions: &[usize],
    indices: &[usize],
    symbol_count: usize,
    seed: [u8; 32],
    config: DsssConfig,
) -> DsssReadout {
    let mut pn = PnSequence::new(seed);
    let mut bits = Vec::with_capacity(symbol_count);
    let mut correlations = Vec::with_capacity(symbol_count);

    for symbol_idx in 0..symbol_count {
        let mut correlation = 0f32;
        for chip_idx in 0..config.chips_per_symbol {
            let slot = indices[symbol_idx * config.chips_per_symbol + chip_idx];
            let (block_idx, coeff_idx) = slot_to_coeff(coeff_positions, slot);
            let chip = pn.next_chip();
            correlation += coeffs[block_idx][coeff_idx] as f32 * chip as f32;
        }
        correlation /= config.chips_per_symbol as f32;
        bits.push((correlation > config.threshold) as u8);
        correlations.push(correlation);
    }

    DsssReadout { bits, correlations }
}

pub fn signal_report(
    correlations: &[f32],
    raw_ber: Option<f32>,
    psnr_db: Option<f32>,
) -> SignalReport {
    let average_correlation_peak = if correlations.is_empty() {
        0.0
    } else {
        correlations
            .iter()
            .map(|correlation| correlation.abs())
            .sum::<f32>()
            / correlations.len() as f32
    };

    SignalReport {
        average_correlation_peak,
        raw_ber,
        psnr_db,
        symbols: correlations.len(),
    }
}

pub fn bit_error_rate(expected: &[u8], actual: &[u8]) -> Option<f32> {
    if expected.is_empty() || expected.len() != actual.len() {
        return None;
    }

    let errors = expected
        .iter()
        .zip(actual)
        .filter(|(expected, actual)| expected != actual)
        .count();
    Some(errors as f32 / expected.len() as f32)
}

pub fn psnr_rgb(original: &RgbImage, modified: &RgbImage) -> Option<f32> {
    if original.dimensions() != modified.dimensions() {
        return None;
    }

    let mut mse = 0f64;
    let samples = original.width() as u64 * original.height() as u64 * 3;
    if samples == 0 {
        return None;
    }

    for (a, b) in original.pixels().zip(modified.pixels()) {
        for channel in 0..3 {
            let delta = a.0[channel] as f64 - b.0[channel] as f64;
            mse += delta * delta;
        }
    }

    mse /= samples as f64;
    if mse == 0.0 {
        Some(f32::INFINITY)
    } else {
        Some((10.0 * ((255.0 * 255.0) / mse).log10()) as f32)
    }
}

fn slot_to_coeff(coeff_positions: &[usize], index: usize) -> (usize, usize) {
    let block_idx = index / coeff_positions.len();
    let coeff_idx = coeff_positions[index % coeff_positions.len()];
    (block_idx, coeff_idx)
}

struct PnSequence {
    rng: Xoshiro256StarStar,
}

impl PnSequence {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: Xoshiro256StarStar::from_seed(seed),
        }
    }

    fn next_chip(&mut self) -> i32 {
        if self.rng.next_u32() & 1 == 0 {
            -1
        } else {
            1
        }
    }
}
