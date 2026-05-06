# wired-transport

`wired-transport` is a Rust/WASM prototype for L7 steganography over valid PNG and JPEG carriers. It encrypts payload bytes, applies Reed-Solomon forward error correction, and scatters the protected bitstream across RGB least-significant bits for PNG or DSSS-modulated DCT coefficients for JPEG.

## Workspace

- `wired-core/`: reusable Rust library with `crypto`, `dsss`, `ecc`, `stego_engine`, and `jpeg_dct` modules.
- `wired-wasm/`: Leptos + Trunk browser UI with drag-and-drop PNG/JPEG handling.

## Core API

```rust
use wired_core::{Decoder, Encoder};

let carrier = image::open("carrier.png")?;
let wired = Encoder::inject(carrier, b"payload", b"shared-key")?;
let recovered = Decoder::extract(wired, b"shared-key")?;
```

For byte-oriented container detection, use the unified API:

```rust
let encoded = Encoder::inject_bytes(&carrier_bytes, b"payload", b"shared-key")?;
let recovered = Decoder::extract_bytes(&encoded.bytes, b"shared-key")?;
```

For adversarial JPEG lab tests:

```rust
let report = wired_core::stress_test(&carrier_bytes, b"payload", b"shared-key", 50, config)?;
println!("BER: {:?}", report.signal.raw_ber);
println!("correlation: {}", report.signal.average_correlation_peak);
```

Use `Encoder::inject_with_config` to tune recovery overhead:

```rust
use wired_core::{Encoder, StegoConfig};

let config = StegoConfig {
    recovery_rate: 0.25,
    bit_repetition: 15,
};
```

## L7-Steganography Approach

1. Payload bytes are encrypted with `ring` ChaCha20-Poly1305 AEAD on native targets. The WASM target uses a pure-Rust ChaCha20-Poly1305/SHA-256 backend because `ring` requires a C toolchain path that is not consistently available for `wasm32-unknown-unknown` browser builds.
2. Encrypted bytes are packetized into fixed-size Reed-Solomon shards using `reed-solomon-erasure`.
3. Each shard receives a SHA-256-derived integrity tag so corrupted shards can be marked as erasures before reconstruction.
4. For PNG, the ECC packet is converted to bits, repeated, and written into RGB LSB channels only.
5. For JPEG, `wired-core` decodes with pure-Rust JPEG support from the `image` stack, performs an internal 8x8 luminance DCT, and embeds each symbol with Direct Sequence Spread Spectrum over mid-band AC coefficients while skipping DC coefficients.
6. `rand_xoshiro` maps bit positions from a key/salt-derived seed, scattering data across the image rather than creating a visible noisy block.
7. Outputs are saved as normal PNG or JPEG files; container structure is produced by the pure-Rust `image` codecs and remains valid/viewable.

## Robustness Model

The default config uses `recovery_rate = 0.25` and `bit_repetition = 15`. Repetition absorbs random LSB or DCT coefficient disturbance at the bit level, while Reed-Solomon parity reconstructs shards that still fail integrity checks. PNG mode is intended to survive moderate random pixel/channel modification when dimensions and RGB samples are preserved.

JPEG mode uses additive DSSS modulation: each bit is multiplied by a pseudo-random noise sequence and spread across multiple mid-frequency coefficients. Decoding correlates received coefficients against the same PN sequence and thresholds the dot product. The stress-test path reports average correlation peak, raw BER before Reed-Solomon recovery, and PSNR, and is tested against a JPEG quality-50 recompression round-trip. Resizing, cropping, aggressive denoising, or workflows that alter 8x8 block alignment can still destroy the deterministic mapping. For hostile lossy pipelines, increase carrier size and avoid transforms that change dimensions.

## Browser UI

The WASM app provides a dark terminal-style interface:

- Drag or select a PNG or JPEG carrier.
- Enter a shared key and plaintext payload.
- Click `inject` to produce `wired-carrier.png` or `wired-carrier.jpg`.
- Load a wired PNG/JPEG and click `extract` with the same key.
- Click `stress test` to encode, recompress at JPEG quality 50, decode, and display `[SIGNAL]`, `[DEBUG] Raw BER`, and `[DEBUG] PSNR` metrics.

Run locally:

```bash
cd wired-wasm
trunk serve
```

## Build Checks

```bash
cargo test -p wired-core
cargo check -p wired-wasm --target wasm32-unknown-unknown
```

If the WASM target is missing:

```bash
rustup target add wasm32-unknown-unknown
```
