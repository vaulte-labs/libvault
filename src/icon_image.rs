//! Turning icons into plain pixels, in memory-safe code.
//!
//! A website chooses the bytes of its favicon, and any enrolled device chooses the bytes of a
//! saved icon. Image decoders are a classic way in, and the platform's are written in C, so no
//! interface hands an icon to one. This module decodes PNG instead, and interfaces get pixels,
//! which take no parsing to draw. The decoder and its inflate forbid unsafe code, so what they do
//! with hostile bytes is fail. Only their checksums use SIMD, over bytes they do not interpret.
//!
//! This runs in the client. The broker holds the keys, and it never decodes an icon.

use std::io::Cursor;

use png::{BitDepth, ColorType, Compression, Decoder, Encoder, Limits, Transformations};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A saved icon's limits. Every byte stays in the log for good, so this is what a list needs.
pub(crate) const LARGEST_ICON: usize = 3 * 1024;
pub(crate) const LARGEST_SIDE: u32 = 64;
/// A website's image can be larger than what is kept, but not by much: this is an icon.
const LARGEST_SOURCE: usize = 256 * 1024;
const LARGEST_SOURCE_SIDE: u32 = 512;
const BYTES_PER_PIXEL: usize = 4;
/// Enough for the largest source after decoding, so a small file cannot unpack into a huge one.
const DECODE_LIMIT: usize = (LARGEST_SOURCE_SIDE as usize).pow(2) * BYTES_PER_PIXEL * 2;
/// Tried in turn, so a detailed icon loses resolution rather than being refused.
const SIDES_TO_TRY: [u32; 5] = [LARGEST_SIDE, 48, 32, 24, 16];

/// An icon as pixels, ready to draw without any image decoder. Four bytes per pixel, in red,
/// green, blue and alpha order, row by row from the top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Icon {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

fn to_rgba(color: ColorType, pixels: &[u8]) -> Option<Vec<u8>> {
    let channels: &dyn Fn(&[u8]) -> [u8; 4] = match color {
        ColorType::Rgba => &|p| [p[0], p[1], p[2], p[3]],
        ColorType::Rgb => &|p| [p[0], p[1], p[2], u8::MAX],
        ColorType::GrayscaleAlpha => &|p| [p[0], p[0], p[0], p[1]],
        ColorType::Grayscale => &|p| [p[0], p[0], p[0], u8::MAX],
        ColorType::Indexed => return None,
    };
    Some(pixels.chunks_exact(color.samples()).flat_map(channels).collect())
}

fn decoded(bytes: &[u8], largest_side: u32) -> Option<Icon> {
    let mut decoder = Decoder::new_with_limits(Cursor::new(bytes), Limits { bytes: DECODE_LIMIT });
    decoder.set_transformations(Transformations::normalize_to_color8() | Transformations::ALPHA);
    let mut reader = decoder.read_info().ok()?;
    let (width, height) = reader.info().size();
    if width == 0 || height == 0 || width > largest_side || height > largest_side {
        return None;
    }
    let mut pixels = vec![0; reader.output_buffer_size()?];
    let frame = reader.next_frame(&mut pixels).ok()?;
    (frame.bit_depth == BitDepth::Eight).then_some(())?;
    let rgba = to_rgba(frame.color_type, &pixels[..frame.buffer_size()])?;
    (rgba.len() == width as usize * height as usize * BYTES_PER_PIXEL).then_some(Icon { width, height, rgba })
}

/// Averages each block of pixels, weighting by alpha so transparent pixels add no color.
fn shrunk(icon: &Icon, largest_side: u32) -> Icon {
    let longest = icon.width.max(icon.height);
    if longest <= largest_side {
        return icon.clone();
    }
    let scaled = |side: u32| (side * largest_side / longest).max(1);
    let (width, height) = (scaled(icon.width), scaled(icon.height));
    // Block `index` of `count` starts here, and every block holds at least one source pixel.
    let block = |index: u32, count: u32, side: u32| {
        let start = index * side / count;
        (start, ((index + 1) * side / count).max(start + 1))
    };
    let mut rgba = Vec::with_capacity(width as usize * height as usize * BYTES_PER_PIXEL);
    for y in 0..height {
        let (top, bottom) = block(y, height, icon.height);
        for x in 0..width {
            let (left, right) = block(x, width, icon.width);
            let (mut color, mut alpha, mut count) = ([0u64; 3], 0u64, 0u64);
            for source_y in top..bottom {
                for source_x in left..right {
                    let at = (source_y as usize * icon.width as usize + source_x as usize) * BYTES_PER_PIXEL;
                    let pixel_alpha = u64::from(icon.rgba[at + 3]);
                    (0..3).for_each(|channel| color[channel] += u64::from(icon.rgba[at + channel]) * pixel_alpha);
                    alpha += pixel_alpha;
                    count += 1;
                }
            }
            let average = |value: u64, of: u64| u8::try_from(value.checked_div(of).unwrap_or(0)).unwrap_or(u8::MAX);
            rgba.extend(color.map(|channel| average(channel, alpha)));
            rgba.push(average(alpha, count));
        }
    }
    Icon { width, height, rgba }
}

fn encoded(icon: &Icon) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes, icon.width, icon.height);
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(BitDepth::Eight);
    encoder.set_compression(Compression::High);
    encoder.write_header().ok()?.write_image_data(&icon.rgba).ok()?;
    Some(bytes)
}

/// Turns a website's PNG into one worth keeping. The result is drawn fresh from the pixels, so
/// nothing else the file carried, such as text chunks or extra frames, goes into the vault.
pub(crate) fn prepare(image: &[u8]) -> Result<Vec<u8>> {
    if image.len() > LARGEST_SOURCE {
        return Err(Error::Invalid("that image is too large to be an icon"));
    }
    let source = decoded(image, LARGEST_SOURCE_SIDE).ok_or(Error::Invalid("an icon has to be a PNG of at most 512 pixels"))?;
    let small_enough = |side: &u32| encoded(&shrunk(&source, *side)).filter(|png| png.len() <= LARGEST_ICON);
    SIDES_TO_TRY.iter().find_map(small_enough).ok_or(Error::Invalid("that image is too detailed to keep as an icon"))
}

/// Reads an icon from the vault. Any enrolled device can write one, so what cannot be read is
/// simply no icon, and the interface draws its letter instead.
pub(crate) fn saved(png: &[u8]) -> Option<Icon> {
    if png.len() > LARGEST_ICON {
        return None;
    }
    decoded(png, LARGEST_SIDE)
}

#[cfg(test)]
#[path = "icon_image_tests.rs"]
mod tests;
