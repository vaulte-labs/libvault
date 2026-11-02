use super::*;

fn png_of(width: u32, height: u32, color: ColorType, depth: BitDepth, pixels: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes, width, height);
    encoder.set_color(color);
    encoder.set_depth(depth);
    encoder.write_header().unwrap().write_image_data(pixels).unwrap();
    bytes
}

fn solid(side: u32, pixel: [u8; 4]) -> Vec<u8> {
    let pixels: Vec<u8> = std::iter::repeat_n(pixel, (side * side) as usize).flatten().collect();
    png_of(side, side, ColorType::Rgba, BitDepth::Eight, &pixels)
}

/// Bytes that look random enough to defeat compression, and are the same on every run.
fn noise(side: u32) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let pixels: Vec<u8> = (0..side * side * 4)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    png_of(side, side, ColorType::Rgba, BitDepth::Eight, &pixels)
}

#[test]
fn every_common_kind_of_png_becomes_the_same_pixels() {
    let red = [200, 10, 20, 255];
    assert_eq!(saved(&png_of(1, 1, ColorType::Rgba, BitDepth::Eight, &red)).unwrap().rgba, red);
    assert_eq!(saved(&png_of(1, 1, ColorType::Rgb, BitDepth::Eight, &red[..3])).unwrap().rgba, red);
    assert_eq!(saved(&png_of(1, 1, ColorType::Grayscale, BitDepth::Eight, &[9])).unwrap().rgba, [9, 9, 9, 255]);
    assert_eq!(saved(&png_of(1, 1, ColorType::GrayscaleAlpha, BitDepth::Eight, &[9, 7])).unwrap().rgba, [9, 9, 9, 7]);
    assert_eq!(saved(&png_of(1, 1, ColorType::Rgba, BitDepth::Sixteen, &[200, 0, 10, 0, 20, 0, 255, 255])).unwrap().rgba, [200, 10, 20, 255]);
}

#[test]
fn a_palette_image_keeps_its_colors_and_transparency() {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes, 2, 1);
    encoder.set_color(ColorType::Indexed);
    encoder.set_depth(BitDepth::Eight);
    encoder.set_palette(vec![1, 2, 3, 4, 5, 6]);
    encoder.set_trns(vec![255, 0]);
    encoder.write_header().unwrap().write_image_data(&[0, 1]).unwrap();
    assert_eq!(saved(&bytes).unwrap().rgba, [1, 2, 3, 255, 4, 5, 6, 0]);
}

#[test]
fn a_saved_icon_is_what_was_drawn() {
    let icon = saved(&prepare(&solid(32, [10, 20, 30, 255])).unwrap()).unwrap();
    assert_eq!((icon.width, icon.height), (32, 32));
    assert_eq!(icon.rgba, [10, 20, 30, 255].repeat(32 * 32));
}

#[test]
fn a_large_image_comes_down_to_size_and_a_small_one_is_left_alone() {
    assert_eq!(saved(&prepare(&solid(512, [1, 2, 3, 255])).unwrap()).unwrap().width, 64);
    assert_eq!(saved(&prepare(&solid(16, [1, 2, 3, 255])).unwrap()).unwrap().width, 16);
}

#[test]
fn a_tall_image_keeps_its_shape() {
    let pixels = vec![9; 8 * 128 * 4];
    let icon = saved(&prepare(&png_of(8, 128, ColorType::Rgba, BitDepth::Eight, &pixels)).unwrap()).unwrap();
    assert_eq!((icon.width, icon.height), (4, 64));
}

#[test]
fn shrinking_averages_and_transparent_pixels_add_no_color() {
    let half_clear = Icon { width: 2, height: 1, rgba: vec![200, 100, 50, 255, 9, 9, 9, 0] };
    assert_eq!(shrunk(&half_clear, 1).rgba, [200, 100, 50, 127]);
    let two_grays = Icon { width: 2, height: 1, rgba: vec![100, 100, 100, 255, 200, 200, 200, 255] };
    assert_eq!(shrunk(&two_grays, 1).rgba, [150, 150, 150, 255]);
    let clear = Icon { width: 2, height: 1, rgba: vec![9, 9, 9, 0, 9, 9, 9, 0] };
    assert_eq!(shrunk(&clear, 1).rgba, [0, 0, 0, 0]);
}

#[test]
fn a_detailed_image_loses_resolution_rather_than_being_refused() {
    let kept = prepare(&noise(128)).unwrap();
    assert!(kept.len() <= LARGEST_ICON, "{}", kept.len());
    assert!(saved(&kept).unwrap().width < LARGEST_SIDE);
}

#[test]
fn what_is_kept_is_only_the_pixels() {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes, 2, 2);
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(BitDepth::Eight);
    encoder.add_text_chunk("Comment".to_owned(), "tracking-marker".to_owned()).unwrap();
    encoder.write_header().unwrap().write_image_data(&[7; 16]).unwrap();
    assert!(bytes.windows(15).any(|window| window == b"tracking-marker"), "the source carries it");
    assert!(!prepare(&bytes).unwrap().windows(15).any(|window| window == b"tracking-marker"));
}

#[test]
fn a_source_too_large_or_too_wide_is_refused() {
    assert!(prepare(&solid(513, [1, 2, 3, 255])).is_err());
    assert!(prepare(&vec![0; LARGEST_SOURCE + 1]).is_err());
}

#[test]
fn a_saved_icon_past_the_limits_is_no_icon() {
    assert_eq!(saved(&solid(LARGEST_SIDE + 1, [1, 2, 3, 255])), None);
    let mut padded = solid(16, [1, 2, 3, 255]);
    padded.resize(LARGEST_ICON + 1, 0);
    assert_eq!(saved(&padded), None);
}

#[test]
fn nothing_hostile_gets_past_being_no_icon() {
    let good = solid(16, [1, 2, 3, 255]);
    let header_only = good[..33].to_vec();
    let mut empty_image = good.clone();
    empty_image[16..24].fill(0);
    let mut claims_huge = good.clone();
    claims_huge[16..24].copy_from_slice(&[0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff]);
    let mut wrecked_data = good.clone();
    let end = wrecked_data.len() - 12;
    wrecked_data[41..end].fill(0xff);
    for hostile in [&b""[..], b"<svg onload=alert(1)>", &header_only, &empty_image, &claims_huge, &wrecked_data, &good[..good.len() / 2]] {
        assert_eq!(saved(hostile), None, "{hostile:?}");
    }
}

#[test]
fn no_single_damaged_byte_or_cut_breaks_the_decoder() {
    let good = solid(16, [1, 2, 3, 255]);
    for at in 0..good.len() {
        for bit in 0..8 {
            let mut damaged = good.clone();
            damaged[at] ^= 1 << bit;
            if let Some(icon) = saved(&damaged) {
                assert_eq!(icon.rgba.len(), icon.width as usize * icon.height as usize * 4);
            }
        }
        // A cut after the last pixel loses only the end marker, so the image is still all there.
        if let Some(icon) = saved(&good[..at]) {
            assert_eq!(Some(icon), saved(&good), "cut at {at}");
        }
    }
}
