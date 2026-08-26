//! The app's mark, drawn in code.
//!
//! # Why a PNG encoder lives here
//!
//! iOS takes an SVG for the browser tab but wants a PNG for the Home Screen,
//! and without one it uses a screenshot of the page — which is how a saved app
//! ends up with a picture of a loading spinner as its icon.
//!
//! The alternatives were a binary blob committed to the repository, or an image
//! crate and its decoders for formats nothing here reads. This is ninety lines
//! of arithmetic with no dependencies, no build step, and no binary in the
//! tree, and it is exactly as auditable as the rest of the file.
//!
//! Deflate is used in *stored* mode — no compression at all. A 180×180 icon is
//! 130KB uncompressed, which is nothing to serve over loopback, and a real
//! deflate implementation would be several hundred lines to save bytes nobody
//! is paying for.

/// The icon's edge, in pixels.
///
/// 180 is what iOS asks for at 3× on a phone-sized screen.
const SIZE: u32 = 180;

/// The mark, as an SVG.
///
/// A ring with a gap: a figure that is *almost* closed. That is the product —
/// a copy of someone that is never quite complete, and whose remaining gap is
/// the thing being measured.
pub const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180">
<rect width="180" height="180" rx="40" fill="#0d0e12"/>
<circle cx="90" cy="90" r="46" fill="none" stroke="#7dd3a0" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="215 74" transform="rotate(-45 90 90)"/>
<circle cx="90" cy="90" r="9" fill="#7dd3a0"/>
</svg>"##;

/// The same mark, rasterised.
#[must_use]
pub fn png() -> Vec<u8> {
    let pixels = raster();
    encode(&pixels, SIZE, SIZE)
}

/// Draws the mark into an RGBA buffer.
///
/// Antialiased by supersampling: the distance to each edge is measured in
/// fractional pixels and used as coverage, so the ring does not come out with
/// staircase edges on a screen that renders it at three times this size.
fn raster() -> Vec<u8> {
    const BG: [u8; 3] = [0x0d, 0x0e, 0x12];
    const FG: [u8; 3] = [0x7d, 0xd3, 0xa0];

    let mid = f32::from(u16::try_from(SIZE).unwrap_or(180)) / 2.0;
    let ring = mid * 0.51;
    let stroke = mid * 0.067;
    let dot = mid * 0.10;
    let corner = mid * 0.444;

    let mut out = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let dx = fx - mid;
            let dy = fy - mid;
            let radius = dx.hypot(dy);

            // The gap in the ring, opening toward the lower right. `atan2`
            // gives the angle; the gap is the arc this test excludes.
            let angle = dy.atan2(dx);
            let in_gap = (0.55..1.85).contains(&angle);

            let mut coverage = if in_gap {
                0.0
            } else {
                edge(stroke / 2.0 - (radius - ring).abs())
            };
            coverage = coverage.max(edge(dot - radius));

            // The rounded square, as a mask. Outside it the icon is
            // transparent, so iOS can apply its own corner radius over ours
            // without a dark square peeking out from underneath.
            let inset_x = (dx.abs() - (mid - corner)).max(0.0);
            let inset_y = (dy.abs() - (mid - corner)).max(0.0);
            let outside = inset_x.hypot(inset_y) - corner;
            let alpha = edge(-outside);

            let colour = blend(BG, FG, coverage);
            out.extend_from_slice(&[
                colour[0],
                colour[1],
                colour[2],
                (alpha * 255.0).round().clamp(0.0, 255.0) as u8,
            ]);
        }
    }
    out
}

/// Coverage for a signed distance, one pixel wide.
fn edge(distance: f32) -> f32 {
    (distance + 0.5).clamp(0.0, 1.0)
}

/// Mixes two colours.
fn blend(from: [u8; 3], to: [u8; 3], amount: f32) -> [u8; 3] {
    let mix = |a: u8, b: u8| {
        (f32::from(a) + (f32::from(b) - f32::from(a)) * amount)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    [
        mix(from[0], to[0]),
        mix(from[1], to[1]),
        mix(from[2], to[2]),
    ]
}

/// Wraps RGBA pixels in a PNG container.
fn encode(pixels: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(pixels.len() + height as usize);
    for row in pixels.chunks_exact((width * 4) as usize) {
        // Filter type 0: none. Filtering exists to help compression, and there
        // is no compression here to help.
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, RGBA, no interlace

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    chunk(&mut out, b"IHDR", &header);
    chunk(&mut out, b"IDAT", &zlib_stored(&raw));
    chunk(&mut out, b"IEND", &[]);
    out
}

/// Appends one PNG chunk, with its length and CRC.
fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(body);

    let mut crc = crc32(kind);
    crc = crc32_continue(crc, body);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// A zlib stream of stored (uncompressed) deflate blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    // 0x78 0x01: deflate, 32K window, no preset dictionary, fastest setting.
    let mut out = vec![0x78, 0x01];
    let mut rest = data;
    while !rest.is_empty() {
        // A stored block's length field is 16 bits, so this is the ceiling.
        let take = rest.len().min(0xFFFF);
        let (block, remainder) = rest.split_at(take);
        let last = u8::from(remainder.is_empty());
        let len = u16::try_from(take).unwrap_or(u16::MAX);
        out.push(last);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
        rest = remainder;
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// CRC-32, as PNG specifies it.
fn crc32(data: &[u8]) -> u32 {
    crc32_continue(0, data)
}

/// Continues a CRC over more bytes.
///
/// Takes and returns the *finalised* value, so callers can chain a chunk's kind
/// and its body without knowing the internal representation.
fn crc32_continue(previous: u32, data: &[u8]) -> u32 {
    let mut crc = !previous;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            // The reflected CRC-32 polynomial.
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Adler-32, as zlib specifies it.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from RFC 1950 §9 and the zlib documentation. A CRC that is
    /// subtly wrong produces a PNG every decoder rejects, and "the icon is
    /// missing" is a bad way to find out.
    #[test]
    fn the_checksums_match_their_specifications() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
    }

    #[test]
    fn a_crc_can_be_taken_in_two_parts() {
        let whole = crc32(b"IHDRbody");
        let split = crc32_continue(crc32(b"IHDR"), b"body");
        assert_eq!(whole, split);
    }

    #[test]
    fn the_png_is_well_formed() {
        let png = png();
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        assert!(png.ends_with(&[0xAE, 0x42, 0x60, 0x82]), "IEND and its CRC");

        // IHDR announces the size the manifest promises.
        let width = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
        let height = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
        assert_eq!((width, height), (SIZE, SIZE));
    }

    /// A stored block whose length and complement disagree is rejected by every
    /// decoder, and it is the easiest thing to get wrong here.
    #[test]
    fn every_stored_block_carries_its_own_complement() {
        let data = vec![0u8; 0xFFFF * 2 + 7];
        let stream = zlib_stored(&data);
        let mut at = 2;
        let mut blocks = 0;
        loop {
            let last = stream[at];
            let len = u16::from_le_bytes([stream[at + 1], stream[at + 2]]);
            let not_len = u16::from_le_bytes([stream[at + 3], stream[at + 4]]);
            assert_eq!(not_len, !len, "block {blocks}");
            blocks += 1;
            at += 5 + len as usize;
            if last == 1 {
                break;
            }
        }
        assert_eq!(blocks, 3, "two full blocks and a remainder");
        assert_eq!(
            at + 4,
            stream.len(),
            "the adler checksum, and nothing after"
        );
    }

    /// The corners are transparent so iOS can round them itself without a dark
    /// square showing through, and the middle is the mark rather than the
    /// background.
    #[test]
    fn the_icon_is_a_mark_on_a_rounded_transparent_field() {
        let pixels = raster();
        let at = |x: u32, y: u32| {
            let i = ((y * SIZE + x) * 4) as usize;
            [pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3]]
        };

        assert_eq!(at(0, 0)[3], 0, "the corner is transparent");
        assert_eq!(at(SIZE - 1, SIZE - 1)[3], 0, "and so is the far corner");
        assert_eq!(at(SIZE / 2, 2)[3], 255, "the top edge is opaque");

        let centre = at(SIZE / 2, SIZE / 2);
        assert_eq!(&centre[..3], &[0x7d, 0xd3, 0xa0], "the dot");
    }

    /// Same bytes every time: a favicon that changed on each build would be
    /// re-fetched forever and would show up in every diff.
    #[test]
    fn the_icon_is_deterministic() {
        assert_eq!(png(), png());
    }
}
