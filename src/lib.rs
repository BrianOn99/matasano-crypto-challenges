extern crate hex;
extern crate base64;

pub mod set1;

/// Adhoc way to score ascii text validity by checking class of characters.  mean robust or fast.
/// But good enough for distinguish text from random bytes.  Smaller is better.
// Efficiency is important here because most challanges need to run the function 10000 times
// Previously I made a fancy version which create a HashMap and lookup every u8, challenge 4 took
// 30 secs to run in unoptimized build.  During debugging challenge6 it is very annoying.
// The std AsciiExt trait has some function do something similar by table lookup, but it is
// currently unstable.
fn score_ascii(c: u8) -> f64 {
    match c {
        0x09|0x0A|0x0C|0x0D => 0.1,  // control whitespace
        0x20 => 0.0,  // every hacker know it
        0x2C|0x2E|0x3F => 0.02,  // ,.?
        0x21...0x40|0x5B...0x60|0x7B...0x7E => 0.4,  // fallthrough other punctuations
        b'a'|b'e'|b'i'|b'o'|b'u'|b't' => 0.01,
        0x41...0x5A => 0.06,  // uppercase
        0x61...0x7A => 0.04,  // lowercase
        _ => 10.0
    }
}

pub fn score_text(text: &[u8]) -> f64 {
    let mut counts = [0u32; std::u8::MAX as usize + 1];
    for c in text {
        counts[*c as usize] += 1;
    }

    counts.iter()
        .map(|x| *x as f64 / text.len() as f64)
        .enumerate()
        .fold(0.0, |acc, (i, x)| {
            acc + score_ascii(i as u8) * x
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_text() {
        let good = &b"Who sees the future? \
            Let us have free scope for all directions of research; \
            away with dogmatism.";
        let bad = &b"S7o0cloGDKno/vpTDdxVODrxcYuknx09IihsBWYQNSE3DCh70PL3is61kSiVahVDW0z2qFYKtH7e";
        assert!(score_text(&good.to_vec()) * 4.0 < score_text(&bad.to_vec()));
    }
}
