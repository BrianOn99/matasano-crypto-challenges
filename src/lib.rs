extern crate hex;
extern crate base64;

pub mod set1;
use std::collections::HashMap;

/* Adhoc way to score ascii text validity by checking several characters frequency.  It is by no
 * mean robust or fast.  But good enough for distinguish text from random bytes.
 * Smaller is better.
 * Data from http://www.data-compression.com/english.html */
pub fn score_text(text: &[u8]) -> f64 {
    let ground_truth: HashMap<u8, f64> = 
        [(b' ', 0.191), (b'a', 0.0652), (b'e', 0.1041), (b'i', 0.0558), (b'b', 0.0124)]
        .iter()
        .map(|x| x.clone())
        .collect();

    let mut counts = [0u32; std::u8::MAX as usize + 1];
    for c in text {
        counts[*c as usize] += 1
    }

    counts.iter()
        .map(|x| *x as f64 / text.len() as f64)
        .enumerate()
        .fold(0.0, |acc, (i, x)| {
            acc + match ground_truth.get(&(i as u8)) {
                None => 0.0,
                Some(v) => (v-x)*(v-x)
            }
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
