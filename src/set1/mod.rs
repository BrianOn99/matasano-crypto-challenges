pub mod challenges;

use std;

pub fn xor_buffers<'a>(b1: &'a [u8], b2: &'a [u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect()
}

/// Assume the text is encypted by xor with single byte.  Try all 256 possible bytes and return the
/// highest score plaintext
pub fn decrypt_simple_xor(ciphertext: &[u8]) -> Vec<u8> {
    let mut best_plaintext: Vec<u8> = vec![];
    let mut best_score = std::f64::MAX;
    for key in 0u8..std::u8::MAX {
        let trial_text = xor_buffers(&ciphertext, &vec![key]);
        let trial_score = ::score_text(&trial_text);
        if trial_score < best_score {
            best_plaintext = trial_text;
            best_score = trial_score;
        }
    }

    best_plaintext
}
