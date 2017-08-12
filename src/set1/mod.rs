#![allow(non_snake_case)]

#[cfg(test)]
pub mod challenges;

use std::{self, mem};
use std::ops::Range;
use std::collections::HashMap;

pub fn xor_buffers_cycle<'a>(b1: &'a [u8], b2: &'a [u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect()
}

/// Same as xor_buffers_cycle with a provided buffer, to avoid repeated allocation.
/// In challenge4 this run time is reduced by 3% in optimized build
pub fn xor_buffers_cycle_buf(b1: &[u8], b2: &[u8], out: &mut [u8]) {
    let iter = b1.iter().zip(b2.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .enumerate();
    for (i, item) in iter {
        out[i] = item;
    }
}

pub fn xor_buffers(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; b1.len()];
    xor_buffers_buf(b1, b2, &mut out);
    out
}

pub fn xor_buffers_buf(b1: &[u8], b2: &[u8], out: &mut [u8]) {
    let iter = b1.iter().zip(b2.iter())
        .map(|(&x, &y)| x ^ y)
        .enumerate();
    for (i, item) in iter {
        out[i] = item;
    }
}

/// Assume the text is encypted by xor with single byte.  Try all 256 possible bytes and return the
/// highest score plaintext
pub fn decrypt_simple_xor(ciphertext: &[u8]) -> (u8, f64) {
    let mut best_key: u8 = 0;
    let mut best_score = std::f64::MAX;
    let mut trial_text = vec![0u8; ciphertext.len()];
    // It is annoying Rust does not has inclusive range
    let mut key: u8 = 0;
    loop {
        xor_buffers_cycle_buf(&ciphertext, &[key], &mut trial_text);
        let trial_score = ::score_text(&trial_text);
        if trial_score < best_score {
            best_key = key;
            best_score = trial_score;
        }
        if key == 255u8 { break; }
        key += 1;
    }

    (best_key, best_score)
}

pub fn find_repeating_xor_key(ciphertext: &[u8], r: Range<usize>) -> Vec<u8> {
    let test_len = 16;
    if ciphertext.len() < test_len * r.end {
        panic!("ciphertext is too short");
    }

    // The normailized hamming distance with correct key size is not much lower than others, so we
    // take the best 4
    let key_sizes = find_key_size(ciphertext, r, 4);

    let mut best_key = vec![];
    let mut best_score = std::f64::MAX;

    for key_size in key_sizes {
        let ciphertext_T = Matrix {
            data: ciphertext[..(key_size*test_len)].to_vec().into_boxed_slice(),
            w: key_size,
            h: test_len,
        }.transpose();

        let (key, score) = ciphertext_T.rows().fold((vec![], 0.0), |(mut key, score): (Vec<u8>, f64), buf| {
            let res = decrypt_simple_xor(buf);
            let score = score +res.1;
            key.push(res.0);
            (key, score)
        });

        let score = score / key_size as f64;
        if score < best_score {
            best_key = key;
            best_score = score;
        }
    }

    best_key
}

pub fn find_key_size(b: &[u8], r: Range<usize>, top_n: usize) -> Vec<usize> {
    let blocks = 4;
    assert!((r.end * blocks *2) < b.len());
    assert!(r.end - r.start > 0);

    let mut ranges: Vec<usize> = r.collect();
    ranges.sort_by_key(|&len| {
        let dist = (0..blocks).map(|x| x*2).fold(0, |acc, i| {
            acc + hamming_distance(&b[i*len..(i+1)*len], &b[(i+1)*len..(i+2)*len])
        });
        // 1000 is just some large number to make int division error small
        (dist * 10000) as usize / len
    });

    ranges.resize(top_n, 0);
    ranges
}

fn hamming_distance(b1: &[u8], b2: &[u8]) -> u32 {
    let diff = xor_buffers(b1, b2);
    diff.iter().fold(0, |acc, x| {
        acc + x.count_ones()
    })
}

pub struct Matrix<T> {
    pub data: Box<[T]>,
    pub w: usize,
    pub h: usize,
}

impl<T> Matrix<T> where T: Copy {
    fn transpose(&self) -> Matrix<T> {
        let new_data = self.data.clone();
        let mut out = Matrix {
            data: new_data,
            w: self.h,
            h: self.w,
        };

        for i in 0..self.w {
            for j in 0..self.h {
                out.data[i*self.h + j] = self.data[j*self.w + i]
            }
        }

        out
    }

    fn rows(&self) -> MatrixEachRow<T> {
        MatrixEachRow {m: self, i:0}
    }
}

pub struct MatrixEachRow<'a, T: 'a> {
    m: &'a Matrix<T>,
    i: usize
}

impl<'a, T> Iterator for MatrixEachRow<'a, T> {
    type Item = &'a [T];

    fn next(&mut self) -> Option<&'a [T]> {
        if self.i >= self.m.h {
            None
        } else {
            let mut i = self.i + 1;
            mem::swap(&mut i, &mut self.i);
            Some(&self.m.data[i*self.m.w .. (i+1)*self.m.w])
        }
    }
}

pub fn is_ecb(b: &[u8], max_chunck: usize) -> bool {
    let mut counts: HashMap<&[u8], u32> = HashMap::new();

    for l in 2..(max_chunck+1) {
        for i in (0..).map(|x| x*l).take_while(|&n| n < b.len() - l) {
            let chunk = &b[i..i+l];
            *counts.entry(chunk).or_insert(0) += 1
        }

        let thres_count = 2 + ((2.0 * (b.len() / l) as f64) / (256f64.powi(l as i32))).ceil() as u32;
        for c in counts.values() {
            if *c > thres_count { return true }
        }

        counts.clear();
    }

    return false;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn test_find_ecb() {
        assert_eq!(is_ecb(b"qidiopjjwiopiopwqa", 4), true);
    }

    /*
     * Find challenge5 key size will not work because the ciphertext is too short to collect enough
     * statistics.  However breaking its key without knowing keysize is still feasible.
    #[test]
    fn test_find_key_size() {
        let challenge5_ans = Vec::from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324").unwrap();
        let ksize = find_key_size(&challenge5_ans, 1..5);
        assert_eq!(ksize, Some(3));
    }
     */
}
