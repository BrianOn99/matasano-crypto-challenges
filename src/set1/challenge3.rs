extern crate matasano;
extern crate hex;

use std::io::{self, Write};
use hex::FromHex;

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext = Vec::from_hex(ciphertext).unwrap();

    let (best_key, _) = matasano::set1::decrypt_simple_xor(&ciphertext);
    let mut best_plaintext = matasano::set1::xor_buffers_cycle(&ciphertext, &[best_key]);
    best_plaintext.push(b'\n');
    io::stdout().write(&best_plaintext).expect("IO Error");
}
