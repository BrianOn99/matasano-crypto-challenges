extern crate matasano;
extern crate hex;

use std::io::{self, Write};
use hex::FromHex;

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext = Vec::from_hex(ciphertext).unwrap();

    let (mut best_plaintext, _) = matasano::set1::decrypt_simple_xor(&ciphertext);
    best_plaintext.push(b'\n');
    io::stdout().write(&best_plaintext).expect("IO Error");
}
