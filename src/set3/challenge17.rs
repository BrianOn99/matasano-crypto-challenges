extern crate openssl;
extern crate matasano;
extern crate rand;

use std::io::{self, Write};
use rand::Rng;
use openssl::symm::*;
use matasano::set2;
use matasano::set3;

struct Server {
    key: Vec<u8>,
    iv: Vec<u8>,
    cipher: Cipher
}

impl Server {
    fn new() -> Self {
        Server {
            key: b"bells inequality".to_vec(),
            iv: b"0000111122223333".to_vec(),
            cipher: Cipher::aes_128_cbc()
        }
    }

    fn encryptd_message(&self) -> Vec<u8> {
       let choices: [&[u8]; 10] = [
           b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
           b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
           b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
           b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
           b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
           b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
           b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
           b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
           b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
           b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"];
        let plaintext = rand::weak_rng().choose(&choices).unwrap();

        encrypt(self.cipher, &self.key, Some(&self.iv), plaintext).unwrap()
    }

    fn validate_padding(&self, buf: &[u8]) -> Result<(), set2::FormatError> {
        let mut c = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(&self.iv)).unwrap();
        c.pad(false);
        let mut out = vec![0; buf.len() + 16];
        let count = c.update(buf, &mut out).unwrap();
        let rest = c.finalize(&mut out[count..]).unwrap();
        out.truncate(count + rest);

        set2::pkcs_7_remove(&mut out)
    }
}

// Below is attacker's code

fn main() {
    let server = Server::new();
    let ciphertext = server.encryptd_message();
    println!("ciphertext {:?}", ciphertext);

    let result = set3::cbc_padding_oracle(&ciphertext, |x: &[u8]| server.validate_padding(x));
    println!("cbc oracle result (excluding first 16 bytes):");
    io::stdout().write(&result).expect("IO Error");
    io::stdout().write(b"\n").expect("IO Error");
}
