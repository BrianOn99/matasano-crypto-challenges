extern crate base64;
extern crate matasano;

use std::io::{Write};
use matasano::set3;

fn main() {
    let key = b"YELLOW SUBMARINE";

    let ciphertext = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let ciphertext = base64::decode_config(ciphertext.as_ref(), base64::MIME).expect("Base64 malformated");

    let out = set3::my_ctr(&ciphertext, key, &[0; 16]);

    std::io::stdout().write(&out).expect("IO Error");
    std::io::stdout().write(b"\n").expect("IO Error");
}
