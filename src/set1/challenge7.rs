extern crate openssl;
extern crate base64;

use std::env;
use std::fs::File;
use std::io::{Write, Read};
use openssl::symm;

fn main() {
    let mut args = env::args();
    args.next();

    let mut input_file = match args.next() {
        Some(arg) => File::open(arg).expect("File not found"),
        None => panic!("No imput file given"),
    };

    let mut buf: Vec<u8> = Vec::new();
    input_file.read_to_end(&mut buf).expect("Error reading file");
    let ciphertext = base64::decode_config(&buf, base64::MIME).expect("Base64 malformated");

    let cipher = symm::Cipher::aes_128_ecb();
    let key = b"YELLOW SUBMARINE";

    let plaintext = symm::decrypt(
        cipher,
        key,
        None,
        &ciphertext).unwrap_or_else(|err| panic!("error decoding AES: {}", err));

    std::io::stdout().write(&plaintext).expect("IO Error");
    println!("");
}
