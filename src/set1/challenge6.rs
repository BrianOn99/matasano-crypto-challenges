extern crate matasano;
extern crate base64;
use std::env;
use std::fs::File;
use std::io::{Read, Write};

fn main() {
    let mut args = env::args();
    args.next();

    let mut input_file = match args.next() {
        Some(arg) => {
            File::open(arg).expect("File not found")
        },
        None => panic!("No imput file given"),
    };

    let mut buf: Vec<u8> = Vec::new();
    input_file.read_to_end(&mut buf).expect("Error reading file");
    let ciphertext = base64::decode_config(&buf, base64::MIME).expect("Base64 malformated");

    let key = matasano::set1::find_repeating_xor_key(&ciphertext, 1..40);
    let plaintext = matasano::set1::xor_buffers_cycle(&ciphertext, &key);
    std::io::stdout().write(&plaintext).expect("IO Error");
}
