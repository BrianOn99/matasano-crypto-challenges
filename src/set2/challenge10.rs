extern crate openssl;
extern crate base64;
extern crate matasano;

use std::env;
use std::fs::File;
use std::io::{Write, Read};
use openssl::symm::*;

/*
 * A toy AES128 with CBC, iv of all zero, implemented based on openssl ECB mode
 */
fn my_cbc(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    decrypter.pad(false);
    let mut decrypted = vec![0u8; data.len()];
    let mut tmp: Vec<u8> = vec![0u8; 32];

    // first block, without xor
    decrypter.update(&data[0..16], &mut decrypted).expect("aes decrypt fail");

    // later blocks
    let mut i = 16;
    loop {
        decrypter.update(&data[i..i+16], &mut tmp).unwrap();
        matasano::set1::xor_buffers_buf(&tmp, &data[i-16..i], &mut decrypted[i..i+16]);
        i += 16;
        if i > data.len() - 16 { break }
    }

    matasano::set2::pkcs_7_remove(&mut decrypted).unwrap();
    return decrypted;
}

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

    let key = b"YELLOW SUBMARINE";
    let plaintext = my_cbc(&ciphertext, key);

    std::io::stdout().write(&plaintext).expect("IO Error");
    println!("");
}
