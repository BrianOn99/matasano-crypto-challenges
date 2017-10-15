extern crate openssl;
extern crate base64;
extern crate matasano;

use std::io::Write;
use openssl::symm;

struct MyEncrypter {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    key: Vec<u8>
}

impl MyEncrypter {
    pub fn new() -> Self {
        MyEncrypter {
            prefix: b"secret PREFIX".to_vec(),
            suffix: b"secret SUFFIX".to_vec(),
            key: b"FourierTransform".to_vec()
        }
    }

    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut plaintext = vec![];
        plaintext.extend_from_slice(&self.prefix);
        plaintext.extend_from_slice(buf);
        plaintext.extend_from_slice(&self.suffix);

        //println!("encrypting {:?}", plaintext);
        let cipher = symm::Cipher::aes_128_ecb();
        return symm::encrypt(
            cipher,
            &self.key,
            None,
            &plaintext).unwrap();
    }
}

fn main() {
    let mut encrypter = MyEncrypter::new();
    let x = matasano::set2::ecb_wrapped_decypt_appended(|buf| encrypter.encrypt(buf));
    std::io::stdout().write(&x).expect("IO Error");
}
