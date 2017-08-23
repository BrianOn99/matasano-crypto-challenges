extern crate openssl;
extern crate rand;

use std::fs::File;
use std::io::Read;
use openssl::symm::{self, Cipher};
use rand::Rng;

struct RandEncrypter {
    urandom: File,
    rng: rand::ThreadRng,
    iv: [u8; 16]
}

impl RandEncrypter {
    pub fn new() -> RandEncrypter {
        RandEncrypter {
            urandom: File::open("/dev/urandom").expect("/dev/urandom not found"),
            rng: rand::thread_rng(),
            iv: [0; 16]
        }
    }

    fn gen_key(&mut self, key: &mut Vec<u8>) {
        self.urandom.read_exact(key).unwrap()
    }

    fn rand_vec(&mut self, n: usize) -> Vec<u8> {
        self.rng
            .gen_iter::<u8>()
            .take(n)
            .collect()
    }

    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 1];
        self.urandom.read_exact(&mut b).unwrap();
        let mut key = vec![0u8; 16];
        self.gen_key(&mut key);

        // add random prefix and suffix
        let pre_count: usize = (self.rng.gen::<usize>() % 6) + 5;
        let suff_count: usize = (self.rng.gen::<usize>() % 6) + 5;

        let mut plaintext = vec![];
        plaintext.append(&mut self.rand_vec(pre_count));
        plaintext.extend_from_slice(buf);
        plaintext.append(&mut self.rand_vec(suff_count));


        let (cipher, iv) = if b[0] > 128 {
            (Cipher::aes_128_ecb(), None)
        } else {
            (Cipher::aes_128_cbc(), Some(self.iv.as_ref()))
        };

        return symm::encrypt(
            cipher,
            &key,
            iv,
            &plaintext).unwrap();
    }
}

#[derive(Debug)]
enum BlockMode {
    ECB,
    Unknown
}

fn check_encrypt_mode<F>(mut f: F) -> BlockMode
        where F: FnMut(&[u8]) -> Vec<u8> {
    let attack_plaintext = [0u8; 48];
    let ciphertext = f(&attack_plaintext);

    return if &ciphertext[16..32] == &ciphertext[32..48] {
        BlockMode::ECB
    } else {
        BlockMode::Unknown
    }
}

fn main() {
    let mut encrypter = RandEncrypter::new();
    println!("Mode is {:?}", check_encrypt_mode(|buf| encrypter.encrypt(buf)));
}
