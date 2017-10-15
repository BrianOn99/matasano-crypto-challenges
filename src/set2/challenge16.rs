extern crate openssl;
extern crate base64;
extern crate matasano;

use openssl::symm::*;

struct Server {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>
}

impl Server {
    fn new() -> Self {
        Server {
            prefix: b"comment1=cooking%20MCs;userdata=".to_vec(),
            suffix: b";comment2=%20like%20a%20pound%20of%20bacon".to_vec(),
            key: b"fermisgoldenrule".to_vec(),
            iv: b"0000111122223333".to_vec()
        }
    }

    fn encrypt(&self, buf: &[u8]) -> Vec<u8> {
        let mut plaintext = vec![];
        plaintext.extend_from_slice(&self.prefix);
        plaintext.extend_from_slice(buf);
        plaintext.extend_from_slice(&self.suffix);

        let cipher = Cipher::aes_128_cbc();
        return encrypt(
            cipher,
            &self.key,
            Some(&self.iv),
            &plaintext).unwrap();
    }

    fn quote(buf: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(buf.len());
        for x in buf {
            match *x {
                b';'|b'=' => {
                    s.push(b'"');
                    s.push(*x);
                    s.push(b'"');
                },
                _ => {
                    s.push(*x);
                }
            }
        }

        s
    }

    fn get_token(&self, buf: &[u8]) -> Vec<u8> {
        self.encrypt(&Self::quote(buf))
    }

    fn is_admin(&self, data: &[u8]) -> bool {
        let cipher = Cipher::aes_128_cbc();
        let mut c = Crypter::new(cipher, Mode::Decrypt, &self.key, Some(&self.iv)).unwrap();
        c.pad(false);
        let mut out = vec![0; data.len() + 16];
        let count = c.update(data, &mut out).unwrap();
        let rest = c.finalize(&mut out[count..]).unwrap();
        out.truncate(count + rest);   
        //std::io::stdout().write(&out).expect("IO Error");

        out.split(|x| *x == b';')
           .any(|x| x == b"role=admin")
    }
}

fn main() {
    let some_stuff = b"111111111111111111111111111111111111111";
    let server = Server::new();
    let mut data = server.get_token(some_stuff);
    // the prefix will consume first 32 bytes
    matasano::set2::cbc_flip(&mut data[32..], some_stuff, b";role=admin;9999");
    if server.is_admin(&data) {
        println!("yes UA");
    }
}
