//challenge 9
pub fn pkcs_7(buf: &mut Vec<u8>, block_len: usize) {
    assert!(block_len < 256);
    let mut remain = block_len as isize - buf.len() as isize;
    let mut new_len = block_len;
    if remain < 0 {
        panic!("buf is larger than block size");
    } else if remain == 0  {
        new_len = block_len + block_len;
        remain = block_len as isize;
    }

    let to_pad = remain as u8;
    unsafe {
        let orig_len = buf.len();
        buf.set_len(new_len);
        let b_ptr = buf.as_mut_ptr().offset(orig_len as isize);
        for x in 0..remain {
            *b_ptr.offset(x as isize) = to_pad;
        }
    }
}

//challenge 10 and 15

#[derive(Debug)]
pub struct FormatError(());

pub fn pkcs_7_remove(buf: &mut Vec<u8>) -> Result<(), FormatError> {
    let last_byte = buf[buf.len() - 1];
    if last_byte as usize > buf.len() {
        return Err(FormatError(()));
    } else {
        let new_len = buf.len()- last_byte as usize;
        for &x in &buf[new_len..buf.len()-2] {
            if x != last_byte {
                return Err(FormatError(()));
            }
        }
        buf.resize(new_len, 0);
        return Ok(());
    }
}

fn shift_suffix<F>(mut f: F, attacker_len: usize, suffix_len: usize) -> Vec<u8> 
        where F: FnMut(&[u8]) -> Vec<u8> {
    let mut attacker: Vec<u8> = vec![0; attacker_len];
    let attacker_len = attacker.len();
    let mut known_suffix: Vec<u8> = vec![];

    while known_suffix.len() != suffix_len {
        let mut ans = f(&vec![0; attacker_len - known_suffix.len() - 1]);
        ans.resize(attacker_len, 0);
        attacker[attacker_len-known_suffix.len()-1 .. attacker_len-1].clone_from_slice(&known_suffix);

        for x in 0u16..256u16 {
            attacker[attacker_len-1] = x as u8;
            // ans and trial result should only differs in 1 block, so it is a waste to compare
            // the whole array, but performance is not too important here.
            if f(&attacker)[..attacker_len] == ans[..attacker_len] {
                known_suffix.push(x as u8);
                break;
            }
        }
    }

    return known_suffix;
}

// challenge 12
pub fn ecb_decypt_appended<F>(mut f: F) -> Vec<u8> 
        where F: FnMut(&[u8]) -> Vec<u8> {
    let p0_len = f(&[0u8; 0]).len();

    let mut block_len = 0;
    let mut suffix_len = 0;
    for x in 1usize.. {
        let l = f(&vec![0u8; x]).len();
        if l != p0_len {
            suffix_len = p0_len - x;
            block_len = l - p0_len;
            break;
        }
    }

    let attacker_len = suffix_len - (suffix_len % block_len) + block_len;
    shift_suffix(f, attacker_len, suffix_len)
}

//challenge14
pub fn ecb_wrapped_decypt_appended<F>(mut f: F) -> Vec<u8> 
        where F: FnMut(&[u8]) -> Vec<u8> {
    let p0_len = f(&[0u8; 0]).len();

    /*
     * Symbols Meaning
     *<--pre--><--attacker_payload--><--post-->
     *^ len:p ^^       len:k        ^^ len:z  ^,  whete p+k+o mod 16 = 0
     *         ^     len:a        ^  ,where p+a mod 16 = 0
     */
    let mut block_len = 0;
    //let mut suffix_len = 0;
    let mut k = 0;
    for x in 1usize.. {
        let l = f(&vec![0u8; x]).len();
        if l != p0_len {
            block_len = l - p0_len;
            k = x + l;  // +l just make k sufficiently large, not always necessary.
            break;
        }
    }

    let mut attacker: Vec<u8> = vec![0; k];
    let enc_all0 = f(&attacker);
    attacker[k-1] = 1;
    let enc_f1 = f(&attacker);
    // pa means p + a
    let pa = enc_all0.iter().zip(enc_f1.iter()).position(|(a,b)| a!= b).unwrap() - 1;
    let mut a = k - 2;  // the index to change from 0 to 1 of attacker

    loop {
        attacker[a] = 1;
        // check if the a-th byte is at block ending boundary by diffing.  Check more than 1 byte
        // to avoid collision.
        if f(&attacker)[pa-1..pa+1] != enc_f1[pa-1..pa+1] {
            break;
        }
        a = a - 1;
    }

    // enc_all0.len()-block_len is equivalent to p+k+z
    let z = (enc_all0.len()-block_len) - pa - (k-a);
    a = a+1;  // convert c-style index to length

    shift_suffix(f, a, z)
}

#[cfg(test)]
mod test {
    use super::*;
    extern crate base64;
    extern crate openssl;
    use self::openssl::symm::{self, Cipher};

    struct MyEncrypter {
        suffix: Vec<u8>,
        key: Vec<u8>
    }

    impl MyEncrypter {
        pub fn new() -> Self {
            let secret = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".to_vec();
            let secret = base64::decode_config(&secret, base64::MIME).expect("Base64 malformated");
            MyEncrypter {
                suffix: secret,
                key: b"LorentzTransform".to_vec()
            }
        }

        pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {
            let mut plaintext = vec![];
            plaintext.extend_from_slice(buf);
            plaintext.extend_from_slice(&self.suffix);

            //println!("encrypting {:?}", plaintext);
            let cipher = Cipher::aes_128_ecb();
            return symm::encrypt(
                cipher,
                &self.key,
                None,
                &plaintext).unwrap();
        }
    }

    #[test]
    fn test_ecb_decypt_appended() {
        let mut encrypter = MyEncrypter::new();
        let res = ecb_decypt_appended(|buf| encrypter.encrypt(buf));
        // The answer starts with "Rollin' in my", not showing the full one here as a spoiler
        assert!(res.starts_with(&b"Rollin' in my"[..]));
    }

    #[test]
    fn test_invalid_pkcs_7_remove() {
        let mut block = b"ICEI ICE BABY\x05\x05\x05\x05".to_vec();
        assert!(pkcs_7_remove(&mut block).is_err());
    }

    #[test]
    fn test_pkcs_7_not_multiple() {
        let mut block = b"Minkowski".to_vec();
        pkcs_7(&mut block, 16);
        assert_eq!(&block, b"Minkowski\x07\x07\x07\x07\x07\x07\x07");
    }

    #[test]
    fn test_pkcs_7_multiple() {
        let mut block = b"Euclid".to_vec();
        pkcs_7(&mut block, 6);
        assert_eq!(&block, b"Euclid\x06\x06\x06\x06\x06\x06");
    }
}
