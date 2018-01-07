use openssl::symm::{encrypt, Cipher};
use set2;
use set1;

struct CipherInfo<'a> {
    f: &'a Fn(&[u8]) -> Result<(), set2::FormatError>,
    ciphertext: &'a [u8],
    block_size: usize
}

/// If pad_len is 2, it is assumed that now the cipher text decryts to [..., 2, 2]
/// Mutate ciphertext such that it decrypts to [..., 3, 3]
fn prepare_attack(ciphertext: &mut [u8], block_size: usize, pad_len: usize) {
    assert!(ciphertext.len() == block_size*2);
    let x = (pad_len ^ (pad_len + 1)) as u8;
    for y in &mut ciphertext[(block_size-pad_len)..block_size] {
        *y ^= x;
    }
}

fn attack_1_block(info: &CipherInfo, i: usize, result: &mut [u8]) {
    let mut dirty_copy = info.ciphertext[i..i+info.block_size*2].to_vec();

    // Set the second last byte of first block sth. different, to destroy the original padding
    // format.  ! in rust means bitwise negation.
    let j = info.block_size - 2;
    dirty_copy[j] = !dirty_copy[j];

    for k in (0..info.block_size).rev() {
        //this will compile to no-op?  for x in 0..256 {
        prepare_attack(&mut dirty_copy, info.block_size, info.block_size-k-1);
        for x in 0..256u16 {
            dirty_copy[k] = x as u8;
            if (info.f)(&dirty_copy).is_ok() {
                break;
            }
        }
    }

    // The decryted text now in the form [xyz, ..., 16,16,16,16, ..., 16] (16 trailing 16)
    // xor the found 16 bytes dirty_copy with 16u8, to get the intermediate CBC,
    // representation, and then xor it with original first 16 bytes.

    for x in &mut dirty_copy[0..info.block_size] {
        *x ^= 16u8;
    }
    set1::xor_buffers_buf(&dirty_copy[0..info.block_size],
                          &info.ciphertext[i..i+info.block_size],
                          result);
}

pub fn cbc_padding_oracle<F>(ciphertext: &[u8], f: F) -> Vec<u8>
        where F: Fn(&[u8]) -> Result<(), set2::FormatError> {
    // The requirement in challenge 17 also decrypts the 1st block, but it requires the iv.  It is
    // not reasonable in realworld so not implemented here.
    let block_size: usize = 16;
    let mut info = CipherInfo {
        f: &f,
        ciphertext: ciphertext,
        block_size: 16
    };
    let mut result = vec![0; ciphertext.len() - block_size];
    // this does not compile: for i in (0..(ciphertext.len()-32)).step_by(16).rev() {
    // [i+16..i+32] is the index to decrypt, decrypts to result[i..i+16]
    let mut i = ciphertext.len() - block_size*2;
    loop {
        attack_1_block(&mut info, i, &mut result[i..]);
        if i < block_size {break;}
        i -= block_size;
    }

    set2::pkcs_7_remove(&mut result).unwrap();
    return result;
}

pub fn my_ctr(text: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    // first 64 bits is nonce, second 64 bits is counter
    let mut ciphing_text = vec![0; 16];
    ciphing_text[0..16].copy_from_slice(nonce);

    let mut out = vec![0; text.len()];

    let mut i = 0;
    let block_count: usize = text.len() / 16;

    while i < block_count {
        let cipher = Cipher::aes_128_ecb();
        let offset = i * 16;

        unsafe {
            let counter: *mut u64 = &mut ciphing_text[8] as *mut u8 as *mut u64;
            // to_le compile to no-op in little endian machine
            *counter = i.to_le() as u64;
        }

        let enc_counter = encrypt(cipher, key, None, &ciphing_text).unwrap();
        set1::xor_buffers_buf(&enc_counter,
                              &text[offset..offset+16],
                              &mut out[offset..offset+16]);
        i += 1;
    }

    out
}
