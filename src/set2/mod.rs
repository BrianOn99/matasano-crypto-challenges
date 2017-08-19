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

pub fn pkcs_7_remove(buf: &mut Vec<u8>) -> bool {
    let last_byte = buf[buf.len() - 1];
    if last_byte as usize > buf.len() {
        return false;
    } else {
        let orig_len = buf.len();
        buf.resize(orig_len - last_byte as usize, 0);
        return true;
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
