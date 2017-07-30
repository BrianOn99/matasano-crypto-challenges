use super::*;
use hex::FromHex;
extern crate base64;

// challenge1
#[test]
fn test_hex_to_base64() {

    fn hex_to_base64(src: &str) -> String {
        let decoded = Vec::from_hex(src).expect("invalid hex string");
        base64::encode(&decoded)
    }

    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}


// challenge2
#[test]
fn test_xor() {
    assert_eq!(
        xor_buffers(&Vec::from_hex("1c0111001f010100061a024b53535009181c").unwrap(),
                    &Vec::from_hex("686974207468652062756c6c277320657965").unwrap()),
        Vec::from_hex("746865206b696420646f6e277420706c6179").unwrap());
}

#[test]
fn test_short_key() {
    let ans: Vec<u8> = vec![0xb0, 0x70];
    assert_eq!(xor_buffers_cycle(&vec![0xe9, 0x29], &vec![0x59]), ans)
}


// challenge5, almost same as challenge2
#[test]
fn test_repeating_key_xor() {
    let plain_text =
b"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = b"ICE";
    let ans = Vec::from_hex(
"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c65\
2a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

    let ciphertext = xor_buffers_cycle(plain_text, key);
    assert_eq!(ciphertext, ans)
}
