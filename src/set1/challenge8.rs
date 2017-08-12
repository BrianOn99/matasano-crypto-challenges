extern crate matasano;
extern crate base64;

use std::env;
use std::fs::File;
use std::io::{BufReader, BufRead};

fn main() {
    let mut args = env::args();
    args.next();

    let input_file = match args.next() {
        Some(arg) => File::open(arg).expect("File not found"),
        None => panic!("No imput file given"),
    };

    let mut reader = BufReader::new(&input_file);
    let mut buf = vec![];
    let mut line_no = 0u32;
    loop {
        let c = reader.read_until(b'\n', &mut buf).expect("Error reading file");
        line_no += 1;
        if c == 0 { break }
        buf.pop();
        let ciphertext = base64::decode(&buf).expect("Base64 malformated");
        if matasano::set1::is_ecb(&ciphertext, 32) {
            println!("probable ecb: line {}", line_no);
        }
        buf.clear();
    }
}
