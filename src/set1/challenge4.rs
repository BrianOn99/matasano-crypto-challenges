extern crate matasano;
extern crate hex;

use std::env;

use std::io::{self, Write};
use std::fs::File;
use hex::FromHex;
use std::io::BufReader;
use std::io::BufRead;
use std::cmp::Ordering;

/* 
 * To practice using trait, A Iterator is implemented for the decrypted lines.
 * It might be a overkill, and actually quite awkward.  And read_until of BufRead should be more
 * strait forward.  Nevertheless it is a good exercise.
 *
 * References:
 * https://stackoverflow.com/questions/30540766/how-can-i-add-new-methods-to-iterator
 * https://users.rust-lang.org/t/using-trait-bounds-on-an-associated-types-type-parameter/5306/2
 */
struct GoodLines<I>
    where I: Iterator
{
    lines: I,
}

impl<I> GoodLines<I>
    where I: Iterator
{
    fn new(iter: I) -> GoodLines<I> {
        GoodLines {
            lines: iter,
        }
    }
}

impl<I> Iterator for GoodLines<I>
    where I: Iterator<Item=Result<String, std::io::Error>>,
{
    type Item = (Vec<u8>, f64);

    fn next(&mut self) -> Option<(Vec<u8>, f64)> {
        match self.lines.next() {
            None => None,
            Some(line) => {
                if let Ok(line) = line {
                    let bytes = Vec::from_hex(line).expect("invalid hex");
                    Some(matasano::set1::decrypt_simple_xor(&bytes))
                } else {
                    None
                }
            }
        }
    }
}

fn main() {
    let mut args = env::args();
    args.next();

    let input_file = match args.next() {
        Some(arg) => {
            File::open(arg).expect("file not found")
        },
        None => panic!("No imput file given"),
    };

    let reader = BufReader::new(&input_file);

    let best_line = GoodLines::new(reader.lines())
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));
    let mut best_plaintext = best_line.unwrap().0;
    best_plaintext.push(b'\n');
    io::stdout().write(&best_plaintext).expect("IO Error");
}
