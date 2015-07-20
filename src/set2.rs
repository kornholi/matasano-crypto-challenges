use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use std::fs::File;
use std::io::{BufReader, BufRead, Read};

use util::*;

pub fn challenge1() {
    let mut padded = "YELLOW SUBMARINE".as_bytes().to_vec();

    pcks7_pad(&mut padded, 20);

    println!("Padded: {:?}", padded);
}

pub fn challenge2() {
    let mut data = vec!();
    File::open("data/10.txt").unwrap().read_to_end(&mut data).unwrap();
    
    let data = data.from_base64().unwrap();    
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let mut output = cbc_decrypt(aes128_decrypt, &data, key, iv);
    
    println!("Result: {:?}", String::from_utf8(output));
}
