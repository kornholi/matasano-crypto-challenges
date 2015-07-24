use serialize::base64::FromBase64;
use serialize::hex::FromHex;

use std::fs::File;
use std::io::{BufReader, BufRead, Read};

use util::*;

pub fn challenge3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex().unwrap();
    let best = break_single_xor(&input[..]);

    println!("Best match: {:?} - {}", best.1, best.0);
}

pub fn challenge6() {
    let mut input = vec!();
    File::open("data/6.txt").unwrap().read_to_end(&mut input).unwrap();
    
    let input = input.from_base64().unwrap();

    let key_size = guess_key_size(&input, 2..40);

    println!("Guessing key size - {:?}", key_size);

    let mut blocks = Vec::with_capacity(key_size);

    for _ in 0..key_size {
        blocks.push(Vec::with_capacity(input.len() / key_size));
    }

    for (i, x) in input.iter().enumerate() {
        blocks[i % key_size].push(*x);
    }

    let mut key = Vec::with_capacity(key_size);

    for block in blocks.iter() {
        let best = break_single_xor(&block[..]);

        key.push(best.1);
    }

    let data = xor(&input[..], &key[..]);

    println!("key: {:?} - {:?}", String::from_utf8(key), String::from_utf8(data));
}

pub fn challenge7() {
    let mut data = vec!();
    File::open("data/7.txt").unwrap().read_to_end(&mut data).unwrap();
    
    let data = data.from_base64().unwrap();
    
    let result = aes128_decrypt(&data, "YELLOW SUBMARINE".as_bytes());

    println!("Result: {:?}", String::from_utf8(result));
}

pub fn challenge8() {
    let input = BufReader::new(File::open("data/8.txt").unwrap());

    for line in input.lines() {
        let data = line.unwrap().from_hex().unwrap();

        if detect_stateless_encryption(&data, 16) {
            println!("POSSIBLE ECB - {:?}", data);
        }
    }
}

