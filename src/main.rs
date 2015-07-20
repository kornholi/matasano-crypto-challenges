#![feature(iter_arith)]

extern crate rustc_serialize as serialize;

//use std::collections::HashMap;

use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use std::fs::File;
use std::io::Read;

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(x, y)| x^y).collect()
}

fn hamming_weight(a: &[u8], b: &[u8]) -> u32 {
    xor(a, b).iter().map(|x| x.count_ones()).sum()
}

// A -> Z
const ENGLISH_FREQUENCY: [f32; 26] = [0.08167, 0.01492, 0.02782,
0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
0.06966, 0.00153, 0.00772, 0.04025, 0.02406,
0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
0.06327, 0.09056, 0.02758, 0.00978, 0.02360,
0.00150, 0.01974, 0.00074];

const ENGLISH_FREQUENCY_LENGTH: f32 = 1.0;

fn english_score(input: &str) -> f32 {
    let mut frequency = [0.0; 26];

    let mut not_letters = 0;

    for c in input.chars() {
        match c {
            'a'...'z' => {
                let idx = c as u8 - 'a' as u8; 
                frequency[idx as usize] += 1.0;
            },

            'A'...'Z' => {
                let idx = c as u8 - 'A' as u8;
                frequency[idx as usize] += 1.0;
            }

            ' ' | '\'' | '.' | '!' | '?' | '\r' | '\n' => (),

            _ => {
                not_letters += 2
            }
        }
    }

    // Cosine similarity
    let sum: f32 = input.len() as f32;//frequency.iter().sum();
    let freq_len: f32 = frequency.iter().map(|x| x*x/(sum*sum)).sum::<f32>().sqrt();
   
    let product: f32 = frequency.iter().zip(ENGLISH_FREQUENCY.iter()).map(|(x, y)| x/sum*y).sum();

    (input.len() as f32 - not_letters as f32) / sum * product / (freq_len * ENGLISH_FREQUENCY_LENGTH)
}

fn break_single_xor(input: &[u8]) -> (String, u8) {
    let mut best = (String::new(), 0.0);
    let mut best_key = 0;

    for key in 1..0xFF {
        let enc = xor(input, &vec!(key));

        let enc_str = match String::from_utf8(enc) {
            Ok(s) => s,
            Err(_) => continue
        };

        let score = english_score(&enc_str);

        if score > best.1 {
            best = (enc_str, score);
            best_key = key;
        }
    }

    (best.0, best_key)
}

fn challenge1_3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex().unwrap();
    let best = break_single_xor(&input[..]);

    println!("Best match: {:?} - {}", best.1, best.0);
}

fn challenge1_6() {
    let mut input = vec!();
    File::open("data/6.txt").unwrap().read_to_end(&mut input).unwrap();
    
    let input = input.from_base64().unwrap();

    let mut best_key_size = (0, std::f32::INFINITY);

    for key_size in 2..40 {
        let mut dist = 0.0;

        for (a, b) in input.chunks(key_size).zip(input.chunks(key_size).skip(1)) {
            dist += hamming_weight(a, b) as f32;
        }

        // Average all chunks
        dist /= input.len() as f32 / key_size as f32;

        // Normalize by key size
        dist /= key_size as f32;

        if dist < best_key_size.1 {
            best_key_size = (key_size, dist);
        }
    }

    println!("Guessing key size - {:?}", best_key_size);

    let key_size = best_key_size.0;

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

fn main() {
    return challenge1_6();

    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

    println!("{}", xor(&input[..].as_bytes(), "ICE".as_bytes()).to_hex());

//    println!("{}", a.iter().zip(b.iter().cloned().cycle()).map(|(x, y)| x^y).collect::<Vec<u8>>().to_hex());

    println!("{}", hamming_weight("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
}


