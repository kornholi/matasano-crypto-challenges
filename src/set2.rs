use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use std::fs::File;
use std::io::{BufReader, BufRead, Read};

use rand::{Rng, OsRng};

use util::*;

pub fn challenge9() {
    let mut padded = "YELLOW SUBMARINE".as_bytes().to_vec();

    pcks7_pad(&mut padded, 20);

    println!("Padded: {:?}", padded);
}

pub fn challenge10() {
    let mut data = vec!();
    File::open("data/10.txt").unwrap().read_to_end(&mut data).unwrap();
    
    let data = data.from_base64().unwrap();    
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let output = cbc_decrypt(aes128_decrypt, &data, key, iv);
    
    println!("Result: {:?}", String::from_utf8(output));
}

pub fn challenge11() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    let mut iv = [0; 16];
    rng.fill_bytes(&mut key);

    let mut encryption_oracle: Box<FnMut(&[u8]) -> Vec<u8>>;

    fn pad_random(input: &[u8], rng: &mut OsRng) -> Vec<u8> {
        let prefix_len = rng.gen_range(5, 10);
        let suffix_len = rng.gen_range(5, 10);

        let mut buf = Vec::<u8>::with_capacity(input.len() + prefix_len + suffix_len);
        
        for _ in 0..prefix_len {
            buf.push(rng.gen());
        }

        buf.extend(input);

        for _ in 0..suffix_len {
            buf.push(rng.gen());
        }

        let padding = 16 - buf.len() % 16;
        for _ in 0..padding {
            buf.push(0);
        }

        buf
    }

    if rng.gen_weighted_bool(2) {
        println!("Chose CBC");
        
        rng.fill_bytes(&mut iv);

        encryption_oracle =
            Box::new(|input| 
                     cbc_encrypt(aes128_encrypt, &pad_random(&input, &mut rng), &key[..], iv));
    } else {
        println!("Chose ECB");
        
        encryption_oracle =
            Box::new(|input|
                     aes128_encrypt(&pad_random(&input, &mut rng), &key[..]));
    }

    /* Attacker Side */
    
    let data = [0; 11+32];

    let encrypted_data = encryption_oracle(&data[..]);

    if detect_stateless_encryption(&encrypted_data, 16) {
        println!("Detected ECB");
    } else {
        println!("Detected non-ECB");
    }
}
