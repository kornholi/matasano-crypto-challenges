use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::str;

use rand::{Rng, OsRng};

use util::*;

pub fn challenge17() {
    const BLOCK_SIZE: usize = 16;
    let strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", 
    ];
    
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; BLOCK_SIZE];
    rng.fill_bytes(&mut key);

    let get = |rng: &mut OsRng| {
        let mut input = rng.choose(&strings).unwrap().from_base64().unwrap();
        pkcs7_pad(&mut input, BLOCK_SIZE);

        let mut iv = [0; BLOCK_SIZE];
        rng.fill_bytes(&mut iv);

        (cbc_encrypt(aes128_encrypt, &input, &key, &iv), iv)
    };

    let oracle = |input: &[u8], iv: &[u8]| {
        let out = cbc_decrypt(aes128_decrypt, input, &key, iv);
        pkcs7_validate(&out)
    };

    let break_cbc_block = |rng: &mut OsRng, block: &[u8], iv: &[u8], p: &mut [u8]| -> bool {
        let mut c = [0; 2 * BLOCK_SIZE];
        c[BLOCK_SIZE..].copy_from_slice(block);

        for i in (0..BLOCK_SIZE).rev() {
            rng.fill_bytes(&mut c[..i]);

            let padding = (BLOCK_SIZE - i) as u8;

            // Set desired padding bytes with known plaintext
            for j in i+1..BLOCK_SIZE {
                c[j] = p[j] ^ iv[j] ^ padding;
            }

            for x in 0...255 {
                c[i] = x;

                if oracle(&c, iv) {
                    break;
                } else if x == 255 {
                    return false;
                }
            }

            p[i] = iv[i] ^ c[i] ^ padding;
        }

        true
    };

    let break_blocks = |rng: &mut OsRng, data: &[u8], iv: &[u8]| {
        let mut plaintext = vec![0; data.len()];

        for (i, block) in data.chunks(BLOCK_SIZE).enumerate() {
            let prev_block = if i == 0 {
                iv
            } else {
                &data[(i - 1)*BLOCK_SIZE..i*BLOCK_SIZE]
            };
            let output = &mut plaintext[i*BLOCK_SIZE..(i+1)*BLOCK_SIZE];

            while !break_cbc_block(rng, block, prev_block, output) {
                // Keep trying with new random bytes in case we got unlucky
            }
        }

        pkcs7_remove(&mut plaintext);
        plaintext
    };

    for _ in 0...10 {
        let (data, iv) = get(&mut rng);
        let plaintext = break_blocks(&mut rng, &data, &iv);

        println!("Decrypted: {:?}", String::from_utf8(plaintext));
    }
}

