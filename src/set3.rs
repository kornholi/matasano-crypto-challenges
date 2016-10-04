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

#[test]
pub fn challenge18() {
    let mut input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".from_base64().unwrap();
    ctr_encrypt(&mut input, b"YELLOW SUBMARINE", 0);

    let output = String::from_utf8(input).unwrap();

    assert!(&output == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
}

pub fn challenge20() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let mut inputs = vec![];
    for line in include_str!("../data/20.txt").lines() { 
        let mut line = line.from_base64().unwrap();
        ctr_encrypt(&mut line, &key, 0);
        inputs.push(line);
    }

    let max_len = inputs.iter().map(|ref x| x.len()).max().unwrap();
    let mut blocks = Vec::with_capacity(max_len);

    for _ in 0..max_len {
        blocks.push(Vec::new());
    }

    for input in &inputs {
        for (i, &x) in input.iter().enumerate() {
            blocks[i].push(x);
        }
    }

    let mut recovered_key = Vec::with_capacity(max_len);

    for block in &blocks {
        let best = break_single_xor(&block);
        recovered_key.push(best.1);
    }

    for input in &inputs {
        println!("{}", String::from_utf8_lossy(&xor(input, &recovered_key)));
    }
}

struct Mt19937 {
    index: i32,
    mt: [u32; 624]
}

impl Mt19937 {
    pub fn new() -> Mt19937 {
        Mt19937 {
            index: 624,
            mt: [0; 624]
        }
    }

    pub fn set_seed(&mut self, seed: u32) {
        self.mt[0] = seed;

        for i in 1..624 {
            self.mt[i] = (1_812_433_253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) as usize + i) as u32;
        }
    }

    pub fn set_mt(&mut self, mt: &[u32]) {
        self.mt.copy_from_slice(mt);
    }

    pub fn extract(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
        }

        let mut y = self.mt[self.index as usize];

        y ^= y >> 11;
        y ^= y << 7 & 2636928640;
        y ^= y << 15 & 4022730752;
        y ^= y >> 18;

        self.index += 1;

        return y;
    }

    pub fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) +
                (self.mt[(i + 1) % 624] & 0x7fffffff);

            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1;

            if y % 2 != 0 {
                self.mt[i] = self.mt[i] ^ 0x9908b0df;
            }
        }

        self.index = 0;
    }
}

/// Given y = x ^ (x >> shift), recover x
fn undo_rightshift_xor(mut x: u32, shift: u32) -> u32 {
    let mut mask = ((1 << shift) - 1) << (32 - shift); 

    // 32 / shift, rounded up
    let num_parts = (32 + shift - 1) / shift;

    for _ in 0..num_parts {
        x ^= (x >> shift) & mask;
        mask >>= shift;
    }

    x
}

/// Given y = x ^ ((x << shift) & mask), recover x
fn undo_leftshift_xor_mask(mut x: u32, shift: u32, given_mask: u32) -> u32 {
    let mut mask = (1 << shift) - 1; 

    // 32 / shift, rounded up
    let num_parts = (32 + shift - 1) / shift;

    for _ in 0..num_parts {
        x ^= (x << shift) & given_mask & mask;
        mask <<= shift;
    }

    x
}

pub fn challenge23() {
    let mut rng = Mt19937::new();
    rng.set_seed(1234567);

    let mut state = [0; 624];
    for i in 0..624 {
        let mut x = rng.extract();
        x = undo_rightshift_xor(x, 18);
        x = undo_leftshift_xor_mask(x, 15, 4022730752);
        x = undo_leftshift_xor_mask(x, 7, 2636928640);
        x = undo_rightshift_xor(x, 11);

        state[i] = x;
    }

    let mut evil_rng = Mt19937::new();
    evil_rng.set_mt(&state);

    for _ in 0..1000 {
        assert_eq!(rng.extract(), evil_rng.extract(), "cloned RNG does not match");
    }

    println!("Real RNG: {} Cloned RNG: {}", rng.extract(), evil_rng.extract());
}