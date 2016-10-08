use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::{str, iter};

use byteorder::{LittleEndian, ByteOrder};
use rand::{Rng, OsRng};
use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use util::*;

pub fn challenge25() {
    let mut rng = OsRng::new().unwrap();
    
    let data = include_bytes!("../data/7.txt").from_base64().unwrap();
    let mut data = aes128_decrypt(&data, b"YELLOW SUBMARINE");
    
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    ctr_encrypt(&mut data, &key, 0);
    
    fn ctr_edit<'a, I>(ciphertext: &mut [u8], key: &[u8], mut offset: usize, new_data: I)
        where I: iter::IntoIterator<Item=&'a u8>
    {
        let mut counter = [0; 16];
        let mut new_data_iter = new_data.into_iter();

        for (i, block) in ciphertext.chunks_mut(16).enumerate() {
            while offset >= 16 {
                offset -= 16;
                continue;
            }

            LittleEndian::write_u64(&mut counter[8..], i as u64);
            let keystream = aes128_encrypt(&counter, key);

            for ((a, &k), d) in block.iter_mut().zip(keystream.iter()).skip(offset).zip(&mut new_data_iter) {
                *a = k ^ d;
            }
            
            offset = 0;
        }
    }

    // Save original ciphertext
    let orig_ciphertext = data.clone();

    // Overwrite with 0s to extract keystream    
    ctr_edit(&mut data, &key, 0, iter::repeat(&0));
   
    // xor original ciphertext with keystream 
    let plaintext: Vec<u8> = xor(&data, &orig_ciphertext); 

    println!("{:?}", String::from_utf8_lossy(&plaintext));
}