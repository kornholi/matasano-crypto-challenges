use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::{str, iter};

use byteorder::{LittleEndian, ByteOrder};
use rand::{Rng, OsRng};
use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use crypto::digest::Digest;
use sha1::Sha1;
use md4::Md4;

use cryptoutil;
use util::*;

pub fn challenge25() {
    let mut rng = OsRng::new().unwrap();
    
    let data = include_bytes!("../data/7.txt").from_base64().unwrap();
    let mut data = aes128_decrypt(&data, b"YELLOW SUBMARINE");
    
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let mut data = ctr_encrypt(&mut data, &key, 0);
    
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

pub fn challenge26() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    let save = |input: &str| {
        let mut safe_input = [&prefix, &input.replace(";", "%3B").replace("=", "%3D")[..], &suffix].concat().into_bytes();
        pkcs7_pad(&mut safe_input, 16);

        ctr_encrypt(&safe_input, &key, 0)
    };

    let load = |input: &[u8]| {
        let mut output = ctr_encrypt(input, &key, 0);
        pkcs7_remove(&mut output);

        output
    };

    let mut ciphertext = save("?admin?true");

    // Flip ?s to ; and =
    ciphertext[0 + 32] ^= 4;
    ciphertext[6 + 32] ^= 2;

    let decrypted = load(&ciphertext);
    let decrypted = String::from_utf8_lossy(&decrypted);

    println!("{:?} -> admin = {}", decrypted, decrypted.contains(";admin=true;"))
}

pub fn challenge27() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let iv = key.clone();

    let message = b"comment1=cooking%20MCs;userdata=supersecretye;comment2=%20like%20a%20pound%20of%20bacon";
    let mut message = message.to_vec();
    pkcs7_pad(&mut message, 16);
    let ciphertext = cbc_encrypt(aes128_encrypt, &message, &key, &iv);    

    let load = |input: &[u8]| {
        let mut output = cbc_decrypt(aes128_decrypt, input, &key, &iv);
        
        if output.iter().any(|&x| x > 0x80) {
            return Err(output);
        }     
        
        pkcs7_remove(&mut output);

        Ok(())
    };

    let status = load(&ciphertext);
    println!("Original ciphertext: {:?}", status);
    
    let mut evil_ciphertext = ciphertext.clone();
    // C3 = C1
    evil_ciphertext[32..48].copy_from_slice(&ciphertext[0..16]);
    // C2 = 0
    evil_ciphertext[16..32].copy_from_slice(&[0; 16]);

    let status = load(&evil_ciphertext);
    println!("Evil ciphertext: {:?}", status);
    let evil_plaintext = status.unwrap_err();
    
    // Key = P1 ^ P3
    let recovered_key = xor(&evil_plaintext[..16], &evil_plaintext[32..48]);
    
    assert_eq!(recovered_key, key);
    println!("Extracted key: {:?}", recovered_key);
    
    let plaintext = cbc_decrypt(aes128_decrypt, &ciphertext, &recovered_key, &recovered_key);    
    println!("Original message: {:?}", String::from_utf8_lossy(&plaintext));
}

pub fn challenge29() {
    fn sign(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut h = Sha1::new();
        h.input(key);
        h.input(message);
        
        let mut r = vec![0; 20];
        h.result(&mut r);
        r
    }
    
    fn validate(key: &[u8], message: &[u8], hmac: &[u8]) -> bool {
        &sign(key, message)[..] == hmac
    }
       
    let key = b"wikb0b0";
    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let hmac = sign(key, message);    

    fn sha1_pad(buf: &mut Vec<u8>, length: usize) {
        // Padding
        buf.push(0x80);
        buf.extend(iter::repeat(0).take(64 - 8 - 1 - (length % 64)));
        
        // Length in bits
        let mut high_bits = [0; 4];
        let mut low_bits = [0; 4];
        let length_bits = length * 8;
        cryptoutil::write_u32_be(&mut high_bits, (length_bits >> 32) as u32);
        cryptoutil::write_u32_be(&mut low_bits, length_bits as u32);
        buf.extend(&high_bits);
        buf.extend(&low_bits);
    }

    fn prefix_key_extend(key_len: usize, original_hash: &[u8], message: &[u8], extension: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut state = [0; 5];
        state[0] = cryptoutil::read_u32_be(&original_hash[0..4]);
        state[1] = cryptoutil::read_u32_be(&original_hash[4..8]);
        state[2] = cryptoutil::read_u32_be(&original_hash[8..12]);
        state[3] = cryptoutil::read_u32_be(&original_hash[12..16]);
        state[4] = cryptoutil::read_u32_be(&original_hash[16..20]);

        let mut evil_hmac = vec![0; 20];    
        let mut cloned_hasher = Sha1::new();
       
        // original data + padding byte (1) + size in bits (8) rounded up to next 64byte block 
        let sha_len = (key_len + message.len() + 1 + 8 + 63) / 64 * 64;
        cloned_hasher.set_state(&state, sha_len as u64 * 8);
        
        cloned_hasher.input(extension);
        cloned_hasher.result(&mut evil_hmac[..]);
    
        let mut evil_message = message.to_vec();
        sha1_pad(&mut evil_message, key_len + message.len());
        evil_message.extend(extension);
        
        (evil_hmac, evil_message)
    }
    
    for candidate_len in 0..24 {
        let (evil_hmac, evil_message) = prefix_key_extend(candidate_len, &hmac, message, b";admin=true");
        let valid = validate(key, &evil_message, &evil_hmac);
       
        if !valid {
            continue
        }
        
        println!("Found key length {}", candidate_len);

        println!("evil_hmac: {:?} valid: {}", evil_hmac, valid);
        println!("evil_message: {:?}", String::from_utf8_lossy(&evil_message));
        
        break;
    }
}

pub fn challenge30() {
    fn sign(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut h = Md4::new();
        h.input(key);
        h.input(message);
        
        let mut r = vec![0; 16];
        h.result(&mut r);
        r
    }
    
    fn validate(key: &[u8], message: &[u8], hmac: &[u8]) -> bool {
        &sign(key, message)[..] == hmac
    }
       
    let key = b"wikb0b0";
    let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let hmac = sign(key, message);    

    fn md4_pad(buf: &mut Vec<u8>, length: usize) {
        // Padding
        buf.push(0x80);
        buf.extend(iter::repeat(0).take(64 - 8 - 1 - (length % 64)));
        
        // Length in bits
        let mut high_bits = [0; 4];
        let mut low_bits = [0; 4];
        let length_bits = length * 8;
        cryptoutil::write_u32_le(&mut high_bits, (length_bits >> 32) as u32);
        cryptoutil::write_u32_le(&mut low_bits, length_bits as u32);
        buf.extend(&low_bits);
        buf.extend(&high_bits);
    }

    fn prefix_key_extend(key_len: usize, original_hash: &[u8], message: &[u8], extension: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut state = [0; 4];
        state[0] = cryptoutil::read_u32_le(&original_hash[0..4]);
        state[1] = cryptoutil::read_u32_le(&original_hash[4..8]);
        state[2] = cryptoutil::read_u32_le(&original_hash[8..12]);
        state[3] = cryptoutil::read_u32_le(&original_hash[12..16]);

        let mut evil_hmac = vec![0; 16];    
        let mut cloned_hasher = Md4::new();
       
        // original data + padding byte (1) + size in bits (8) rounded up to next 64byte block 
        let sha_len = (key_len + message.len() + 1 + 8 + 63) / 64 * 64;
        cloned_hasher.set_state(&state, sha_len as u64);
        
        cloned_hasher.input(extension);
        cloned_hasher.result(&mut evil_hmac[..]);
    
        let mut evil_message = message.to_vec();
        md4_pad(&mut evil_message, key_len + message.len());
        evil_message.extend(extension);
        
        (evil_hmac, evil_message)
    }
    
    for candidate_len in 0..24 {
        let (evil_hmac, evil_message) = prefix_key_extend(candidate_len, &hmac, message, b";admin=true");
        let valid = validate(key, &evil_message, &evil_hmac);
       
        if !valid {
            continue
        }
        
        println!("Found key length {}", candidate_len);

        println!("evil_hmac: {:?} valid: {}", evil_hmac, valid);
        println!("evil_message: {:?}", String::from_utf8_lossy(&evil_message));
        
        break;
    }
}