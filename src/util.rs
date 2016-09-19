use std::f32;
use std::ops::Range;

use byteorder::{LittleEndian, ByteOrder};

use crypto::aes;
use crypto::blockmodes::NoPadding;
use crypto::symmetriccipher::{Decryptor, Encryptor};

use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

// A -> Z
const ENGLISH_FREQUENCY: [f64; 26] = [0.08167, 0.01492, 0.02782,
0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
0.06966, 0.00153, 0.00772, 0.04025, 0.02406,
0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
0.06327, 0.09056, 0.02758, 0.00978, 0.02360,
0.00150, 0.01974, 0.00074];

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(x, y)| x^y).collect()
}

pub fn hamming_weight(a: &[u8], b: &[u8]) -> u32 {
    xor(a, b).iter().map(|x| x.count_ones()).sum()
}

pub fn english_score(input: &str) -> f64 {
    let mut frequency = [0.0; 26];
    let mut not_letters = 0;

    for c in input.chars() {
        match c {
            'a'...'z' => {
                let idx = c as u8 - b'a'; 
                frequency[idx as usize] += 1.0;
            },

            'A'...'Z' => {
                let idx = c as u8 - b'A';
                frequency[idx as usize] += 1.0;
            }

            ' ' | '\'' | '.' | ',' | ';' | '!' | '?' | '/' | '\r' | '\n' => (),

            _ => {
                not_letters += 1
            }
        }
    }

    // Cosine similarity
    let sum: f64 = input.len() as f64;//frequency.iter().sum();
    
    let freq_len: f64 = frequency.iter().map(|x| x*x/(sum*sum)).sum::<f64>().sqrt();
    let product: f64 = frequency.iter().zip(ENGLISH_FREQUENCY.iter()).map(|(x, y)| x/sum*y).sum();

    let text_ratio = (input.len() as f64 - not_letters as f64) / sum;

    text_ratio * product / freq_len
}

pub fn break_single_xor(input: &[u8]) -> (String, u8) {
    let mut best = (String::new(), 0.0);
    let mut best_key = 0;

    for key in 1...255 {
        let enc = xor(input, &[key]);
        let enc_str = String::from_utf8_lossy(&enc);

        let score = english_score(&enc_str);

        if score > best.1 {
            best = (enc_str.into_owned(), score);
            best_key = key;
        }
    }

    (best.0, best_key)
}

pub fn guess_key_size(data: &[u8], range: Range<usize>) -> usize {
    let mut best_key_size = (0, f32::INFINITY);

    for key_size in range {
        let mut dist = 0.0;

        for (a, b) in data.chunks(key_size).zip(data.chunks(key_size).skip(1)) {
            dist += hamming_weight(a, b) as f32;
        }

        // Average all chunks
        dist /= data.len() as f32 / key_size as f32;

        // Normalize by key size
        dist /= key_size as f32;

        if dist < best_key_size.1 {
            best_key_size = (key_size, dist);
        }
    }

    best_key_size.0
}

// 1.8
pub fn detect_stateless_encryption(data: &[u8], block_size: usize) -> bool {
    let mut blocks: Vec<&[u8]> = data.chunks(block_size).collect();

    // If we have duplicate blocks, 
    // the data might have been encrypted in ECB mode.
    let len = blocks.len();
    blocks.sort();
    blocks.dedup();
    let dedup_len = blocks.len();

    len != dedup_len
}

pub fn aes128_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut aes = aes::ecb_decryptor(aes::KeySize::KeySize128, key, NoPadding);

    let mut buffer = [0; 1024];
    let mut final_result = Vec::new();
    let mut read_buffer = RefReadBuffer::new(&data);
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        use crypto::buffer::BufferResult::*;

        let result = aes.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferUnderflow => break,
            BufferOverflow => ()
        }
    }

    final_result
}

pub fn aes128_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut aes = aes::ecb_encryptor(aes::KeySize::KeySize128, key, NoPadding);

    let mut buffer = [0; 1024];
    let mut final_result = Vec::new();
    let mut read_buffer = RefReadBuffer::new(&data);
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        use crypto::buffer::BufferResult::*;

        let result = aes.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferUnderflow => break,
            BufferOverflow => ()
        }
    }

    final_result
}

pub fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    let n = block_size - (data.len() % block_size);

    assert!(n < 0xFF);

    for _ in 0..n {
        data.push(n as u8);
    }
}

pub fn pkcs7_validate(data: &[u8]) -> bool {
    if data.len() == 0 {
        return false;
    }

    let padding = data[data.len() - 1] as usize;
    if padding == 0 {
        return false;
    }

    if data.len() < padding {
        return false;
    }
    
    data[data.len() - padding..].iter().all(|&x| x == padding as u8)
}

pub fn pkcs7_remove(data: &mut Vec<u8>) -> bool {
    if !pkcs7_validate(&data) {
        return false;
    }

    let end = data.len() - data[data.len() - 1] as usize;
    data.truncate(end);

    true
}

pub fn cbc_encrypt<F>(encrypt_fn: F, data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8>
    where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    let mut output = vec![];
    let mut last_block = [0; 16];
    last_block.copy_from_slice(iv);
    
    for block in data.chunks(16) {
        let in_block = xor(&block, &last_block);
        let mut out_block = encrypt_fn(&in_block, key);
       
        last_block.copy_from_slice(&out_block);
        output.append(&mut out_block);
    }

    output
}

pub fn cbc_decrypt<F>(decrypt_fn: F, data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8>
    where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    let mut output = vec![];
    let mut last_block = [0; 16];
    last_block.copy_from_slice(iv);

    for block in data.chunks(16) {
        let out_block = decrypt_fn(&block, key);
        let mut out_block = xor(&out_block, &last_block);
        
        last_block.copy_from_slice(&block);
        output.append(&mut out_block);
    }

    output
}

pub fn break_block<F>(oracle_fn: &F, data: &mut [u8], offset: usize, block_size: usize)
    where F: Fn(&[u8]) -> Vec<u8>
{
    let (prev_blocks, mut block) = data.split_at_mut(offset);

    if offset >= block_size {
        let prev_block = &prev_blocks[offset - block_size..offset];
        block[..block_size].copy_from_slice(prev_block);
    }

    for i in 0..block_size {
        let needle_block = oracle_fn(&block[..block_size-i-1]);

        for i in 1..block_size {
            block[i - 1] = block[i];
        }

        for b in 0...255 {
            block[block_size - 1] = b;
            let test_block = oracle_fn(block);

            if needle_block[offset..offset+block_size] == test_block[..block_size] {
                break
            }
        }
    }
}

pub fn ctr_encrypt(data: &mut [u8], key: &[u8], nonce: u64) {
    let mut counter = [0; 16];

    LittleEndian::write_u64(&mut counter, nonce);

    for (i, block) in data.chunks_mut(16).enumerate() {
        LittleEndian::write_u64(&mut counter[8..], i as u64);
        let keystream = aes128_encrypt(&counter, key);

        for (a, &k) in block.iter_mut().zip(keystream.iter()) {
            *a ^= k;
        }
    }
}