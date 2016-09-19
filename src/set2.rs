use serialize::base64::{self, ToBase64, FromBase64};
use serialize::hex::{FromHex, ToHex};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufRead, Read};
use std::str;

use rand::{Rng, OsRng};

use util::*;

pub fn challenge9() {
    let mut padded = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_pad(&mut padded, 20);

    println!("Padded: {:?}", padded);
}

pub fn challenge10() {
    let mut data = vec![];
    File::open("data/10.txt").unwrap().read_to_end(&mut data).unwrap();
    
    let data = data.from_base64().unwrap();    
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let output = cbc_decrypt(aes128_decrypt, &data, key, &iv);
    
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
                     cbc_encrypt(aes128_encrypt, &pad_random(&input, &mut rng), &key[..], &iv));
    } else {
        println!("Chose ECB");
        
        encryption_oracle =
            Box::new(|input|
                     aes128_encrypt(&pad_random(&input, &mut rng), &key[..]));
    }

    /* Attacker Side */
    let data = [0; 11+32];

    let encrypted_data = encryption_oracle(&data);

    if detect_stateless_encryption(&encrypted_data, 16) {
        println!("Detected ECB");
    } else {
        println!("Detected non-ECB");
    }
}

pub fn challenge12() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let suffix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".from_base64().unwrap();

    let encryption_oracle = |data: &[u8]| -> Vec<u8> {
        let mut input_data = [data, &suffix[..]].concat();
        pkcs7_pad(&mut input_data, 16);
        aes128_encrypt(&input_data, &key)
    };

    /* Attacker side */
    let input = vec![b'A'; 40];

    let mut out = encryption_oracle(&[]);
    let empty_len = out.len();

    let mut secret_padding = 0;

    // Detect block size and length of secret
    for i in 1..40 {
        out = encryption_oracle(&input[..i]);

        if out.len() > empty_len {
            secret_padding = i;
            break
        }
    }

    let block_size = out.len() - empty_len;
    let secret_len = empty_len - secret_padding;

    let out = encryption_oracle(&input[..2 * block_size]);
    let is_ecb = detect_stateless_encryption(&out, block_size);

    println!("Block size: {}, ECB: {}, Secret length: {}", block_size, is_ecb, secret_len);

    let mut secret = vec![0; empty_len];

    for i in (0..secret.len()).step_by(block_size) {
        break_block(&encryption_oracle, &mut secret, i, block_size);
    }

    secret.truncate(secret_len);

    println!("Decrypted secret: {:?}", String::from_utf8(secret));
}

/* ECB cut-and-paste */
pub fn challenge13() {
    fn parse_kv(input: &str) -> BTreeMap<String, String> {
        let mut h = BTreeMap::new();

        for elem in input.split('&') {
            let mut kv = elem.splitn(2, '=');

            let k = kv.next().unwrap();
            let v = kv.next().unwrap();

            h.insert(k.to_string(), v.to_string());
        }

        h
    }

    fn encode_kv(h: BTreeMap<&str, Cow<str>>) -> String {
        let mut s = String::new();

        for (k, v) in &h {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('&');
        }

        s.pop(); // Remove last &

        s
    }

    fn profile_for(email: &str) -> BTreeMap<&str, Cow<str>> {
        let mut h = BTreeMap::new();

        let safe_email = email.replace("&", "").replace("=", "");            

        h.insert("email", Cow::Owned(safe_email));
        h.insert("uid", Cow::Borrowed("10"));
        h.insert("role", Cow::Borrowed("user"));

        h
    }

    let mut rng = OsRng::new().unwrap();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let retrieve_profile = |email: &str| -> Vec<u8> {
        let mut kv = encode_kv(profile_for(email)).into_bytes();
    
        pkcs7_pad(&mut kv, 16);
        aes128_encrypt(&kv, &key)
    };

    let load_profile = |data: &[u8]| -> BTreeMap<String, String> {
        let mut decrypted = aes128_decrypt(data, &key);
        pkcs7_remove(&mut decrypted);

        parse_kv(&str::from_utf8(&decrypted).unwrap())
    };

    // Attacker
    let mut profile = retrieve_profile("foo@bar123456789.com");

    let mut source_email = String::new();
    source_email.push_str("foo@bar123456789.comxrolex");
    
    // Force a new block to be just "admin" padded with pkcs#7 
    source_email.push_str("admin");
    for _ in 0..(16 - 5) {
        source_email.push((16 - 5) as u8 as char);
    }
    
    let source_profile = retrieve_profile(&source_email);
    println!("original: {:?}", load_profile(&profile));

    // Copy the evil 3rd block into our profile
    // "email=foo......" "..........&role=" "admin.........."
    profile[32..32+16].copy_from_slice(&source_profile[32..32+16]);
    println!("evil: {:?}", load_profile(&profile)); 
}

pub fn challenge14() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let suffix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".from_base64().unwrap();

    let num_prefix_bytes = rng.gen::<u8>() as usize;
    let mut prefix = vec![0; num_prefix_bytes];
    rng.fill_bytes(&mut prefix);

    let encryption_oracle = |data: &[u8]| -> Vec<u8> {
        let mut input_data = [&prefix[..], data, &suffix[..]].concat();
        pkcs7_pad(&mut input_data, 16);
        aes128_encrypt(&input_data, &key)
    };

    /* Attacker side */
    let empty_len = encryption_oracle(&[]).len();

    // Detect block size and length of secret
    let input = vec![b'A'; 48];
    let mut secret_padding = 0;
    let mut block_size = 0;

    for i in 1..48 {
        let out = encryption_oracle(&input[..i]);

        if out.len() > empty_len {
            secret_padding = i;
            block_size = out.len() - empty_len;
            break
        }
    }

    let out = encryption_oracle(&input[..3 * block_size]);

    println!("Block size: {}", block_size);

    let mut offset = 0;
    for (i, (a, b)) in out.chunks(block_size).zip(out.chunks(block_size).skip(1)).enumerate() {
        if a == b {
            offset = i * block_size;
            break;
        }
    }

    // Find prefix len
    let mut prefix_len = 3 * block_size;
    loop {
        let out = encryption_oracle(&input[..prefix_len]);
        let is_ecb = detect_stateless_encryption(&out, block_size);

        if !is_ecb {
            prefix_len = prefix_len + 1 - 2 * block_size;
            break
        }

        prefix_len -= 1;
    }

    let secret_len = empty_len - (offset - prefix_len) - secret_padding;
    println!("Found offset {} n {} -> secret len {}", offset, prefix_len, secret_len);

    let input_prefix = vec![0; prefix_len];
    let mut secret = vec![0; secret_len + (block_size - secret_len % block_size)];

    let adjusted_oracle = |input: &[u8]| {
        let input_data = [&input_prefix[..], &input].concat();
        let mut output = encryption_oracle(&input_data);
        output.drain(..offset).count();
        output
    };

    for i in (0..secret_len).step_by(block_size) {
        break_block(&adjusted_oracle, &mut secret, i, block_size);
    }

    secret.truncate(secret_len);
    println!("Decrypted secret: {:?}", String::from_utf8(secret));
}

#[test]
pub fn challenge15() {
    assert_eq!(true, pkcs7_validate(&[1]));
    assert_eq!(true, pkcs7_validate(&[1, 1]));
    assert_eq!(true, pkcs7_validate(&[2, 1]));
    assert_eq!(true, pkcs7_validate(&[2, 2]));
    
    assert_eq!(false, pkcs7_validate(&[0]));
    assert_eq!(false, pkcs7_validate(&[2]));
    assert_eq!(false, pkcs7_validate(&[1, 2]));
    assert_eq!(false, pkcs7_validate(&[4, 4, 4]));
}

/* CRC bit-flipping attacks */
pub fn challenge16() {
    let mut rng = OsRng::new().unwrap();

    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);

    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    let save = |input: &str| {
        let mut safe_input = [&prefix, &input.replace(";", "%3B").replace("=", "%3D")[..], &suffix].concat().into_bytes();
        pkcs7_pad(&mut safe_input, 16);

        cbc_encrypt(aes128_encrypt, &safe_input, &key, &iv)
    };

    let load = |input: &[u8]| {
        let mut output = cbc_decrypt(aes128_decrypt, input, &key, &iv);
        pkcs7_remove(&mut output);

        output
    };

    let mut ciphertext = save("?admin?true");

    // Flip ?s to ; and =
    ciphertext[0 + 16] ^= 4;
    ciphertext[6 + 16] ^= 2;

    let decrypted = load(&ciphertext);
    let decrypted = String::from_utf8_lossy(&decrypted);

    println!("{:?} -> admin = {}", decrypted, decrypted.contains(";admin=true;"));
}