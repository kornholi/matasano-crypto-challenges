use util::*;

pub fn challenge1() {
    let mut padded = "YELLOW SUBMARINE".as_bytes().to_vec();

    pcks7_pad(&mut padded, 20);

    println!("Padded: {:?}", padded);
}

