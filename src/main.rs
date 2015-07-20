#![feature(iter_arith)]

extern crate rustc_serialize as serialize;
extern crate crypto;

mod util;

mod set1;
mod set2;

fn main() {
    for arg in std::env::args().skip(1) {
        println!("Challenge {} results:", arg);

        match &arg[..] {
            "1.3" => set1::challenge1_3(),
            "1.6" => set1::challenge1_6(),
            "1.7" => set1::challenge1_7(),
            "1.8" => set1::challenge1_8(),

            "2.1" => set2::challenge1(),
            _ => ()
        }
    }
}


