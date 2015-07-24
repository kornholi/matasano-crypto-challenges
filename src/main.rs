#![feature(iter_arith, slice_bytes, append)]

extern crate rand;
extern crate rustc_serialize as serialize;
extern crate crypto;

mod util;

mod set1;
mod set2;

fn main() {
    for arg in std::env::args().skip(1) {
        println!("Challenge {} results:", arg);

        match &arg[..] {
            "1.3" => set1::challenge3(),
            "1.6" => set1::challenge6(),
            "1.7" => set1::challenge7(),
            "1.8" => set1::challenge8(),

            "2.1" => set2::challenge9(),
            "2.2" => set2::challenge10(),
            "2.3" => set2::challenge11(),
            _ => ()
        }
    }
}


