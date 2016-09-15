#![feature(step_by)]
#![allow(unused_imports)]

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
            "3" => set1::challenge3(),
            "6" => set1::challenge6(),
            "7" => set1::challenge7(),
            "8" => set1::challenge8(),

            "9" => set2::challenge9(),
            "10" => set2::challenge10(),
            "11" => set2::challenge11(),
            "12" => set2::challenge12(),
            "13" => set2::challenge13(),
            "14" => set2::challenge14(),
            "16" => set2::challenge16(),
            _ => println!("Unknown challenge")
        }
    }
}


