//! Batch scanning multiple files

use std::fs;
use std::path::Path;

fn main() {
    let files = vec!["sample1.exe", "sample2.wasm", "sample3.elf"];
    
    for file in files {
        if Path::new(file).exists() {
            match fs::read(file) {
                Ok(data) => println!("{}: {} bytes", file, data.len()),
                Err(e) => eprintln!("{}: Error - {}", file, e),
            }
        }
    }
}
