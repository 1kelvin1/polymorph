//! Basic usage example

use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file>", args[0]);
        process::exit(1);
    }

    match fs::read(&args[1]) {
        Ok(data) => {
            println!("File size: {} bytes", data.len());
            println!("First 16 bytes: {:02x?}", &data[..16.min(data.len())]);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
