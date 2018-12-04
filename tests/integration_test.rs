#![feature(test)]
extern crate base64;
extern crate file_crypto;
extern crate rayon;
extern crate ring;
extern crate test;

use file_crypto::crypto::*;
use file_crypto::meta::*;
use file_crypto::*;
use std::time::Instant;
use walkdir::WalkDir;

#[test]
fn cipher_integration() {
    let key = Key::new();
    let meta0 = CipherMeta::init("./Cargo.lock");
    let gen_path = encrypt(key, meta0);

    let meta1 = CipherMeta::init(&gen_path);
    decrypt(key, meta1);
}

#[ignore]
#[test]
fn encrypt_bench() {
    let key = Key::new();
    let mb = 1048576.0;
    for path in get_files_from("/Users/wei.huang/Downloads/cipher") {
        let meta = CipherMeta::init(&path);
        let name = meta.gen_file_path.clone();
        let size = meta.gen_file_size;
        println!("Name: {}", name);
        println!("Size: {}", size as f64 / mb);

        let just_now = Instant::now();
        encrypt(key, meta);
        println!("Time: {:?}\n", Instant::now().duration_since(just_now));
    }
}

fn get_files_from(dir_path: &str) -> Vec<String> {
    WalkDir::new(dir_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.metadata().unwrap().is_file() && !e.file_name().to_str().unwrap().starts_with(".")
        })
        .map(|e| e.path().to_str().unwrap().to_owned())
        .collect()
}
