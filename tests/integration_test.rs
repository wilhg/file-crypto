extern crate base64;
extern crate file_crypto;
extern crate rayon;
extern crate ring;

use file_crypto::crypto::*;
use file_crypto::ctrl::*;
use file_crypto::*;
use std::time::Instant;
use walkdir::WalkDir;

#[test]
fn cipher_integration() {
    let key = Key::new();
    let meta0 = CipherCtrl::init("./Cargo.lock");
    // let meta0 = CipherCtrl::init("/Users/wei.huang/Downloads/cipher/googlechrome.dmg");
    let gen_path = encrypt(&key, &meta0);

    let meta1 = CipherCtrl::init(&gen_path);
    decrypt(&key, &meta1);
}

#[test]
fn par_reduce() {
    use rayon::prelude::*;
    let s0 = (0u32..1000000u32)
        .into_par_iter()
        .map(|x| x.to_string())
        .reduce_with(|mut a, b| {
            a.push_str(&b);
            a
        }).unwrap();
    let s1 = (0u32..1000000u32)
        .into_iter()
        .map(|x| x.to_string())
        .fold(String::new(), |mut a, b| {
            a.push_str(&b);
            a
        });
    assert_eq!(s0, s1);
}

#[ignore]
#[test]
fn encrypt_bench() {
    let key = Key::new();
    let mb = 1048576.0;
    for path in get_files_from("/Users/wei.huang/Downloads/cipher") {
        let meta = CipherCtrl::init(&path);
        let name = meta.new_meta.path.clone();
        let size = meta.new_meta.size;
        println!("Name: {}", name);
        println!("Size: {}", size as f64 / mb);

        let just_now = Instant::now();
        encrypt(&key, &meta);
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
