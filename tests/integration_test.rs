#![feature(test)]
extern crate base64;
extern crate file_crypto;
extern crate rayon;
extern crate ring;
extern crate test;

use file_crypto::crypto::*;
use file_crypto::file::*;
use file_crypto::meta::*;
use file_crypto::*;
use std::fs::{File, OpenOptions};

#[test]
fn cipher_integration() {
    let key = Key::new();
    let meta0 = CipherMeta::init("/Users/wei.huang/Downloads/cuebyte-fireman-development.zip");
    let gen_path = encrypt(key, meta0);

    let meta1 = CipherMeta::init(&gen_path);
    decrypt(key, meta1);
}
