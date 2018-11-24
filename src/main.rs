#![feature(toowned_clone_into)]
extern crate base64;
extern crate ring;

mod crypto;
mod file;

use ring::aead::*;

fn main() {
    let key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=";
    let mut en = crypto::Encryption::with_key(key);
    let mut de = crypto::Decryption::new(&en.key());

    // let mut buf: Vec<u8> = Vec::new();
    // String::from("Af").as_bytes().clone_into(&mut buf);
    let content = b"content to encrypt".to_vec();
    // Ring uses the same input variable as output
    let mut in_out = content.clone();

    // The input/output variable need some space for a suffix
    // println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    // for _ in 0..CHACHA20_POLY1305.tag_len() {
    //     in_out.push(0u8);
    // }

    println!("0: {:?}", in_out);
    let mut b = en.encrypt(&mut in_out).unwrap();
    println!("a: {:?}", b);
    println!("b: {:?}", de.decrypt(&mut b));
}
