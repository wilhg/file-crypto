#![feature(toowned_clone_into)]
extern crate ring;

mod crypto;
mod file;

use ring::aead::*;

fn main() {
    let token = [1u8; 32];
    let mut en = crypto::Encryption::with_token(&token);
    let mut de = crypto::Decryption::new(&token, &en.nonce());

    // let mut buf: Vec<u8> = Vec::new();
    // String::from("Af").as_bytes().clone_into(&mut buf);
    let content = b"content to encrypt".to_vec();
    // Ring uses the same input variable as output
    let mut in_out = content.clone();

    // The input/output variable need some space for a suffix
    println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    for _ in 0..CHACHA20_POLY1305.tag_len() {
        in_out.push(0);
    }
    println!("0: {:?}", in_out);
    en.encrypt(&mut in_out).unwrap();
    println!("a: {:?}", in_out);
    println!("b: {:?}", de.decrypt(&mut in_out));
}
