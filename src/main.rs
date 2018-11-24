extern crate base64;
extern crate ring;
mod crypto;
mod file;

use ring::aead::*;
use self::crypto::*;

fn main() {
    let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);
    
    let mut in_out = b"content to encrypt".to_vec();

    println!("0: {:?}", in_out);
    let mut b = en.encrypt(&mut in_out).unwrap();
    println!("a: {:?}", b);
    println!("b: {:?}", de.decrypt(&mut b));
}
