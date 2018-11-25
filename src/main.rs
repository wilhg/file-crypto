extern crate base64;
extern crate ring;
mod crypto;

use self::crypto::*;

fn main() {
    let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);

    let mut in_out = b"d".to_vec();
    in_out.extend_from_slice(&vec![0u8; 16]);

    println!("0: {:?}", in_out);
    en.encrypt(&mut in_out);
    println!("a: {:?}", in_out);
    de.decrypt(&mut in_out);
    println!("b: {:?}", in_out);
}
