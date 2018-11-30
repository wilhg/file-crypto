pub mod crypto;
pub mod file;
pub mod meta;

use file_crypto::crypto::*;
use file_crypto::meta::*;
use file_crypto::*;

extern crate clap;
use clap::{App, Arg};
fn main() {
     let matches = App::new("File Crypto")
          .version("0.1.0")
          .author("William Huang <william.hng@outlook.com>")
          .about("file-crypto is a platform-cross command line tool for fastly encrypting / decrypting any file with AES-256-GCM")
          .arg(Arg::with_name("encrypt")
               .short("e")
               .long("encrypt")
               .help("To encrypt the file"))
          .arg(Arg::with_name("decrypt")
               .short("d")
               .long("decrypt")
               .help("To decrypt the file"))
          .arg(Arg::with_name("key")
               .short("k")
               .long("key")
               .value_name("KEY")
               .help("The key for encrypt/decrypt the file")
               .takes_value(true))
          .arg(Arg::with_name("FILE")
               .help("The path for the target file")
               .required(true)
               .index(1))
          .get_matches();

     let path = matches.value_of("FILE").unwrap();
     let encrypt_mode = (matches.is_present("encrypt") as u8) << 1;
     let decrypt_mode = matches.is_present("decrypt") as u8;
     let meta = match encrypt_mode | decrypt_mode {
          0b01 => CipherMeta::init_with_type(path, ProcessType::Decrypt),
          0b10 => CipherMeta::init_with_type(path, ProcessType::Encrypt),
          0b11 => panic!("Cannot set encrypt-mode and decrypt-mode at the same time"),
          _ => CipherMeta::init(path),
     };

     let key = matches.value_of("key").map_or(Key::new(), |k| Key::from(k));
     match meta.proc_type {
          ProcessType::Encrypt => println!(
               "The new key is: {}\n (Please keep the key in the safe way.)\nThe encrypted file is at: {}",
               key.base64(),
               encrypt(key, meta)
          ),
          ProcessType::Decrypt => println!("The decrypted file is at {}", decrypt(key, meta)),
     };
}
