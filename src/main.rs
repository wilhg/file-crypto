extern crate base64;
extern crate file_crypto;
extern crate rayon;
extern crate ring;

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
          .about("Encrypt/Decrypt any file")
          .arg(Arg::with_name("FILE")
               .help("The path for the target file")
               .required(true)
               .index(1))
          .arg(Arg::with_name("key")
               .short("k")
               .long("key")
               .value_name("KEY")
               .help("The key for encrypt/decrypt the file")
               .takes_value(true))
          .get_matches();

     let key = matches
          .value_of("key")
          .map_or(Key::new(), |k| Key::from(k));
     let meta = CipherMeta::init(matches.value_of("FILE").unwrap());

     match meta.proc_type {
          ProcessType::Encrypt => println!("Key: {}\n The encrypted file is at {}", key.base64(), encrypt(key, meta)),
          ProcessType::Decrypt => println!("The decrypted file is at {}", decrypt(key, meta)),
     };
}
