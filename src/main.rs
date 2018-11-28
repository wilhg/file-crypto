extern crate base64;
extern crate rayon;
extern crate ring;

pub mod crypto;
pub mod file;

use self::crypto::*;
use self::file::*;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering};

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
          .map_or(Key::new(), |k| Key::from(k.as_bytes()));

     TODO put the logic below to lib
     let origin_file = File::open(matches.value_of("FILE").unwrap()).expect("File not exists");
}
