extern crate base64;
extern crate ring;
mod crypto;
mod file;
use std::fs::{self, File, OpenOptions};

use self::crypto::*;
use self::file::*;

fn main() {
    // let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    // let mut en = Encryption::new(key);
    // let mut de = Decryption::new(key);

    // let mut in_out = b"d".to_vec();
    // in_out.extend_from_slice(&vec![0u8; 16]);

    // println!("0: {:?}", in_out);
    // en.encrypt(&mut in_out);
    // println!("a: {:?}", in_out);
    // de.decrypt(&mut in_out);
    // println!("b: {:?}", in_out);

    let f = File::open("/Users/wei.huang/Downloads/ubuntu.iso").unwrap();
    let f2 = OpenOptions::new().read(true).write(true).create(true).open("/Users/wei.huang/Downloads/ideaIU-2018.3.dmg1").unwrap();
    let mut fr = FileReader::new(&f, 0x6400000);
    let mut fw = FileWriter::new(&f2, f.metadata().unwrap().len() as usize, 0x6400000);

    while let Some(r) = fr.next_mmap() {
        let mut w = fw.next_mmap().unwrap();
        println!("{:?}", w.len());
        w.copy_from_slice(&r);
        w.flush().unwrap();
    }
}

