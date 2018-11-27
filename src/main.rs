extern crate base64;
extern crate rayon;
extern crate ring;

mod crypto;
mod file;

use self::crypto::*;
use self::file::*;
use std::fs::{self, File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {
    let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);

    let f = File::open("/Users/wei.huang/Downloads/ubuntu.iso").unwrap();
    
    let f_size = f.metadata().unwrap().len();
    let chunk_num = if f_size % PLAIN_CHUNK_LEN == 0 {
        f_size / PLAIN_CHUNK_LEN
    } else {
        f_size / PLAIN_CHUNK_LEN + 1
    };

    let fb = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/Users/wei.huang/Downloads/ubuntu2.dmg")
        .unwrap();
    let mut fr = FileReader::new(&f, PLAIN_CHUNK_LEN);
    let mut fw = FileWriter::new(&fb, chunk_num * CIPHER_CHUNK_LEN, CIPHER_CHUNK_LEN);

    let mut page = AtomicUsize::new(0);
    while let Some(r) = fr.get_mmap(page) {
        https://doc.rust-lang.org/nomicon/atomics.html
        page+=1;
    }

    // rayon::scope(|s| {});

    // let mut in_out = b"d".to_vec();
    // in_out.extend_from_slice(&vec![0u8; 16]);

    // println!("0: {:?}", in_out);
    // en.encrypt(&mut in_out);
    // println!("a: {:?}", in_out);
    // de.decrypt(&mut in_out);
    // println!("b: {:?}", in_out);

    // let f = File::open("/Users/wei.huang/Downloads/ubuntu.iso").unwrap();
    // let f2 = OpenOptions::new().read(true).write(true).create(true).open("/Users/wei.huang/Downloads/ideaIU-2018.3.dmg1").unwrap();
    // let mut fr = FileReader::new(&f, 0x6400000);
    // let mut fw = FileWriter::new(&f2, f.metadata().unwrap().len() as usize, 0x6400000);

    // while let Some(r) = fr.next_mmap() {
    //     let mut w = fw.next_mmap().unwrap();
    //     println!("{:?}", w.len());
    //     w.copy_from_slice(&r);
    //     w.flush().unwrap();
    // }
}
