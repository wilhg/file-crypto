#![feature(test)]
extern crate test;
extern crate base64;
extern crate rayon;
extern crate ring;
extern crate file_crypto;

use file_crypto::crypto::*;
use file_crypto::file::*;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use test::Bencher;

#[bench]
fn sync_bench_en(b: &mut Bencher) {
    let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    let mut en = Encryption::new(key);

    let f = File::open("/Users/william/Downloads/ubuntu.dmg").unwrap();

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
        .open("/Users/william/Downloads/ubuntu2.dmg")
        .unwrap();
    let mut fr = FileReader::new(&f, PLAIN_CHUNK_LEN);
    let mut fw = FileWriter::new(
        &fb,
        f.metadata().unwrap().len() + chunk_num * TAG_LEN as u64,
        CIPHER_CHUNK_LEN,
    );
    const TAG: [u8; TAG_LEN as usize] = [0u8; TAG_LEN as usize];
    b.iter(|| {
        let mut i = 0u64;
        while let Some(chunk) = fr.get_chunk(i) {
            let mut buf = chunk.mmap.to_vec();
            buf.extend_from_slice(&TAG);
            en.encrypt(&mut buf);
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf);
            mmap_mut.flush().unwrap();
            i += 1;
        }
    });
}