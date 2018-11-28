#![feature(test)]
extern crate base64;
extern crate file_crypto;
extern crate rayon;
extern crate ring;
extern crate test;

use file_crypto::crypto::*;
use file_crypto::file::*;
use std::fs::{File, OpenOptions};

const TAG: [u8; TAG_LEN as usize] = [0u8; TAG_LEN as usize];

#[test]
fn cipher() {
    let key = Key::new();
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);
    let content = b"abcdefg";
    let len = content.len();
    let mut buf = content.to_vec();

    buf.extend_from_slice(&TAG);
    en.encrypt(&mut buf, &Nonce::from(1));
    let tag = Vec::from(&buf[len..]);
    assert_ne!(content, &buf[..len]);
    de.decrypt(&mut buf, &Nonce::from(1));
    assert_eq!(content, &buf[..len]);
    // assert_eq!(tag, &buf[len..]);
}

#[test]
fn async_test() {
    let key = Key::new();
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);

    let f = File::open("/Users/wei.huang/Downloads/jdk-11_osx-x64_bin.dmg").unwrap();

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
    let fc = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/Users/wei.huang/Downloads/ubuntu3.dmg")
        .unwrap();
    let fr = FileReader::new(&f, PLAIN_CHUNK_LEN);
    let fw = FileWriter::new(
        &fb,
        f.metadata().unwrap().len() + chunk_num * TAG_LEN as u64,
        CIPHER_CHUNK_LEN,
    );
    let fr2 = FileReader::new(&fb, CIPHER_CHUNK_LEN);
    let fw2 = FileWriter::new(&fc, f.metadata().unwrap().len(), PLAIN_CHUNK_LEN);

    const AD: [u8; 0] = [0u8; 0];
    use rayon::prelude::*;
    use ring::aead::*;

    use std::time::{Duration, Instant};
    let now = Instant::now();
    (0..chunk_num)
        .into_par_iter()
        .map(move |i| {
            let chunk = fr.get_chunk(i).unwrap();
            let mut buf = chunk.mmap.to_vec();
            buf.extend_from_slice(&TAG);
            (i, buf)
        })
        .map(move |(i, mut buf)| {
            let k = SealingKey::new(&AES_256_GCM, &key.0).unwrap();
            seal_in_place(&k, &Nonce::from(i).0, &[], &mut buf, AES_256_GCM.tag_len()).unwrap();
            (i, buf)
        })
        .for_each(move |(i, buf)| {
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf);
            mmap_mut.flush().unwrap();
        });
    let new_now = Instant::now();
    println!("{:?}", new_now.duration_since(now));
}

#[test]
fn bsync_test() {
    let key = Key::from("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDA=");
    let mut en = Encryption::new(key);
    let mut de = Decryption::new(key);

    let f = File::open("/Users/wei.huang/Downloads/ubuntu.dmg").unwrap();

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
    let fc = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/Users/wei.huang/Downloads/ubuntu3.dmg")
        .unwrap();
    let mut fr = FileReader::new(&f, PLAIN_CHUNK_LEN);
    let mut fw = FileWriter::new(
        &fb,
        f.metadata().unwrap().len() + chunk_num * TAG_LEN as u64,
        CIPHER_CHUNK_LEN,
    );
    let mut fr2 = FileReader::new(&fb, CIPHER_CHUNK_LEN);
    let mut fw2 = FileWriter::new(&fc, f.metadata().unwrap().len(), PLAIN_CHUNK_LEN);

    let mut i = 0u64;
    while let Some(chunk) = fr.get_chunk(i) {
        let mut buf = chunk.mmap.to_vec();
        buf.extend_from_slice(&TAG);
        en.encrypt(&mut buf, &Nonce::from(i));
        let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;

        mmap_mut.copy_from_slice(&buf);
        mmap_mut.flush().unwrap();
        i += 1;
    }

    let mut i = 0u64;
    while let Some(chunk) = fr2.get_chunk(i) {
        let mut buf = chunk.mmap.to_vec();
        de.decrypt(&mut buf, &Nonce::from(i));
        let mut mmap_mut = fw2.get_chunk_mut(i).unwrap().mmap_mut;

        mmap_mut.copy_from_slice(&buf[..buf.len() - TAG_LEN as usize]);
        mmap_mut.flush().unwrap();
        i += 1;
    }
}
