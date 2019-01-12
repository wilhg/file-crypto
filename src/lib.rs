pub mod crypto;
pub mod ctrl;
pub mod file;

use self::crypto::*;
use self::ctrl::*;
use self::file::*;
use rayon::prelude::*;

const TAG: [u8; TAG_LEN as usize] = [0u8; TAG_LEN as usize];

pub fn encrypt(key: &Key, ctrl: &CipherCtrl) -> String {
    let cryption = Cryption::new(key);
    let hmac = Hmac::new(key);
    let fr = FileReader::new(ctrl);
    let fw = FileWriter::new(ctrl);

    let footprint = (0..ctrl.chunk_num)
        .into_par_iter()
        .map(|i| {
            let chunk = fr.get_chunk(i).unwrap();
            let mut buf = chunk.mmap.to_vec();
            buf.extend_from_slice(&TAG);
            (i, buf)
        })
        .map(|(i, mut buf)| {
            cryption.encrypt(&mut buf, &Nonce::from(i));
            (i, buf)
        })
        .map(|(i, buf)| {
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf);
            mmap_mut.flush().unwrap();
            Vec::from(&buf[buf.len() - TAG_LEN..])
        })
        .reduce_with(|mut acc, x| {
            acc.extend(x);
            acc
        })
        .unwrap();
    let data = Header::new(ctrl.old_meta.size as u64, ctrl.new_meta.chunk_size as u64, hmac.sign(&footprint));
    let mut header = fw.header();
    header.copy_from_slice(&data.data());
    header.flush().unwrap();

    ctrl.new_meta.path.clone()
}

pub fn decrypt(key: &Key, ctrl: &CipherCtrl) -> String {
    let cryption = Cryption::new(key);
    let hmac = Hmac::new(key);
    let fr = FileReader::new(ctrl);
    let fw = FileWriter::new(ctrl);

    let header = fr.header();

    let footprint = (0..ctrl.chunk_num)
        .into_par_iter()
        .map(|i| {
            let chunk = fr.get_chunk(i).unwrap();
            let buf = chunk.mmap.to_vec();
            (i, buf)
        })
        .map(|(i, mut buf)| {
            cryption.decrypt(&mut buf, &Nonce::from(i));
            (i, buf)
        })
        .map(|(i, buf)| {
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf[..buf.len() - TAG_LEN]);
            mmap_mut.flush().unwrap();

            Vec::from(&buf[buf.len() - TAG_LEN..])
        })
        .reduce_with(|mut acc, x| {
            acc.extend(x);
            acc
        })
        .unwrap();

    let header_data = Header::from_slice(header.as_ref());
    if !hmac.verify(&footprint, &header_data.signature) {
        panic!("Footprint not match.");
    }

    ctrl.new_meta.path.clone()
}
