pub mod crypto;
pub mod file;
pub mod meta;

use self::crypto::*;
use self::file::*;
use self::meta::*;

const TAG: [u8; TAG_LEN as usize] = [0u8; TAG_LEN as usize];

pub fn encrypt(key: Key, meta: CipherMeta) -> String {
    let en = Encryption::new(key);
    let fr = FileReader::new(&meta.origin_file, meta.plain_chunk_size());
    let fw = FileWriter::new(&meta.gen_file, meta.gen_file_size, meta.cipher_chunk_size());

    let mut track = vec![0u128; meta.chunk_num as usize]; // u128 = u8 * 16

    (0..meta.chunk_num)
        .into_iter()
        .map(|i| {
            let chunk = fr.get_chunk(i).unwrap();
            let mut buf = chunk.mmap.to_vec();
            buf.extend_from_slice(&TAG);

            (i, buf)
        })
        .map(move |(i, mut buf)| {
            en.encrypt(&mut buf, &Nonce::from(i));
            (i, buf)
        })
        .for_each(|(i, buf)| { 
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf);
            mmap_mut.flush().unwrap();
        });
    meta.gen_file_path
}

pub fn decrypt(key: Key, meta: CipherMeta) -> String {
    let de = Decryption::new(key);
    let fr = FileReader::new(&meta.origin_file, meta.cipher_chunk_size());
    let fw = FileWriter::new(&meta.gen_file, meta.gen_file_size, meta.plain_chunk_size());

    (0..meta.chunk_num)
        .into_iter()
        .map(|i| {
            let chunk = fr.get_chunk(i).unwrap();
            let buf = chunk.mmap.to_vec();
            (i, buf)
        })
        .map(|(i, mut buf)| {
            de.decrypt(&mut buf, &Nonce::from(i));
            (i, buf)
        })
        .for_each(|(i, buf)| {
            let mut mmap_mut = fw.get_chunk_mut(i).unwrap().mmap_mut;
            mmap_mut.copy_from_slice(&buf[..buf.len() - TAG_LEN as usize]);
            mmap_mut.flush().unwrap();
        });
    meta.gen_file_path
}
