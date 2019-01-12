use super::file::TAG_LEN;
use std::fs::{File, OpenOptions};

pub struct FileMeta {
    pub file: File,
    pub path: String,
    pub size: usize,
    pub chunk_size: usize,
}

pub struct CipherCtrl {
    pub proc_type: ProcessType,
    pub old_meta: FileMeta,
    pub new_meta: FileMeta,
    pub chunk_num: usize,
}

impl CipherCtrl {
    pub fn init(file_path: &str) -> CipherCtrl {
        let t = if file_path.ends_with(SEALED_SUFFIX) {
            ProcessType::Decrypt
        } else {
            ProcessType::Encrypt
        };
        CipherCtrl::init_with_type(file_path, t)
    }

    pub fn init_with_type(file_path: &str, proc_type: ProcessType) -> CipherCtrl {
        if proc_type == ProcessType::Decrypt && !file_path.ends_with(SEALED_SUFFIX) {
            panic!(format!(
                "The file to be decrypted should with \"{}\"",
                SEALED_SUFFIX
            ));
        }
        let old_file_path = String::from(file_path);
        let old_file = File::open(file_path).expect("File not exists");
        let file_metadata = old_file.metadata().unwrap();
        if !file_metadata.is_file() {
            panic!("The file path is incorrect, or it is a dir path");
        }
        let new_file_path: String = match proc_type {
            ProcessType::Encrypt => format!("{}{}", old_file_path, SEALED_SUFFIX),
            ProcessType::Decrypt => {
                old_file_path[..old_file_path.len() - SEALED_SUFFIX.len()].to_string()
            }
        };
        let new_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&new_file_path)
            .unwrap();
        unimplemented!()
    }
}
#[derive(PartialEq, Clone, Copy)]
pub enum ProcessType {
    Encrypt,
    Decrypt,
}

const SEALED_SUFFIX: &str = ".fc";
// const MIN_CHUNK_SIZE: usize = 0x100000; // 1Mb
const MIN_CHUNK_SIZE: usize = 100; // 1Mb
const PARALLEL_NUM: usize = 64;
pub const HEADER_LEN: usize = 64; // SHA512 / 8
