use super::file::*;
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
        let old_file_size = file_metadata.len() as usize;
        if old_file_size == 0 {
            panic!("The input file should not be empty.")
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

        let (new_file_size, chunk_size, chunk_num) = match proc_type {
            ProcessType::Encrypt => Self::en_chunk_info(old_file_size),
            ProcessType::Decrypt => Self::de_chunk_info(&old_file),
        };
        new_file.set_len(new_file_size as u64).unwrap();
        println!("new_file_size={} size={} num={}",new_file_size, chunk_size, chunk_num);
        println!("ofz={} nfz={}", old_file_size, new_file_size);
        let old = FileMeta {
            file: old_file,
            path: old_file_path,
            size: old_file_size as usize,
            chunk_size: match proc_type {
                ProcessType::Encrypt => chunk_size - TAG_LEN,
                ProcessType::Decrypt => chunk_size,
            },
        };

        let new = FileMeta {
            file: new_file,
            path: new_file_path,
            size: new_file_size,
            chunk_size: match proc_type {
                ProcessType::Encrypt => chunk_size,
                ProcessType::Decrypt => chunk_size - TAG_LEN,
            },
        };

        CipherCtrl {
            old_meta: old,
            new_meta: new,
            proc_type,
            chunk_num,
        }
    }

    fn en_chunk_info(old_file_size: usize) -> (usize, usize, usize) {
        let chunk_size = if old_file_size < (MIN_CHUNK_SIZE - TAG_LEN) * PARALLEL_NUM {
            MIN_CHUNK_SIZE
        } else {
            old_file_size / PARALLEL_NUM
        };
        let chunk_num = if old_file_size % chunk_size == 0 {
            old_file_size / chunk_size
        } else {
            old_file_size / chunk_size + 1
        };
        let new_file_size = old_file_size + chunk_num * TAG_LEN + HEADER_LEN;
        (new_file_size, chunk_size, chunk_num)
    }

    fn de_chunk_info(file: &File) -> (usize, usize, usize) {
        let header = Header::from_file(&file);
        let file_size = header.file_size;
        let chunk_size = header.chunk_size;
        let chunk_num = if file_size % chunk_size == 0 {
            file_size / chunk_size
        } else {
            file_size / chunk_size + 1
        };
        (file_size as usize, chunk_size as usize, chunk_num as usize)
    }
}
#[derive(PartialEq, Clone, Copy)]
pub enum ProcessType {
    Encrypt,
    Decrypt,
}

const SEALED_SUFFIX: &str = ".fc";
const MIN_CHUNK_SIZE: usize = 0x100000; // 1Mb
const PARALLEL_NUM: usize = 64;
