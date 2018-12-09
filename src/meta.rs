use super::file::TAG_LEN;
use std::fs::{File, OpenOptions};

pub struct FileMeta {
    pub file: File,
    pub path: String,
    pub size: usize,
    pub chunk_size: usize,
}

pub struct CipherMeta {
    pub old_meta: FileMeta,
    pub new_meta: FileMeta,
    pub proc_type: ProcessType,
    pub chunk_num: usize,
}

impl CipherMeta {
    pub fn init(file_path: &str) -> CipherMeta {
        let t = if file_path.ends_with(SEALED_SUFFIX) {
            ProcessType::Decrypt
        } else {
            ProcessType::Encrypt
        };
        CipherMeta::init_with_type(file_path, t)
    }

    pub fn init_with_type(file_path: &str, proc_type: ProcessType) -> CipherMeta {
        if proc_type == ProcessType::Decrypt && !file_path.ends_with(SEALED_SUFFIX) {
            panic!(format!(
                "The file to be decrypted should with \"{}\"",
                SEALED_SUFFIX
            ));
        }
        let origin_file_path = String::from(file_path);
        let origin_file = File::open(file_path).expect("File not exists");
        let file_metadata = origin_file.metadata().unwrap();
        if !file_metadata.is_file() {
            panic!("The file path is incorrect, or it is a dir path");
        }
        let gen_file_path: String = match proc_type {
            ProcessType::Encrypt => format!("{}{}", origin_file_path, SEALED_SUFFIX),
            ProcessType::Decrypt => {
                origin_file_path[..origin_file_path.len() - SEALED_SUFFIX.len()].to_string()
            }
        };
        let gen_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&gen_file_path)
            .unwrap();
        let f_size = file_metadata.len() as usize;
        if f_size == 0 {
            panic!("The input file should not be empty.")
        }
        let chunk_size = Self::calc_chunk_size(f_size);
        let chunk_num = Self::calc_chunk_num(f_size, chunk_size);
        let gen_file_size = match proc_type {
            ProcessType::Encrypt => f_size + chunk_num * TAG_LEN + HEADER_LEN,
            ProcessType::Decrypt => f_size - chunk_num * TAG_LEN - HEADER_LEN,
        };
        gen_file.set_len(gen_file_size as u64).unwrap();

        let old = FileMeta {
            file: origin_file,
            path: origin_file_path,
            size: f_size as usize,
            chunk_size: match proc_type {
                ProcessType::Encrypt => chunk_size - TAG_LEN,
                ProcessType::Decrypt => chunk_size,
            },
        };

        let gen = FileMeta {
            file: gen_file,
            path: gen_file_path,
            size: gen_file_size,
            chunk_size: match proc_type {
                ProcessType::Encrypt => chunk_size,
                ProcessType::Decrypt => chunk_size - TAG_LEN,
            },
        };

        CipherMeta {
            old_meta: old,
            new_meta: gen,
            proc_type,
            chunk_num,
        }
    }

    fn calc_chunk_size(f_size: usize) -> usize {
        if f_size < MIN_CHUNK_SIZE * PARALLEL_NUM {
            MIN_CHUNK_SIZE
        } else {
            f_size / PARALLEL_NUM
        }
    }

    fn calc_chunk_num(f_size: usize, chunk_size: usize) -> usize {
        if f_size % chunk_size == 0 {
            f_size / chunk_size
        } else {
            f_size / chunk_size + 1
        }
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
pub const HEADER_LEN: usize = 64; // SHA512 / 8