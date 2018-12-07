use std::fs::{File, OpenOptions};
use super::file::TAG_LEN;

pub struct CipherMeta {
    pub origin_file: File,
    pub origin_file_path: String,
    pub gen_file: File,
    pub gen_file_path: String,
    pub gen_file_size: usize,
    pub proc_type: ProcessType,
    chunk_size: usize,
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
            ProcessType::Encrypt => f_size + chunk_num * TAG_LEN,
            ProcessType::Decrypt => f_size - chunk_num * TAG_LEN,
        };

        CipherMeta {
            origin_file,
            origin_file_path,
            gen_file,
            gen_file_path,
            gen_file_size,
            proc_type,
            chunk_size,
            chunk_num,
        }
    }

    pub fn plain_chunk_size(&self) -> usize {
        self.chunk_size - TAG_LEN
    }

    pub fn cipher_chunk_size(&self) -> usize {
        self.chunk_size
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