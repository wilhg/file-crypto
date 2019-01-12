use super::meta::*;
use memmap::{Mmap, MmapMut, MmapOptions};
use std::fs::File;
use byteorder::{BE, ByteOrder};

pub struct FileReader<'a> {
    file: &'a File,
    file_size: usize,
    chunk_size: usize,
    proc_type: ProcessType,
}

impl<'a> FileReader<'a> {
    pub fn new(meta: &CipherMeta) -> FileReader {
        FileReader {
            file: &meta.old_meta.file,
            file_size: meta.old_meta.size,
            chunk_size: meta.old_meta.chunk_size,
            proc_type: meta.proc_type,
        }
    }

    pub fn get_chunk(&self, page: usize) -> Option<Chunk> {
        let offset = match self.proc_type {
            ProcessType::Encrypt => page * self.chunk_size,
            ProcessType::Decrypt => page * self.chunk_size + HEADER_LEN,
        };
        if offset >= self.file_size {
            return None;
        }
        let mut mmap_option = MmapOptions::new();
        mmap_option
            .offset(offset as u64)
            .len(std::cmp::min(self.chunk_size, self.file_size - offset) as usize);

        Some(Chunk {
            page: page,
            mmap: unsafe { mmap_option.map(&self.file) }.unwrap(),
        })
    }

    pub fn header(&self) -> Mmap {
        let mut mmap_option = MmapOptions::new();
        mmap_option.len(HEADER_LEN);
        unsafe { mmap_option.map(&self.file) }.unwrap()
    }

    pub fn is_page_available(&self, page: usize) -> bool {
        page * self.chunk_size >= self.file_size
    }
}

pub struct FileWriter<'a> {
    file: &'a File,
    file_size: usize,
    chunk_size: usize,
    proc_type: ProcessType,
}

impl<'a> FileWriter<'a> {
    pub fn new(meta: &CipherMeta) -> FileWriter {
        FileWriter {
            file: &meta.new_meta.file,
            file_size: meta.new_meta.size,
            chunk_size: meta.new_meta.chunk_size,
            proc_type: meta.proc_type,
        }
    }

    pub fn get_chunk_mut(&self, page: usize) -> Option<ChunkMut> {
        let offset = match self.proc_type {
            ProcessType::Encrypt => page * self.chunk_size + HEADER_LEN,
            ProcessType::Decrypt => page * self.chunk_size,
        };
        if offset >= self.file_size {
            return None;
        }
        let mut mmap_option = MmapOptions::new();
        mmap_option
            .offset(offset as u64)
            .len(std::cmp::min(self.chunk_size, self.file_size - offset) as usize);

        Some(ChunkMut {
            page: page,
            mmap_mut: unsafe { mmap_option.map_mut(&self.file) }.unwrap(),
        })
    }

    pub fn is_page_available(&self, page: usize) -> bool {
        page * self.chunk_size >= self.file_size
    }

    pub fn header(&self) -> MmapMut {
        let mut mmap_option = MmapOptions::new();
        mmap_option.len(HEADER_LEN);
        unsafe { mmap_option.map_mut(&self.file) }.unwrap()
    }
}

pub struct Header {
    pub file_size: u64,
    pub signature: [u8; 64],
}

impl Header {
    pub fn new() -> Self {
        Header {
            file_size: 0u64,
            signature: [0u8; 64],
        }
    }

    pub fn from_slice(buf: &[u8]) -> Self {
        if buf.len() != 72 {
            panic!("File format is incorrect.");
        };
        let mut sign = [0u8; 64];
        sign.copy_from_slice(&buf[8..]);
        Header {
            file_size: BE::read_u64(&buf[..8]),
            signature: sign,
        }
    }

    pub fn write(&self, buf: &mut [u8]) {
        if buf.len() != 72 {
            panic!("Internal error.");
        };
        BE::write_u64(&mut buf[..8], self.file_size);
        buf[8..].copy_from_slice(&self.signature);
    }
}

pub struct Chunk {
    pub page: usize,
    pub mmap: Mmap,
}
pub struct ChunkMut {
    pub page: usize,
    pub mmap_mut: MmapMut,
}

pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 64; // SHA512 / 8
