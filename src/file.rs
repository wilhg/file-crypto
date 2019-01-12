use super::ctrl::*;
use byteorder::{ByteOrder, BE};
use memmap::{Mmap, MmapMut, MmapOptions};
use std::fs::File;

pub struct FileReader<'a> {
    file: &'a File,
    file_size: usize,
    chunk_size: usize,
    proc_type: ProcessType,
}

impl<'a> FileReader<'a> {
    pub fn new(ctrl: &CipherCtrl) -> FileReader {
        FileReader {
            file: &ctrl.old_meta.file,
            file_size: ctrl.old_meta.size,
            chunk_size: ctrl.old_meta.chunk_size,
            proc_type: ctrl.proc_type,
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
    pub fn new(ctrl: &CipherCtrl) -> FileWriter {
        FileWriter {
            file: &ctrl.new_meta.file,
            file_size: ctrl.new_meta.size,
            chunk_size: ctrl.new_meta.chunk_size,
            proc_type: ctrl.proc_type,
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
    pub chunk_size: u64,
    pub signature: [u8; 64],
}

impl Header {
    pub fn new(file_size: u64, chunk_size: u64, signature: [u8; 64]) -> Self {
        Header {
            file_size,
            chunk_size,
            signature,
        }
    }

    pub fn from_slice(buf: &[u8]) -> Self {
        if buf.len() != HEADER_LEN {
            panic!("File format is incorrect.");
        };
        let mut sign = [0u8; 64];
        sign.copy_from_slice(&buf[16..]);
        Header {
            file_size: BE::read_u64(&buf[..8]),
            chunk_size: BE::read_u64(&buf[8..16]),
            signature: sign,
        }
    }

    pub fn from_file(file: &File) -> Self {
        let mut mmap_option = MmapOptions::new();
        mmap_option.len(HEADER_LEN);
        let mmap = unsafe{mmap_option.map(file)}.unwrap();
        Self::from_slice(mmap.as_ref())
    }

    pub fn data(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        BE::write_u64(&mut buf[..8], self.file_size);
        BE::write_u64(&mut buf[8..16], self.chunk_size);
        buf[16..].copy_from_slice(&self.signature);
        buf
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
pub const HEADER_LEN: usize = 80; // SHA512 / 8 + u64 + u64
