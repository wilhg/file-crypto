use memmap::{Mmap, MmapMut, MmapOptions};
use std::fs::{self, File, OpenOptions};
use std::io::Result;

pub struct FileReader<'a> {
    file: &'a File,
    file_size: u64,
    chunk_size: u64,
}

impl<'a> FileReader<'a> {
    pub fn new(file: &File, chunk_size: u64) -> FileReader {
        FileReader {
            file,
            file_size: file.metadata().unwrap().len(),
            chunk_size,
        }
    }

    pub fn get_mmap(&mut self, page: u64) -> Option<Chunk> {
        let offset = page * self.chunk_size;
        if offset >= self.file_size {
            return None;
        }
        let mut mmap_option = MmapOptions::new();
        mmap_option
            .offset(offset)
            .len(std::cmp::min(self.chunk_size, self.file_size - offset) as usize);

        Some(Chunk {
            page: page,
            mmap: unsafe { mmap_option.map(&self.file) }.unwrap(),
        })
    }
}

pub struct FileWriter<'a> {
    file: &'a File,
    file_size: u64,
    chunk_size: u64,
}

impl<'a> FileWriter<'a> {
    pub fn new(file: &File, file_size: u64, chunk_size: u64) -> FileWriter {
        file.set_len(file_size as u64).unwrap();
        FileWriter {
            file,
            file_size,
            chunk_size,
        }
    }

    pub fn get_mmap_mut(&mut self, page: u64) -> Option<ChunkMut> {
        let offset = page * self.chunk_size;
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
}

pub struct Chunk {
    pub page: u64,
    pub mmap: Mmap,
}
pub struct ChunkMut {
    pub page: u64,
    pub mmap_mut: MmapMut,
}

const CIPHER_FILE_HEADER_LEN: u64 = 8; // The size of the original file
pub const PLAIN_CHUNK_LEN: u64 = 0x100000; // 1Mb = 2 block size
pub const CIPHER_CHUNK_LEN: u64 = PLAIN_CHUNK_LEN + 16; // 1Mb + tag_len
