use memmap::{Mmap, MmapMut, MmapOptions};
use std::fs::File;

pub struct FileReader<'a> {
    file: &'a File,
    file_size: usize,
    chunk_size: usize,
}

impl<'a> FileReader<'a> {
    pub fn new(file: &File, chunk_size: usize) -> FileReader {
        FileReader {
            file,
            file_size: file.metadata().unwrap().len() as usize,
            chunk_size,
        }
    }

    pub fn get_chunk(&self, page: usize) -> Option<Chunk> {
        let offset = page * self.chunk_size;
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

    pub fn is_page_available(&self, page: usize) -> bool {
        page * self.chunk_size >= self.file_size
    }
}

pub struct FileWriter<'a> {
    file: &'a File,
    file_size: usize,
    chunk_size: usize,
}

impl<'a> FileWriter<'a> {
    pub fn new(file: &File, file_size: usize, chunk_size: usize) -> FileWriter {
        file.set_len(file_size as u64).unwrap();
        FileWriter {
            file,
            file_size,
            chunk_size,
        }
    }

    pub fn get_chunk_mut(&self, page: usize) -> Option<ChunkMut> {
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

    pub fn is_page_available(&self, page: usize) -> bool {
        page * self.chunk_size >= self.file_size
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
