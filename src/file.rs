use memmap::{Mmap, MmapMut, MmapOptions};
use std::fs::{self, File, OpenOptions};
use std::io::Result;

pub struct FileReader<'a> {
    file: &'a File,
    file_size: usize,
    cursor: usize,
    chunk_size: usize,
}

impl<'a> FileReader<'a> {
    pub fn new(file: &File, chunk_size: usize) -> FileReader {
        FileReader {
            file,
            file_size: file.metadata().unwrap().len() as usize,
            chunk_size,
            cursor: 0,
        }
    }

    pub fn next_mmap(&mut self) -> Option<Mmap> {
        if self.cursor >= self.file_size {
            return None;
        }
        let mut mmap_option = MmapOptions::new();
        mmap_option
            .offset(self.cursor as u64)
            .len(std::cmp::min(self.chunk_size, self.file_size - self.cursor));

        self.cursor += self.chunk_size;
        Some(unsafe { mmap_option.map(&self.file) }.unwrap())
    }
}

pub struct FileWriter<'a> {
    file: &'a File,
    file_size: usize,
    cursor: usize,
    chunk_size: usize,
}

impl<'a> FileWriter<'a> {
    pub fn new(file: &File, file_size: usize, chunk_size: usize) -> FileWriter {
        file.set_len(file_size as u64).unwrap();
        FileWriter {
            file,
            file_size,
            chunk_size,
            cursor: 0,
        }
    }

    pub fn next_mmap(&mut self) -> Option<MmapMut> {
        if self.cursor >= self.file_size {
            return None;
        }
        let mut mmap_option = MmapOptions::new();
        mmap_option
            .offset(self.cursor as u64)
            .len(std::cmp::min(self.chunk_size, self.file_size - self.cursor));

        self.cursor += self.chunk_size;
        Some(unsafe { mmap_option.map_mut(&self.file) }.unwrap())
    }
}


const CYPHER_FILE_HEADER_LEN: usize = 8; // The size of the original file
const PLAIN_CHUNK_LEN: usize = 0x80000; // 512kb = 1 block size
const CYPHER_CHUNK_LEN: usize = PLAIN_CHUNK_LEN + 16; // 100Mb + tag_len
