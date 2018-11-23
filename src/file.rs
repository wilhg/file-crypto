use std::io::{Read, Result, Write};


pub struct FileWalker {}

impl Read for FileWalker {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }
}

impl Write for FileWalker {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }
    fn flush(&mut self) -> Result<()> {
        unimplemented!()
    }
}