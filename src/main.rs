extern crate base64;
extern crate rayon;
extern crate ring;

pub mod crypto;
pub mod file;

use self::crypto::*;
use self::file::*;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering};

fn main() {}