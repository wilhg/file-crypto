use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Result;
use base64::{encode, decode};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
type Nonce = [u8; NONCE_LEN];

pub struct KEY([u8; KEY_LEN]);
impl KEY {
    pub fn new() -> Self {
        gen_key()
    }
    pub fn from(s: &str) -> Self {
        let v = decode(s).unwrap();
        if v.len() > NONCE_LEN {
            panic!("Key too long");
        }
        
    }
}

pub struct Encryption {
    key: KEY,
    nonce: Nonce,
    sealing_key: SealingKey,
}
impl Encryption {
    pub fn new() -> Self {
        let key = gen_key();
        Encryption {
            key,
            nonce: gen_nonce(),
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, &key).unwrap(),
        }
    }

    pub fn with_key(key: &str) -> Self {
        Encryption {
            key: *key,
            nonce: gen_nonce(),
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, key).unwrap(),
        }
    }

    pub fn key(&self) -> KEY {
        self.key
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(seal_in_place(
            &self.sealing_key,
            &self.nonce,
            &[],
            buf,
            CHACHA20_POLY1305.tag_len(),
        )
        .unwrap())
    }
}

pub struct Decryption {
    nonce: Nonce,
    opening_key: OpeningKey,
}

impl Decryption {
    pub fn new(key: &KEY, nonce: &Nonce) -> Self {
        Decryption {
            nonce: *nonce,
            opening_key: OpeningKey::new(&CHACHA20_POLY1305, key).unwrap(),
        }
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) -> Vec<u8> {
        Vec::from(open_in_place(&self.opening_key, &self.nonce, &[], 0, buf).unwrap())
    }
}

fn gen_key() -> KEY {
    let mut key = [0u8; KEY_LEN];
    SystemRandom::new().fill(&mut key).unwrap();
    key
}

fn gen_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).unwrap();
    nonce
}