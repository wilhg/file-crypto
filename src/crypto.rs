use base64::{decode, encode};
use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Result;

const KEY_LEN: usize = 32;
const NONCE: [u8; 12] = [0u8; 12];

#[derive(Clone, Copy)]
pub struct Key([u8; KEY_LEN]);
impl Key {
    pub fn new() -> Self {
        let mut key = [0u8; KEY_LEN];
        SystemRandom::new().fill(&mut key).unwrap();
        Key(key)
    }

    pub fn base64(&self) -> String {
        encode(&self.0)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        let key = decode(s).unwrap();
        Self::from(key.as_slice())
    }
}

impl From<&[u8]> for Key {
    fn from(key: &[u8]) -> Self {
        if key.len() > KEY_LEN {
            panic!("Key too long, maximum length is 32.");
        }
        let mut x = key.to_vec();
        for _ in key.len()..KEY_LEN {
            x.push(0);
        }
        let mut result = [0u8; KEY_LEN];
        result.copy_from_slice(&x);
        Key(result)
    }
}

pub struct Encryption {
    key: Key,
    sealing_key: SealingKey,
}
impl Encryption {
    pub fn new() -> Self {
        let key = Key::new();
        Encryption {
            key,
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, &key.0).unwrap(),
        }
    }

    pub fn with_key(input: &str) -> Self {
        let key = Key::from(input);
        Encryption {
            key,
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, &key.0).unwrap(),
        }
    }

    pub fn key(&self) -> Key {
        self.key
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<Vec<u8>> {
        let mut b = Vec::from(buf);
        b.extend_from_slice(&vec![0u8; CHACHA20_POLY1305.tag_len()]);
        seal_in_place(
            &self.sealing_key,
            &NONCE,
            &[],
            &mut b,
            CHACHA20_POLY1305.tag_len(),
        )
        .unwrap();
        Ok(b)
    }
}

pub struct Decryption {
    opening_key: OpeningKey,
}

impl Decryption {
    pub fn new(key: &Key) -> Self {
        Decryption {
            opening_key: OpeningKey::new(&CHACHA20_POLY1305, &key.0).unwrap(),
        }
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) -> Vec<u8> {
        Vec::from(open_in_place(&self.opening_key, &NONCE, &[], 0, buf).unwrap())
    }
}
