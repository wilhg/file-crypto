use base64::{decode, encode};
use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};

const KEY_LEN: usize = 32;
const NONCE: [u8; 12] = [0u8; 12];
const AD: [u8; 0] = [0u8; 0];

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
            x.push(0u8);
        }
        let mut result = [0u8; KEY_LEN];
        result.copy_from_slice(&x);
        Key(result)
    }
}

pub struct Encryption {
    sealing_key: SealingKey,
}
impl Encryption {
    pub fn new(key: Key) -> Self {
        Encryption {
            sealing_key: SealingKey::new(&AES_256_GCM, &key.0).unwrap(),
        }
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) -> usize {
        seal_in_place(&self.sealing_key, &NONCE, &[], buf, AES_256_GCM.tag_len()).unwrap()
    }
}

pub struct Decryption {
    opening_key: OpeningKey,
}

impl Decryption {
    pub fn new(key: Key) -> Self {
        Decryption {
            opening_key: OpeningKey::new(&AES_256_GCM, &key.0).unwrap(),
        }
    }

    pub fn decrypt<'a>(&mut self, buf: &'a mut [u8]) -> &'a mut [u8] {
        open_in_place(&self.opening_key, &NONCE, &AD, 0, buf).unwrap()
    }
}
