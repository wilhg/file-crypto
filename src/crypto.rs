use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{Read, Result, Write};

type Token = [u8; 32];
type Nonce = [u8; 12];

pub struct Encryption {
    token: Token,
    nonce: Nonce,
    sealing_key: SealingKey,
}
impl Encryption {
    pub fn new() -> Self {
        let token = gen_token();
        Encryption {
            token,
            nonce: gen_nonce(),
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, &token).unwrap(),
        }
    }

    pub fn with_token(token: &Token) -> Self {
        Encryption {
            token: *token,
            nonce: gen_nonce(),
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, token).unwrap(),
        }
    }

    pub fn token(&self) -> Token {
        self.token
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
    pub fn new(token: &Token, nonce: &Nonce) -> Self {
        Decryption {
            nonce: *nonce,
            opening_key: OpeningKey::new(&CHACHA20_POLY1305, token).unwrap(),
        }
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) -> Vec<u8> {
        Vec::from(open_in_place(&self.opening_key, &self.nonce, &[], 0, buf).unwrap())
    }
}

fn gen_token() -> Token {
    let mut token = [0u8; 32];
    SystemRandom::new().fill(&mut token).unwrap();
    token
}

fn gen_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    SystemRandom::new().fill(&mut nonce).unwrap();
    nonce
}