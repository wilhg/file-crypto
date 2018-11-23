use ring::aead::chacha20_poly1305_openssh as chacha;
// use ring::aead::SealingKey;
use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{Read, Result, Write};

type Token = [u8; 64];
type Nonce = [u8; 16];

pub struct Encoder {
    token: Token,
    nonce: Nonce,
    sealing_key: SealingKey,
}
impl Encoder {
    pub fn new() -> Self {
        let token = gen_token();
        Encoder {
            token,
            nonce: [0u8; 16],
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, &token).unwrap(),
        }
    }

    pub fn with_token(token: &Token) -> Self {
        Encoder {
            token: *token,
            nonce: [0u8; 16],
            sealing_key: SealingKey::new(&CHACHA20_POLY1305, token).unwrap(),
        }
    }
}

impl Read for Encoder {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
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

impl Write for Encoder {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }
    fn flush(&mut self) -> Result<()> {
        unimplemented!()
    }
}

pub struct Decoder {}

impl Read for Decoder {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }
}

impl Write for Decoder {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }
    fn flush(&mut self) -> Result<()> {
        unimplemented!()
    }
}

fn gen_token() -> Token {
    let mut token = [0u8; 64];
    SystemRandom::new().fill(&mut token).unwrap();
    token
}
