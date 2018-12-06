use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use byteorder::{BE, ByteOrder};
const KEY_LEN: usize = 32;
const AD: [u8; 0] = [0u8; 0];

pub struct Nonce(pub [u8; 12]);
impl From<u64> for Nonce {
    fn from(n: u64) -> Nonce {
        let mut result = [0u8; 12];
        BE::write_u64(&mut result, n);
        Nonce(result)
    }
}

#[derive(Clone, Copy)]
pub struct Key(pub [u8; KEY_LEN]);
impl Key {
    pub fn new() -> Self {
        let mut key = [0u8; KEY_LEN];
        SystemRandom::new().fill(&mut key).unwrap();
        Key(key)
    }

    pub fn base64(&self) -> String {
        base64::encode(&self.0)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        if let Ok(key) = base64::decode(s) {
            Key::from(key.as_slice())
        } else {
            Key::from(s.as_bytes())
        }
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

    pub fn encrypt(&self, buf: &mut [u8], nonce: &Nonce) -> usize {
        seal_in_place(&self.sealing_key, &nonce.0, &[], buf, AES_256_GCM.tag_len()).unwrap()
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

    pub fn decrypt<'a>(&self, buf: &'a mut [u8], nonce: &Nonce) -> &'a mut [u8] {
        if let Ok(result) = open_in_place(&self.opening_key, &nonce.0, &AD, 0, buf) {
            result
        } else {
            panic!("The file cannot be decrypted, maybe your are using a incorrect key :)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key() {
        let s = "abc";
        let k = Key::from(s);
        assert_eq!(k.0, Key::from(k.base64().as_str()).0);
    }

    #[test]
    fn cipher() {
        let key = Key::new();
        let en = Encryption::new(key);
        let de = Decryption::new(key);
        let content = b"abcdefg";
        let len = content.len();
        let mut buf = content.to_vec();

        buf.extend_from_slice(&[0u8; 16]);
        en.encrypt(&mut buf, &Nonce::from(1));
        assert_ne!(content, &buf[..len]);
        de.decrypt(&mut buf, &Nonce::from(1));
        assert_eq!(content, &buf[..len]);
    }
}
