use ring::aead::*;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use byteorder::{BE, ByteOrder};
const KEY_LEN: usize = 32;
const AD: [u8; 0] = [0u8; 0];

pub struct Nonce(pub [u8; 12]);
impl From<usize> for Nonce {
    fn from(n: usize) -> Nonce {
        let mut result = [0u8; 12];
        BE::write_u64(&mut result, n as u64);
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

pub struct Cryption {
    sealing_key: SealingKey,
    opening_key: OpeningKey,
}
impl Cryption {
    pub fn new(key: &Key) -> Self {
        Cryption {
            sealing_key: SealingKey::new(&AES_256_GCM, &key.0).unwrap(),
            opening_key: OpeningKey::new(&AES_256_GCM, &key.0).unwrap(),
        }
    }
    pub fn encrypt(&self, buf: &mut [u8], nonce: &Nonce) -> usize {
        seal_in_place(&self.sealing_key, &nonce.0, &[], buf, AES_256_GCM.tag_len()).unwrap()
    }
    pub fn decrypt<'a>(&self, buf: &'a mut [u8], nonce: &Nonce) -> &'a mut [u8] {
        if let Ok(result) = open_in_place(&self.opening_key, &nonce.0, &AD, 0, buf) {
            result
        } else {
            panic!("The file cannot be decrypted, maybe your are using a incorrect key :)");
        }
    }
}

pub struct Hmac {
    signing_key: hmac::SigningKey,
    verify_key: hmac::VerificationKey,
}

impl Hmac {
    pub fn new(key: &Key) -> Self {
        Hmac {
            signing_key: hmac::SigningKey::new(&digest::SHA512, &key.0),
            verify_key: hmac::VerificationKey::new(&digest::SHA512, &key.0),
        }
    }
    pub fn sign(&self, buf: &[u8]) -> [u8; digest::SHA512_OUTPUT_LEN] {
        let mut output = [0u8; digest::SHA512_OUTPUT_LEN];
        output.copy_from_slice(hmac::sign(&self.signing_key, buf).as_ref());
        output
    }
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        hmac::verify(&self.verify_key, data, signature).is_ok()
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
        let cryption = Cryption::new(&key);
        let content = b"abcdefg";
        let len = content.len();
        let mut buf = content.to_vec();

        buf.extend_from_slice(&[0u8; 16]);
        cryption.encrypt(&mut buf, &Nonce::from(1));
        assert_ne!(content, &buf[..len]);
        cryption.decrypt(&mut buf, &Nonce::from(1));
        assert_eq!(content, &buf[..len]);
    }
}
