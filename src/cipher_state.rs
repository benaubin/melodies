use zeroize::{Zeroize};
use crate::crypto::{CIPHER_KEY_LEN, Cipher};

#[derive(Clone, Zeroize)]
pub struct CipherState<C: Cipher> {
    cipher: Option<C>,
    pub nonce: u64,
}

impl<C: Cipher> CipherState<C> {
    pub const fn empty() -> Self {
        Self { cipher: None, nonce: 0 }
    }
    pub fn initialize_key(&mut self, key: &[u8; CIPHER_KEY_LEN]) {
        C::new(key, &mut self.cipher);
        self.nonce = 0;
    }
    pub fn has_key(&self) -> bool {
        self.cipher.is_some()
    }
    pub fn into_stateless(self) -> Option<C> {
        self.cipher
    }
    pub fn rekey(&mut self) {
        self.cipher.as_mut().unwrap().rekey();
    }
    pub fn encrypt(&mut self, ad: &[u8], buf: &mut [u8]) -> Option<[u8; 16]> {
        match &self.cipher {
            Some(cipher) => {
                let res = cipher.encrypt(self.nonce, ad, buf);
                self.nonce += 1;
                Some(res)
            },
            None => None
        }
    }
    pub fn decrypt<'a>(&mut self, ad: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], ()> {
        match &self.cipher {
            Some(cipher) => {
                let res = cipher.decrypt(self.nonce, ad, buf);
                if res.is_ok() { self.nonce += 1; }
                res
            },
            None => Ok(buf)
        }
    }
}
