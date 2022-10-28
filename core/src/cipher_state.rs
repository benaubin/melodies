use crate::crypto::{Cipher, CIPHER_KEY_LEN, TAG_SIZE};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherState<Nonce = u64> {
    key: [u8; CIPHER_KEY_LEN],
    #[zeroize(skip)]
    pub(crate) cipher: &'static dyn Cipher,
    /// Note that a nonce of u64::MAX will cause an error on every call to encrypt
    #[zeroize(skip)]
    pub nonce: Nonce,
}

impl<T> CipherState<T> {
    /// Encrypt, with a provided nonce (must prevent reuse).
    /// This occurs in place. The last TAG_SIZE bytes of buf will be replaced with the AEAD tag.
    pub fn encrypt_with_nonce(&self, n: u64, ad: &[u8], buf: &mut [u8]) {
        assert_ne!(n, u64::MAX);
        let (buf, tag) = buf.split_at_mut(buf.len() - TAG_SIZE);
        let tag = tag.try_into().unwrap();
        self.cipher.encrypt(&self.key, n, ad, buf, tag);
    }
    pub fn decrypt_with_nonce<'a>(&self, n: u64, ad: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
        assert_ne!(n, u64::MAX);
        self.cipher.decrypt(&self.key, n, ad, buf)
    }
    pub fn rekey(&mut self) {
        let tmp = Zeroizing::new(self.key);
        self.cipher.rekey(&tmp, &mut self.key);
    }
}


impl CipherState<u64> {
    #[inline(always)]
    pub(crate) const fn new(cipher: &'static dyn Cipher) -> Self {
        Self {
            key: [0; CIPHER_KEY_LEN],
            cipher,
            nonce: u64::MAX,
        }
    }
    pub(crate) fn initialize_key(&mut self, key: &[u8; CIPHER_KEY_LEN]) {
        self.key = *key;
        self.nonce = 0;
    }
    #[inline(always)]
    pub fn into_stateless(self) -> CipherState<()> {
        CipherState {
            key: self.key,
            cipher: self.cipher,
            nonce: (),
        }
    }
    /// Returns the size of the encrypted message. Buf should have space for a tag
    pub fn encrypt(&mut self, ad: &[u8], buf: &mut [u8]) -> usize {
        self.encrypt_with_nonce(self.nonce, ad, buf);
        self.nonce += 1;
        buf.len()
    }
    /// Returns the decrypted payload
    pub fn decrypt<'a>(&mut self, ad: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let res = self.decrypt_with_nonce(self.nonce, ad, buf);
        if res.is_some() {
            self.nonce += 1;
        }
        res
    }
}

