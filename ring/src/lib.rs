use melodies_core::{
    crypto::{Cipher, HashFunction},
    util::ForcedZeroizing,
};
use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    digest,
};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SHA(ForcedZeroizing<Option<digest::Context>>);

impl HashFunction<32> for SHA {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self(ForcedZeroizing::new(Some(digest::Context::new(
            &digest::SHA256,
        ))))
    }

    const NAME: &'static str = "SHA256";

    const BLOCKLEN: usize = 64;

    fn update(&mut self, data: &[u8]) {
        self.0.as_mut().unwrap().update(data);
    }

    fn finalize_reset(&mut self, out: &mut [u8; 32]) {
        let digest = ForcedZeroizing::new(self.0.take().unwrap().finish());
        out.copy_from_slice(digest.as_ref());
        *self.0 = Some(digest::Context::new(&digest::SHA256));
    }
}

impl HashFunction<64> for SHA {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self(ForcedZeroizing::new(Some(digest::Context::new(
            &digest::SHA512,
        ))))
    }

    const NAME: &'static str = "SHA512";

    const BLOCKLEN: usize = 128;

    fn update(&mut self, data: &[u8]) {
        self.0.as_mut().unwrap().update(data);
    }

    fn finalize_reset(&mut self, out: &mut [u8; 64]) {
        let digest = ForcedZeroizing::new(self.0.take().unwrap().finish());
        out.copy_from_slice(digest.as_ref());
        *self.0 = Some(digest::Context::new(&digest::SHA512));
    }
}

pub struct AESGCM;

impl Cipher for AESGCM {
    fn name(&self) -> &str {
        "AESGCM"
    }

    fn encrypt(
        &self,
        key: &[u8; melodies_core::crypto::CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &mut [u8],
        tag: &mut [u8; melodies_core::crypto::TAG_SIZE],
    ) {
        let key = UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let tag_out = LessSafeKey::new(key)
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), buf)
            .unwrap();
        tag.copy_from_slice(tag_out.as_ref());
    }

    fn decrypt<'a>(
        &self,
        key: &[u8; melodies_core::crypto::CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let key = UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        LessSafeKey::new(key)
            .open_in_place(nonce, aead::Aad::from(ad), buf).ok().map(|a| &a[..])
    }
}

pub struct ChaChaPoly;

impl Cipher for ChaChaPoly {
    fn name(&self) -> &str {
        "ChaChaPoly"
    }

    fn encrypt(
        &self,
        key: &[u8; melodies_core::crypto::CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &mut [u8],
        tag: &mut [u8; melodies_core::crypto::TAG_SIZE],
    ) {
        let key = UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let tag_out = LessSafeKey::new(key)
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), buf)
            .unwrap();
        tag.copy_from_slice(tag_out.as_ref());
    }

    fn decrypt<'a>(
        &self,
        key: &[u8; melodies_core::crypto::CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let key = UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        LessSafeKey::new(key)
            .open_in_place(nonce, aead::Aad::from(ad), buf).ok().map(|a| &a[..])
    }
}
