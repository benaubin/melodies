use chacha20poly1305::{aead::Nonce, AeadInPlace, ChaCha20Poly1305, KeyInit, Tag};
use melodies_core::crypto::Cipher;

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
        tag_out: &mut [u8; melodies_core::crypto::TAG_SIZE],
    ) {
        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce);
        let tag = AeadInPlace::encrypt_in_place_detached(&cipher, nonce, ad, buf).unwrap();
        tag_out.copy_from_slice(&tag);
    }

    fn decrypt<'a>(
        &self,
        key: &[u8; melodies_core::crypto::CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &'a mut [u8],
        tag: &'a [u8; melodies_core::crypto::TAG_SIZE],
    ) -> bool {
        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce);
        let tag = Tag::from_slice(&tag[..]);
        AeadInPlace::decrypt_in_place_detached(&cipher, nonce, ad, buf, tag).is_ok()
    }
}
