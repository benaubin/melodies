use core::marker::PhantomData;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    cipher_state::CipherState,
    crypto::{hkdf, Cipher, HashFunction},
};

#[derive(Zeroize)]
pub struct SymmetricState<
    const HASHLEN: usize,
    C: Cipher,
    H: HashFunction<HASHLEN>
> {
    cipher_state: CipherState<C>,
    chaining_key: [u8; HASHLEN],
    hash: [u8; HASHLEN],
    phantom: PhantomData<H>
}

impl<
    const HASHLEN: usize,
    C: Cipher,
    H: HashFunction<HASHLEN>
> SymmetricState<HASHLEN, C, H> {
    pub fn has_key(&self) -> bool {
        self.cipher_state.has_key()
    }
    pub fn new(
        protocol_name: &'static str
    ) -> Self {
        let mut hash = [0; HASHLEN];
        if protocol_name.len() > hash.len() {
            let mut hasher = H::new();
            hasher.update(protocol_name.as_bytes());
            hasher.finalize_reset(&mut hash);
        } else {
            hash[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
        }
        Self {
            cipher_state: CipherState::empty(),
            chaining_key: hash.clone(),
            hash,
            phantom: PhantomData
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut ck = Zeroizing::new([0; HASHLEN]);
        let mut temp_k = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(
            &self.chaining_key,
            input_key_material,
            &mut [&mut ck, &mut temp_k],
        );
        self.chaining_key.as_mut().copy_from_slice(ck.as_ref());
        self.cipher_state.initialize_key(&temp_k[..32].try_into().unwrap());
    }

    pub fn mix_hash_with(&mut self, cb: impl FnOnce(&mut H) -> ()) {
        let mut hash = H::new();
        hash.update(self.hash.as_ref());
        (cb)(&mut hash);
        hash.finalize_reset(&mut self.hash);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.mix_hash_with(|hash| hash.update(&data))
    }

    /// This function is used for handling pre-shared symmetric keys, as described in Section 9.
    /// It executes the following steps:This function is used for handling pre-shared symmetric keys,
    /// as described in Section 9. It executes the following steps:
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let mut ck = Zeroizing::new([0; HASHLEN]);
        let mut temp_h = Zeroizing::new([0; HASHLEN]);
        let mut temp_k = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(
            &self.chaining_key,
            input_key_material,
            &mut [&mut ck, &mut temp_h, &mut temp_k],
        );
        self.mix_hash(temp_h.as_ref());
        self.chaining_key.as_mut().copy_from_slice(temp_k.as_ref());
        self.cipher_state.initialize_key(&temp_k[..32].try_into().unwrap());
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext).
    ///
    /// Returns tag which should be appended to buffer, if any
    ///
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn encrypt_and_hash(&mut self, buf: &mut [u8]) -> Option<[u8; 16]> {
        let tag = self.cipher_state.encrypt(self.hash.as_ref(), buf);
        self.mix_hash_with(|hash| {
            hash.update(buf);
            if let Some(tag) = tag {
                hash.update(&tag[..])
            }
        });
        tag
    }

    /// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
    ///
    /// Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    pub fn decrypt_and_hash<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], ()> {
        let mut hash = H::new();
        hash.update(self.hash.as_ref());
        hash.update(buf);
        let out = self.cipher_state.decrypt(self.hash.as_ref(), buf)?;
        hash.finalize_reset(&mut self.hash);
        Ok(out)
    }

    /// Returns a pair of CipherState objects for encrypting transport messages.
    ///
    /// The output is a handshake hash, which can be used for channel binding, as described in Section 11.2
    pub fn split(
        self,
        c1: &mut CipherState<C>,
        c2: &mut CipherState<C>,
    ) -> [u8; HASHLEN] {
        let mut temp_k1 = Zeroizing::new([0; HASHLEN]);
        let mut temp_k2 = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(&self.chaining_key, &[], &mut [&mut temp_k1, &mut temp_k2]);
        c1.initialize_key(&temp_k1[..32].try_into().unwrap());
        c2.initialize_key(&temp_k2[..32].try_into().unwrap());
        self.hash
    }
}
