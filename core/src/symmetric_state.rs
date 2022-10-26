use core::marker::PhantomData;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    cipher_state::CipherState,
    crypto::{hkdf, Cipher, HashFunction, TAG_SIZE},
    handshake_state::ProtocolName,
};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SymmetricStateData<const HASHLEN: usize> {
    h: [u8; HASHLEN],
    ck: [u8; HASHLEN],
    has_key: bool,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SymmetricState<const HASHLEN: usize, H: HashFunction<HASHLEN>> {
    data: SymmetricStateData<HASHLEN>,
    cipher: CipherState<u64>,
    #[zeroize(skip)]
    phantom: PhantomData<H>,
}

fn protocol_name_to_hash<const HASHLEN: usize, H: HashFunction<HASHLEN>>(
    protocol_name: &ProtocolName,
) -> [u8; HASHLEN] {
    let protocol_name_len: usize = protocol_name.iter().map(|chunk| chunk.len()).sum();
    let mut hash = [0; HASHLEN];
    if protocol_name_len > hash.len() {
        let mut hasher = H::new();
        for chunk in protocol_name {
            hasher.update(chunk.as_bytes());
        }
        hasher.finalize_reset(&mut hash);
        hash
    } else {
        let mut i = 0;
        for chunk in protocol_name {
            hash[i..][..chunk.len()].copy_from_slice(chunk.as_bytes());
            i += chunk.len();
        }
        hash
    }
}

impl<const HASHLEN: usize, H: HashFunction<HASHLEN>> SymmetricState<HASHLEN, H> {
    #[inline(always)] pub(crate) fn snapshot(&self) -> SymmetricStateData<HASHLEN> {
        SymmetricStateData {
            h: self.data.h,
            ck: self.data.ck,
            has_key: self.data.has_key
        }
    }
    #[inline(always)] pub(crate) fn restore(&mut self, data: SymmetricStateData<HASHLEN>) {
        self.data = data
    }

    pub fn has_key(&self) -> bool {
        self.data.has_key
    }

    pub fn new(protocol_name: &ProtocolName, cipher: &'static dyn Cipher) -> Self {
        let hash = protocol_name_to_hash::<HASHLEN, H>(protocol_name);
        Self {
            cipher: CipherState::new(cipher),
            data: SymmetricStateData {
                ck: hash,
                h: hash,
                has_key: false,
            },
            phantom: PhantomData,
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut ck = Zeroizing::new([0; HASHLEN]);
        let mut temp_k = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(
            &self.data.ck,
            input_key_material,
            &mut [&mut ck, &mut temp_k],
        );
        self.data.ck.as_mut().copy_from_slice(ck.as_ref());
        self.cipher
            .initialize_key(&temp_k[..32].try_into().unwrap());
        self.data.has_key = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hash = H::new();
        hash.update(self.data.h.as_ref());
        hash.update(data);
        hash.finalize_reset(&mut self.data.h);
    }

    /// This function is used for handling pre-shared symmetric keys, as described in Section 9.
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let mut ck = Zeroizing::new([0; HASHLEN]);
        let mut temp_h = Zeroizing::new([0; HASHLEN]);
        let mut temp_k = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(
            &self.data.ck,
            input_key_material,
            &mut [&mut ck, &mut temp_h, &mut temp_k],
        );
        self.mix_hash(temp_h.as_ref());
        self.data.ck.as_mut().copy_from_slice(temp_k.as_ref());
        self.cipher
            .initialize_key(&temp_k[..32].try_into().unwrap());
        self.data.has_key = true;
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext).
    ///
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn encrypt_and_hash(&mut self, buf: &mut [u8]) -> usize {
        let buf = if self.has_key() {
            let len = self.cipher.encrypt(&self.data.h, buf);
            &buf[..len]
        } else {
            &buf[..buf.len() - TAG_SIZE]
        };
        self.mix_hash(buf);
        buf.len()
    }

    /// Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
    ///
    /// Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    pub fn decrypt_and_hash<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut hash = H::new();
        hash.update(&self.data.h);
        hash.update(buf);
        let out = if self.has_key() {
            self.cipher.decrypt(&self.data.h, buf)?
        } else {
            buf
        };
        hash.finalize_reset(&mut self.data.h);
        Some(out)
    }

    /// Returns a pair of CipherState objects for encrypting transport messages.
    ///
    /// The output is a handshake hash, which can be used for channel binding, as described in Section 11.2
    #[inline(always)]
    pub fn split(self) -> (CipherState, CipherState, [u8; HASHLEN]) {
        let mut temp_k1 = Zeroizing::new([0; HASHLEN]);
        let mut temp_k2 = Zeroizing::new([0; HASHLEN]);
        hkdf::<HASHLEN, H>(&self.data.ck, &[], &mut [&mut temp_k1, &mut temp_k2]);
        let mut out = (
            CipherState::new(self.cipher.cipher),
            CipherState::new(self.cipher.cipher),
            self.data.h,
        );
        out.0.initialize_key(&temp_k1[..32].try_into().unwrap());
        out.1.initialize_key(&temp_k2[..32].try_into().unwrap());
        out
    }
}
