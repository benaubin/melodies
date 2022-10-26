use zeroize::{Zeroizing, ZeroizeOnDrop};

pub const CIPHER_KEY_LEN: usize = 32;
pub const TAG_SIZE: usize = 16;

const MAX_HASH_BLOCKLEN: usize = 128;

/// DH functions
///
/// Spec: 4.1. DH functions
pub trait DHKeypair<const DHLEN: usize>: Clone + ZeroizeOnDrop {
    const NAME: &'static str;

    /// Generates a new Diffie-Hellman key pair.
    fn generate_keypair(out: &mut Option<Self>) where Self: Sized;

    /// Get the public key
    fn public_key(&self) -> [u8; DHLEN];

    /// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key and
    /// returns an output sequence of bytes of length DHLEN.
    ///
    /// For security, the Gap-DH problem based on this function must be unsolvable by any practical
    /// cryptanalytic adversary [2]. The public_key either encodes some value which is a generator in a large
    /// prime-order group (which value may have multiple equivalent encodings), or is an invalid value.
    ///
    /// Implementations must handle invalid public keys either by returning some output which is purely a function
    /// of the public key and does not depend on the private key.
    fn dh(&self, public_key: &[u8; DHLEN], output: &mut [u8; DHLEN]);
}

/// Cipher functions
///
/// Spec: 4.2. Cipher functions
pub trait Cipher {
    fn name(&self) -> &str;
    /// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte
    /// unsigned integer nonce nwhich must be unique for the key k.
    ///
    /// Encryption must be done with an "AEAD" encryption mode with the associated
    /// data ad (using the terminology from [1]) and returns a ciphertext that is
    /// the same size as the plaintext (in place) plus 16 bytes for authentication data.
    ///
    /// The entire ciphertext must be indistinguishable from random if the key is
    /// secret (note that this is an additional requirement that isn't necessarily
    /// met by all AEAD schemes).
    ///
    /// Deviation: Rather than return ciphertext, the buffer is encrypted in place and tag is written with the tag.
    fn encrypt(&self, key: &[u8; CIPHER_KEY_LEN], n: u64, ad: &[u8], buf: &mut [u8], tag: &mut [u8; TAG_SIZE]);
    /// Decrypts ciphertext in-place using a cipher key k of 32 bytes, an 8-byte unsigned
    /// integer nonce n, and associated data ad.
    /// 
    /// The tag which was appended to the ciphertext is passed as `tag`
    /// 
    /// Returns true on success
    fn decrypt<'a>(
        &self, 
        key: &[u8; CIPHER_KEY_LEN],
        n: u64,
        ad: &[u8],
        buf: &'a mut [u8],
        tag: &'a [u8; TAG_SIZE]
    ) -> bool;
    /// Sets the key to a 32-byte cipher key as a pseudorandom function of k.
    fn rekey(&self, key: &[u8; CIPHER_KEY_LEN], out: &mut [u8; CIPHER_KEY_LEN]) {
        let mut tmp = [0; TAG_SIZE];
        // If this function is not specifically defined for some set of cipher functions,
        // then it defaults to returning the first 32 bytes from ENCRYPT(k,    maxnonce, zerolen, zeros),
        // where maxnonce equals 2^64-1, zerolen is a zero-length byte sequence, and zeros is a sequence of
        // 32 bytes filled with zeros.
        self.encrypt(key, u64::MAX, &[], &mut out[..], &mut tmp);
    }
}

pub trait HashFunction<const L: usize>: ZeroizeOnDrop {
    /// the hash function with an empty input
    fn new() -> Self where Self: Sized;

    /// the protocol name for this hash function
    const NAME: &'static str;

    /// Bytes that the hash function uses internally to divide its input for iterative processing.
    /// This is needed to use the hash function with HMAC (BLOCKLEN is B in [3]).
    const BLOCKLEN: usize;

    /// concatinate self to the input of the hash function
    fn update(&mut self, data: &[u8]);

    /// write the hash output to `out`, zeroize internal state and reset to initial
    fn finalize_reset(&mut self, out: &mut [u8; L]);
}

// Applies HMAC from [3] using the HASH() function. This function is only called as part of HKDF(), below.
fn hmac<const L: usize, H: HashFunction<L>>(
    key: &[u8; L],
    out: &mut [u8; L],
    write_text: impl FnOnce(&mut H) -> ()
) {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut hash = H::new();
    let key_block = &mut Zeroizing::new([0; MAX_HASH_BLOCKLEN])[..H::BLOCKLEN];

    // append zeros to the end of K to create a B byte string
    key_block[..key.as_ref().len()].copy_from_slice(key.as_ref());

    // out = H(K XOR ipad, text)
    for p in key_block.iter_mut() {
        *p ^= IPAD;
    }
    hash.update(&key_block);
    (write_text)(&mut hash);
    hash.finalize_reset(out);

    // out = H(K XOR opad, out)
    for p in key_block.iter_mut() {
        *p ^= IPAD ^ OPAD;
    }
    hash.update(&key_block);
    hash.update(out.as_ref());
    hash.finalize_reset(out);
}

/// Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material byte sequence with length either
/// zero bytes, 32 bytes, or DHLEN bytes. Returns a pair or triple of byte sequences each of length HASHLEN,
/// depending on whether num_outputs is two or three:
pub fn hkdf<const L: usize, H: HashFunction<L>>(
    chaining_key: &[u8; L],
    input_key_material: &[u8],
    outputs: &mut [&mut [u8; L]],
) {
    assert!(matches!(outputs.len(), 2..=3));

    let mut temp_key = Zeroizing::new([0; L]);

    hmac::<L, H>(chaining_key, &mut temp_key, |hash| {
        hash.update(input_key_material)
    });

    let mut prev = &[][..];
    for (i, output) in outputs.iter_mut().enumerate() {
        hmac::<L, H>(&temp_key, *output, |hash| {
            hash.update(prev);
            hash.update(&[i as u8 + 1]);
        });
        prev = (*output).as_ref();
    }
}
