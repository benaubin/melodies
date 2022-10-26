use melodies_core::crypto::DHKeypair;
use x25519_dalek::{self, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DH25519 {
    key: x25519_dalek::StaticSecret
}

impl DH25519 {
    pub fn new(data: &[u8]) -> Self {
        let data: [u8; 32] = data.try_into().unwrap();
        Self { key: StaticSecret::from(data) }
    }
}

impl DHKeypair<32> for DH25519 {
    const NAME: &'static str = "25519";

    fn generate_keypair(out: &mut Option<Self>) where Self: Sized {
        let rng = rand::rngs::OsRng::default();
        *out = Some(DH25519 {
            key: x25519_dalek::StaticSecret::new(rng)
        });
    }

    fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.key).to_bytes()
    }

    fn dh(&self, public_key: &[u8; 32], output: &mut [u8; 32]) {
        let theirs = PublicKey::from(*public_key);
        let secret = self.key.diffie_hellman(&theirs);
        if secret.was_contributory() {
            output.copy_from_slice(secret.as_bytes());
        } else {
            output.fill(0);
        }
    }
}
