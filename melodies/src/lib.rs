#![no_std]

pub use melodies_core::crypto::{DHKeypair, TAG_SIZE};
pub use melodies_core::{HandshakeState, TransportState, cipher_state::CipherState};

pub use melodies_core::patterns;
pub mod crypto {
    pub use melodies_ring::*;
    pub use melodies_blake2::BLAKE2s;
    pub use melodies_x25519_dalek::DH25519;
}