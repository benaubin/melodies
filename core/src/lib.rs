#![no_std]

mod symmetric_state;
mod handshake_pattern;
mod handshake_state;

use cipher_state::CipherState;
pub use handshake_pattern::patterns;

pub mod crypto;
pub mod cipher_state;
pub mod util;

pub use handshake_state::HandshakeState;


pub struct TransportState<const HASHLEN: usize> {
    pub send: CipherState<u64>,
    pub recv: CipherState<u64>,
    pub hash: [u8; HASHLEN]
}
