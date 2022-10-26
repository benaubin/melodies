use zeroize::Zeroizing;

use crate::crypto::{Cipher, TAG_SIZE};
use crate::handshake_pattern::MessageToken::*;
use crate::TransportState;
use crate::{
    crypto::{DHKeypair, HashFunction},
    handshake_pattern::{HandshakePattern, MessageToken},
    symmetric_state::SymmetricState,
};

pub struct HandshakeState<
    const DHLEN: usize,
    const HASHLEN: usize,
    K: DHKeypair<DHLEN>,
    H: HashFunction<HASHLEN>,
> {
    symmetric_state: SymmetricState<HASHLEN, H>,
    /// The local static key pair
    s: Option<K>,
    /// The local ephemeral key pair
    e: Option<K>,
    /// The remote party's static public key
    rs: Option<[u8; DHLEN]>,
    /// The remote party's ephemeral public key
    re: Option<[u8; DHLEN]>,
    /// A boolean indicating the initiator or responder role.
    pub initiator: bool,
    /// The turn number, 0 is for before first message, 1 is after first message, etc...
    pub turn: u8,
    pub pattern: &'static HandshakePattern,
}

pub type ProtocolName = [&'static str; 8];
impl<const DHLEN: usize, const HASHLEN: usize, K: DHKeypair<DHLEN>, H: HashFunction<HASHLEN>>
    HandshakeState<DHLEN, HASHLEN, K, H>
{
    pub fn protocol_name(
        pattern: &HandshakePattern,
        cipher: &'static dyn Cipher,
    ) -> [&'static str; 8] {
        [
            "Noise_",
            pattern.name,
            "_",
            K::NAME,
            "_",
            cipher.name(),
            "_",
            H::NAME,
        ]
    }

    #[inline(always)]
    pub fn new(
        cipher: &'static dyn Cipher,
        pattern: &'static HandshakePattern,
        initiator: bool,
        prologue: &[u8],
        s: Option<&K>,
        e: Option<&K>,
        rs: Option<[u8; DHLEN]>,
        re: Option<[u8; DHLEN]>,
    ) -> Self {
        pattern.validate().expect("pattern must be valid");

        let mut state = Self {
            symmetric_state: SymmetricState::new(&Self::protocol_name(&pattern, cipher), cipher),
            s: s.cloned(),
            e: e.cloned(),
            rs,
            re,
            initiator,
            turn: 0,
            pattern,
        };
        state.symmetric_state.mix_hash(prologue);
        for (i, pre_msg) in pattern.patterns[..2].iter().enumerate() {
            let local = i == !initiator as usize;
            for tok in pre_msg.iter() {
                let key = match tok {
                    E => {
                        if local {
                            state
                                .e
                                .as_ref()
                                .expect("requires local ephemeral key in premessage")
                                .public_key()
                        } else {
                            state.re.expect("remote emphemeral key")
                        }
                    }
                    S => {
                        if local {
                            state
                                .s
                                .as_ref()
                                .expect("requires local static key in premessage")
                                .public_key()
                        } else {
                            state.rs.expect("remote static key")
                        }
                    }
                    _ => unreachable!(),
                };
                state.symmetric_state.mix_hash(&key);
            }
        }
        state
    }

    fn dh(&mut self, tok: MessageToken) {
        let (ini, resp) = match tok {
            EE => (E, E),
            ES => (E, S),
            SE => (S, E),
            SS => (S, S),
            _ => unreachable!(),
        };
        let (local, remote) = if self.initiator {
            (ini, resp)
        } else {
            (resp, ini)
        };
        let local = match local {
            E => self.e.as_ref().expect("dh requires e"),
            S => self.s.as_ref().expect("dh requires s"),
            _ => unreachable!(),
        };
        let remote = match remote {
            E => self.re.as_ref().expect("dh requires re"),
            S => self.rs.as_ref().expect("dh requires rs"),
            _ => unreachable!(),
        };
        let mut tmp = Zeroizing::new([0; DHLEN]);
        local.dh(&remote, &mut tmp);
        self.symmetric_state.mix_key(&tmp[..]);
    }

    pub fn is_our_turn(&self) -> bool {
        self.turn % 2 == (!self.initiator as u8)
    }

    pub fn write_msg(&mut self, buf: &mut [u8], payload_size: usize) -> usize {
        assert!(self.is_our_turn());
        let msg = &self.pattern.patterns[self.turn as usize + 2];
        self.turn += 1;

        let buf_size = buf.len();
        let mut buf_remaining = &mut buf[payload_size..];

        for tok in msg.iter() {
            match tok {
                E => {
                    if self.e.is_none() {
                        K::generate_keypair(&mut self.e);
                    }
                    let e_pub = self.e.as_ref().unwrap().public_key();
                    self.symmetric_state.mix_hash(&e_pub);
                    buf_remaining[..e_pub.len()].copy_from_slice(&e_pub);
                    buf_remaining = &mut buf_remaining[e_pub.len()..];
                }
                S => {
                    let s_pub = self.s.as_ref().unwrap().public_key();
                    buf_remaining[..s_pub.len()].copy_from_slice(&s_pub);
                    let len = self
                        .symmetric_state
                        .encrypt_and_hash(&mut buf_remaining[..s_pub.len() + TAG_SIZE]);
                    buf_remaining = &mut buf_remaining[len..];
                }
                EE | ES | SE | SS => self.dh(*tok),
                PSK => todo!(),
            }
        }

        let payload_headers_size = buf_size - buf_remaining.len();
        let headers_size = payload_headers_size - payload_size;
        drop(buf_remaining);

        // move headers before payload
        buf[..payload_headers_size].rotate_left(payload_size);
        let ciphertext_size = self
            .symmetric_state
            .encrypt_and_hash(&mut buf[headers_size..][..payload_size + TAG_SIZE]);

        headers_size + ciphertext_size
    }

    pub fn read_msg<'b>(&mut self, mut buf: &'b mut [u8]) -> Option<&'b [u8]> {
        assert!(!self.is_our_turn());
        let msg = &self.pattern.patterns[self.turn as usize + 2];
        let snapshot = self.symmetric_state.snapshot();
        let mut fail = false;

        for tok in msg.iter() {
            match tok {
                E => {
                    assert!(self.re.is_none());
                    let (re_buf, rest) = buf.split_at_mut(DHLEN);
                    buf = rest;
                    self.re = Some(re_buf.try_into().unwrap());
                    self.symmetric_state.mix_hash(&re_buf);
                }
                S => {
                    assert!(self.rs.is_none());
                    let s_len = if self.symmetric_state.has_key() {
                        DHLEN + TAG_SIZE
                    } else {
                        DHLEN
                    };
                    let (tmp, rest) = buf.split_at_mut(s_len);
                    buf = rest;
                    match self.symmetric_state.decrypt_and_hash(tmp) {
                        Some(tmp) => {
                            self.rs = Some([0; DHLEN]);
                            self.rs.as_mut().unwrap().copy_from_slice(tmp);
                        }
                        None => {
                            fail = true;
                            break;
                        }
                    }
                }
                EE | ES | SE | SS => self.dh(*tok),
                PSK => todo!(),
            }
        }

        if !fail {
            if let Some(payload) = self.symmetric_state.decrypt_and_hash(buf) {
                self.turn += 1;
                return Some(payload);
            };
        }

        if msg.contains(&E) {
            self.re = None;
        }
        if msg.contains(&S) {
            self.rs = None;
        }
        self.symmetric_state.restore(snapshot);

        None
    }

    pub fn is_finished(&self) -> bool {
        self.turn as usize + 2 >= self.pattern.patterns.len()
    }

    #[inline(always)]
    pub fn split(self) -> TransportState<HASHLEN> {
        assert!(self.is_finished());
        let (ini, res, hash) = self.symmetric_state.split();
        let (send, recv) = match self.initiator {
            true => (ini, res),
            false => (res, ini),
        };
        TransportState { send, recv, hash }
    }
}
