use zeroize::{Zeroize, Zeroizing};

use crate::handshake_pattern::MessageToken::*;
use crate::{
    crypto::{Cipher, DHKeypair, HashFunction},
    handshake_pattern::{HandshakePattern, MessagePattern, MessageToken},
    symmetric_state::SymmetricState,
};

#[derive(Zeroize)]
pub struct HandshakeState<
    const DHLEN: usize,
    const HASHLEN: usize,
    K: DHKeypair<DHLEN>,
    C: Cipher,
    H: HashFunction<HASHLEN>,
> {
    pub symmetric_state: SymmetricState<HASHLEN, C, H>,
    /// The local static key pair
    pub s: Option<K>,
    /// The local ephemeral key pair
    pub e: Option<K>,
    /// The remote party's static public key
    pub rs: Option<[u8; DHLEN]>,
    /// The remote party's ephemeral public key
    #[zeroize(skip)]
    pub re: Option<[u8; DHLEN]>,
    /// A boolean indicating the initiator or responder role.
    #[zeroize(skip)]
    pub initiator: bool,
    /// Is it our turn?
    #[zeroize(skip)]
    pub is_our_turn: bool,
    /// The remaining portion of the handshake pattern
    #[zeroize(skip)]
    pub remaining_messages: &'static [MessagePattern],
}

impl<
        const DHLEN: usize,
        const HASHLEN: usize,
        K: DHKeypair<DHLEN>,
        C: Cipher,
        H: HashFunction<HASHLEN>,
    > HandshakeState<DHLEN, HASHLEN, K, C, H>
{
    pub fn new(
        protocol_name: &'static str,
        pattern: HandshakePattern,
        initiator: bool,
        s: Option<&K>,
        e: Option<&K>,
        rs: Option<[u8; DHLEN]>,
        re: Option<[u8; DHLEN]>,
        out: &mut Option<Self>,
    ) {
        pattern.validate().expect("pattern must be valid");

        let (pre_msgs, remaining_messages) = pattern.patterns.split_at(2);
        let local_preshared = pre_msgs[initiator as usize];
        let remote_preshared = pre_msgs[!initiator as usize];

        assert_eq!(e.is_some(), local_preshared.contains(&E));
        assert_eq!(rs.is_some(), remote_preshared.contains(&S));
        assert_eq!(re.is_some(), remote_preshared.contains(&E));

        let mut state = Self {
            symmetric_state: SymmetricState::new(protocol_name),
            s: None,
            e: None,
            rs,
            re,
            initiator,
            is_our_turn: initiator,
            remaining_messages,
        };

        if let Some(s) = s {
            state.s = Some(s.clone());
        }
        if let Some(e) = e {
            state.e = Some(e.clone());
        }

        *out = Some(state);
    }

    fn dh(&mut self, tok: MessageToken) {
        let (local, remote) = match tok {
            EE => (&self.e, &self.re),
            SS => (&self.s, &self.rs),
            ES if self.initiator => (&self.e, &self.rs),
            SE if self.initiator => (&self.s, &self.re),
            ES => (&self.s, &self.re),
            SE => (&self.e, &self.rs),
            _ => unreachable!(),
        };
        let mut tmp = Zeroizing::new([0; DHLEN]);
        local
            .as_ref()
            .unwrap()
            .dh(remote.as_ref().unwrap(), &mut tmp);
        self.symmetric_state.mix_key(&tmp[..]);
    }

    pub fn write_msg(&mut self, buf: &mut [u8], size: usize) -> usize {
        assert!(self.is_our_turn);
        self.is_our_turn = false;

        let mut bytes_written = size;

        let (msg, remaining_messages) = self.remaining_messages.split_first().unwrap();
        self.remaining_messages = remaining_messages;

        for tok in msg.iter() {
            match tok {
                E => {
                    assert!(self.e.is_none());
                    K::generate_keypair(&mut self.e);
                    let e_pub = self.e.as_ref().unwrap().public_key();
                    self.symmetric_state.mix_hash(e_pub);
                    buf[bytes_written..][..e_pub.len()].copy_from_slice(e_pub);
                    bytes_written += e_pub.len();
                }
                S => {
                    let mut s_pub = self.s.as_ref().unwrap().public_key().clone();
                    let tag = self.symmetric_state.encrypt_and_hash(&mut s_pub);
                    buf[bytes_written..][..s_pub.len()].copy_from_slice(&s_pub);
                    bytes_written += s_pub.len();
                    if let Some(tag) = tag {
                        buf[bytes_written..][..tag.len()].copy_from_slice(&tag);
                        bytes_written += tag.len();
                    }
                }
                EE | ES | SE | SS => self.dh(*tok),
                PSK => todo!(),
            }
        }

        let tag = self.symmetric_state.encrypt_and_hash(&mut buf[..size]);
        buf[..bytes_written].rotate_left(size);

        if let Some(tag) = tag {
            buf[bytes_written..][..tag.len()].copy_from_slice(&tag);
            bytes_written += tag.len();
        }

        bytes_written
    }

    pub fn read_msg<'b>(&mut self, mut buf: &'b mut [u8]) -> Result<&'b [u8], ()> {
        assert!(!self.is_our_turn);
        self.is_our_turn = true;

        let (msg, remaining_messages) = self.remaining_messages.split_first().unwrap();
        self.remaining_messages = remaining_messages;

        for tok in msg.iter() {
            match tok {
                E => {
                    assert!(self.re.is_none());
                    let (re, rest) = buf.split_at_mut(DHLEN);
                    buf = rest;
                    let re = re.try_into().unwrap();
                    self.re = Some(re);
                    self.symmetric_state.mix_hash(&re);
                }
                S => {
                    assert!(self.rs.is_none());
                    let len = DHLEN + self.symmetric_state.has_key().then_some(16).unwrap_or(0);
                    let (temp, rest) = buf.split_at_mut(len);
                    buf = rest;
                    let rs = self.symmetric_state.decrypt_and_hash(temp)?; // todo: better abort
                    let rs = rs.try_into().unwrap();
                    self.rs = Some(rs);
                }
                EE | ES | SE | SS => self.dh(*tok),
                PSK => todo!(),
            }
        }

        self.symmetric_state.decrypt_and_hash(buf) // better abort needed
    }

}
