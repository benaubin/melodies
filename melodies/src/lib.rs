pub use melodies_blake2::BLAKE2s;
pub use melodies_core::crypto::{DHKeypair, TAG_SIZE};
pub use melodies_x25519_dalek::DH25519;
pub use melodies_core::patterns;
pub use melodies_core::{HandshakeState, TransportState, cipher_state::CipherState};

pub type NoiseHandshake25519BLAKE2s = melodies_core::HandshakeState::<32, 32, DH25519, BLAKE2s>;

#[cfg(test)]
mod tests {
    use super::NoiseHandshake25519BLAKE2s;
    use melodies_core::crypto::{DHKeypair, TAG_SIZE};
    use melodies_x25519_dalek::DH25519;
    use melodies_core::patterns;

    #[test]
    fn it_works() {
        let mut ikey = None;
        DH25519::generate_keypair(&mut ikey);
        let mut rkey = None;
        DH25519::generate_keypair(&mut rkey);

        let mut initiator = NoiseHandshake25519BLAKE2s::new(
            &melodies_chacha20poly1305::ChaChaPoly,
            &patterns::XX,
            true,
            &b""[..],
            ikey.as_ref(),
            None,
            None,
            None,
        );
        let mut responder = NoiseHandshake25519BLAKE2s::new(
            &melodies_chacha20poly1305::ChaChaPoly,
            &patterns::XX,
            false,
            &b""[..],
            rkey.as_ref(),
            None,
            None,
            None,
        );

        let payload_1 = b"message 1";
        let payload_2 = b"message 2";
        let payload_3 = b"message 3";
        let payload_4 = b"message 4";

        let mut buf = [0; 1024];

        buf[..payload_1.len()].copy_from_slice(payload_1);
        let msg_len = initiator.write_msg(&mut buf, payload_1.len());
        let recv_payload = responder.read_msg(&mut buf[..msg_len]).unwrap();
        assert_eq!(payload_1, recv_payload);

        buf[..payload_2.len()].copy_from_slice(payload_2);
        let msg_len = responder.write_msg(&mut buf, payload_2.len());
        let recv_payload = initiator.read_msg(&mut buf[..msg_len]).unwrap();
        assert_eq!(payload_2, recv_payload);

        buf[..payload_3.len()].copy_from_slice(payload_3);
        let msg_len = initiator.write_msg(&mut buf, payload_3.len());
        let recv_payload = responder.read_msg(&mut buf[..msg_len]).unwrap();
        assert_eq!(payload_3, recv_payload);

        let mut initiator = initiator.split();
        let mut responder = responder.split();

        buf[..payload_4.len()].copy_from_slice(payload_4);
        let msg_len = initiator.send.encrypt(&[], &mut buf[..payload_4.len() + TAG_SIZE]);
        let recv_payload = responder.recv.decrypt(&[], &mut buf[..msg_len]).unwrap();
        assert_eq!(payload_4, recv_payload);
        assert_eq!(initiator.hash, responder.hash);
    }
}
