use std::time::{Instant};

use melodies::{patterns, TAG_SIZE};
use melodies::crypto::{BLAKE2s, DH25519,};

use melodies_blake2::BLAKE2b;
use melodies_core::crypto::Cipher;
use melodies_ring::SHA;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(transparent)]
pub struct Bytes(#[serde(with = "hex")] Vec<u8>);

#[derive(serde::Deserialize)]
pub struct Vector {
    pub protocol_name: String,
    pub init_prologue: Bytes,
    pub init_static: Option<Bytes>,
    pub init_ephemeral: Option<Bytes>,
    pub init_remote_ephemeral: Option<Bytes>,
    pub init_remote_static: Option<Bytes>,
    pub init_psks: Option<Vec<Bytes>>,
    pub resp_prologue: Bytes,
    pub resp_static: Option<Bytes>,
    pub resp_ephemeral: Option<Bytes>,
    pub resp_remote_ephemeral: Option<Bytes>,
    pub resp_remote_static: Option<Bytes>,
    pub resp_psks: Option<Vec<Bytes>>,
    pub handshake_hash: Option<Bytes>,
    pub messages: Vec<Message>,
}

#[derive(serde::Deserialize)]
pub struct Message {
    #[serde(with = "hex")]
    pub payload: Vec<u8>,
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Deserialize)]
pub struct VectorFile {
    vectors: Vec<Vector>,
}

pub fn read_vectors(src: &'static str) -> VectorFile {
    serde_json::from_str(src).unwrap()
}

fn do_handshake<
    const DHLEN: usize,
    const HASHLEN: usize,
    K: melodies_core::crypto::DHKeypair<DHLEN>,
    H: melodies_core::crypto::HashFunction<HASHLEN>,
>(
    mut initiator: melodies::HandshakeState<DHLEN, HASHLEN, K, H>,
    mut responder: melodies::HandshakeState<DHLEN, HASHLEN, K, H>,
    vector: &Vector,
) {
    if let Some(psks) = vector.init_psks.as_ref() {
        if psks.len() > 0 {
            assert_eq!(psks.len(), 1, "only one psk is currently supported");
            initiator.insert_psk(&psks[0].0);
        }
    }

    if let Some(psks) = vector.resp_psks.as_ref() {
        if psks.len() > 0 {
            assert_eq!(psks.len(), 1, "only one psk is currently supported");
            responder.insert_psk(&psks[0].0);
        }
    }

    let mut init_turn = true;
    let mut buf = [0; 1024];
    let mut iter = vector.messages.iter();
    let (mut initiator, mut responder) = loop {
        let message = iter.next().expect("handshake did not finish");
        let payload_size = message.payload.len();
        buf[..payload_size].copy_from_slice(&message.payload);
        let message_size = if init_turn {
            initiator.write_msg(&mut buf, payload_size)
        } else {
            responder.write_msg(&mut buf, payload_size)
        };
        let ciphertext = &mut buf[..message_size];
        assert_eq!(&message.ciphertext, ciphertext);

        let received = if init_turn {
            responder.read_msg(ciphertext)
        } else {
            initiator.read_msg(ciphertext)
        };

        let received = received.expect("failed to read message");
        assert_eq!(message.payload, received);

        init_turn = !init_turn;

        assert_eq!(initiator.is_finished(), responder.is_finished());
        if initiator.is_finished() {
            break (initiator.split(), responder.split());
        }
    };

    if let Some(hh) = vector.handshake_hash.as_ref() {
        assert_eq!(&initiator.hash[..], &hh.0[..]);
        assert_eq!(&responder.hash[..], &hh.0[..]);
    }

    for message in iter {
        let payload_size = message.payload.len();
        buf[..payload_size].copy_from_slice(&message.payload);

        let message_size = if init_turn {
            initiator
                .send
                .encrypt(&[], &mut buf[..payload_size + TAG_SIZE])
        } else {
            responder
                .send
                .encrypt(&[], &mut buf[..payload_size + TAG_SIZE])
        };
        let ciphertext = &mut buf[..message_size];
        assert_eq!(&message.ciphertext, ciphertext);

        let received = if init_turn {
            responder.recv.decrypt(&[], ciphertext)
        } else {
            initiator.recv.decrypt(&[], ciphertext)
        };

        let received = received.expect("failed to read message");
        assert_eq!(message.payload, received);

        init_turn = !init_turn;
    }
}

pub fn test_vectors(vectors: VectorFile, use_ring_chacha: bool) {
    let start = Instant::now();
    let mut test_count = 0;
    let mut skipped = 0;
    for vector in vectors.vectors.iter() {
        let mut parts = vector.protocol_name.split("_");
        parts.next();
        let pattern = parts.next().unwrap();
        let dh = parts.next().unwrap();
        let cipher_name = parts.next().unwrap();
        let hash = parts.next().unwrap();

        let pattern = match patterns::ALL.iter().find(|p| p.name == pattern) {
            Some(pat) => pat,
            None => continue,
        };

        let cipher = match cipher_name {
            "ChaChaPoly" => match use_ring_chacha {
                true => &melodies_ring::ChaChaPoly as &'static dyn Cipher,
                false => &melodies_chacha20poly1305::ChaChaPoly as &'static dyn Cipher,
            }
            "AESGCM" => &melodies_ring::AESGCM,
            _ => continue,
        };

        match (dh, hash) {
            ("25519", "BLAKE2s") => {
                let initiator = melodies::HandshakeState::<32, 32, _, BLAKE2s>::new(
                    cipher,
                    &pattern,
                    true,
                    &vector.init_prologue.0,
                    vector
                        .init_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .init_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                let responder = melodies::HandshakeState::<32, 32, _, BLAKE2s>::new(
                    cipher,
                    pattern,
                    false,
                    &vector.resp_prologue.0,
                    vector
                        .resp_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .resp_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                do_handshake(initiator, responder, &vector)
            },
            ("25519", "BLAKE2b") => {
                let initiator = melodies::HandshakeState::<32, 64, _, BLAKE2b>::new(
                    cipher,
                    &pattern,
                    true,
                    &vector.init_prologue.0,
                    vector
                        .init_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .init_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                let responder = melodies::HandshakeState::<32, 64, _, BLAKE2b>::new(
                    cipher,
                    pattern,
                    false,
                    &vector.resp_prologue.0,
                    vector
                        .resp_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .resp_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                do_handshake(initiator, responder, &vector)
            }
            ("25519", "SHA256") => {
                let initiator = melodies::HandshakeState::<32, 32, _, SHA>::new(
                    cipher,
                    &pattern,
                    true,
                    &vector.init_prologue.0,
                    vector
                        .init_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .init_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                let responder = melodies::HandshakeState::<32, 32, _, SHA>::new(
                    cipher,
                    pattern,
                    false,
                    &vector.resp_prologue.0,
                    vector
                        .resp_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .resp_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                do_handshake(initiator, responder, &vector)
            }
            ("25519", "SHA512") => {
                let initiator = melodies::HandshakeState::<32, 64, _, SHA>::new(
                    cipher,
                    &pattern,
                    true,
                    &vector.init_prologue.0,
                    vector
                        .init_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .init_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .init_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                let responder = melodies::HandshakeState::<32, 64, _, SHA>::new(
                    cipher,
                    pattern,
                    false,
                    &vector.resp_prologue.0,
                    vector
                        .resp_static
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_ephemeral
                        .as_ref()
                        .map(|b| DH25519::new(&b.0))
                        .as_ref(),
                    vector
                        .resp_remote_static
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                    vector
                        .resp_remote_ephemeral
                        .as_ref()
                        .map(|b| b.0.clone().try_into().unwrap()),
                );
                do_handshake(initiator, responder, &vector)
            }
            _ => {
                skipped += 1; continue},
        };

        test_count += 1;
    }
    let dur = Instant::now().duration_since(start).as_millis();
    println!("Tested {test_count} vectors in {dur}ms, skipped {skipped}");
}

#[test]
pub fn cacophony() {
    let vectors = read_vectors(include_str!("./vectors/cacophony.json"));
    test_vectors(vectors, false);
}

#[test]
pub fn cacophony_ring_chacha() {
    let vectors = read_vectors(include_str!("./vectors/snow.json"));
    test_vectors(vectors, true);
}


#[test]
pub fn snow() {
    let vectors = read_vectors(include_str!("./vectors/snow.json"));
    test_vectors(vectors, false);
}

#[test]
pub fn snow_ring_chacha() {
    let vectors = read_vectors(include_str!("./vectors/snow.json"));
    test_vectors(vectors, true);
}
