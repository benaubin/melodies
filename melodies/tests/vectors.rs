use melodies::{patterns, DH25519, TAG_SIZE};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(transparent)]
pub struct Bytes(
    #[serde(with = "hex")]
    Vec<u8>
);

#[derive(serde::Deserialize)]
pub struct Vector {
    pub protocol_name: String,
    pub init_prologue: Bytes,
    pub init_static: Option<Bytes>,
    pub init_ephemeral: Option<Bytes>,
    pub init_remote_ephemeral: Option<Bytes>,
    pub init_remote_static: Option<Bytes>,
    pub resp_prologue: Bytes,
    pub resp_static: Option<Bytes>,
    pub resp_ephemeral: Option<Bytes>,
    pub resp_remote_ephemeral: Option<Bytes>,
    pub resp_remote_static: Option<Bytes>,
    pub handshake_hash: Bytes,
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
    vectors: Vec<Vector>
}

pub fn read_vectors(src: &'static str) -> VectorFile {
    serde_json::from_str(src).unwrap()
}

#[test]
pub fn cacophony() {
    let vectors = read_vectors(include_str!("./vectors/cacophony.json"));
    for vector in vectors.vectors {
        let mut parts = vector.protocol_name.split("_");
        parts.next();
        let pattern = parts.next().unwrap();
        let dh = parts.next().unwrap();
        let cipher = parts.next().unwrap();
        let hash = parts.next().unwrap();

        let pattern = match pattern {
            "NN" => &patterns::NN,
            "XX" => &patterns::XX,
            "KK" => &patterns::KK,
            _ => continue
        };

        let cipher = match cipher {
            "ChaChaPoly" => &melodies_chacha20poly1305::ChaChaPoly,
            _ => continue,
        };

        match (dh, hash) {
            ("25519", "BLAKE2s") => {
                let mut initiator = melodies::NoiseHandshake25519BLAKE2s::new(
                    cipher,
                    &pattern,
                    true,
                    &vector.init_prologue.0,
                    vector.init_static.map(|b| DH25519::new(&b.0)).as_ref(),
                    vector.init_ephemeral.map(|b| DH25519::new(&b.0)).as_ref(),
                    vector.init_remote_static.map(|b| b.0.try_into().unwrap()),
                    vector.init_remote_ephemeral.map(|b| b.0.try_into().unwrap()),
                );
                let mut responder = melodies::NoiseHandshake25519BLAKE2s::new(
                    cipher,
                    pattern,
                    false,
                    &vector.resp_prologue.0,
                    vector.resp_static.map(|b| DH25519::new(&b.0)).as_ref(),
                    vector.resp_ephemeral.map(|b| DH25519::new(&b.0)).as_ref(),
                    vector.resp_remote_static.map(|b| b.0.try_into().unwrap()),
                    vector.resp_remote_ephemeral.map(|b| b.0.try_into().unwrap()),
                );

                let mut init_turn = true;
                let mut buf = [0; 1024];
                let mut iter = vector.messages.iter();
                let transports = loop {
                    let message = if let Some(message) = iter.next() {
                        message
                    } else {
                        break None;
                    };
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
                        break Some((initiator.split(), responder.split()));
                    }
                    
                };
                let (mut initiator, mut responder) = match transports {
                    Some(t) => t,
                    None => continue
                };
                for message in iter {
                    let payload_size = message.payload.len();
                    buf[..payload_size].copy_from_slice(&message.payload);

                    
                    let message_size = if init_turn {
                        initiator.send.encrypt(&[], &mut buf[..payload_size + TAG_SIZE])
                    } else {
                        responder.send.encrypt(&[], &mut buf[..payload_size + TAG_SIZE])
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
            _ => continue,
        };
    }
}
