#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MessageToken {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    PSK,
}

pub type MessagePattern = &'static [MessageToken];

pub struct HandshakePattern {
    pub(crate) name: &'static str,
    /// index 0: initiator pre-message
    /// index 1: responder pre-message
    /// index 2: message 1, from initator
    pub(crate) patterns: &'static [MessagePattern],
}

pub mod patterns {
    use super::MessageToken::*;
    use super::{HandshakePattern};

    pub const NN: HandshakePattern = HandshakePattern {
        name: "NN",
        patterns: &[&[], &[], &[E], &[E, EE]],
    };
    pub const NK: HandshakePattern = HandshakePattern {
        name: "NK",
        patterns: &[&[], &[S], &[E, ES], &[E, EE]],
    };
    pub const NX: HandshakePattern = HandshakePattern {
        name: "NX",
        patterns: &[&[], &[], &[E], &[E, EE, S, ES]],
    };
    pub const XN: HandshakePattern = HandshakePattern {
        name: "XN",
        patterns: &[
            &[],
            &[],
            &[E],
            &[E, EE],
            &[S, SE]
        ],
    };
    pub const XK: HandshakePattern = HandshakePattern {
        name: "XK",
        patterns: &[
            &[],
            &[S],
            &[E, ES],
            &[E, EE],
            &[S, SE]
        ],
    };
    pub const XX: HandshakePattern = HandshakePattern {
        name: "XX",
        patterns: &[
            &[],
            &[],
            &[E],
            &[E, EE, S, ES],
            &[S, SE]
        ],
    };
    pub const KN: HandshakePattern = HandshakePattern {
        name: "KN",
        patterns: &[
            &[S],
            &[],
            &[E],
            &[E, EE, SE]
        ],
    };
    pub const KK: HandshakePattern = HandshakePattern {
        name: "KK",
        patterns: &[
            &[S],
            &[S],
            &[E, ES, SS],
            &[E, EE, SE]
        ],
    };
    pub const KX: HandshakePattern = HandshakePattern {
        name: "KX",
        patterns: &[
            &[S],
            &[],
            &[E],
            &[E, EE, SE, S, ES]
        ],
    };
    pub const IN: HandshakePattern = HandshakePattern {
        name: "IN",
        patterns: &[
            &[],
            &[],
            &[E, S],
            &[E, EE, SE],
        ],
    };
    pub const IK: HandshakePattern = HandshakePattern {
        name: "IK",
        patterns: &[
            &[],
            &[S],
            &[E, ES, S, SS],
            &[E, EE, SE],
        ],
    };
    pub const IX: HandshakePattern = HandshakePattern {
        name: "IX",
        patterns: &[
            &[],
            &[],
            &[E, S],
            &[E, EE, SE, S, ES],
        ],
    };
}

#[derive(Debug)]
pub enum InvalidReason {
    InvalidName,
    TooShort,
    BadPremessage,
    MissingEphemeralDH,
    MissingKey,
    RedundantTransmission,
    EncryptAfterPSKBeforeE
}

impl HandshakePattern {
    pub fn validate(&self) -> Result<(), InvalidReason> {
        use MessageToken::*;

        if !self
            .name
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric())
        {
            return Err(InvalidReason::InvalidName);
        }

        if self.patterns.len() < 2 {
            return Err(InvalidReason::TooShort);
        }

        for pre_msg in &self.patterns[..=1] {
            if !matches!(pre_msg, [] | [E] | [S] | [E, S]) {
                return Err(InvalidReason::BadPremessage);
            }
        }

        let mut in_e = false;
        let mut in_s = false;
        let mut re_e = false;
        let mut re_s = false;
        let (mut ee, mut es, mut se, mut ss) = (false, false, false, false);

        let transports = [&[][..], &[][..]];
        let incl_transport = self.patterns.iter().chain(transports.iter());
        for (i, msg) in incl_transport.enumerate() {
            let initiator = i % 2 == 0;

            let mut has_psk = false;
            for tok in msg.iter() {
                // ensure we have necessary remote public keys

                if initiator {
                    match tok {
                        EE | SE if !re_e => return Err(InvalidReason::MissingKey),
                        ES | SS if !re_s => return Err(InvalidReason::MissingKey),
                        _ => {}
                    }
                } else {
                    match tok {
                        EE | ES if !in_e => return Err(InvalidReason::MissingKey),
                        SE | SS if !in_s => return Err(InvalidReason::MissingKey),
                        _ => {}
                    }
                }

                let existing = match tok {
                    // only one of each dh key can be sent in a handshake
                    EE => &mut ee,
                    ES => &mut es,
                    SE => &mut se,
                    SS => &mut ss,
                    // only one psk per message
                    PSK => &mut has_psk,
                    // only one of each public key
                    E if initiator => &mut in_e,
                    S if initiator => &mut in_s,
                    E => &mut re_e,
                    S => &mut re_s,
                };
                if *existing {
                    return Err(InvalidReason::RedundantTransmission)
                }
                *existing = true;

                let sent_e = if initiator { in_e } else { re_e };
                if has_psk && matches!(tok, S) && !sent_e {
                    return Err(InvalidReason::EncryptAfterPSKBeforeE);
                }
            }

            if initiator {
                if se {
                    if !ee { return Err(InvalidReason::MissingEphemeralDH) }
                }
                if ss {
                    if !es { return Err(InvalidReason::MissingEphemeralDH) }
                }
            } else {
                if es {
                    if !ee { return Err(InvalidReason::MissingEphemeralDH) }
                }
                if ss {
                    if !es { return Err(InvalidReason::MissingEphemeralDH) }
                }
            }
            
            let sent_e = if initiator { in_e } else { re_e };
            if has_psk && !sent_e {
                return Err(InvalidReason::EncryptAfterPSKBeforeE);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use crate::handshake_pattern::patterns::*;

    use super::{HandshakePattern, MessageToken::*};

    #[test]
    fn validate() {
        XX.validate().unwrap();
        XK.validate().unwrap();
        NN.validate().unwrap();
        assert!(HandshakePattern {
            name: "",
            patterns: &[&[], &[]]
        }
        .validate().is_ok());
        assert!(!HandshakePattern {
            name: "",
            patterns: &[&[PSK], &[]]
        }
        .validate().is_ok());
        assert!(HandshakePattern {
            name: "",
            patterns: &[&[], &[], &[E], &[E, EE]]
        }
        .validate().is_ok());
    }
}
