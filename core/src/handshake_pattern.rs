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

#[derive(Debug)]
pub struct HandshakePattern {
    pub name: &'static str,
    /// index 0: initiator pre-message
    /// index 1: responder pre-message
    /// index 2: message 1, from initator
    pub patterns: &'static [MessagePattern],
}

#[allow(non_upper_case_globals)]
pub mod patterns {
    use super::HandshakePattern;
    use super::MessageToken::*;


    macro_rules! spattern {
        (
            $(-> $($pre_tok:ident),*)?
            $(<- $($pre_tok_r:ident),*)?
            ...
            $( -> $($tok:ident),* $(<- $($tok_r:ident),*)? )*
        ) => {
            &[
                &[$( $($pre_tok),* )?],
                &[$( $($pre_tok_r),* )?],
                $(
                    &[ $($tok),* ],
                    $(&[ $($tok_r),* ])?
                ),*
            ]
        };
        (
            $( -> $($tok:ident),* $(<- $($tok_r:ident),*)? )*
        ) => {
            spattern! {
                ...
                $( -> $($tok),* $(<- $($tok_r),*)? )*
            }
        };
    }

    macro_rules! patterns {
        (
            $($name:ident: [
                $([ $($tok:ident),* ]),*
            ])*
        ) => {
            $(
                pub static $name: HandshakePattern = HandshakePattern {
                    name: core::stringify!($name),
                    patterns: &[
                        $( &[ $($tok),* ] ),*
                    ],
                };
            )*

            pub static ALL: &'static [&HandshakePattern] = &[ $(&$name),* ];
        };
        (
            $($name:ident: { $($tt:tt)* })*
        ) => {
            $(
                pub static $name: HandshakePattern = HandshakePattern {
                    name: core::stringify!($name),
                    patterns: spattern! { $($tt)* },
                };
            )*

            pub static ALL: &'static [&HandshakePattern] = &[ $(&$name),* ];
        };
    }

    patterns! {
        NN: {
            -> E
            <- E, EE
        }
        NNpsk0: {
            -> PSK, E
            <- E, EE
        }
        NNpsk2: {
            -> E
            <- E, EE, PSK
        }
        NK: {
            <- S
            ...
            -> E, ES
            <- E, EE
        }
        NKpsk0: {
            <- S
            ...
            -> PSK, E, ES
            <- E, EE
        }
        NKpsk2: {
            <- S
            ...
            -> E, ES
            <- E, EE, PSK
        }
        NX: {
            -> E
            <- E, EE, S, ES
        }
        NXpsk2: {
            -> E
            <- E, EE, S, ES, PSK
        }
        XN: {
            -> E
            <- E, EE
            -> S, SE
        }
        XNpsk3: {
            -> E
            <- E, EE
            -> S, SE, PSK
        }
        XK: {
            <- S
            ...
            -> E, ES
            <- E, EE
            -> S, SE
        }
        XKpsk3: {
            <- S
            ...
            -> E, ES
            <- E, EE
            -> S, SE, PSK
        }
        XX: {
            -> E
            <- E, EE, S, ES
            -> S, SE
        }
        XXpsk3: {
            -> E
            <- E, EE, S, ES
            -> S, SE, PSK
        }
        KN: {
            -> S
            ...
            -> E
            <- E, EE, SE
        }
        KNpsk0: {
            -> S
            ...
            -> PSK, E
            <- E, EE, SE
        }
        KNpsk2: {
            -> S
            ...
            -> E
            <- E, EE, SE, PSK
        }
        KK: {
            -> S
            <- S
            ...
            -> E, ES, SS
            <- E, EE, SE
        }
        KKpsk0: {
            -> S
            <- S
            ...
            -> PSK, E, ES, SS
            <- E, EE, SE
        }
        KKpsk2: {
            -> S
            <- S
            ...
            -> E, ES, SS
            <- E, EE, SE, PSK
        }
        KX: {
            -> S
            ...
            -> E
            <- E, EE, SE, S, ES
        }
        KXpsk2: {
            -> S
            ...
            -> E
            <- E, EE, SE, S, ES, PSK
        }
        IN: {
            -> E, S
            <- E, EE, SE
        }
        INpsk1: {
            -> E, S, PSK
            <- E, EE, SE
        }
        INpsk2: {
            -> E, S
            <- E, EE, SE, PSK
        }
        IK: {
            <- S
            ...
            -> E, ES, S, SS
            <- E, EE, SE
        }
        IKpsk1: {
            <- S
            ...
            -> E, ES, S, SS, PSK
            <- E, EE, SE
        }
        IKpsk2: {
            <- S
            ...
            -> E, ES, S, SS
            <- E, EE, SE, PSK
        }
        IX: {
            -> E, S
            <- E, EE, SE, S, ES
        }
        IXpsk2: {
            -> E, S
            <- E, EE, SE, S, ES, PSK
        }
    }
}

#[derive(Debug)]
pub enum InvalidReason {
    InvalidName,
    TooShort,
    BadPremessage,
    MissingEphemeralDH,
    MissingKey,
    RedundantTransmission,
    EncryptAfterPSKBeforeE,
}

impl HandshakePattern {
    pub(crate) fn has_psk(&self) -> bool {
        self.patterns.iter().any(|p| p.contains(&MessageToken::PSK))
    }

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
                    return Err(InvalidReason::RedundantTransmission);
                }
                *existing = true;

                let sent_e = if initiator { in_e } else { re_e };
                if has_psk && matches!(tok, S) && !sent_e {
                    return Err(InvalidReason::EncryptAfterPSKBeforeE);
                }
            }

            if initiator {
                if se {
                    if !ee {
                        return Err(InvalidReason::MissingEphemeralDH);
                    }
                }
                if ss {
                    if !es {
                        return Err(InvalidReason::MissingEphemeralDH);
                    }
                }
            } else {
                if es {
                    if !ee {
                        return Err(InvalidReason::MissingEphemeralDH);
                    }
                }
                if ss {
                    if !es {
                        return Err(InvalidReason::MissingEphemeralDH);
                    }
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
        .validate()
        .is_ok());
        assert!(!HandshakePattern {
            name: "",
            patterns: &[&[PSK], &[]]
        }
        .validate()
        .is_ok());
        assert!(HandshakePattern {
            name: "",
            patterns: &[&[], &[], &[E], &[E, EE]]
        }
        .validate()
        .is_ok());
    }
}
