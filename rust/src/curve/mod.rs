#![allow(dead_code)]

use crate::error::*;
use rand_core::OsRng;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NamedCurve {
    Unsupported = 0x0000,
    P256 = 0x0017,
    P384 = 0x0018,
    X25519 = 0x001d,
}

impl From<u16> for NamedCurve {
    fn from(val: u16) -> Self {
        match val {
            0x0017 => NamedCurve::P256,
            0x0018 => NamedCurve::P384,
            0x001d => NamedCurve::X25519,
            _ => NamedCurve::Unsupported,
        }
    }
}

impl From<NamedCurve> for u16 {
    fn from(curve: NamedCurve) -> u16 {
        curve as u16
    }
}

pub(crate) enum NamedCurvePrivateKey {
    EphemeralSecretP256(p256::ecdh::EphemeralSecret),
}

pub struct NamedCurveKeypair {
    pub(crate) curve: NamedCurve,
    pub(crate) public_key: Vec<u8>,
    pub(crate) private_key: NamedCurvePrivateKey,
}

fn elliptic_curve_keypair(curve: NamedCurve) -> Result<NamedCurveKeypair> {
    let (public_key, private_key) = match curve {
        NamedCurve::P256 => {
            let secret_key = p256::ecdh::EphemeralSecret::random(&mut OsRng);

            // Not sure if it correct ??? Is it uncompressed point ???
            let public_key = p256::EncodedPoint::from(secret_key.public_key());
            (
                public_key.as_bytes().to_vec(),
                NamedCurvePrivateKey::EphemeralSecretP256(secret_key),
            )
        }
        _ => return Err(Error::ErrInvalidNamedCurve),
    };

    Ok(NamedCurveKeypair {
        curve,
        public_key,
        private_key,
    })
}

impl NamedCurve {
    pub fn generate_keypair(&self) -> Result<NamedCurveKeypair> {
        match *self {
            NamedCurve::P256 => elliptic_curve_keypair(NamedCurve::P256),
            _ => Err(Error::ErrInvalidNamedCurve),
        }
    }
}
