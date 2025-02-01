use crate::curve::*;
use crate::error::*;
use rcgen::{generate_simple_self_signed, CertifiedKey, KeyPair};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};

use rustls::pki_types::CertificateDer;

pub mod crypto_gcm;

#[derive(Clone, PartialEq, Debug)]
pub struct Certificate {
    /// DER-encoded certificates.
    pub certificate: Vec<CertificateDer<'static>>,
    /// Private key.
    pub private_key: CryptoPrivateKey,
}

impl Certificate {
    pub fn generate_self_signed(subject_alt_names: impl Into<Vec<String>>) -> Result<Self> {
        let params = rcgen::CertificateParams::new(subject_alt_names).unwrap();
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        Ok(Certificate {
            certificate: vec![cert.der().to_owned()],
            private_key: CryptoPrivateKey::try_from(&key_pair)?,
        })
    }
}

#[derive(Debug)]
pub enum CryptoPrivateKeyKind {
    Ed25519(Ed25519KeyPair),
    Ecdsa256(EcdsaKeyPair),
}

#[derive(Debug)]
pub struct CryptoPrivateKey {
    /// Keypair.
    pub kind: CryptoPrivateKeyKind,
    /// DER-encoded keypair.
    pub serialized_der: Vec<u8>,
}

impl TryFrom<&KeyPair> for CryptoPrivateKey {
    type Error = Error;

    fn try_from(key_pair: &KeyPair) -> Result<Self> {
        Self::from_key_pair(key_pair)
    }
}

impl CryptoPrivateKey {
    pub fn from_key_pair(key_pair: &KeyPair) -> Result<Self> {
        let serialized_der = key_pair.serialize_der();
        if key_pair.is_compatible(&rcgen::PKCS_ED25519) {
            Ok(CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ed25519(
                    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&serialized_der)
                        .map_err(|e| Error::Other(e.to_string()))?,
                ),
                serialized_der,
            })
        } else if key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            Ok(CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ecdsa256(
                    EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        &serialized_der,
                        &SystemRandom::new(),
                    )
                    .map_err(|e| Error::Other(e.to_string()))?,
                ),
                serialized_der,
            })
        } else {
            Err(Error::Other("Unsupported key_pair".to_owned()))
        }
    }
}

impl PartialEq for CryptoPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        if self.serialized_der != other.serialized_der {
            return false;
        }

        matches!(
            (&self.kind, &other.kind),
            (
                CryptoPrivateKeyKind::Ecdsa256(_),
                CryptoPrivateKeyKind::Ecdsa256(_)
            ) | (
                CryptoPrivateKeyKind::Ed25519(_),
                CryptoPrivateKeyKind::Ed25519(_)
            )
        )
    }
}

impl Clone for CryptoPrivateKey {
    fn clone(&self) -> Self {
        match self.kind {
            CryptoPrivateKeyKind::Ed25519(_) => CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ed25519(
                    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&self.serialized_der).unwrap(),
                ),
                serialized_der: self.serialized_der.clone(),
            },

            CryptoPrivateKeyKind::Ecdsa256(_) => CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ecdsa256(
                    EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        &self.serialized_der,
                        &SystemRandom::new(),
                    )
                    .unwrap(),
                ),
                serialized_der: self.serialized_der.clone(),
            },
        }
    }
}

pub(crate) fn value_key_message(
    client_random: &[u8],
    server_random: &[u8],
    public_key: &[u8],
    named_curve: NamedCurve,
) -> Vec<u8> {
    let mut server_ecdh_params = vec![0u8; 4];
    server_ecdh_params[0] = 3; // named curve
    server_ecdh_params[1..3].copy_from_slice(&(named_curve as u16).to_be_bytes());
    server_ecdh_params[3] = public_key.len() as u8;

    let mut plaintext = vec![];
    plaintext.extend_from_slice(client_random);
    plaintext.extend_from_slice(server_random);
    plaintext.extend_from_slice(&server_ecdh_params);
    plaintext.extend_from_slice(public_key);

    plaintext
}

// If the client provided a "signature_algorithms" extension, then all
// certificates provided by the server MUST be signed by a
// hash/signature algorithm pair that appears in that extension
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
pub(crate) fn generate_key_signature(
    client_random: &[u8],
    server_random: &[u8],
    public_key: &[u8],
    named_curve: NamedCurve,
    private_key: &CryptoPrivateKey, /*, hash_algorithm: HashAlgorithm*/
) -> Result<Vec<u8>> {
    let msg = value_key_message(client_random, server_random, public_key, named_curve);
    let signature = match &private_key.kind {
        CryptoPrivateKeyKind::Ed25519(kp) => kp.sign(&msg).as_ref().to_vec(),
        CryptoPrivateKeyKind::Ecdsa256(kp) => {
            let system_random = SystemRandom::new();
            kp.sign(&system_random, &msg)
                .map_err(|e| Error::Other(e.to_string()))?
                .as_ref()
                .to_vec()
        }
    };

    Ok(signature)
}
