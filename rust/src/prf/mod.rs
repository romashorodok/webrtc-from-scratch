#![allow(dead_code)]

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha2::*;

type HmacSha256 = Hmac<Sha256>;

use crate::cipher_suite::CipherSuiteHash;
use crate::curve::{NamedCurve, NamedCurvePrivateKey};
use crate::error::*;

pub(crate) const PRF_MASTER_SECRET_LABEL: &str = "master secret";
pub(crate) const PRF_EXTENDED_MASTER_SECRET_LABEL: &str = "extended master secret";
pub(crate) const PRF_KEY_EXPANSION_LABEL: &str = "key expansion";
pub(crate) const PRF_VERIFY_DATA_CLIENT_LABEL: &str = "client finished";
pub(crate) const PRF_VERIFY_DATA_SERVER_LABEL: &str = "server finished";

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct EncryptionKeys {
    pub(crate) master_secret: Vec<u8>,
    pub(crate) client_mac_key: Vec<u8>,
    pub(crate) server_mac_key: Vec<u8>,
    pub(crate) client_write_key: Vec<u8>,
    pub(crate) server_write_key: Vec<u8>,
    pub(crate) client_write_iv: Vec<u8>,
    pub(crate) server_write_iv: Vec<u8>,
}

impl fmt::Display for EncryptionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = "EncryptionKeys:\n".to_string();

        out += format!("- master_secret: {:?}\n", self.master_secret).as_str();
        out += format!("- client_mackey: {:?}\n", self.client_mac_key).as_str();
        out += format!("- server_mackey: {:?}\n", self.server_mac_key).as_str();
        out += format!("- client_write_key: {:?}\n", self.client_write_key).as_str();
        out += format!("- server_write_key: {:?}\n", self.server_write_key).as_str();
        out += format!("- client_write_iv: {:?}\n", self.client_write_iv).as_str();
        out += format!("- server_write_iv: {:?}\n", self.server_write_iv).as_str();

        write!(f, "{out}")
    }
}

fn elliptic_curve_pre_master_secret(
    public_key: &[u8],
    private_key: &NamedCurvePrivateKey,
    curve: NamedCurve,
) -> Result<Vec<u8>> {
    return match curve {
        NamedCurve::P256 => {
            let pub_key = p256::EncodedPoint::from_bytes(public_key)?;
            let public = p256::PublicKey::from_sec1_bytes(pub_key.as_ref())?;
            if let NamedCurvePrivateKey::EphemeralSecretP256(secret) = private_key {
                return Ok(secret.diffie_hellman(&public).raw_secret_bytes().to_vec());
            }

            Err(Error::ErrNamedCurveAndPrivateKeyMismatch)
        }
        NamedCurve::P384 => return Err(Error::ErrUnimplementedNamedCurve),
        NamedCurve::X25519 => return Err(Error::ErrUnimplementedNamedCurve),
        _ => return Err(Error::ErrInvalidNamedCurve),
    };
}

pub(crate) fn prf_pre_master_secret(
    public_key: &[u8],
    private_key: &NamedCurvePrivateKey,
    curve: NamedCurve,
) -> Result<Vec<u8>> {
    match curve {
        NamedCurve::P256 => elliptic_curve_pre_master_secret(public_key, private_key, curve),
        NamedCurve::P384 => elliptic_curve_pre_master_secret(public_key, private_key, curve),
        NamedCurve::X25519 => elliptic_curve_pre_master_secret(public_key, private_key, curve),
        _ => Err(Error::ErrInvalidNamedCurve),
    }
}

//  This PRF with the SHA-256 hash function is used for all cipher suites
//  defined in this document and in TLS documents published prior to this
//  document when TLS 1.2 is negotiated.  New cipher suites MUST explicitly
//  specify a PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
//  stronger standard hash function.
//
//     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                            HMAC_hash(secret, A(2) + seed) +
//                            HMAC_hash(secret, A(3) + seed) + ...
//
//  A() is defined as:
//
//     A(0) = seed
//     A(i) = HMAC_hash(secret, A(i-1))
//
//  P_hash can be iterated as many times as necessary to produce the
//  required quantity of data.  For example, if P_SHA256 is being used to
//  create 80 bytes of data, it will have to be iterated three times
//  (through A(3)), creating 96 bytes of output data; the last 16 bytes
//  of the final iteration will then be discarded, leaving 80 bytes of
//  output data.
//
// https://tools.ietf.org/html/rfc4346w
fn hmac_sha(h: CipherSuiteHash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = match h {
        CipherSuiteHash::Sha256 => {
            HmacSha256::new_from_slice(key).map_err(|e| Error::Other(e.to_string()))?
        }
    };
    mac.update(data);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(code_bytes.to_vec())
}

pub(crate) fn prf_p_hash(
    secret: &[u8],
    seed: &[u8],
    requested_length: usize,
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    let mut last_round = seed.to_vec();
    let mut out = vec![];

    let iterations = ((requested_length as f64) / (h.size() as f64)).ceil() as usize;
    for _ in 0..iterations {
        last_round = hmac_sha(h, secret, &last_round)?;

        let mut last_round_seed = last_round.clone();
        last_round_seed.extend_from_slice(seed);
        let with_secret = hmac_sha(h, secret, &last_round_seed)?;

        out.extend_from_slice(&with_secret);
    }

    Ok(out[..requested_length].to_vec())
}

pub(crate) fn prf_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    let mut seed = PRF_MASTER_SECRET_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_p_hash(pre_master_secret, &seed, 48, h)
}

pub(crate) fn prf_encryption_keys(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    prf_mac_len: usize,
    prf_key_len: usize,
    prf_iv_len: usize,
    h: CipherSuiteHash,
) -> Result<EncryptionKeys> {
    let mut seed = PRF_KEY_EXPANSION_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let material = prf_p_hash(
        master_secret,
        &seed,
        (2 * prf_mac_len) + (2 * prf_key_len) + (2 * prf_iv_len),
        h,
    )?;
    let mut key_material = &material[..];

    let client_mac_key = key_material[..prf_mac_len].to_vec();
    key_material = &key_material[prf_mac_len..];

    let server_mac_key = key_material[..prf_mac_len].to_vec();
    key_material = &key_material[prf_mac_len..];

    let client_write_key = key_material[..prf_key_len].to_vec();
    key_material = &key_material[prf_key_len..];

    let server_write_key = key_material[..prf_key_len].to_vec();
    key_material = &key_material[prf_key_len..];

    let client_write_iv = key_material[..prf_iv_len].to_vec();
    key_material = &key_material[prf_iv_len..];

    let server_write_iv = key_material[..prf_iv_len].to_vec();

    Ok(EncryptionKeys {
        master_secret: master_secret.to_vec(),
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}
pub(crate) fn prf_verify_data(
    master_secret: &[u8],
    handshake_bodies: &[u8],
    label: &str,
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    let mut hasher = match h {
        CipherSuiteHash::Sha256 => sha2::Sha256::new(),
    };

    hasher.update(handshake_bodies);
    let result = hasher.finalize();
    let mut seed = label.as_bytes().to_vec();
    seed.extend_from_slice(&result);

    prf_p_hash(master_secret, &seed, 12, h)
}

pub(crate) fn prf_verify_data_client(
    master_secret: &[u8],
    handshake_bodies: &[u8],
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    prf_verify_data(
        master_secret,
        handshake_bodies,
        PRF_VERIFY_DATA_CLIENT_LABEL,
        h,
    )
}

pub(crate) fn prf_verify_data_server(
    master_secret: &[u8],
    handshake_bodies: &[u8],
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    prf_verify_data(
        master_secret,
        handshake_bodies,
        PRF_VERIFY_DATA_SERVER_LABEL,
        h,
    )
}
