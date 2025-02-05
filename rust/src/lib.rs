mod error;

mod cipher_suite;
mod crypto;
mod curve;
mod prf;

use cipher_suite::CipherSuite;
use curve::{NamedCurve, NamedCurveKeypair};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};

impl std::convert::From<error::Error> for PyErr {
    fn from(value: error::Error) -> Self {
        PyValueError::new_err(value.to_string())
    }
}

#[pyclass]
struct CipherSuiteAes128GcmSha256 {
    suite: cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256,
}

#[pymethods]
impl CipherSuiteAes128GcmSha256 {
    #[new]
    fn new() -> Result<Self, PyErr> {
        Ok(CipherSuiteAes128GcmSha256 {
            suite: cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256::new(),
        })
    }

    fn init(
        &mut self,
        prf_master_secret: &Bound<'_, PyBytes>,
        client_random: &Bound<'_, PyBytes>,
        server_random: &Bound<'_, PyBytes>,
        is_client: bool,
    ) -> Result<(), PyErr> {
        Ok(self.suite.init(
            prf_master_secret.as_bytes(),
            client_random.as_bytes(),
            server_random.as_bytes(),
            is_client,
        )?)
    }

    fn encrypt(&self, raw: &Bound<'_, PyBytes>) -> Result<Vec<u8>, PyErr> {
        Ok(self.suite.encrypt(raw.as_bytes())?)
    }

    fn decrypt(&self, ciphertext: &Bound<'_, PyBytes>) -> Result<Vec<u8>, PyErr> {
        Ok(self.suite.decrypt(ciphertext.as_bytes())?)
    }
}

#[pyclass]
struct Keypair {
    keypair: NamedCurveKeypair,
    certificate: crypto::Certificate,
}

#[pymethods]
impl Keypair {
    #[new]
    fn new(curve: u16) -> Result<Self, PyErr> {
        let named_curve = NamedCurve::from(curve);
        Ok(Self {
            keypair: named_curve.generate_keypair()?,
            certificate: crypto::Certificate::generate_self_signed(vec!["webrtc".to_owned()])?,
        })
    }

    fn pubkey_der(&self) -> Vec<u8> {
        self.keypair.public_key.to_vec()
    }

    fn curve_id(&self) -> u16 {
        self.keypair.curve.into()
    }

    fn certificate_der(&self) -> Result<Vec<u8>, PyErr> {
        let result = self
            .certificate
            .certificate
            .iter()
            .map(|x| x.as_ref().to_owned())
            .next();

        Ok(result.unwrap())
    }

    fn certificate_fingerprint(&self) -> Result<String, PyErr> {
        let certificate = self.certificate.certificate.iter().next().unwrap();
        let mut hash = Sha256::new();
        hash.update(certificate.as_ref());
        let hashed = hash.finalize();
        let values: Vec<String> = hashed.iter().map(|x| format! {"{x:02x}"}).collect();
        Ok(values.join(":"))
    }

    fn generate_server_signature(
        &self,
        client_random: &Bound<'_, PyBytes>,
        server_random: &Bound<'_, PyBytes>,
    ) -> Result<Vec<u8>, PyErr> {
        let client_random_bytes = client_random.as_bytes();
        let server_random_bytes = server_random.as_bytes();

        Ok(crypto::generate_key_signature(
            client_random_bytes,
            server_random_bytes,
            &self.keypair.public_key,
            self.keypair.curve,
            &self.certificate.private_key,
        )?)
    }
}

#[pyfunction]
fn generate_aead_additional_data(
    sequence_number: &Bound<'_, PyBytes>,
    epoch: &Bound<'_, PyBytes>,
    content_type: u8,
    protocol_version_major: u8,
    protocol_version_minor: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut additional_data = vec![0u8; 13];

    additional_data[..8].copy_from_slice(sequence_number.as_bytes());
    additional_data[..2].copy_from_slice(epoch.as_bytes());
    additional_data[8] = content_type as u8;
    additional_data[9] = protocol_version_major;
    additional_data[10] = protocol_version_minor;
    additional_data[11..].copy_from_slice(&(payload_len as u16).to_be_bytes());

    additional_data
}

#[pyfunction]
fn prf_pre_master_secret(
    client_public_key: &Bound<'_, PyBytes>,
    keypair: &Bound<'_, Keypair>,
) -> Result<Vec<u8>, PyErr> {
    let keypair_ref = keypair.borrow();
    Ok(prf::prf_pre_master_secret(
        client_public_key.as_bytes(),
        &keypair_ref.keypair.private_key,
        keypair_ref.keypair.curve,
    )?)
}

#[pyfunction]
fn prf_master_secret(
    pre_master_secret: &Bound<'_, PyBytes>,
    client_random: &Bound<'_, PyBytes>,
    server_random: &Bound<'_, PyBytes>,
) -> Result<Vec<u8>, PyErr> {
    Ok(prf::prf_master_secret(
        pre_master_secret.as_bytes(),
        client_random.as_bytes(),
        server_random.as_bytes(),
        cipher_suite::CipherSuiteHash::Sha256,
    )?)
}

#[pyfunction]
fn prf_verify_data_server(
    prf_master_secret: &Bound<'_, PyBytes>,
    handshake_bodies: &Bound<'_, PyBytes>,
) -> Result<Vec<u8>, PyErr> {
    Ok(prf::prf_verify_data_server(
        prf_master_secret.as_bytes(),
        handshake_bodies.as_bytes(),
        cipher_suite::CipherSuiteHash::Sha256,
    )?)
}

#[pymodule]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Keypair>()?;
    m.add_class::<CipherSuiteAes128GcmSha256>()?;

    m.add_function(wrap_pyfunction!(generate_aead_additional_data, m)?)?;
    m.add_function(wrap_pyfunction!(prf_pre_master_secret, m)?)?;
    m.add_function(wrap_pyfunction!(prf_master_secret, m)?)?;
    m.add_function(wrap_pyfunction!(prf_verify_data_server, m)?)?;
    Ok(())
}
