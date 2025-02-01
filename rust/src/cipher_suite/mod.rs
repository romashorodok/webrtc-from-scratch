pub mod cipher_suite_aes_128_gcm_sha256;

use std::fmt;

use super::error::*;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CipherSuiteId {
    // AES-128-CCM
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm = 0xc0ac,
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 = 0xc0ae,

    // AES-128-GCM-SHA256
    Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 = 0xc02b,
    Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 = 0xc02f,

    // AES-256-CBC-SHA
    Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha = 0xc00a,
    Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha = 0xc014,

    Tls_Psk_With_Aes_128_Ccm = 0xc0a4,
    Tls_Psk_With_Aes_128_Ccm_8 = 0xc0a8,
    Tls_Psk_With_Aes_128_Gcm_Sha256 = 0x00a8,

    Unsupported,
}

impl fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm => write!(f, "TLS_PSK_WITH_AES_128_CCM"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8 => write!(f, "TLS_PSK_WITH_AES_128_CCM_8"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_PSK_WITH_AES_128_GCM_SHA256")
            }
            _ => write!(f, "Unsupported CipherSuiteID"),
        }
    }
}

impl From<u16> for CipherSuiteId {
    fn from(val: u16) -> Self {
        match val {
            // AES-128-CCM
            0xc0ac => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            0xc0ae => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,

            // AES-128-GCM-SHA256
            0xc02b => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            0xc02f => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,

            // AES-256-CBC-SHA
            0xc00a => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            0xc014 => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,

            0xc0a4 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            0xc0a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            0x00a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,

            _ => CipherSuiteId::Unsupported,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CipherSuiteHash {
    Sha256,
}

impl CipherSuiteHash {
    pub(crate) fn size(&self) -> usize {
        match *self {
            CipherSuiteHash::Sha256 => 32,
        }
    }
}

pub trait CipherSuite {
    fn is_initialized(&self) -> bool;

    // Generate the internal encryption state
    fn init(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()>;

    fn encrypt(&self, record_layer_header_aead: &[u8], raw: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, record_layer_header_aead: &[u8], input: &[u8]) -> Result<Vec<u8>>;
}
