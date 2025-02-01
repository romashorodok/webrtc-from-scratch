use super::*;

use crate::crypto::crypto_gcm::*;

use crate::prf::*;

#[derive(Clone)]
pub struct CipherSuiteAes128GcmSha256 {
    gcm: Option<CryptoGcm>,
}

impl CipherSuiteAes128GcmSha256 {
    const PRF_MAC_LEN: usize = 0;
    const PRF_KEY_LEN: usize = 16;
    const PRF_IV_LEN: usize = 4;

    pub fn new() -> Self {
        CipherSuiteAes128GcmSha256 { gcm: None }
    }
}

impl CipherSuite for CipherSuiteAes128GcmSha256 {
    fn is_initialized(&self) -> bool {
        self.gcm.is_some()
    }

    fn init(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()> {
        let keys = prf_encryption_keys(
            master_secret,
            client_random,
            server_random,
            CipherSuiteAes128GcmSha256::PRF_MAC_LEN,
            CipherSuiteAes128GcmSha256::PRF_KEY_LEN,
            CipherSuiteAes128GcmSha256::PRF_IV_LEN,
            CipherSuiteHash::Sha256,
        )?;

        if is_client {
            self.gcm = Some(CryptoGcm::new(
                &keys.client_write_key,
                &keys.client_write_iv,
                &keys.server_write_key,
                &keys.server_write_iv,
            ));
        } else {
            self.gcm = Some(CryptoGcm::new(
                &keys.server_write_key,
                &keys.server_write_iv,
                &keys.client_write_key,
                &keys.client_write_iv,
            ));
        }

        Ok(())
    }

    fn encrypt(&self, record_layer_header_aead: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
        if let Some(cg) = &self.gcm {
            cg.encrypt(record_layer_header_aead, raw)
        } else {
            Err(Error::Other(
                "CipherSuite has not been initialized, unable to encrypt".to_owned(),
            ))
        }
    }

    fn decrypt(&self, record_layer_header_aead: &[u8], input: &[u8]) -> Result<Vec<u8>> {
        if let Some(cg) = &self.gcm {
            cg.decrypt(record_layer_header_aead, input)
        } else {
            Err(Error::Other(
                "CipherSuite has not been initialized, unable to decrypt".to_owned(),
            ))
        }
    }
}
