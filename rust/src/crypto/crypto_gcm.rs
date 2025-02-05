// AES-GCM (Galois Counter Mode)
// The most widely used block cipher worldwide.
// Mandatory as of TLS 1.2 (2008) and used by default by most clients.
// RFC 5288 year 2008 https://tools.ietf.org/html/rfc5288

// https://github.com/RustCrypto/AEADs
// https://docs.rs/aes-gcm/0.8.0/aes_gcm/

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use rand::Rng;
use std::io::{Cursor, Read, Write};

use crate::error::*;

const CRYPTO_GCM_TAG_LENGTH: usize = 16;
const CRYPTO_GCM_NONCE_LENGTH: usize = 12;
const RECORD_LAYER_HEADER_SIZE: usize = 13;

// State needed to handle encrypted input/output
#[derive(Clone)]
pub struct CryptoGcm {
    local_gcm: Aes128Gcm,
    remote_gcm: Aes128Gcm,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

pub const MAX_SEQUENCE_NUMBER: u64 = 0x0000FFFFFFFFFFFF;

pub const DTLS1_2MAJOR: u8 = 0xfe;
pub const DTLS1_2MINOR: u8 = 0xfd;

pub const DTLS1_0MAJOR: u8 = 0xfe;
pub const DTLS1_0MINOR: u8 = 0xff;

// VERSION_DTLS12 is the DTLS version in the same style as
// VersionTLSXX from crypto/tls
pub const VERSION_DTLS12: u16 = 0xfefd;

pub const PROTOCOL_VERSION1_0: ProtocolVersion = ProtocolVersion {
    major: DTLS1_0MAJOR,
    minor: DTLS1_0MINOR,
};
pub const PROTOCOL_VERSION1_2: ProtocolVersion = ProtocolVersion {
    major: DTLS1_2MAJOR,
    minor: DTLS1_2MINOR,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

/// ## Specifications
///
/// * [RFC 4346 §6.2.1]
///
/// [RFC 4346 §6.2.1]: https://tools.ietf.org/html/rfc4346#section-6.2.1
#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    #[default]
    Invalid,
}

impl From<u8> for ContentType {
    fn from(val: u8) -> Self {
        match val {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct RecordLayerHeader {
    pub content_type: ContentType,
    pub protocol_version: ProtocolVersion,
    pub epoch: u16,
    pub sequence_number: u64, // uint48 in spec
    pub content_len: u16,
}

impl RecordLayerHeader {
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let content_type = reader.read_u8()?.into();
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let epoch = reader.read_u16::<BigEndian>()?;

        // SequenceNumber is stored as uint48, make into uint64
        let mut be: [u8; 8] = [0u8; 8];
        reader.read_exact(&mut be[2..])?;
        let sequence_number = u64::from_be_bytes(be);

        let protocol_version = ProtocolVersion { major, minor };
        if protocol_version != PROTOCOL_VERSION1_0 && protocol_version != PROTOCOL_VERSION1_2 {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }
        let content_len = reader.read_u16::<BigEndian>()?;

        Ok(RecordLayerHeader {
            content_type,
            protocol_version,
            epoch,
            sequence_number,
            content_len,
        })
    }
}

pub(crate) fn generate_aead_additional_data(h: &RecordLayerHeader, payload_len: usize) -> Vec<u8> {
    let mut additional_data = vec![0u8; 13];
    // SequenceNumber MUST be set first
    // we only want uint48, clobbering an extra 2 (using uint64, rust doesn't have uint48)
    additional_data[..8].copy_from_slice(&h.sequence_number.to_be_bytes());
    additional_data[..2].copy_from_slice(&h.epoch.to_be_bytes());
    additional_data[8] = h.content_type as u8;
    additional_data[9] = h.protocol_version.major;
    additional_data[10] = h.protocol_version.minor;
    additional_data[11..].copy_from_slice(&(payload_len as u16).to_be_bytes());

    additional_data
}

impl CryptoGcm {
    pub fn new(
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let key = GenericArray::from_slice(local_key);
        let local_gcm = Aes128Gcm::new(key);

        let key = GenericArray::from_slice(remote_key);
        let remote_gcm = Aes128Gcm::new(key);

        CryptoGcm {
            local_gcm,
            local_write_iv: local_write_iv.to_vec(),
            remote_gcm,
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[RECORD_LAYER_HEADER_SIZE..];
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        let mut nonce = vec![0u8; CRYPTO_GCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.local_write_iv[..4]);
        rand::thread_rng().fill(&mut nonce[4..]);
        let nonce = GenericArray::from_slice(&nonce);

        let header = &raw[..RECORD_LAYER_HEADER_SIZE];
        let mut reader = Cursor::new(header);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        let additional_data = generate_aead_additional_data(&h, payload.len());

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(payload);

        self.local_gcm
            .encrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut r = Vec::with_capacity(raw.len() + nonce.len() + buffer.len());
        r.extend_from_slice(raw);
        r.extend_from_slice(&nonce[4..]);
        r.extend_from_slice(&buffer);

        // Update recordLayer size to include explicit nonce
        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        if r.len() <= (RECORD_LAYER_HEADER_SIZE + 8) {
            return Err(Error::ErrNotEnoughRoomForNonce);
        }

        let mut nonce = vec![];
        nonce.extend_from_slice(&self.remote_write_iv[..4]);
        nonce.extend_from_slice(&r[RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + 8]);
        let nonce = GenericArray::from_slice(&nonce);

        let out = &r[RECORD_LAYER_HEADER_SIZE + 8..];

        let additional_data = generate_aead_additional_data(&h, out.len() - CRYPTO_GCM_TAG_LENGTH);

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(out);

        self.remote_gcm
            .decrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + buffer.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}
