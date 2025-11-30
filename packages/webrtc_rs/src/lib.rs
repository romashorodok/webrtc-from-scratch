use std::sync::Arc;
use std::vec;

use bytes::{Bytes, BytesMut};
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};

use tokio::runtime::{Builder, Runtime};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use webrtc_dtls::{crypto, extension};
use webrtc_rtp::packetizer::Payloader;
use webrtc_util::marshal::Marshal;
use webrtc_rtp::codecs::av1;

// ECDH curves for key exchange (re-exported from webrtc_dtls)
use webrtc_dtls::p256::ecdh::EphemeralSecret as P256Secret;
use webrtc_dtls::p256::PublicKey as P256PublicKey;
use webrtc_dtls::p256::EncodedPoint as P256EncodedPoint;
use webrtc_dtls::p256::elliptic_curve::sec1::FromEncodedPoint;
use webrtc_dtls::x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519PublicKey};

// AES-GCM from existing dtls crate
use webrtc_dtls::crypto::crypto_gcm::CryptoGcm;
use webrtc_dtls::record_layer::record_layer_header::RecordLayerHeader;
use webrtc_dtls::content::ContentType;
use webrtc_dtls::record_layer::record_layer_header::ProtocolVersion;

// Random bytes (re-exported from webrtc_dtls)
use webrtc_dtls::rand_core::{OsRng, RngCore};

/// Internal enum for storing different curve private keys
enum ECDHPrivateKey {
    P256(P256Secret),
    X25519(X25519Secret),
}

/// ECDH key pair for DTLS key exchange
/// Supports P-256 (secp256r1) and X25519 curves
#[pyclass]
struct ECDHKeyPair {
    curve: String,
    public_key: Vec<u8>,
    private_key: ECDHPrivateKey,
}

#[pymethods]
impl ECDHKeyPair {
    /// Create a new ECDH key pair for the specified curve
    ///
    /// Args:
    ///     curve: "P-256" or "X25519"
    #[new]
    fn new(curve: &str) -> PyResult<Self> {
        match curve {
            "P-256" | "P256" | "secp256r1" => {
                let secret = P256Secret::random(&mut OsRng);
                let public_key = P256EncodedPoint::from(secret.public_key());
                Ok(Self {
                    curve: "P-256".to_string(),
                    public_key: public_key.as_bytes().to_vec(),
                    private_key: ECDHPrivateKey::P256(secret),
                })
            }
            "X25519" | "x25519" => {
                let secret = X25519Secret::random_from_rng(OsRng);
                let public_key = X25519PublicKey::from(&secret);
                Ok(Self {
                    curve: "X25519".to_string(),
                    public_key: public_key.as_bytes().to_vec(),
                    private_key: ECDHPrivateKey::X25519(secret),
                })
            }
            _ => Err(PyValueError::new_err(format!(
                "Unsupported curve: {}. Use 'P-256' or 'X25519'",
                curve
            ))),
        }
    }

    /// Get the public key bytes
    ///
    /// For P-256: Returns uncompressed point (65 bytes, starts with 0x04)
    /// For X25519: Returns 32 bytes
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Get the curve name
    fn curve_name(&self) -> String {
        self.curve.clone()
    }

    /// Compute the shared secret using peer's public key
    ///
    /// Args:
    ///     peer_public: Peer's public key bytes
    ///
    /// Returns:
    ///     32-byte shared secret (pre-master secret for DTLS)
    fn compute_shared_secret(&self, peer_public: Vec<u8>) -> PyResult<Vec<u8>> {
        match &self.private_key {
            ECDHPrivateKey::P256(secret) => {
                // P-256 expects uncompressed point format (65 bytes starting with 0x04)
                let peer_point = P256EncodedPoint::from_bytes(&peer_public)
                    .map_err(|e| PyValueError::new_err(format!("Invalid P-256 public key: {:?}", e)))?;

                let peer_pk = P256PublicKey::from_encoded_point(&peer_point);
                if peer_pk.is_none().into() {
                    return Err(PyValueError::new_err("Invalid P-256 public key point"));
                }
                let peer_pk = peer_pk.unwrap();

                let shared = secret.diffie_hellman(&peer_pk);
                Ok(shared.raw_secret_bytes().to_vec())
            }
            ECDHPrivateKey::X25519(secret) => {
                // X25519 expects 32 bytes
                if peer_public.len() != 32 {
                    return Err(PyValueError::new_err(format!(
                        "X25519 public key must be 32 bytes, got {}",
                        peer_public.len()
                    )));
                }
                let mut peer_bytes = [0u8; 32];
                peer_bytes.copy_from_slice(&peer_public);
                let peer_pk = X25519PublicKey::from(peer_bytes);

                let shared = secret.diffie_hellman(&peer_pk);
                Ok(shared.as_bytes().to_vec())
            }
        }
    }
}

/// AES-128-GCM cipher for DTLS record encryption/decryption
///
/// Wraps the existing CryptoGcm implementation from webrtc_dtls.
/// Handles both local (encrypt) and remote (decrypt) keys.
///
/// DTLS 1.2 uses AES-GCM with:
/// - 16-byte key
/// - 4-byte implicit IV (from key derivation)
/// - 8-byte explicit nonce (from record sequence number)
/// - 12-byte total nonce = implicit_iv || explicit_nonce
/// - 16-byte authentication tag
#[pyclass]
struct AesGcmCipher {
    gcm: CryptoGcm,
    is_client: bool,
}

#[pymethods]
impl AesGcmCipher {
    /// Create a new AES-128-GCM cipher from derived keys
    ///
    /// Args:
    ///     client_write_key: 16-byte client write key
    ///     client_write_iv: 4-byte client write IV
    ///     server_write_key: 16-byte server write key
    ///     server_write_iv: 4-byte server write IV
    ///     is_client: True if this is the client side
    #[new]
    fn new(
        client_write_key: Vec<u8>,
        client_write_iv: Vec<u8>,
        server_write_key: Vec<u8>,
        server_write_iv: Vec<u8>,
        is_client: bool,
    ) -> PyResult<Self> {
        if client_write_key.len() != 16 {
            return Err(PyValueError::new_err(format!(
                "client_write_key must be 16 bytes, got {}",
                client_write_key.len()
            )));
        }
        if server_write_key.len() != 16 {
            return Err(PyValueError::new_err(format!(
                "server_write_key must be 16 bytes, got {}",
                server_write_key.len()
            )));
        }
        if client_write_iv.len() != 4 {
            return Err(PyValueError::new_err(format!(
                "client_write_iv must be 4 bytes, got {}",
                client_write_iv.len()
            )));
        }
        if server_write_iv.len() != 4 {
            return Err(PyValueError::new_err(format!(
                "server_write_iv must be 4 bytes, got {}",
                server_write_iv.len()
            )));
        }

        // CryptoGcm expects: local_key, local_iv, remote_key, remote_iv
        // For client: local=client, remote=server
        // For server: local=server, remote=client
        let gcm = if is_client {
            CryptoGcm::new(
                &client_write_key,
                &client_write_iv,
                &server_write_key,
                &server_write_iv,
            )
        } else {
            CryptoGcm::new(
                &server_write_key,
                &server_write_iv,
                &client_write_key,
                &client_write_iv,
            )
        };

        Ok(Self { gcm, is_client })
    }

    /// Encrypt a DTLS record
    ///
    /// Args:
    ///     content_type: DTLS content type (22=handshake, 23=application_data, 21=alert)
    ///     epoch: DTLS epoch number
    ///     sequence_number: Record sequence number within epoch
    ///     payload: Plaintext payload to encrypt
    ///
    /// Returns:
    ///     Complete encrypted DTLS record (header + explicit_nonce + ciphertext + tag)
    fn encrypt(
        &self,
        content_type: u8,
        epoch: u16,
        sequence_number: u64,
        payload: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        // Build record layer header
        let rlh = RecordLayerHeader {
            content_type: ContentType::from(content_type),
            protocol_version: ProtocolVersion { major: 0xFE, minor: 0xFD }, // DTLS 1.2
            epoch,
            sequence_number,
            content_len: payload.len() as u16,
        };

        // Build raw record (header + payload)
        let mut raw = Vec::with_capacity(13 + payload.len());
        // Record layer header: type(1) + version(2) + epoch(2) + seq(6) + len(2)
        raw.push(content_type);
        raw.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2
        raw.extend_from_slice(&epoch.to_be_bytes());
        raw.extend_from_slice(&sequence_number.to_be_bytes()[2..]); // Only 6 bytes
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(&payload);

        self.gcm
            .encrypt(&rlh, &raw)
            .map_err(|e| PyValueError::new_err(format!("Encryption failed: {:?}", e)))
    }

    /// Decrypt a DTLS record
    ///
    /// Args:
    ///     record: Complete encrypted DTLS record bytes
    ///
    /// Returns:
    ///     Decrypted record (header + plaintext payload)
    fn decrypt(&self, record: Vec<u8>) -> PyResult<Vec<u8>> {
        self.gcm
            .decrypt(&record)
            .map_err(|e| PyValueError::new_err(format!("Decryption failed: {:?}", e)))
    }

    /// Check if this cipher is for client-side encryption
    fn is_client(&self) -> bool {
        self.is_client
    }
}

#[pyclass]
struct  Av1Payloader {
    payloader: av1::Av1Payloader
}

fn convert_vec_bytes(input: Vec<Bytes>) -> Vec<Vec<u8>> {
    input.into_iter().map(|b| b.to_vec()).collect()
}

#[pymethods]
impl Av1Payloader {
    #[new]
    fn new() -> Self {
        Self {
            payloader: av1::Av1Payloader {}
        }
    }

    fn packetize(&mut self, mtu: usize, frame: Vec<u8>)  -> Vec<Vec<u8>> {
        let f = Bytes::from(frame);
        let result = self.payloader.payload(mtu, &f).unwrap();
        convert_vec_bytes(result)
    }
}

#[pyclass]
struct Certificate {
    cert: crypto::Certificate,
    /// ECDH keypair for key exchange (separate from signing keypair)
    ecdh_keypair: ECDHKeyPair,
}

#[pymethods]
impl Certificate {
    #[new]
    fn new() -> PyResult<Self> {
        let cert =
            webrtc_dtls::crypto::Certificate::generate_self_signed(vec!["webrtc".to_owned()])
                .map_err(|e| PyValueError::new_err(format!("Failed to generate certificate: {}", e)))?;
        // Generate ECDH keypair for key exchange (P-256 to match certificate)
        let ecdh_keypair = ECDHKeyPair::new("P-256")?;
        Ok(Self { cert, ecdh_keypair })
    }

    fn certificate_fingerprint(&self) -> String {
        self.cert.certificate_fingerprint()
    }

    /// Get certificate DER bytes
    fn certificate_der(&self) -> Vec<u8> {
        self.cert.certificate.first()
            .map(|c| c.as_ref().to_vec())
            .unwrap_or_default()
    }

    /// Get public key DER bytes (for key exchange, from ECDH keypair)
    fn pubkey_der(&self) -> Vec<u8> {
        self.ecdh_keypair.public_key.clone()
    }

    /// Get the curve ID for this certificate's keypair
    /// Returns P-256 (0x0017 = 23) since we use ECDSA P-256
    fn curve_id(&self) -> u16 {
        0x0017 // P-256/secp256r1
    }

    /// Generate server signature for ServerKeyExchange
    /// Signs: client_random || server_random || ecdh_params || public_key
    fn generate_server_signature(&self, client_random: Vec<u8>, server_random: Vec<u8>) -> PyResult<Vec<u8>> {
        use webrtc_dtls::curve::named_curve::NamedCurve;

        // Get the public key for key exchange (from ECDH keypair)
        let public_key = &self.ecdh_keypair.public_key;
        let named_curve = NamedCurve::P256;

        // Use the certificate's private key to sign
        crypto::generate_key_signature(
            &client_random,
            &server_random,
            public_key,
            named_curve,
            &self.cert.private_key,
        ).map_err(|e| PyValueError::new_err(format!("Failed to generate signature: {}", e)))
    }

    /// Compute ECDH shared secret with peer's public key
    fn compute_shared_secret(&self, peer_public: Vec<u8>) -> PyResult<Vec<u8>> {
        self.ecdh_keypair.compute_shared_secret(peer_public)
    }

    /// Sign arbitrary data with the certificate's private key
    fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        crypto::generate_certificate_verify(&data, &self.cert.private_key)
            .map_err(|e| PyValueError::new_err(format!("Failed to sign: {}", e)))
    }
}

#[pyclass]
struct DTLS {
    runtime: Runtime,
    dtls: Arc<Mutex<webrtc_dtls::conn::DTLSConn>>,

    inbound_tx: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
    outbound_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

#[pymethods]
impl DTLS {
    #[pyo3(signature = (client, certificate, threads=None))]
    #[new]
    fn new(
        client: bool,
        certificate: PyRef<Certificate>,
        threads: Option<usize>,
    ) -> PyResult<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(threads.unwrap_or(4))
            .enable_all()
            .build()
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to create tokio runtime: {}",
                    e
                ))
            })?;

        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1);

        let inbound_rx = Arc::new(Mutex::new(inbound_rx));
        let outbound_tx = Arc::new(outbound_tx);

        let (dtls, error) = runtime.block_on(async move {
            let cert = certificate.cert.clone();

            let config = webrtc_dtls::config::Config {
                certificates: vec![cert],
                insecure_skip_verify: true,
                extended_master_secret: webrtc_dtls::config::ExtendedMasterSecretType::Disable,
                srtp_protection_profiles: vec![extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80, extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm],
                mtu: 1280,
                ..webrtc_dtls::config::Config::default()
            };

            match webrtc_dtls::conn::DTLSConn::new(inbound_rx, outbound_tx, config, client, None) {
                Ok(conn) => (Some(conn), None),
                Err(e) => (None, Some(e)),
            }
        });

        if let Some(error) = error {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to initialize DTLS: {}",
                error
            )));
        }
        let dtls = dtls.unwrap();

        Ok(DTLS {
            runtime,
            inbound_tx: Arc::new(Mutex::new(inbound_tx)),
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            dtls: Arc::new(Mutex::new(dtls)),
        })
    }

    fn do_handshake(&mut self) -> PyResult<()> {
        let dtls = self.dtls.clone();
        self.runtime.spawn(async move {
            println!("Handshake acquire lock");
            let mut dtls = dtls.lock().await;
            let _ = dtls.do_handshake().await;
            println!("Handshake Completed");
        });
        Ok(())
    }

    fn handshake_success<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let dtls = self.dtls.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut dtls = dtls.lock().await;

            'l: loop {
                select! {
                    _ = dtls.handshake_completed_successfully_watch_rx.changed() => {
                        break 'l;
                    }
                }
            }

            Ok(())
        })
    }

    fn dequeue_record<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let rx = self.outbound_rx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut rx1 = rx.lock().await;
            println!("Dequeue start lock");
            Ok(rx1.recv().await)
        })
    }

    fn enqueue_record<'a>(&self, py: Python<'a>, record: Vec<u8>) -> PyResult<Bound<'a, PyAny>> {
        let tx = self.inbound_tx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Err(_) = tx.lock().await.send(record).await {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to enqueue dtls record",
                )));
            }
            Ok(())
        })
    }
}

const DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW: usize = 64;
const DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW: usize = 64;


#[pyclass]
struct Stream {
    stream: Arc<Mutex<Arc<webrtc_srtp::stream::Stream>>>,
}

#[pymethods]
impl Stream {
    fn recv<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let stream = self.stream.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let stream = stream.lock().await.clone();
            let mut buf = vec![0u8; 1300];
            let pkt = stream.read_rtp(&mut buf).await.unwrap();
            let data = pkt.marshal().unwrap().to_vec();
            Ok(data)
        })
    }

     fn recv_rtcp<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
            let stream = self.stream.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let stream = stream.lock().await.clone();
                let mut buf = vec![0u8; 1300];
                let pkt = stream.read_rtcp(&mut buf).await.unwrap();

                Ok(pkt.to_vec())
            })
        }
 }

#[pyclass]
struct SRTP {
    session: Arc<Mutex<webrtc_srtp::session::Session>>,
    is_rtp: bool,

    tx: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>
}

#[pymethods]
impl SRTP {
    #[new]
    fn new(is_rtp: bool, client: bool, dtls: PyRef<DTLS>) -> PyResult<Self> {
        let dtls_runtime = &dtls.runtime;
        let dtls = dtls.dtls.clone();

        let srtp = dtls_runtime.block_on(async move {
            let dtls = dtls.lock().await;
            let srtp_profile = dtls.selected_srtpprotection_profile();


            let srtp_protection_profile = match srtp_profile {
                    webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => {
                        webrtc_srtp::protection_profile::ProtectionProfile::AeadAes128Gcm
                    }
                    webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => {
                        webrtc_srtp::protection_profile::ProtectionProfile::AeadAes256Gcm
                    }
                    webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
                        webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80
                    }
                    webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => {
                        webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_32
                    }
                    _ => {
                        return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "Failed to enqueue dtls record",
                        )));
                    }
                };


            let profile = { srtp_protection_profile };

            let mut srtp_config = webrtc_srtp::config::Config { profile, ..Default::default() };
            srtp_config.remote_rtp_options = Some(webrtc_srtp::option::srtp_replay_protection(DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW));
            srtp_config.remote_rtcp_options = Some(webrtc_srtp::option::srtcp_replay_protection(DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW));


            let result = srtp_config.extract_session_keys_from_dtls(dtls.connection_state().await, client).await;
            if let Err(err) = result {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to extract_session_keys_from_dtls {:?}", err
                )));
            }


            let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1);
            let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1);

            let inbound_rx = Arc::new(Mutex::new(inbound_rx));
            let outbound_tx = Arc::new(outbound_tx); 

            let session = webrtc_srtp::session::Session::new(inbound_rx, outbound_tx, srtp_config, is_rtp).await;
            if let Err(err) = session {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to start srtp session {:?}", err
                )));
            }

            let session = session.unwrap();

            Ok(SRTP{
                session: Arc::new(Mutex::new(session)),
                tx: Arc::new(Mutex::new(inbound_tx)),
                rx: Arc::new(Mutex::new(outbound_rx)),
                is_rtp
            })
        });

        if let Err(err) = srtp {
            return Err(err);
        }

        let srtp = srtp.unwrap();
        println!("Sesssion SRTP successfully created");

        Ok(srtp)
    }

    /// Create SRTP session from raw keying material (Python DTLS handshake)
    ///
    /// Args:
    ///     is_rtp: True for RTP, False for RTCP
    ///     tx_key: Local master key + salt (30 bytes for AES-128-CM-HMAC-SHA1-80)
    ///     rx_key: Remote master key + salt (30 bytes for AES-128-CM-HMAC-SHA1-80)
    #[staticmethod]
    fn from_keying_material(is_rtp: bool, tx_key: Vec<u8>, rx_key: Vec<u8>) -> PyResult<Self> {
        // SRTP_AES128_CM_HMAC_SHA1_80: 16 byte key + 14 byte salt = 30 bytes
        const KEY_LEN: usize = 16;
        const SALT_LEN: usize = 14;

        if tx_key.len() != KEY_LEN + SALT_LEN {
            return Err(PyValueError::new_err(format!(
                "tx_key must be {} bytes (key + salt), got {}", KEY_LEN + SALT_LEN, tx_key.len()
            )));
        }
        if rx_key.len() != KEY_LEN + SALT_LEN {
            return Err(PyValueError::new_err(format!(
                "rx_key must be {} bytes (key + salt), got {}", KEY_LEN + SALT_LEN, rx_key.len()
            )));
        }

        // Split keys and salts
        let local_master_key = tx_key[..KEY_LEN].to_vec();
        let local_master_salt = tx_key[KEY_LEN..].to_vec();
        let remote_master_key = rx_key[..KEY_LEN].to_vec();
        let remote_master_salt = rx_key[KEY_LEN..].to_vec();

        // Use SRTP_AES128_CM_HMAC_SHA1_80 (most common profile for WebRTC)
        let profile = webrtc_srtp::protection_profile::ProtectionProfile::Aes128CmHmacSha1_80;

        let keys = webrtc_srtp::config::SessionKeys {
            local_master_key,
            local_master_salt,
            remote_master_key,
            remote_master_salt,
        };

        let mut srtp_config = webrtc_srtp::config::Config {
            keys,
            profile,
            ..Default::default()
        };
        srtp_config.remote_rtp_options = Some(webrtc_srtp::option::srtp_replay_protection(DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW));
        srtp_config.remote_rtcp_options = Some(webrtc_srtp::option::srtcp_replay_protection(DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW));

        // Create channels for packet I/O
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1);

        let inbound_rx = Arc::new(Mutex::new(inbound_rx));
        let outbound_tx = Arc::new(outbound_tx);

        // Create SRTP session using the pyo3_async_runtimes global tokio runtime
        // This ensures the session runs on the same runtime used by encrypt_nonblock, etc.
        let rt = pyo3_async_runtimes::tokio::get_runtime();

        let session = rt.block_on(async {
            webrtc_srtp::session::Session::new(inbound_rx, outbound_tx, srtp_config, is_rtp).await
        }).map_err(|e| {
            PyRuntimeError::new_err(format!("Failed to create SRTP session: {:?}", e))
        })?;

        println!("SRTP session created from keying material (is_rtp={})", is_rtp);

        Ok(SRTP {
            session: Arc::new(Mutex::new(session)),
            tx: Arc::new(Mutex::new(inbound_tx)),
            rx: Arc::new(Mutex::new(outbound_rx)),
            is_rtp,
        })
    }

    fn encrypt_nonblock<'a>(&self, py: Python<'a>, pkt: Vec<u8>) -> PyResult<Bound<'a, PyAny>> {
        let session = self.session.clone();
        let is_rtp = self.is_rtp;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = session.lock().await;
            let pkt = session.encrypt_write(pkt, is_rtp).await.unwrap();
            Ok(pkt)
        })
    }

    fn encrypt<'a>(&self, py: Python<'a>, pkt: Vec<u8>) -> PyResult<Bound<'a, PyAny>> {
        let session = self.session.clone();
        let is_rtp = self.is_rtp;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = session.lock().await;
            let data = BytesMut::from(pkt.as_slice());
            let _ = session.write(&data.freeze(), is_rtp).await;
            Ok(())
        })
    }

    fn write_pkt<'a>(&self, py: Python<'a>, pkt: Vec<u8>) -> PyResult<Bound<'a, PyAny>> {
        let tx = self.tx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Err(err) = tx.lock().await.send(pkt).await {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Unable write the packet in srtp session {:?}", err
                )));
            }
            Ok(())
        })
    }

    fn read_pkt<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
        let rx = self.rx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut rx = rx.lock().await;
            Ok(rx.recv().await)
        })
    }

    fn ssrc_stream<'a>(&self, py: Python<'a>, ssrc: u32) -> PyResult<Bound<'a, PyAny>> {
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = session.lock().await;
            let stream = session.open(ssrc).await;
            Ok(Stream {
                stream: Arc::new(Mutex::new(stream)),
            })
        })
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Certificate>()?;
    m.add_class::<DTLS>()?;
    m.add_class::<SRTP>()?;
    m.add_class::<Stream>()?;
    m.add_class::<Av1Payloader>()?;
    m.add_class::<ECDHKeyPair>()?;
    m.add_class::<AesGcmCipher>()?;
    m.add_function(wrap_pyfunction!(generate_random_bytes, m)?)?;
    Ok(())
}

/// Generate cryptographically secure random bytes
///
/// Args:
///     length: Number of random bytes to generate
///
/// Returns:
///     Vec of random bytes
#[pyfunction]
fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
