use std::sync::Arc;
use std::vec;

use pyo3::prelude::*;

use tokio::runtime::{Builder, Runtime};
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use webrtc_dtls::{crypto, extension};

#[pyclass]
struct Certificate {
    cert: crypto::Certificate,
}

#[pymethods]
impl Certificate {
    #[new]
    fn new() -> Self {
        let cert =
            webrtc_dtls::crypto::Certificate::generate_self_signed(vec!["webrtc".to_owned()])
                .unwrap();
        Self { cert }
    }

    fn certificate_fingerprint(&self) -> String {
        self.cert.certificate_fingerprint()
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

            loop {
                select! {
                    _ = dtls.handshake_completed_successfully_watch_rx.changed() => {
                        break;
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
struct SRTP {
    session: webrtc_srtp::session::Session,

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
                session,
                tx: Arc::new(Mutex::new(inbound_tx)),
                rx: Arc::new(Mutex::new(outbound_rx))
            })
        });

        if let Err(err) = srtp {
            return Err(err);
        }

        let srtp = srtp.unwrap();

        Ok(srtp)
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
            Ok(rx.lock().await.recv().await)
        })
    }
}

#[pymodule]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Certificate>()?;
    m.add_class::<DTLS>()?;
    m.add_class::<SRTP>()?;
    Ok(())
}
