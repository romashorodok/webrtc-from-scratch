use std::sync::Arc;
use std::vec;

use pyo3::prelude::*;

use tokio::runtime::{Builder, Runtime};
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

#[pymodule]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Certificate>()?;
    m.add_class::<DTLS>()?;
    Ok(())
}
