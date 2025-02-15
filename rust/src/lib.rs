use std::sync::Arc;
use std::vec;

use pyo3::types::PyBytes;
use pyo3::{prelude::*, types::PyString};

use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, Mutex};
use webrtc_dtls::conn;

#[pyclass]
struct DTLS {
    runtime: Runtime,
    dtls: Arc<Mutex<webrtc_dtls::conn::DTLSConn>>,

    inbound_tx: Arc<Mutex<mpsc::Sender<Vec<u8>>>>,
    outbound_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

#[pymethods]
impl DTLS {
    #[new]
    fn new(client: bool, threads: Option<usize>) -> PyResult<Self> {
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
            let cert =
                webrtc_dtls::crypto::Certificate::generate_self_signed(vec!["webrtc".to_owned()])
                    .unwrap();

            let config = webrtc_dtls::config::Config {
                certificates: vec![cert],
                insecure_skip_verify: true,
                extended_master_secret: webrtc_dtls::config::ExtendedMasterSecretType::Disable,
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

        Ok(DTLS {
            runtime,
            inbound_tx: Arc::new(Mutex::new(inbound_tx)),
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            dtls: Arc::new(Mutex::new(dtls.unwrap())),
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
            if let Err(result) = tx.lock().await.send(record).await {
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
    m.add_class::<DTLS>()?;
    Ok(())
}
