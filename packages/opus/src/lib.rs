//! Opus encoder/decoder Python bindings
//!
//! Exposes Opus codec to Python via PyO3.
//! Follows rav1e pattern with synchronous API (no unnecessary async).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod ffi;
mod encoder;
mod decoder;

use encoder::Encoder as RustEncoder;
use decoder::Decoder as RustDecoder;
use ffi::{Application, ErrorCode};

/// Convert Opus errors to Python exceptions
trait ToPyErr {
    fn to_py_err(self) -> PyErr;
}

impl ToPyErr for ErrorCode {
    fn to_py_err(self) -> PyErr {
        PyValueError::new_err(format!("Opus error: {}", self))
    }
}

impl<T> ToPyErr for Result<T, ErrorCode> {
    fn to_py_err(self) -> PyErr {
        match self {
            Ok(_) => PyValueError::new_err("Unexpected success in error context"),
            Err(e) => e.to_py_err(),
        }
    }
}

/// Opus encoder for Python
#[pyclass]
struct OpusEncoder {
    encoder: RustEncoder,
}

#[pymethods]
impl OpusEncoder {
    /// Create new Opus encoder
    ///
    /// Args:
    ///     sample_rate: Sample rate in Hz (typically 48000)
    ///     channels: Number of channels (1 = mono, 2 = stereo)
    ///     application: Application type ("voip", "audio", or "lowdelay")
    #[new]
    fn new(
        sample_rate: usize,
        channels: usize,
        application: &str,
    ) -> PyResult<Self> {
        let app = match application {
            "voip" => Application::Voip,
            "audio" => Application::Audio,
            "lowdelay" => Application::LowDelay,
            _ => {
                return Err(PyValueError::new_err(
                    "Invalid application: must be 'voip', 'audio', or 'lowdelay'",
                ))
            }
        };

        let encoder = RustEncoder::new(sample_rate, channels, app)
            .map_err(|e| e.to_py_err())?;

        Ok(OpusEncoder { encoder })
    }

    /// Encode audio frame
    ///
    /// Args:
    ///     pcm: Input PCM samples as bytes (i16 little-endian)
    ///
    /// Returns:
    ///     Encoded Opus frame as bytes
    ///
    /// Note:
    ///     Input must be exactly 960 samples per channel (20ms @ 48kHz)
    fn encode(&mut self, pcm: &[u8]) -> PyResult<Vec<u8>> {
        // Convert bytes to i16 samples
        if pcm.len() % 2 != 0 {
            return Err(PyValueError::new_err("PCM buffer length must be even"));
        }

        let samples: Vec<i16> = pcm
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        // Allocate output buffer (max Opus frame size is ~1275 bytes)
        let mut output = vec![0u8; 4000];

        let encoded_len = self
            .encoder
            .encode(&samples[..], &mut output)
            .map_err(|e| e.to_py_err())?;

        output.truncate(encoded_len);
        Ok(output)
    }

    /// Set encoder bitrate
    ///
    /// Args:
    ///     bitrate: Target bitrate in bits per second (e.g., 32000)
    fn set_bitrate(&mut self, bitrate: i32) -> PyResult<()> {
        self.encoder
            .set_bitrate(bitrate)
            .map_err(|e| e.to_py_err())
    }

    /// Set encoder complexity (0-10)
    ///
    /// Args:
    ///     complexity: Computational complexity (0=fastest, 10=best quality)
    fn set_complexity(&mut self, complexity: i32) -> PyResult<()> {
        self.encoder
            .set_complexity(complexity)
            .map_err(|e| e.to_py_err())
    }

    /// Enable/disable DTX (discontinuous transmission)
    ///
    /// Args:
    ///     enabled: True to enable DTX
    fn set_dtx(&mut self, enabled: bool) -> PyResult<()> {
        self.encoder.set_dtx(enabled).map_err(|e| e.to_py_err())
    }

    /// Reset encoder state
    fn reset(&mut self) -> PyResult<()> {
        self.encoder.reset().map_err(|e| e.to_py_err())
    }
}

/// Opus decoder for Python
#[pyclass]
struct OpusDecoder {
    decoder: RustDecoder,
    channels: usize,
}

#[pymethods]
impl OpusDecoder {
    /// Create new Opus decoder
    ///
    /// Args:
    ///     sample_rate: Sample rate in Hz (typically 48000)
    ///     channels: Number of channels (1 = mono, 2 = stereo)
    #[new]
    fn new(sample_rate: usize, channels: usize) -> PyResult<Self> {
        let decoder = RustDecoder::new(sample_rate, channels)
            .map_err(|e| e.to_py_err())?;

        Ok(OpusDecoder { decoder, channels })
    }

    /// Decode Opus frame
    ///
    /// Args:
    ///     opus_frame: Encoded Opus frame (or None for packet loss concealment)
    ///     frame_size: Number of samples per channel to decode (typically 960)
    ///     decode_fec: Use forward error correction if available
    ///
    /// Returns:
    ///     Decoded PCM samples as bytes (i16 little-endian)
    #[pyo3(signature = (opus_frame, frame_size, decode_fec=false))]
    fn decode(
        &mut self,
        opus_frame: Option<&[u8]>,
        frame_size: usize,
        decode_fec: bool,
    ) -> PyResult<Vec<u8>> {
        // Allocate output buffer
        let mut samples = vec![0i16; frame_size * self.channels];

        let decoded_samples = self
            .decoder
            .decode(opus_frame, &mut samples[..], decode_fec)
            .map_err(|e| e.to_py_err())?;

        // Convert i16 to bytes
        let pcm: Vec<u8> = samples[..decoded_samples * self.channels]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect();

        Ok(pcm)
    }

    /// Set decoder gain (in dB)
    ///
    /// Args:
    ///     gain_db: Gain in decibels
    fn set_gain(&mut self, gain_db: i32) -> PyResult<()> {
        self.decoder.set_gain(gain_db).map_err(|e| e.to_py_err())
    }

    /// Reset decoder state
    fn reset(&mut self) -> PyResult<()> {
        self.decoder.reset().map_err(|e| e.to_py_err())
    }
}

/// Opus codec module
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OpusEncoder>()?;
    m.add_class::<OpusDecoder>()?;
    Ok(())
}
