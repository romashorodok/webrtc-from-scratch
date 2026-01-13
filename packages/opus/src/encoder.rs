//! Safe Opus encoder wrapper

use crate::ffi::{self, Application, AudioBuffer, ErrorCode, Result};

/// Opus multistream encoder
pub struct Encoder {
    enc: *mut ffi::OpusMSEncoder,
    channels: usize,
    sample_rate: usize,
}

unsafe impl Send for Encoder {}
unsafe impl Sync for Encoder {}

impl Encoder {
    /// Create a new Opus encoder
    ///
    /// # Arguments
    /// * `sample_rate` - Sample rate in Hz (8000, 12000, 16000, 24000, or 48000)
    /// * `channels` - Number of channels (1 or 2)
    /// * `application` - Application mode (Voip, Audio, or LowDelay)
    ///
    /// For WebRTC use case:
    /// - sample_rate: 48000 (standard)
    /// - channels: 1 (mono) or 2 (stereo)
    /// - application: Voip (optimized for voice)
    pub fn new(
        sample_rate: usize,
        channels: usize,
        application: Application,
    ) -> Result<Self> {
        // For simple stereo/mono, use 1 stream
        let streams = 1;
        let coupled_streams = if channels == 2 { 1 } else { 0 };

        // Channel mapping (0 = left/mono, 1 = right)
        let mapping: Vec<u8> = (0..channels as u8).collect();

        Self::create(
            sample_rate,
            channels,
            streams,
            coupled_streams,
            &mapping,
            application,
        )
    }

    /// Create encoder with explicit multistream configuration
    pub fn create(
        sample_rate: usize,
        channels: usize,
        streams: usize,
        coupled_streams: usize,
        mapping: &[u8],
        application: Application,
    ) -> Result<Self> {
        let mut err = 0;
        let enc = unsafe {
            ffi::opus_multistream_encoder_create(
                sample_rate as i32,
                channels as i32,
                streams as i32,
                coupled_streams as i32,
                mapping.as_ptr(),
                application as i32,
                &mut err,
            )
        };

        if err < 0 {
            Err(err.into())
        } else {
            Ok(Encoder {
                enc,
                channels,
                sample_rate,
            })
        }
    }

    /// Encode audio frame
    ///
    /// # Arguments
    /// * `input` - Input PCM samples (i16 or f32)
    /// * `output` - Output buffer for encoded data
    ///
    /// # Returns
    /// Number of bytes written to output buffer
    ///
    /// # Note
    /// Input must contain exactly 960 samples (20ms @ 48kHz) per channel
    pub fn encode<'a, I>(
        &mut self,
        input: I,
        output: &mut [u8],
    ) -> Result<usize>
    where
        I: Into<AudioBuffer<'a>>,
    {
        let ret = match input.into() {
            AudioBuffer::F32(v) => unsafe {
                ffi::opus_multistream_encode_float(
                    self.enc,
                    v.as_ptr(),
                    (v.len() / self.channels) as i32,
                    output.as_mut_ptr(),
                    output.len() as i32,
                )
            },
            AudioBuffer::I16(v) => unsafe {
                ffi::opus_multistream_encode(
                    self.enc,
                    v.as_ptr(),
                    (v.len() / self.channels) as i32,
                    output.as_mut_ptr(),
                    output.len() as i32,
                )
            },
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(ret as usize)
        }
    }

    /// Set encoder bitrate (bits per second)
    pub fn set_bitrate(&mut self, bitrate: i32) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_encoder_ctl(
                self.enc,
                ffi::OPUS_SET_BITRATE_REQUEST,
                bitrate,
            )
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }

    /// Set encoder complexity (0-10, default 9)
    pub fn set_complexity(&mut self, complexity: i32) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_encoder_ctl(
                self.enc,
                ffi::OPUS_SET_COMPLEXITY_REQUEST,
                complexity,
            )
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }

    /// Enable/disable DTX (discontinuous transmission)
    pub fn set_dtx(&mut self, dtx: bool) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_encoder_ctl(
                self.enc,
                ffi::OPUS_SET_DTX_REQUEST,
                dtx as i32,
            )
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }

    /// Reset encoder state
    pub fn reset(&mut self) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_encoder_ctl(self.enc, ffi::OPUS_RESET_STATE)
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe {
            ffi::opus_multistream_encoder_destroy(self.enc);
        }
    }
}
