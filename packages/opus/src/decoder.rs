//! Safe Opus decoder wrapper

use crate::ffi::{self, AudioBufferMut, ErrorCode, Result};
use std::ptr;

/// Opus multistream decoder
pub struct Decoder {
    dec: *mut ffi::OpusMSDecoder,
    channels: usize,
}

unsafe impl Send for Decoder {}
unsafe impl Sync for Decoder {}

impl Decoder {
    /// Create a new Opus decoder
    ///
    /// # Arguments
    /// * `sample_rate` - Sample rate in Hz (8000, 12000, 16000, 24000, or 48000)
    /// * `channels` - Number of channels (1 or 2)
    pub fn new(sample_rate: usize, channels: usize) -> Result<Self> {
        let streams = 1;
        let coupled_streams = if channels == 2 { 1 } else { 0 };
        let mapping: Vec<u8> = (0..channels as u8).collect();

        Self::create(sample_rate, channels, streams, coupled_streams, &mapping)
    }

    /// Create decoder with explicit multistream configuration
    pub fn create(
        sample_rate: usize,
        channels: usize,
        streams: usize,
        coupled_streams: usize,
        mapping: &[u8],
    ) -> Result<Self> {
        let mut err = 0;
        let dec = unsafe {
            ffi::opus_multistream_decoder_create(
                sample_rate as i32,
                channels as i32,
                streams as i32,
                coupled_streams as i32,
                mapping.as_ptr(),
                &mut err,
            )
        };

        if err < 0 {
            Err(err.into())
        } else {
            Ok(Decoder { dec, channels })
        }
    }

    /// Decode Opus frame
    ///
    /// # Arguments
    /// * `input` - Encoded Opus data (None for packet loss concealment)
    /// * `output` - Output buffer for PCM samples
    /// * `decode_fec` - Use forward error correction if available
    ///
    /// # Returns
    /// Number of decoded samples per channel
    pub fn decode<'a, I, O>(
        &mut self,
        input: I,
        output: O,
        decode_fec: bool,
    ) -> Result<usize>
    where
        I: Into<Option<&'a [u8]>>,
        O: Into<AudioBufferMut<'a>>,
    {
        let (data, len) = input
            .into()
            .map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));

        let ret = match output.into() {
            AudioBufferMut::F32(v) => unsafe {
                ffi::opus_multistream_decode_float(
                    self.dec,
                    data,
                    len as i32,
                    v.as_mut_ptr(),
                    (v.len() / self.channels) as i32,
                    decode_fec as i32,
                )
            },
            AudioBufferMut::I16(v) => unsafe {
                ffi::opus_multistream_decode(
                    self.dec,
                    data,
                    len as i32,
                    v.as_mut_ptr(),
                    (v.len() / self.channels) as i32,
                    decode_fec as i32,
                )
            },
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(ret as usize)
        }
    }

    /// Set decoder gain (in dB, Q8 format: gain_db * 256)
    pub fn set_gain(&mut self, gain_db: i32) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_decoder_ctl(
                self.dec,
                ffi::OPUS_SET_GAIN_REQUEST,
                gain_db * 256,
            )
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }

    /// Reset decoder state
    pub fn reset(&mut self) -> Result<()> {
        let ret = unsafe {
            ffi::opus_multistream_decoder_ctl(self.dec, ffi::OPUS_RESET_STATE)
        };

        if ret < 0 {
            Err(ret.into())
        } else {
            Ok(())
        }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            ffi::opus_multistream_decoder_destroy(self.dec);
        }
    }
}
