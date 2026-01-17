//! Safe FFI wrappers around unsafe Opus C API

use std::ffi::CStr;
use std::fmt;

// Import generated bindings
#[allow(warnings, clippy::all, non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]
include!("libopus.rs");

/// Opus error codes
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    BadArg = OPUS_BAD_ARG,
    BufferTooSmall = OPUS_BUFFER_TOO_SMALL,
    InternalError = OPUS_INTERNAL_ERROR,
    InvalidPacket = OPUS_INVALID_PACKET,
    Unimplemented = OPUS_UNIMPLEMENTED,
    InvalidState = OPUS_INVALID_STATE,
    AllocFail = OPUS_ALLOC_FAIL,
    Unknown = i32::MAX,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = unsafe { CStr::from_ptr(opus_strerror(*self as i32)) };
        write!(f, "{}", s.to_string_lossy())
    }
}

impl std::error::Error for ErrorCode {}

impl From<i32> for ErrorCode {
    fn from(v: i32) -> Self {
        match v {
            OPUS_BAD_ARG => ErrorCode::BadArg,
            OPUS_BUFFER_TOO_SMALL => ErrorCode::BufferTooSmall,
            OPUS_INTERNAL_ERROR => ErrorCode::InternalError,
            OPUS_INVALID_PACKET => ErrorCode::InvalidPacket,
            OPUS_UNIMPLEMENTED => ErrorCode::Unimplemented,
            OPUS_INVALID_STATE => ErrorCode::InvalidState,
            OPUS_ALLOC_FAIL => ErrorCode::AllocFail,
            _ => ErrorCode::Unknown,
        }
    }
}

/// Result type for Opus operations
pub type Result<T> = std::result::Result<T, ErrorCode>;

/// Application mode for encoder
#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum Application {
    /// Best for VoIP/videoconference (voice-optimized)
    Voip = OPUS_APPLICATION_VOIP,
    /// Best for music/high quality audio
    Audio = OPUS_APPLICATION_AUDIO,
    /// Low delay mode (for real-time applications)
    LowDelay = OPUS_APPLICATION_RESTRICTED_LOWDELAY,
}

/// Audio buffer types (supports both f32 and i16)
pub enum AudioBuffer<'a> {
    F32(&'a [f32]),
    I16(&'a [i16]),
}

impl<'a> From<&'a [i16]> for AudioBuffer<'a> {
    fn from(v: &'a [i16]) -> Self {
        AudioBuffer::I16(v)
    }
}

impl<'a> From<&'a [f32]> for AudioBuffer<'a> {
    fn from(v: &'a [f32]) -> Self {
        AudioBuffer::F32(v)
    }
}

/// Mutable audio buffer
pub enum AudioBufferMut<'a> {
    F32(&'a mut [f32]),
    I16(&'a mut [i16]),
}

impl<'a> From<&'a mut [f32]> for AudioBufferMut<'a> {
    fn from(v: &'a mut [f32]) -> Self {
        AudioBufferMut::F32(v)
    }
}

impl<'a> From<&'a mut [i16]> for AudioBufferMut<'a> {
    fn from(v: &'a mut [i16]) -> Self {
        AudioBufferMut::I16(v)
    }
}
