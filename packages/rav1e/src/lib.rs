// Copyright (c) 2017-2022, The rav1e contributors. All rights reserved
//
// This source code is subject to the terms of the BSD 2 Clause License and
// the Alliance for Open Media Patent License 1.0. If the BSD 2 Clause License
// was not distributed with this source code in the LICENSE file, you can
// obtain it at www.aomedia.org/license/software. If the Alliance for Open
// Media Patent License 1.0 was not distributed with this source code in the
// PATENTS file, you can obtain it at www.aomedia.org/license/patent.

//! rav1e is an [AV1] video encoder. It is designed to eventually cover all use
//! cases, though in its current form it is most suitable for cases where
//! libaom (the reference encoder) is too slow.
//!
//! ## Features
//!
//! * Intra and inter frames
//! * 64x64 superblocks
//! * 4x4 to 64x64 RDO-selected square and 2:1/1:2 rectangular blocks
//! * DC, H, V, Paeth, smooth, and a subset of directional prediction modes
//! * DCT, (FLIP-)ADST and identity transforms (up to 64x64, 16x16 and 32x32
//!   respectively)
//! * 8-, 10- and 12-bit depth color
//! * 4:2:0 (full support), 4:2:2 and 4:4:4 (limited) chroma sampling
//! * Variable speed settings
//! * Near real-time encoding at high speed levels
//!
//! ## Usage
//!
//! Encoding is done through the [`Context`] struct. Examples on
//! [`Context::receive_packet`] show how to create a [`Context`], send frames
//! into it and receive packets of encoded data.
//!
//! [AV1]: https://aomediacodec.github.io/av1-spec/av1-spec.pdf
//! [`Context`]: struct.Context.html
//! [`Context::receive_packet`]: struct.Context.html#method.receive_packet
use api::{ChromaSamplePosition, PixelRange, Rational};
use api::{SceneDetectionSpeed, SpeedSettings};
use error::CliError;
use num_traits::FromPrimitive;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use v_frame::pixel::ChromaSampling;
use y4m::Colorspace;

#[macro_use]
extern crate log; // Override assert! and assert_eq! in tests
#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

pub use crate::api::color;
pub use crate::api::{
  Config, Context, EncoderConfig, EncoderStatus, InvalidConfig, Packet,
};
use crate::encoder::*;
pub use crate::frame::Frame;
pub use crate::util::{CastFromPrimitive, Pixel, PixelType};

use std::fs::File;
use std::io::Read;
use std::io::{self, Seek};

pub(crate) mod built_info {
  // The file has been placed there by the build script.
  include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

mod serialize {
  cfg_if::cfg_if! {
    if #[cfg(feature="serialize")] {
      pub use serde::*;
    } else {
      pub use noop_proc_macro::{Deserialize, Serialize};
    }
  }
}

mod wasm_bindgen {
  cfg_if::cfg_if! {
    if #[cfg(feature="wasm")] {
      pub use wasm_bindgen::prelude::*;
    } else {
      pub use noop_proc_macro::wasm_bindgen;
    }
  }
}

#[cfg(any(cargo_c, feature = "capi"))]
pub mod capi;

#[macro_use]
mod transform;
#[macro_use]
mod cpu_features;

mod activity;
pub(crate) mod asm;
mod dist;
mod ec;
mod partition;
mod predict;
mod quantize;
mod rdo;
mod rdo_tables;
#[macro_use]
mod util;
mod cdef;
#[doc(hidden)]
pub mod context;
mod deblock;
mod encoder;
mod entropymode;
mod levels;
mod lrf;
mod mc;
mod me;
mod rate;
mod recon_intra;
mod sad_plane;
mod scan_order;
#[cfg(feature = "scenechange")]
pub mod scenechange;
#[cfg(not(feature = "scenechange"))]
mod scenechange;
mod segmentation;
mod stats;
#[doc(hidden)]
pub mod tiling;
mod token_cdfs;

mod api;
mod error;
mod frame;
mod header;

/// Commonly used types and traits.
pub mod prelude {
  pub use crate::api::*;
  pub use crate::encoder::{Sequence, Tune};
  pub use crate::frame::{
    Frame, FrameParameters, FrameTypeOverride, Plane, PlaneConfig,
  };
  pub use crate::partition::BlockSize;
  pub use crate::predict::PredictionMode;
  pub use crate::transform::TxType;
  pub use crate::util::{CastFromPrimitive, Pixel, PixelType};
}

/// Basic data structures
pub mod data {
  pub use crate::api::{
    ChromaticityPoint, EncoderStatus, FrameType, Packet, Rational,
  };
  pub use crate::frame::{Frame, FrameParameters};
  pub use crate::stats::EncoderStats;
  pub use crate::util::{CastFromPrimitive, Pixel, PixelType};
}

/// Encoder configuration and settings
pub mod config {
  pub use crate::api::config::{
    GrainTableSegment, NoiseGenArgs, TransferFunction, NUM_UV_COEFFS,
    NUM_UV_POINTS, NUM_Y_COEFFS, NUM_Y_POINTS,
  };
  pub use crate::api::{
    Config, EncoderConfig, InvalidConfig, PredictionModesSetting,
    RateControlConfig, RateControlError, RateControlSummary, SpeedSettings,
  };
  pub use crate::cpu_features::CpuFeatureLevel;
}

/// Version information
///
/// The information is recovered from `Cargo.toml` and `git describe`, when available.
///
/// ```
/// use rav1e::version;
/// use semver::Version;
///
/// let major = version::major();
/// let minor = version::minor();
/// let patch = version::patch();
///
/// let short = version::short();
///
/// let v1 = Version::new(major, minor, patch);
/// let v2 = Version::parse(&short).unwrap();
///
/// assert_eq!(v1.major, v2.major);
/// ```
pub mod version {
  /// Major version component
  ///
  /// It is increased every time a release presents a incompatible API change.
  ///
  /// # Panics
  ///
  /// Will panic if package is not built with Cargo,
  /// or if the package version is not a valid triplet of integers.
  pub fn major() -> u64 {
    env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap()
  }
  /// Minor version component
  ///
  /// It is increased every time a release presents new functionalities are added
  /// in a backwards-compatible manner.
  ///
  /// # Panics
  ///
  /// Will panic if package is not built with Cargo,
  /// or if the package version is not a valid triplet of integers.
  pub fn minor() -> u64 {
    env!("CARGO_PKG_VERSION_MINOR").parse().unwrap()
  }
  /// Patch version component
  ///
  /// It is increased every time a release provides only backwards-compatible bugfixes.
  ///
  /// # Panics
  ///
  /// Will panic if package is not built with Cargo,
  /// or if the package version is not a valid triplet of integers.
  pub fn patch() -> u64 {
    env!("CARGO_PKG_VERSION_PATCH").parse().unwrap()
  }

  /// Version information as presented in `[package]` `version`.
  ///
  /// e.g. `0.1.0`
  ///
  /// Can be parsed by [semver](https://crates.io/crates/semver).
  pub fn short() -> String {
    env!("CARGO_PKG_VERSION").to_string()
  }

  /// Version information as presented in `[package] version` followed by the
  /// short commit hash if present.
  ///
  /// e.g. `0.1.0 - g743d464`
  ///
  pub fn long() -> String {
    let s = short();
    let hash = hash();

    if hash.is_empty() {
      s
    } else {
      format!("{s} - {hash}")
    }
  }

  cfg_if::cfg_if! {
    if #[cfg(feature="git_version")] {
      fn git_version() -> &'static str {
        crate::built_info::GIT_VERSION.unwrap_or_default()
      }

      fn git_hash() -> &'static str {
        crate::built_info::GIT_COMMIT_HASH.unwrap_or_default()
      }
    } else {
      fn git_version() -> &'static str {
        "UNKNOWN"
      }

      fn git_hash() -> &'static str {
        "UNKNOWN"
      }
    }
  }
  /// Commit hash (short)
  ///
  /// Short hash of the git commit used by this build
  ///
  /// e.g. `g743d464`
  ///
  pub fn hash() -> String {
    git_hash().to_string()
  }

  /// Version information with the information
  /// provided by `git describe --tags`.
  ///
  /// e.g. `0.1.0 (v0.1.0-1-g743d464)`
  ///
  pub fn full() -> String {
    format!("{} ({})", short(), git_version(),)
  }
}
#[cfg(all(
  any(test, fuzzing),
  any(feature = "decode_test", feature = "decode_test_dav1d")
))]
mod test_encode_decode;

#[cfg(feature = "bench")]
pub mod bench {
  pub mod api {
    pub use crate::api::*;
  }
  pub mod cdef {
    pub use crate::cdef::*;
  }
  pub mod context {
    pub use crate::context::*;
  }
  pub mod dist {
    pub use crate::dist::*;
  }
  pub mod ec {
    pub use crate::ec::*;
  }
  pub mod encoder {
    pub use crate::encoder::*;
  }
  pub mod mc {
    pub use crate::mc::*;
  }
  pub mod partition {
    pub use crate::partition::*;
  }
  pub mod frame {
    pub use crate::frame::*;
  }
  pub mod predict {
    pub use crate::predict::*;
  }
  pub mod rdo {
    pub use crate::rdo::*;
  }
  pub mod tiling {
    pub use crate::tiling::*;
  }
  pub mod transform {
    pub use crate::transform::*;
  }
  pub mod util {
    pub use crate::util::*;
  }
  pub mod cpu_features {
    pub use crate::cpu_features::*;
  }
}

#[cfg(fuzzing)]
pub mod fuzzing;
pub trait ToError {
  fn context(&self, msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
  }
}

impl ToError for InvalidConfig {
  fn context(&self, msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
  }
}

impl ToError for CliError {
  fn context(&self, msg: &str) -> PyErr {
    PyValueError::new_err(msg.to_string())
  }
}

pub trait FrameBuilder<T: Pixel> {
  fn new_frame(&self) -> Frame<T>;
}

pub trait Decoder: Send {
  fn get_video_details(&self) -> VideoDetails;
  fn read_frame<T: Pixel, F: FrameBuilder<T>>(
    &mut self, ctx: &F, cfg: &VideoDetails,
  ) -> Result<Frame<T>, DecodeError>;
}

#[derive(Debug)]
pub enum DecodeError {
  EOF,
  BadInput,
  UnknownColorspace,
  ParseError,
  IoError,
  MemoryLimitExceeded,
}

#[derive(Debug, Clone, Copy)]
pub struct VideoDetails {
  pub width: usize,
  pub height: usize,
  pub sample_aspect_ratio: Rational,
  pub bit_depth: usize,
  pub chroma_sampling: ChromaSampling,
  pub chroma_sample_position: ChromaSamplePosition,
  pub time_base: Rational,
}

impl Default for VideoDetails {
  fn default() -> Self {
    VideoDetails {
      width: 640,
      height: 480,
      sample_aspect_ratio: Rational { num: 1, den: 1 },
      bit_depth: 8,
      chroma_sampling: ChromaSampling::Cs420,
      chroma_sample_position: ChromaSamplePosition::Unknown,
      time_base: Rational { num: 30, den: 1 },
    }
  }
}

impl Decoder for y4m::Decoder<Box<dyn Read + Send>> {
  fn get_video_details(&self) -> VideoDetails {
    let width = self.get_width();
    let height = self.get_height();
    let aspect_ratio = self.get_pixel_aspect();
    let color_space = self.get_colorspace();
    let bit_depth = color_space.get_bit_depth();
    let (chroma_sampling, chroma_sample_position) =
      map_y4m_color_space(color_space);
    let framerate = self.get_framerate();
    let time_base = Rational::new(framerate.den as u64, framerate.num as u64);

    VideoDetails {
      width,
      height,
      sample_aspect_ratio: if aspect_ratio.num == 0 && aspect_ratio.den == 0 {
        Rational::new(1, 1)
      } else {
        Rational::new(aspect_ratio.num as u64, aspect_ratio.den as u64)
      },
      bit_depth,
      chroma_sampling,
      chroma_sample_position,
      time_base,
    }
  }

  fn read_frame<T: Pixel, F: FrameBuilder<T>>(
    &mut self, ctx: &F, cfg: &VideoDetails,
  ) -> Result<Frame<T>, DecodeError> {
    let bytes = self.get_bytes_per_sample();
    self
      .read_frame()
      .map(|frame| {
        let mut f = ctx.new_frame();

        let (chroma_width, _) =
          cfg.chroma_sampling.get_chroma_dimensions(cfg.width, cfg.height);

        f.planes[0].copy_from_raw_u8(
          frame.get_y_plane(),
          cfg.width * bytes,
          bytes,
        );
        if cfg.chroma_sampling != ChromaSampling::Cs400 {
          f.planes[1].copy_from_raw_u8(
            frame.get_u_plane(),
            chroma_width * bytes,
            bytes,
          );
          f.planes[2].copy_from_raw_u8(
            frame.get_v_plane(),
            chroma_width * bytes,
            bytes,
          );
        }
        f
      })
      .map_err(Into::into)
  }
}

impl From<y4m::Error> for DecodeError {
  fn from(e: y4m::Error) -> DecodeError {
    match e {
      y4m::Error::EOF => DecodeError::EOF,
      y4m::Error::BadInput => DecodeError::BadInput,
      y4m::Error::UnknownColorspace => DecodeError::UnknownColorspace,
      y4m::Error::ParseError(_) => DecodeError::ParseError,
      y4m::Error::IoError(_) => DecodeError::IoError,
      // Note that this error code has nothing to do with the system running out of memory,
      // it means the y4m decoder has exceeded its memory allocation limit.
      y4m::Error::OutOfMemory => DecodeError::MemoryLimitExceeded,
    }
  }
}

pub const fn map_y4m_color_space(
  color_space: y4m::Colorspace,
) -> (ChromaSampling, ChromaSamplePosition) {
  use crate::ChromaSamplePosition::*;
  use crate::ChromaSampling::*;
  use y4m::Colorspace::*;
  match color_space {
    Cmono | Cmono12 => (Cs400, Unknown),
    C420jpeg | C420paldv => (Cs420, Unknown),
    C420mpeg2 => (Cs420, Vertical),
    C420 | C420p10 | C420p12 => (Cs420, Colocated),
    C422 | C422p10 | C422p12 => (Cs422, Colocated),
    C444 | C444p10 | C444p12 => (Cs444, Colocated),
    _ => unimplemented!(),
  }
}

impl<T: Pixel> FrameBuilder<T> for Context<T> {
  fn new_frame(&self) -> Frame<T> {
    Context::new_frame(self)
  }
}

struct Source<D: Decoder> {
  limit: usize,
  count: usize,
  input: D,
}

impl<D: Decoder> Source<D> {
  fn new(limit: usize, input: D) -> Self {
    Self { limit, input, count: 0 }
  }

  #[profiling::function]
  fn read_frame<T: Pixel>(
    &mut self, ctx: &mut Context<T>, video_info: VideoDetails,
  ) -> Result<(), CliError> {
    if self.limit != 0 && self.count == self.limit {
      ctx.flush();
      return Ok(());
    }

    match self.input.read_frame(ctx, &video_info) {
      Ok(frame) => {
        match video_info.bit_depth {
          8 | 10 | 12 => {}
          _ => return Err(CliError::new("Unsupported bit depth")),
        }
        self.count += 1;
        let _ = ctx.send_frame(Some(Arc::new(frame)));
      }
      _ => {
        // ctx.flush();
      }
    };
    Ok(())
  }
}

fn process_frame<T: Pixel, D: Decoder>(
  ctx: &mut Context<T>, source: &mut Source<D>,
) -> Result<Option<Vec<u8>>, CliError> {
  let y4m_details = source.input.get_video_details();

  loop {
    match ctx.receive_packet() {
      Ok(pkt) => return Ok(Some(pkt.data)),
      Err(EncoderStatus::NeedMoreData) => {
        source.read_frame(ctx, y4m_details)?;
        continue;
      }
      Err(EncoderStatus::EnoughData) => {
        println!("Enough data");
        unreachable!()
      }
      Err(EncoderStatus::LimitReached) => {
        println!("limit reached");
        return Ok(None);
      }
      Err(EncoderStatus::Failure) => {
        println!("failure");
        unreachable!()
      }
      Err(EncoderStatus::NotReady) => {
        println!("not ready");
        unreachable!()
      }
      Err(EncoderStatus::Encoded) => {
        continue;
      }
    }
  }
}

struct LoopingReader {
  inner: File,
}

impl LoopingReader {
  fn new(inner: File) -> Self {
    Self { inner }
  }
}

impl Read for LoopingReader {
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    match self.inner.read(buf) {
      Ok(0) => {
        self.inner.seek(io::SeekFrom::Start(0))?;
        self.inner.read(buf)
      }
      other => other,
    }
  }
}

#[pyclass]
struct Rav1e {
  filename: String,
  // cfg: Config,
  // ctx: Context<u8>,
  // frame_rx: Arc<Mutex<mpsc::Receiver<PyFrame>>>,
  // frame_tx: Arc<Mutex<mpsc::Sender<PyFrame>>>,
}

#[pymethods]
impl Rav1e {
  #[new]
  fn new(filename: String) -> PyResult<Self> {
    // let mut enc_cfg = EncoderConfig::with_speed_preset(10);
    // enc_cfg.width = width;
    // enc_cfg.height = height;
    // enc_cfg.sample_aspect_ratio =
    //   Rational::new(sample_aspect_ratio_num, sample_aspect_ratio_den);
    // enc_cfg.bit_depth = bit_depth;
    // enc_cfg.chroma_sampling =
    //   ChromaSampling::from_u64(chroma_sampling).unwrap();
    // enc_cfg.chroma_sample_position = ChromaSamplePosition::Vertical;
    // enc_cfg.pixel_range = PixelRange::Limited;
    // enc_cfg.time_base = Rational::new(time_base_num, time_base_dem);
    // enc_cfg.low_latency = true;
    // enc_cfg.speed_settings = SpeedSettings::from_preset(10);
    // enc_cfg.tune = Tune::Psnr;
    // enc_cfg.min_quantizer = 255;
    // enc_cfg.quantizer = 255;
    // enc_cfg.min_key_frame_interval = 15;
    // enc_cfg.max_key_frame_interval = 30;
    // enc_cfg.reservoir_frame_delay = Some(15);
    // enc_cfg.tile_cols = 2;
    // enc_cfg.tile_rows = 1;
    // enc_cfg.tiles = 0;
    // enc_cfg.enable_timing_info = true;
    // enc_cfg.bitrate = 0;
    // enc_cfg.bitrate = 90000;

    // let mut speed_settings = SpeedSettings::from_preset(10);
    // speed_settings.scene_detection_mode = SceneDetectionSpeed::None;
    // speed_settings.cdef = false;
    // enc_cfg.speed_settings = speed_settings;

    // let mut enc_cfg =
    //   EncoderConfig { width: 640, height: 480, ..Default::default() };

    // enc_cfg.low_latency = true;
    // enc_cfg.speed_settings = SpeedSettings::from_preset(10);
    // enc_cfg.tune = Tune::Psnr;
    // enc_cfg.quantizer = 90;
    // enc_cfg.min_quantizer = 50;
    // enc_cfg.min_key_frame_interval = 15;
    // enc_cfg.max_key_frame_interval = 30;
    // enc_cfg.reservoir_frame_delay = Some(15);
    // enc_cfg.tile_cols = 4;
    // enc_cfg.tile_rows = 1;
    // enc_cfg.tiles = 0;
    // enc_cfg.enable_timing_info = false;
    // enc_cfg.bitrate = 0;

    // let cfg = Config::new()
    //   .with_encoder_config(enc_cfg)
    //   .with_threads(16)
    //   .with_parallel_gops(30);
    // let tiling = cfg
    //   .tiling_info()
    //   .map_err(|e| e.context("Invalid configuration"))
    //   .unwrap();
    // if tiling.tile_count() == 1 {
    //   println!("Using 1 tile");
    // } else {
    //   println!(
    //     "Using {} tiles ({}x{})",
    //     tiling.tile_count(),
    //     tiling.cols,
    //     tiling.rows
    //   );
    // }

    // TODO: bit depth 8 vs 16
    // let ctx = cfg
    //   .new_context::<u8>()
    //   .map_err(|e| e.context("Invalid encoder config"))
    //   .unwrap();

    // let (tx, rx) = mpsc::channel::<PyFrame>(30 * 4);

    // println!("Rav1e config {:?}", ctx);

    let (tx, rx) = mpsc::channel::<Vec<u8>>(30 * 4);

    Ok(Self {
      filename,
      // cfg,
      // source,
      // ctx,
      // ctx: Arc::new(Mutex::new(ctx)),
      // frame_rx: Arc::new(Mutex::new(rx)),
      // frame_tx: Arc::new(Mutex::new(tx)),
    })
  }

  fn start<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
    let filename = self.filename.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      // let file = File::open(filename).unwrap();

      // let input: Box<dyn Read + Send> = Box::new(LoopingReader::new(file));

      // let limit = y4m::Limits {
      //   // Use saturating operations to gracefully handle 32-bit architectures
      //   bytes: 64usize
      //     .saturating_mul(64)
      //     .saturating_mul(4096)
      //     .saturating_mul(2304)
      //     .saturating_add(1024),
      // };
      // let y4m_dec = match y4m::Decoder::new_with_limits(input, limit) {
      //   Err(e) => {
      //     return Err(CliError::new(match e {
      //       y4m::Error::ParseError(_) => {
      //         "Could not parse input video. Is it a y4m file?"
      //       }
      //       y4m::Error::IoError(_) => {
      //         "Could not read input file. Check that the path is correct and you have read permissions."
      //       }
      //       y4m::Error::UnknownColorspace => {
      //         "Unknown colorspace or unsupported bit depth."
      //       }
      //       y4m::Error::OutOfMemory => "The video's frame size exceeds the limit.",
      //       y4m::Error::EOF => "Unexpected end of input.",
      //       y4m::Error::BadInput => "Bad y4m input parameters provided.",
      //     })).unwrap()
      //   }
      //   Ok(d) => d,
      // };
      // let video_info = y4m_dec.get_video_details();

      // let mut source = Source::new(0, y4m_dec);

      // let enc = EncoderConfig {
      //   width: video_info.width,
      //   height: video_info.height,
      //   sample_aspect_ratio: video_info.sample_aspect_ratio,
      //   bit_depth: video_info.bit_depth,
      //   chroma_sampling: video_info.chroma_sampling,
      //   chroma_sample_position: video_info.chroma_sample_position,
      //   time_base: video_info.time_base,
      //   speed_settings: SpeedSettings::from_preset(10),
      //   ..Default::default()
      // };
      // let cfg = Config::new().with_encoder_config(enc.clone()).with_threads(8);

      // let mut ctx: Context<u8> = cfg
      //   .new_context()
      //   .map_err(|e| e.context("Invalid encoder config"))
      //   .unwrap();

      // println!("do encode");
      // while let Some(frame) = process_frame(&mut ctx, &mut source).unwrap() {
      //   println!("encoded {:?}", frame.len());

      //   // tokio::task::yield_now().await;
      // }

      Ok(())
    })
  }
  fn receive_packet(&mut self) -> PyResult<Option<Vec<u8>>> {
    // let pkt_wrapped = self.ctx.receive_packet();

    // let ret: Option<Vec<u8>> = match pkt_wrapped {
    //   Ok(pkt) => {
    //     // println!("encoded packet frame {:?}", pkt);
    //     Some(pkt.data)
    //   }
    //   Err(EncoderStatus::NeedMoreData) => None,
    //   Err(EncoderStatus::EnoughData) => {
    //     println!("Enough data");
    //     unreachable!()
    //   }
    //   Err(EncoderStatus::LimitReached) => {
    //     println!("limit reached");
    //     unreachable!()
    //   }
    //   Err(e @ EncoderStatus::Failure) => {
    //     // Err(e.context("Failed to encode video"))
    //     // Err(Some(None))
    //     println!("failure");
    //     unreachable!()
    //   }
    //   Err(e @ EncoderStatus::NotReady) => {
    //     // Err(e.context("Mismanaged handling of two-pass stats data"))
    //     println!("not ready");
    //     unreachable!()
    //   }
    //   Err(EncoderStatus::Encoded) => {
    //     println!("Encoded");
    //     None
    //   }
    // };
    // Ok(ret)
    Ok(Some(vec![]))

    // let ctx = self.ctx.clone();
    // let frame_rx = self.frame_rx.clone();
    // pyo3_async_runtimes::tokio::future_into_py(py, async move {
    //   'l: loop {
    //     let mut ctx = ctx.lock().await;
    //     let pkt_wrapped = ctx.receive_packet();

    //     let ret: Result<Vec<u8>, PyErr> = match pkt_wrapped {
    //       Ok(pkt) => {
    //         println!("encoded packet frame {:?}", pkt);
    //         Ok(pkt.data)
    //       }
    //       Err(EncoderStatus::NeedMoreData) => {
    //         println!("need more data lock");
    //         let frame = frame_rx.lock().await.recv().await.unwrap();
    //         let mut f = ctx.new_frame();
    //         println!("need more data unlock");

    //         let width = 640;
    //         let height = 480;
    //         let chroma_width = width / 2;
    //         let chroma_height = height / 2;
    //         let bytewidth = 1; // 8-bit per channel

    //         // Red color in YUV (BT.601 approximation)
    //         let y_val = 76u8;
    //         let u_val = 85u8;
    //         let v_val = 255u8;

    //         println!(
    //           "Y len {:?} U len {:?} V len {:?} width: {:?} chroma_width: {:?}  bytes_per_sample: {:?}",
    //           frame.y_plane.len(),
    //           frame.u_plane.len(),
    //           frame.v_plane.as_slice().len(),
    //           frame.width,
    //           frame.chroma_width,
    //           frame.bytes_per_sample,
    //         );

    //         // f.planes[0].copy_from_raw_u8(
    //         //   frame.y_plane.as_slice(),
    //         //   frame.width * frame.bytes_per_sample,
    //         //   // frame.bytes_per_sample,
    //         //   1,
    //         // );
    //         // f.planes[1].copy_from_raw_u8(
    //         //   frame.u_plane.as_slice(),
    //         //   frame.chroma_width * frame.bytes_per_sample,
    //         //   // frame.bytes_per_sample,
    //         //   1,
    //         // );
    //         // f.planes[2].copy_from_raw_u8(
    //         //   frame.v_plane.as_slice(),
    //         //   frame.chroma_width * frame.bytes_per_sample,
    //         //   // frame.bytes_per_sample,
    //         //   1,
    //         // );

    //         f.planes[0].copy_from_raw_u8(
    //           frame.y_plane.as_slice(),
    //           frame.width, // stride in bytes
    //           1,           // bytes per pixel (8-bit)
    //         );

    //         // U plane
    //         f.planes[1].copy_from_raw_u8(
    //           frame.u_plane.as_slice(),
    //           frame.chroma_width,
    //           1,
    //         );

    //         // V plane
    //         f.planes[2].copy_from_raw_u8(
    //           frame.v_plane.as_slice(),
    //           frame.chroma_width,
    //           1,
    //         );

    //         ctx.send_frame(Some(Arc::new(f))).unwrap();
    //         continue 'l;
    //       }
    //       Err(EncoderStatus::EnoughData) => {
    //         unreachable!()
    //       }
    //       Err(EncoderStatus::LimitReached) => {
    //         println!("limit reached");
    //         unreachable!()
    //       }
    //       Err(e @ EncoderStatus::Failure) => {
    //         // Err(e.context("Failed to encode video"))
    //         // Err(Some(None))
    //         println!("failure");
    //         unreachable!()
    //       }
    //       Err(e @ EncoderStatus::NotReady) => {
    //         // Err(e.context("Mismanaged handling of two-pass stats data"))
    //         println!("not ready");
    //         unreachable!()
    //       }

    //       Err(EncoderStatus::Encoded) => {
    //         continue 'l;
    //       }
    //     };
    //     return Ok(ret.unwrap());
    //   }
    // })
  }

  fn send_packet(
    &mut self, bytes_per_sample: usize, width: usize, chroma_width: usize,
    y_plane: Vec<u8>, u_plane: Vec<u8>, v_plane: Vec<u8>,
  ) -> PyResult<()> {
    // let mut f = self.ctx.new_frame();

    // // let pixels = vec![42; 640 * 480];

    // // for p in &mut f.planes {
    // //   let stride = (640 + p.cfg.xdec) >> p.cfg.xdec;
    // //   p.copy_from_raw_u8(&pixels, stride, 1);
    // // }

    // f.planes[0].copy_from_raw_u8(
    //   y_plane.as_slice(),
    //   width, // stride in bytes
    //   1,     // bytes per pixel (8-bit)
    // );
    // // U plane
    // f.planes[1].copy_from_raw_u8(u_plane.as_slice(), chroma_width, 1);
    // // V plane
    // f.planes[2].copy_from_raw_u8(v_plane.as_slice(), chroma_width, 1);

    // self.ctx.send_frame(f);

    // let mut f = self.ctx.new_frame();

    // f.planes[0].copy_from_raw_u8(
    //   y_plane.as_slice(),
    //   width, // stride in bytes
    //   1,     // bytes per pixel (8-bit)
    // );

    // // U plane
    // f.planes[1].copy_from_raw_u8(u_plane.as_slice(), chroma_width, 1);

    // // V plane
    // f.planes[2].copy_from_raw_u8(v_plane.as_slice(), chroma_width, 1);

    // self.ctx.send_frame(f).unwrap();

    Ok(())
  }

  // fn send_packet<'a>(
  //   &self, py: Python<'a>, bytes_per_sample: usize, width: usize,
  //   chroma_width: usize, y_plane: Vec<u8>, u_plane: Vec<u8>, v_plane: Vec<u8>,
  // ) -> PyResult<Bound<'a, PyAny>> {
  //   // let frame_tx = self.frame_tx.clone();
  //   // pyo3_async_runtimes::tokio::future_into_py(py, async move {
  //   //   println!("send lock");
  //   //   frame_tx
  //   //     .lock()
  //   //     .await
  //   //     .send(PyFrame {
  //   //       bytes_per_sample,
  //   //       width,
  //   //       chroma_width,
  //   //       y_plane,
  //   //       u_plane,
  //   //       v_plane,
  //   //     })
  //   //     .await
  //   //     .unwrap();
  //   //   println!("send unlock");

  //   //   Ok(())
  //   // })
  // }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
  m.add_class::<Rav1e>()?;
  Ok(())
}
