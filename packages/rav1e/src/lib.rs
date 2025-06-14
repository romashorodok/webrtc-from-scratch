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
#![allow(missing_abi)]
#![allow(unused_unsafe)]

use api::SpeedSettings;
use api::{ChromaSamplePosition, PixelRange, Rational};
use num_traits::FromPrimitive;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use v_frame::pixel::ChromaSampling;

#[macro_use]
extern crate log; // Override assert! and assert_eq! in tests
#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

pub use crate::api::color;
pub use crate::api::{
  Config, Context, EncoderConfig, EncoderStatus, InvalidConfig, Packet,
};
use crate::api::{
  PredictionModesSetting, RateControlConfig, SceneDetectionSpeed,
  SegmentationLevel,
};
use crate::encoder::*;
pub use crate::frame::Frame;
pub use crate::util::{CastFromPrimitive, Pixel, PixelType};

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
mod scan_order;
mod segmentation;
mod stats;
#[doc(hidden)]
pub mod tiling;
mod token_cdfs;

mod api;
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

struct PyFrame {
  bytes_per_sample: usize,
  width: usize,
  chroma_width: usize,
  y_plane: Vec<u8>,
  u_plane: Vec<u8>,
  v_plane: Vec<u8>,
}

#[pyclass]
struct Rav1e {
  ctx: Arc<Mutex<Context<u8>>>,
  frame_rx: Arc<Mutex<mpsc::Receiver<PyFrame>>>,
  frame_tx: Arc<Mutex<mpsc::Sender<PyFrame>>>,
}

#[pymethods]
impl Rav1e {
  #[new]
  fn new(
    width: usize, height: usize, sample_aspect_ratio_num: u64,
    sample_aspect_ratio_den: u64, bit_depth: usize, chroma_sampling: u64,
    time_base_num: u64, time_base_dem: u64,
  ) -> Self {
    let mut enc_cfg = EncoderConfig::with_speed_preset(10);
    let mut speed_cfg = SpeedSettings::from_preset(10);
    speed_cfg.rdo_lookahead_frames = 1;
    speed_cfg.transform.tx_domain_distortion = true;
    speed_cfg.transform.tx_domain_rate = true;

    speed_cfg.transform.reduced_tx_set = true;
    speed_cfg.prediction.fine_directional_intra = false;
    speed_cfg.prediction.prediction_modes = PredictionModesSetting::Simple;

    speed_cfg.segmentation = SegmentationLevel::Simple;
    // speed_cfg.scene_detection_mode = SceneDetectionSpeed::None;
    speed_cfg.scene_detection_mode = SceneDetectionSpeed::Fast;

    enc_cfg.speed_settings = speed_cfg;

    enc_cfg.width = width;
    enc_cfg.height = height;

    enc_cfg.sample_aspect_ratio =
      Rational::new(sample_aspect_ratio_num, sample_aspect_ratio_den);

    enc_cfg.bit_depth = bit_depth;
    enc_cfg.chroma_sampling =
      ChromaSampling::from_u64(chroma_sampling).unwrap();
    enc_cfg.chroma_sample_position = ChromaSamplePosition::Vertical;
    enc_cfg.pixel_range = PixelRange::Limited;
    enc_cfg.time_base = Rational::new(time_base_num, time_base_dem);
    enc_cfg.low_latency = true;
    enc_cfg.tune = Tune::Psnr;
    enc_cfg.quantizer = 100;
    enc_cfg.min_quantizer = 100;

    // enc_cfg.min_quantizer = 60;
    // enc_cfg.min_key_frame_interval = 60;
    // enc_cfg.max_key_frame_interval = 300;
    // Best
    // enc_cfg.min_key_frame_interval = 15;
    // enc_cfg.max_key_frame_interval = 30;
    enc_cfg.min_key_frame_interval = 1;
    enc_cfg.max_key_frame_interval = 30;

    // enc_cfg.min_key_frame_interval = 30;
    // enc_cfg.max_key_frame_interval = 90;

    enc_cfg.reservoir_frame_delay = None;
    // enc_cfg.reservoir_frame_delay = Some(30);

    // enc_cfg.tile_cols = 2;
    // enc_cfg.tile_rows = 2;
    enc_cfg.tile_cols = 2;
    enc_cfg.tile_rows = 1;

    enc_cfg.tiles = 0;
    enc_cfg.enable_timing_info = true;

    enc_cfg.bitrate = 60000;
    // enc_cfg.bitrate = 90000;
    // enc_cfg.bitrate = 150000;
    // enc_cfg.bitrate = 250000;

    let cfg = Config::new().with_encoder_config(enc_cfg).with_threads(8);

    let tiling = cfg
      .tiling_info()
      .map_err(|e| e.context("Invalid configuration"))
      .unwrap();

    if tiling.tile_count() == 1 {
      println!("Using 1 tile");
    } else {
      println!(
        "Using {} tiles ({}x{})",
        tiling.tile_count(),
        tiling.cols,
        tiling.rows
      );
    }

    // TODO: bit depth 8 vs 16
    let ctx = cfg
      .new_context::<u8>()
      .map_err(|e| e.context("Invalid encoder config"))
      .unwrap();

    let (tx, rx) = mpsc::channel::<PyFrame>(30 * 4);

    println!("Rav1e config {:?}", ctx);

    Self {
      ctx: Arc::new(Mutex::new(ctx)),
      frame_rx: Arc::new(Mutex::new(rx)),
      frame_tx: Arc::new(Mutex::new(tx)),
    }
  }

  fn receive_packet<'a>(&self, py: Python<'a>) -> PyResult<Bound<'a, PyAny>> {
    let ctx = self.ctx.clone();
    let frame_rx = self.frame_rx.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      'l: loop {
        let mut ctx = ctx.lock().await;
        let pkt_wrapped = ctx.receive_packet();

        let ret: Result<Vec<u8>, PyErr> = match pkt_wrapped {
          Ok(pkt) => {
            // println!("encoded packet frame {:?}", pkt);
            Ok(pkt.data)
          }
          Err(EncoderStatus::NeedMoreData) => {
            // println!("need more data lock");
            let frame = frame_rx.lock().await.recv().await.unwrap();
            let mut f = ctx.new_frame();
            // println!("need more data unlock");

            let width = 640;
            let height = 480;
            let chroma_width = width / 2;
            let chroma_height = height / 2;
            let bytewidth = 1; // 8-bit per channel

            // Red color in YUV (BT.601 approximation)
            let y_val = 76u8;
            let u_val = 85u8;
            let v_val = 255u8;

            // Fill luma (Y) plane
            // let y_plane = vec![y_val; width * height];
            // f.planes[0].copy_from_raw_u8(
            //   &y_plane,
            //   width * bytewidth,
            //   bytewidth,
            // );
            // // Fill chroma U (Cb)
            // let u_plane = vec![u_val; chroma_width * chroma_height];
            // f.planes[1].copy_from_raw_u8(
            //   &u_plane,
            //   chroma_width * bytewidth,
            //   bytewidth,
            // );
            //
            // // Fill chroma V (Cr)
            // let v_plane = vec![v_val; chroma_width * chroma_height];
            // f.planes[2].copy_from_raw_u8(
            //   &v_plane,
            //   chroma_width * bytewidth,
            //   bytewidth,
            // );

            // f.planes[0].copy_from_raw_u8(
            //   frame.y_plane.as_slice(),
            //   frame.width * frame.bytes_per_sample,
            //   // frame.bytes_per_sample,
            //   1,
            // );
            // f.planes[1].copy_from_raw_u8(
            //   frame.u_plane.as_slice(),
            //   frame.chroma_width * frame.bytes_per_sample,
            //   // frame.bytes_per_sample,
            //   1,
            // );
            // f.planes[2].copy_from_raw_u8(
            //   frame.v_plane.as_slice(),
            //   frame.chroma_width * frame.bytes_per_sample,
            //   // frame.bytes_per_sample,
            //   1,
            // );

            f.planes[0].copy_from_raw_u8(
              frame.y_plane.as_slice(),
              frame.width, // stride in bytes
              1,           // bytes per pixel (8-bit)
            );

            // U plane
            f.planes[1].copy_from_raw_u8(
              frame.u_plane.as_slice(),
              frame.chroma_width,
              1,
            );

            // V plane
            f.planes[2].copy_from_raw_u8(
              frame.v_plane.as_slice(),
              frame.chroma_width,
              1,
            );

            ctx.send_frame(Some(Arc::new(f))).unwrap();
            continue 'l;
          }
          Err(EncoderStatus::EnoughData) => {
            unreachable!()
          }
          Err(EncoderStatus::LimitReached) => {
            println!("limit reached");
            unreachable!()
          }
          Err(e @ EncoderStatus::Failure) => {
            // Err(e.context("Failed to encode video"))
            // Err(Some(None))
            println!("failure");
            unreachable!()
          }
          Err(e @ EncoderStatus::NotReady) => {
            // Err(e.context("Mismanaged handling of two-pass stats data"))
            println!("not ready");
            unreachable!()
          }

          Err(EncoderStatus::Encoded) => {
            continue 'l;
          }
        };
        return Ok(ret.unwrap());
      }
    })
  }

  fn send_packet<'a>(
    &self, py: Python<'a>, bytes_per_sample: usize, width: usize,
    chroma_width: usize, y_plane: Vec<u8>, u_plane: Vec<u8>, v_plane: Vec<u8>,
  ) -> PyResult<Bound<'a, PyAny>> {
    let frame_tx = self.frame_tx.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      // println!("send lock");
      frame_tx
        .lock()
        .await
        .send(PyFrame {
          bytes_per_sample,
          width,
          chroma_width,
          y_plane,
          u_plane,
          v_plane,
        })
        .await
        .unwrap();
      // println!("send unlock");

      Ok(())
    })
  }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
  m.add_class::<Rav1e>()?;
  Ok(())
}
