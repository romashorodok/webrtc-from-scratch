// Copyright (c) 2017-2023, The rav1e contributors. All rights reserved
//
// This source code is subject to the terms of the BSD 2 Clause License and
// the Alliance for Open Media Patent License 1.0. If the BSD 2 Clause License
// was not distributed with this source code in the LICENSE file, you can
// obtain it at www.aomedia.org/license/software. If the Alliance for Open
// Media Patent License 1.0 was not distributed with this source code in the
// PATENTS file, you can obtain it at www.aomedia.org/license/patent.

#[macro_use]
extern crate log;

mod common;
mod decoder;
mod error;
mod muxer;
mod stats;

use crate::common::*;
use crate::error::*;
use crate::stats::*;
use rav1e::config::CpuFeatureLevel;
use rav1e::prelude::*;

use crate::decoder::{Decoder, FrameBuilder, VideoDetails};
use crate::muxer::*;
use std::io::Read;
use std::process::exit;
use std::sync::Arc;

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
        ctx.flush();
      }
    };
    Ok(())
  }
}

// Encode and write a frame.
// Returns frame information in a `Result`.
#[profiling::function]
fn process_frame<T: Pixel, D: Decoder>(
  ctx: &mut Context<T>, output_file: &mut dyn Muxer, source: &mut Source<D>,
  metrics_cli: MetricsEnabled,
) -> Result<Option<Vec<FrameSummary>>, CliError> {
  let y4m_details = source.input.get_video_details();

  let mut frame_summaries = Vec::new();

  let pkt_wrapped = ctx.receive_packet();

  let (ret, _emit_pass_data) = match pkt_wrapped {
    Ok(pkt) => {
      output_file.write_frame(
        pkt.input_frameno,
        pkt.data.as_ref(),
        pkt.frame_type,
      );

      // println!("frame {:?}", pkt.data);

      frame_summaries.push(build_frame_summary(
        pkt,
        y4m_details.bit_depth,
        y4m_details.chroma_sampling,
        metrics_cli,
      ));

      Ok((Some(frame_summaries), true))
    }

    Err(EncoderStatus::NeedMoreData) => {
      // TODO: this is the place when i need a get a next frame and add the ctx
      // ctx.send_frame()
      source.read_frame(ctx, y4m_details)?;
      Ok((Some(frame_summaries), false))
    }

    Err(EncoderStatus::EnoughData) => {
      unreachable!()
    }

    Err(EncoderStatus::LimitReached) => Ok((None, true)),

    Err(e @ EncoderStatus::Failure) => {
      Err(e.context("Failed to encode video"))
    }

    Err(e @ EncoderStatus::NotReady) => {
      Err(e.context("Mismanaged handling of two-pass stats data"))
    }

    Err(EncoderStatus::Encoded) => Ok((Some(frame_summaries), true)),
  }?;

  Ok(ret)
}

fn do_encode<T: Pixel, D: Decoder>(
  cfg: Config,
  verbose: Verboseness,
  mut progress: ProgressInfo,
  output: &mut dyn Muxer,
  mut source: Source<D>,
  // mut y4m_enc: Option<y4m::Encoder<Box<dyn Write + Send>>>,
  metrics_enabled: MetricsEnabled,
) -> Result<(), CliError> {
  let mut ctx: Context<T> =
    cfg.new_context().map_err(|e| e.context("Invalid encoder settings"))?;

  while let Some(frame_info) = process_frame(
    &mut ctx,
    &mut *output,
    &mut source,
    // y4m_enc.as_mut(),
    metrics_enabled,
  )? {
    // if verbose != Verboseness::Quiet {
    for frame in frame_info {
      progress.add_frame(frame.clone());
      // if verbose == Verboseness::Verbose {
      println!("{} - {}", frame.frame_type, progress);
      // } else {
      // Print a one-line progress indicator that overrides itself with every update
      // eprint!("\r{progress}                    ");
      // };
    }

    output.flush().unwrap();
    // }
  }
  // if verbose != Verboseness::Quiet {
  // if verbose == Verboseness::Verbose {
  // eprint!("\r");
  // }
  progress.print_summary(true);
  // }
  Ok(())
}

fn build_frame<T: Pixel, F: FrameBuilder<T>>(
  ctx: &F, bytes_per_sample: usize, width: usize, chroma_width: usize,
  y_plane: &[u8], u_plane: &[u8], v_plane: &[u8],
) -> Frame<T> {
  let mut f = ctx.new_frame();

  f.planes[0].copy_from_raw_u8(
    y_plane,
    width * bytes_per_sample,
    bytes_per_sample,
  );

  f.planes[1].copy_from_raw_u8(
    u_plane,
    chroma_width * bytes_per_sample,
    bytes_per_sample,
  );

  f.planes[2].copy_from_raw_u8(
    v_plane,
    chroma_width * bytes_per_sample,
    bytes_per_sample,
  );

  f
}

fn encode(frames: impl Iterator<Item = Frame<u8>>) {}

fn main() {
  run().unwrap_or_else(|e| {
    error::print_error(&e);
    exit(1);
  });
}

fn run() -> Result<(), error::CliError> {
  let mut cli = parse_cli()?;

  // Maximum frame size by specification + maximum y4m header
  let limit = y4m::Limits {
    // Use saturating operations to gracefully handle 32-bit architectures
    bytes: 64usize
      .saturating_mul(64)
      .saturating_mul(4096)
      .saturating_mul(2304)
      .saturating_add(1024),
  };

  let mut y4m_dec = match y4m::Decoder::new_with_limits(cli.io.input, limit) {
    Err(e) => {
      return Err(CliError::new(match e {
        y4m::Error::ParseError(_) => {
          "Could not parse input video. Is it a y4m file?"
        }
        y4m::Error::IoError(_) => {
          "Could not read input file. Check that the path is correct and you have read permissions."
        }
        y4m::Error::UnknownColorspace => {
          "Unknown colorspace or unsupported bit depth."
        }
        y4m::Error::OutOfMemory => "The video's frame size exceeds the limit.",
        y4m::Error::EOF => "Unexpected end of input.",
        y4m::Error::BadInput => "Bad y4m input parameters provided.",
      }))
    }
    Ok(d) => d,
  };
  let video_info = y4m_dec.get_video_details();

  cli.enc.width = video_info.width;
  cli.enc.height = video_info.height;
  cli.enc.sample_aspect_ratio = video_info.sample_aspect_ratio;
  cli.enc.bit_depth = video_info.bit_depth;
  cli.enc.chroma_sampling = video_info.chroma_sampling;
  cli.enc.chroma_sample_position = video_info.chroma_sample_position;

  // If no pixel range is specified via CLI, assume limited,
  // as it is the default for the Y4M format.
  if !cli.color_range_specified {
    cli.enc.pixel_range = PixelRange::Limited;
  }

  if !cli.override_time_base {
    cli.enc.time_base = video_info.time_base;
  }

  if cli.photon_noise > 0 && cli.enc.film_grain_params.is_none() {
    cli.enc.film_grain_params = Some(vec![generate_photon_noise_params(
      0,
      u64::MAX,
      NoiseGenArgs {
        iso_setting: cli.photon_noise as u32 * 100,
        width: video_info.width as u32,
        height: video_info.height as u32,
        transfer_function: if cli.enc.is_hdr() {
          TransferFunction::SMPTE2084
        } else {
          TransferFunction::BT1886
        },
        chroma_grain: false,
        random_seed: None,
      },
    )]);
  }

  let cfg = Config::new()
    .with_encoder_config(cli.enc.clone())
    .with_threads(cli.threads);

  cli.io.output.write_header(
    video_info.width,
    video_info.height,
    cli.enc.time_base.den as usize,
    cli.enc.time_base.num as usize,
  );

  let tiling =
    cfg.tiling_info().map_err(|e| e.context("Invalid configuration"))?;
  if cli.verbose != Verboseness::Quiet {
    info!("CPU Feature Level: {}", CpuFeatureLevel::default());

    info!(
      "Using y4m decoder: {}x{}p @ {}/{} fps, {}, {}-bit",
      video_info.width,
      video_info.height,
      video_info.time_base.den,
      video_info.time_base.num,
      video_info.chroma_sampling,
      video_info.bit_depth
    );
    info!("Encoding settings: {}", cli.enc);

    if tiling.tile_count() == 1 {
      info!("Using 1 tile");
    } else {
      info!(
        "Using {} tiles ({}x{})",
        tiling.tile_count(),
        tiling.cols,
        tiling.rows
      );
    }
  }

  let progress = ProgressInfo::new(
    Rational { num: video_info.time_base.den, den: video_info.time_base.num },
    if cli.limit == 0 { None } else { Some(cli.limit) },
    MetricsEnabled::All,
  );

  for _ in 0..cli.skip {
    match y4m_dec.read_frame() {
      Ok(f) => f,
      Err(_) => {
        return Err(CliError::new("Skipped more frames than in the input"))
      }
    };
  }

  let source = Source::new(cli.limit, y4m_dec);

  // output is a `create_muxer` from src/bin/muxer/mod.rs
  if video_info.bit_depth == 8 && !cli.force_highbitdepth {
    do_encode::<u8, y4m::Decoder<Box<dyn Read + Send>>>(
      cfg,
      cli.verbose,
      progress,
      &mut *cli.io.output,
      source,
      MetricsEnabled::All,
    )?
  } else {
    do_encode::<u16, y4m::Decoder<Box<dyn Read + Send>>>(
      cfg,
      cli.verbose,
      progress,
      &mut *cli.io.output,
      source,
      MetricsEnabled::All,
    )?
  }

  Ok(())
}
