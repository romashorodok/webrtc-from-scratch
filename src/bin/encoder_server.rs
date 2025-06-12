use bytes::Bytes;
use num_traits::FromPrimitive;
use rav1e::prelude::*;
use serde::Deserialize;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::HashSet, error::Error, sync::Arc};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::{select, sync::RwLock};
use v_frame::pixel::ChromaSampling;
use zeromq::{prelude::*, ZmqMessage};

#[derive(Debug, Deserialize)]
struct RemoteConfig {
    width: usize,
    height: usize,
    bit_depth: usize,
    chroma_sampling: u64,

    sample_aspect_ratio_num: u64,
    sample_aspect_ratio_den: u64,

    time_base_num: u64,
    time_base_dem: u64,
}

struct Encoder {
    ctx: Context<u8>,
}

impl Encoder {
    fn new(remote: RemoteConfig) -> Result<Self, Box<dyn Error>> {
        let mut enc_cfg = EncoderConfig::with_speed_preset(10);
        enc_cfg.speed_settings = SpeedSettings::from_preset(10);

        enc_cfg.width = remote.width;
        enc_cfg.height = remote.height;
        enc_cfg.enable_timing_info = false;
        enc_cfg.low_latency = true;
        enc_cfg.tune = Tune::Psnr;
        enc_cfg.chroma_sample_position = ChromaSamplePosition::Vertical;
        enc_cfg.quantizer = 200;
        enc_cfg.min_quantizer = 200;
        enc_cfg.min_key_frame_interval = 15;
        enc_cfg.max_key_frame_interval = 30;
        enc_cfg.reservoir_frame_delay = Some(15);
        enc_cfg.tile_cols = 2;
        enc_cfg.tile_rows = 2;
        enc_cfg.tiles = 0;
        enc_cfg.bitrate = 0;

        enc_cfg.bit_depth = remote.bit_depth;
        enc_cfg.chroma_sampling = ChromaSampling::from_u64(remote.chroma_sampling).unwrap();
        enc_cfg.sample_aspect_ratio = Rational::new(
            remote.sample_aspect_ratio_num,
            remote.sample_aspect_ratio_den,
        );
        enc_cfg.time_base = Rational::new(remote.time_base_num, remote.time_base_dem);

        let cfg = Config::new()
            .with_encoder_config(enc_cfg)
            .with_threads(8)
            .with_parallel_gops(2);

        // let tiling = cfg.tiling_info()?;

        // if tiling.tile_count() == 1 {
        //     println!("Using 1 tile");
        // } else {
        //     println!(
        //         "Using {} tiles ({}x{})",
        //         tiling.tile_count(),
        //         tiling.cols,
        //         tiling.rows
        //     );
        // }

        let ctx = cfg.new_context::<u8>()?;

        println!("Encoder context {:?}", ctx);

        Ok(Self { ctx })
    }

    fn write(
        &mut self,
        bytes_per_pixel: usize,
        width: usize,
        chroma_width: usize,
        y_plane: Vec<u8>,
        u_plane: Vec<u8>,
        v_plane: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let mut f = self.ctx.new_frame();

        f.planes[0].copy_from_raw_u8(
            y_plane.as_slice(),
            width, // stride in bytes
            1,     // bytes per pixel (8-bit)
        );

        // U plane
        f.planes[1].copy_from_raw_u8(u_plane.as_slice(), chroma_width, 1);

        // V plane
        f.planes[2].copy_from_raw_u8(v_plane.as_slice(), chroma_width, 1);

        self.ctx.send_frame(Some(Arc::new(f))).unwrap();
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let controller_ipc = "ipc:///tmp/transport.sock";
    let frame_receiver_ipc = "ipc:///tmp/yuv.sock";

    let _ = std::fs::remove_file("/tmp/transport.sock");
    let _ = std::fs::remove_file("/tmp/yuv.sock");

    let mut controller = zeromq::RouterSocket::new();
    controller.bind(controller_ipc).await?;

    let mut frame_receiver = zeromq::PullSocket::new();
    frame_receiver.bind(frame_receiver_ipc).await?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(30 * 5);

    let (heartbeat_tx, mut heartbeat_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let heartbeat_tx = Arc::new(Mutex::new(heartbeat_tx));

    let encoder: Arc<RwLock<Option<Encoder>>> = Arc::new(RwLock::new(None));
    let encoder_notify = Arc::new(Notify::new());

    let heartbeat = Arc::clone(&heartbeat_tx);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(4));
            let _ = heartbeat.lock().await.send(Bytes::from("heartbeat").into());
        }
    });

    let notify = encoder_notify.clone();
    let enc = encoder.clone();
    tokio::spawn(async move {
        'l: loop {
            {
                loop {
                    let read_guard = enc.read().await;
                    if read_guard.is_some() {
                        break;
                    }
                    drop(read_guard);
                    notify.notified().await;
                }

                if let Some(enc) = enc.write().await.as_mut() {
                    match enc.ctx.receive_packet() {
                        Ok(pkt) => {
                            tx.send(pkt.data).await.unwrap();
                            continue 'l;
                            // println!("encoded packet frame {:?}", pkt);
                            // Ok(pkt.data)
                        }
                        Err(EncoderStatus::NeedMoreData) => {
                            if let Ok(msg) = frame_receiver.recv().await {
                                let _: Result<_, Box<dyn std::error::Error>> = (|| {
                                    if msg.len() < 6 {
                                        return Err("expected at least 6 message parts".into());
                                    }

                                    let id1 = u32::from_be_bytes(
                                        msg.get(0)
                                            .ok_or("missing msg part 0")?
                                            .slice(0..4)
                                            .as_ref()
                                            .try_into()?,
                                    ) as usize;

                                    let id2 = u32::from_be_bytes(
                                        msg.get(1)
                                            .ok_or("missing msg part 1")?
                                            .slice(0..4)
                                            .as_ref()
                                            .try_into()?,
                                    ) as usize;

                                    let id3 = u32::from_be_bytes(
                                        msg.get(2)
                                            .ok_or("missing msg part 2")?
                                            .slice(0..4)
                                            .as_ref()
                                            .try_into()?,
                                    ) as usize;

                                    let data1 = msg.get(3).ok_or("missing msg part 3")?.to_vec();
                                    let data2 = msg.get(4).ok_or("missing msg part 4")?.to_vec();
                                    let data3 = msg.get(5).ok_or("missing msg part 5")?.to_vec();

                                    enc.write(id1, id2, id3, data1, data2, data3)?;

                                    Ok(())
                                })(
                                );
                            }

                            continue 'l;
                        }
                        Err(EncoderStatus::EnoughData) => {
                            unreachable!()
                        }
                        Err(EncoderStatus::LimitReached) => {
                            println!("limit reached");
                            unreachable!()
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
                            continue 'l;
                        }
                    };
                }
            }

            // match msg {
            //     Ok(msg) => {
            //         println!("[Encoder] Got frame, broadcasting {:?} bytes", msg);
            //     }
            //     Err(_) => continue,
            // }
        }
    });

    let client_identities = Arc::new(RwLock::new(HashSet::<Bytes>::new()));
    let identities = Arc::clone(&client_identities);

    let current_sender = Arc::new(RwLock::new(Option::<Bytes>::None));

    let heartbeat = Arc::clone(&heartbeat_tx);
    let notify = encoder_notify.clone();
    let enc = encoder.clone();
    'l: loop {
        select! {
            Ok(incoming) = controller.recv() => {
                if let Some(identity) = incoming.get(0) {
                    {
                        let mut guard = client_identities.write().await;
                        guard.insert(identity.clone());
                    }

                    {
                        if let Some(sender) = current_sender.read().await.as_ref() {
                            let identities = client_identities.read().await;
                            if !identities.contains(sender) {
                                let mut new_sender = current_sender.write().await;
                                *new_sender = None
                            }
                        }

                    }

                    {
                        let mut sender_guard = current_sender.write().await;
                        println!("sender?? {:?}", sender_guard);
                        if sender_guard.is_none() {
                            // Assign the first connected client as sender
                            let msg = ZmqMessage::try_from(vec![identity.clone(), Bytes::from("nominated")]).unwrap();
                            controller.send(msg).await?;
                            *sender_guard = Some(identity.clone());
                            println!("Assigned new sender: {:?}", identity);
                            notify.notify_waiters();

                            continue 'l;
                        }

                    }


                    if let Some(message) = incoming.get(1) {
                        let message_type: &str = std::str::from_utf8(message)?;

                        match message_type {
                            "config" => {
                                let data = incoming.get(2);
                                if let Some(json) = data {
                                    let config: RemoteConfig =  serde_json::from_slice(json.to_vec().as_slice())?;

                                    {
                                        let mut enc_guard = enc.write().await;
                                        match Encoder::new(config) {
                                            Ok(encoder) => {
                                                *enc_guard = Some(encoder);
                                                notify.notify_waiters();
                                            }
                                            Err(err) => {
                                                println!("Unexpected encoder config {:?}", err);
                                            }
                                        }

                                    }

                                    continue 'l;
                                }
                            },
                            "bitrate" => {},
                            _ => {}
                        }


                    }

                    println!("Received: {:?}", incoming);
                    let reply = ZmqMessage::try_from(vec![identity.clone(), Bytes::from("connected")]).unwrap();
                    notify.notify_waiters();
                    controller.send(reply).await?;
                }
            }


            Some(msg) = rx.recv() => {

                {
                    let identities_guard = identities.read().await;
                    for identity in identities_guard.iter() {
                        let frame =
                            ZmqMessage::try_from(vec![identity.clone(), Bytes::from("frame") , msg.clone().into()]).unwrap();

                        match controller.send(frame).await {
                            Ok(_) => continue,
                            Err(err) => {
                                println!("error sending to {:?}: {:?}", identity, err);
                                let _ = heartbeat.lock().await.send(Bytes::from("heartbeat").into());
                            }
                        }
                    }
                }

            }

            Some(heartbeat) = heartbeat_rx.recv() => {
                let mut to_remove = Vec::new();

                {
                    let identities_guard = identities.read().await;
                    for identity in identities_guard.iter() {
                        let message =
                            ZmqMessage::try_from(vec![identity.clone(), Bytes::from("heartbeat") , heartbeat.clone().into()]).unwrap();

                        match controller.send(message).await {
                            Ok(_) => continue,
                            Err(err) => {
                                println!("error sending heartbeat to {:?}: {:?}", identity, err);
                                to_remove.push(identity.clone());
                            }
                        }
                    }
                }

                let mut was_sender_removed = false;

                if !to_remove.is_empty() {
                    let mut identities_guard = identities.write().await;
                    let mut sender_guard = current_sender.write().await;

                    for id in &to_remove {
                        identities_guard.remove(id);
                        if sender_guard.as_ref() == Some(id) {
                            was_sender_removed = true;
                        }
                    }

                    println!("was sender removed? {:?}", was_sender_removed);

                    if was_sender_removed {
                        *sender_guard = None;
                        if let Some(new_sender) = identities_guard.iter().next() {
                            println!("new sender");
                            let msg = ZmqMessage::try_from(vec![new_sender.clone(), Bytes::from("nominated")]).unwrap();
                            controller.send(msg).await?;
                            *sender_guard = Some(new_sender.clone());
                        }
                    }
                }
            }
        }
    }
}
