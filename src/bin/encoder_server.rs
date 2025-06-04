use bytes::Bytes;
use rav1e::prelude::*;
use serde::Deserialize;
use std::{collections::HashSet, error::Error, sync::Arc, thread::sleep, time::Duration};
use tokio::{
    select,
    sync::{mpsc, RwLock},
};
use zeromq::{prelude::*, ZmqMessage};

#[derive(Debug, Deserialize)]
struct EncoderConfig {
    width: usize,
    height: usize,
    bit_depth: usize,
    chroma_sampling: u64,

    sample_aspect_ratio_num: u64,
    sample_aspect_ratio_den: u64,

    time_base_num: u64,
    time_base_dem: u64,
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

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(async move {
        loop {
            let msg = frame_receiver.recv().await;
            match msg {
                Ok(msg) => {
                    println!("[Encoder] Got frame, broadcasting {:?} bytes", msg);
                }
                Err(_) => continue,
            }
        }
    });

    let client_identities = Arc::new(RwLock::new(HashSet::<Bytes>::new()));
    let identities = Arc::clone(&client_identities);

    let current_sender = Arc::new(RwLock::new(Option::<Bytes>::None));

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(60));
            let _ = tx.send(Bytes::from("test").into());
        }
    });

    println!("hello world");
    'l: loop {
        select! {
            Ok(incoming) = controller.recv() => {
                if let Some(identity) = incoming.get(0) {
                    {
                        let mut guard = client_identities.write().await;
                        guard.insert(identity.clone());
                    }

                    {
                        let mut sender_guard = current_sender.write().await;
                        if sender_guard.is_none() {
                            // Assign the first connected client as sender
                            let msg = ZmqMessage::try_from(vec![identity.clone(), Bytes::from("nominated")]).unwrap();
                            controller.send(msg).await?;
                            *sender_guard = Some(identity.clone());
                            println!("Assigned new sender: {:?}", identity);
                            continue 'l;
                        }
                    }

                    if let Some(message) = incoming.get(1) {
                        let message_type: &str = std::str::from_utf8(message)?;

                        match message_type {
                            "config" => {
                                let data = incoming.get(2);
                                if let Some(json) = data {
                                    let config: EncoderConfig =  serde_json::from_slice(json.to_vec().as_slice())?;
                                    println!("got the config {:?}", config);
                                    continue 'l;
                                }
                            },
                            "bitrate" => {},
                            _ => {}
                        }


                    }

                    println!("Received: {:?}", incoming);
                    let reply = ZmqMessage::try_from(vec![identity.clone(), Bytes::from("connected")]).unwrap();
                    controller.send(reply).await?;
                }
            }
            Some(msg) = rx.recv() => {
                let mut to_remove = Vec::new();

                {
                    let identities_guard = identities.read().await;
                    for identity in identities_guard.iter() {
                        let frame =
                            ZmqMessage::try_from(vec![identity.clone(), Bytes::from("frame") , msg.clone().into()]).unwrap();

                        // println!("send {:?}", frame);

                        match controller.send(frame).await {
                            Ok(_) => continue,
                            Err(err) => {
                                println!("error sending to {:?}: {:?}", identity, err);
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
