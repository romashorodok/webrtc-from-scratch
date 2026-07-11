# Full Peer Connection E2E Performance Tracing Plan

## Goal

Review and extend tracing/performance coverage for the complete peer connection packet pipeline, from UDP socket ingress/egress through ICE, DTLS, SRTP, RTP/RTCP media handling, and application-visible packet receipt.

This document is a plan only. No runtime implementation is marked complete here.

## Current State

Existing coverage already includes:

- SDP offer/answer phase timing.
- ICE gather, remote credential/candidate setup, candidate-pair creation, STUN send/receive, pair success, nomination, and transport readiness.
- DTLS start, record transmit/receive, handshake completion, SRTP key derivation, and SRTP readiness.
- AV1 RTP packetization/depacketization and TWCC feedback confirmation in an isolated media performance test.

Known gaps in the full peer connection E2E path:

- UDP socket datagram receive/send boundaries are not explicit performance events.
- ICE packet classification/demux into DTLS, RTP, and RTCP queues is not fully traced.
- Candidate-pair controller task lifecycle is traced by task context, but packet-level processing inside the loop needs phase events.
- DTLS record parsing/reconstruction is partially traced, but queue wait, parse, reconstruct, and FSM dispatch are not separated enough to identify CPU-bound work.
- SRTP RTP/RTCP encrypt/decrypt operations are synchronous and not individually covered by performance events.
- SRTP stream creation, stream queue delivery, and stream drops are not asserted in the E2E baseline.
- RTP sender frame packetization and network send are not covered in the full secured peer-connection loopback test.
- RTCP transmit/receive and feedback confirmation are covered in the isolated TWCC test, not in the full peer-connection E2E pipeline.
- Peer-level public send helpers exist in `PeerContext`, but the corresponding `PeerConnection` media send path should be reviewed before tests rely on it.
- CPU-bound operations are not consistently marked as `bounded` peer tasks or offloaded through the runtime executor.

## Pipeline To Cover

Target packet path:

1. Application or test creates an AV1 frame.
2. RTP packetizer creates one or more RTP packets.
3. RTP packets include transport-wide sequence numbers where negotiated/used.
4. Peer connection sends RTP through DTLS/SRTP.
5. SRTP encrypts RTP.
6. ICE selected candidate-pair transport sends the encrypted packet.
7. UDP socket transmits the datagram.
8. Remote UDP socket receives the datagram.
9. ICE candidate-pair controller receives the datagram.
10. ICE demux routes it to DTLS, RTP, or RTCP.
11. RTP receive loop passes encrypted RTP to SRTP.
12. SRTP decrypts RTP.
13. SRTP routes decrypted RTP to the correct stream by SSRC.
14. RTP receiver/track reads the packet.
15. Test depacketizes AV1 and verifies the frame bytes.
16. Receiver emits RTCP/TWCC confirmation for every received transport sequence.
17. Sender receives and parses RTCP feedback.
18. Test verifies every sent RTP packet has a corresponding confirmation.

## Stage 0: Coverage Audit

Status: planned

Tasks:

- Inventory every packet boundary from `webrtc/ice/net/udp_mux.py`, `webrtc/ice/agent.py`, `webrtc/dtls/dtlstransport.py`, `webrtc/srtp/session.py`, `webrtc/transceiver.py`, `webrtc/peer_connection.py`, and `webrtc/peer_context.py`.
- Produce a trace coverage matrix with these columns:
  - component
  - boundary
  - current event
  - missing event
  - expected counter
  - CPU-bound risk
  - offload candidate
- Compare matrix against current baselines:
  - `tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json`
  - `tests/performance/baselines/av1_rtp_packetization_twcc.json`

Done when:

- Every socket-to-track boundary is classified as covered, partially covered, or missing.
- Every missing event has a proposed event name and counter.

## Stage 1: Trace Event Contract

Status: planned

Add or standardize event names before implementation:

- `udp.datagram.tx`
- `udp.datagram.rx`
- `ice.packet_demux.dtls`
- `ice.packet_demux.rtp`
- `ice.packet_demux.rtcp`
- `ice.controller.loop_started`
- `ice.controller.packet_received`
- `ice.controller.packet_routed`
- `dtls.record.parse.started`
- `dtls.record.parse.completed`
- `dtls.record.reconstruct.started`
- `dtls.record.reconstruct.completed`
- `dtls.fsm.dispatch.started`
- `dtls.fsm.dispatch.completed`
- `srtp.rtp_encrypt.started`
- `srtp.rtp_encrypt.completed`
- `srtp.rtcp_encrypt.started`
- `srtp.rtcp_encrypt.completed`
- `srtp.rtp_decrypt.started`
- `srtp.rtp_decrypt.completed`
- `srtp.rtcp_decrypt.started`
- `srtp.rtcp_decrypt.completed`
- `srtp.stream.created`
- `srtp.stream.delivered`
- `srtp.stream.dropped`
- `rtp.frame.packetize.started`
- `rtp.frame.packetize.completed`
- `rtp.packet.send.started`
- `rtp.packet.send.completed`
- `rtp.packet.receive.completed`
- `rtp.frame.verified`
- `rtcp.feedback.send.completed`
- `rtcp.feedback.receive.completed`
- `rtcp.twcc.confirmed`

Counter metadata should use the existing `counter.*` convention:

- `counter.udp.datagrams_tx`
- `counter.udp.datagrams_rx`
- `counter.ice.demux_dtls`
- `counter.ice.demux_rtp`
- `counter.ice.demux_rtcp`
- `counter.srtp.rtp_encrypted`
- `counter.srtp.rtp_decrypted`
- `counter.srtp.rtcp_encrypted`
- `counter.srtp.rtcp_decrypted`
- `counter.srtp.stream_packets_delivered`
- `counter.rtp.packets_sent`
- `counter.rtp.packets_received`
- `counter.rtcp.feedback_sent`
- `counter.rtcp.feedback_received`
- `counter.rtcp.confirmed_packets`

Done when:

- Event names are documented and do not conflict with current baselines.
- Every event has clear ownership and expected metadata.

## Stage 2: Socket And ICE Tracing

Status: planned

Areas:

- `webrtc/ice/net/udp_mux.py`
- `webrtc/ice/agent.py`

Tasks:

- Trace UDP datagram send/receive with address, port, and size.
- Trace ICE controller packet receive before STUN/non-STUN branching.
- Trace ICE demux result for DTLS, RTP, and RTCP.
- Trace queue insertion failures or drops if queue limits are added later.

CPU-bound review:

- Keep socket callback work minimal.
- Do not parse full RTP/RTCP payloads inside `datagram_received`.
- Do only classification and queue handoff in the hot socket callback.

Done when:

- Full E2E baseline can assert UDP tx/rx and demux counters.

## Stage 3: DTLS Tracing And Offload Review

Status: planned

Areas:

- `webrtc/dtls/dtlstransport.py`
- `webrtc/dtls/fsm.py`
- `webrtc/dtls/handshake_reconstructor.py`
- `webrtc/dtls/dtls_record.py`

Tasks:

- Split DTLS receive instrumentation into parse, reconstruct, enqueue, and FSM dispatch events.
- Mark long-running receive loops as task ownership traces only, not phase duration metrics.
- Add failure events for malformed records, reconstruction failures, and FSM dispatch failures.
- Review CPU-heavy areas:
  - record batch parsing
  - handshake reconstruction
  - certificate verification
  - key derivation
  - crypto operations in handshake flights

Optimization suggestion:

- Keep FSM orchestration on the event loop.
- Offload expensive certificate/key/crypto helper calls through `PeerContext.offload_sync()` or runtime executor only when measurement shows they block the loop.
- Use `bounded=True` metadata for short protocol tasks that must complete, and `expected_long_running=True` for loops.

Done when:

- DTLS timings identify whether time is spent waiting for network, parsing records, reconstructing handshake bytes, or dispatching FSM work.

## Stage 4: SRTP RTP/RTCP Tracing

Status: planned

Areas:

- `webrtc/srtp/session.py`
- `webrtc/dtls/dtlstransport.py`

Tasks:

- Trace RTP and RTCP encryption separately.
- Trace RTP and RTCP decryption separately.
- Trace SRTP stream creation and packet delivery by SSRC.
- Trace stream queue drops as forbidden events in performance baselines.
- Add metadata for packet type, SSRC, sequence number when available, and encrypted/decrypted size.

CPU-bound review:

- SRTP crypto is synchronous today.
- Measure it first; if it shows loop blocking under burst load, move burst encryption/decryption to executor-backed `offload_sync`.
- Avoid offloading single tiny packets unless measurements show benefit, because thread handoff may cost more than crypto.

Done when:

- E2E test proves encrypted RTP and RTCP packets are decrypted and delivered to streams.

## Stage 5: PeerConnection Public Media Send Path

Status: planned

Areas:

- `webrtc/peer_connection.py`
- `webrtc/peer_context.py`
- `webrtc/transceiver.py`

Tasks:

- Review and finalize public methods needed by tests and applications:
  - `PeerConnection.send_rtp_packet`
  - `PeerConnection.send_rtp_packets`
  - `PeerConnection.send_rtcp_packet`
  - existing `PeerContext` wrappers
- Ensure send helpers wait for SRTP readiness and selected transport readiness.
- Trace send start/completion/failure.
- Keep packet mutation, serialization, and encryption boundaries separate.

CPU-bound review:

- Packetization and serialization may remain inline for small packets.
- AV1 packetization bursts should be measured as a candidate for executor offload.
- Batch send should avoid per-packet task spawning; prefer one bounded task for a burst.

Done when:

- Tests can send media through public peer APIs without reaching through private fields.

## Stage 6: Full AV1 RTP E2E Test

Status: planned

Areas:

- `tests/performance/test_peer_connection_e2e_perf.py`
- `tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json`
- optional new baseline: `pc_e2e_loopback_av1_rtp_rtcp_twcc.json`

Tasks:

- Extend or add a loopback E2E test after ICE/DTLS/SRTP readiness.
- Use AV1 media, not Opus.
- Generate deterministic AV1 frame bytes.
- Packetize into RTP packets with TWCC transport sequence extensions.
- Send packets through peer connection public APIs.
- Receive packets from the remote track/stream.
- Parse RTP and verify:
  - payload type
  - SSRC
  - sequence continuity
  - timestamp continuity
  - marker on final packet
  - TWCC extension on every packet
- Depacketize and verify the reconstructed frame equals the original bytes.
- Generate RTCP/TWCC feedback for all received packets.
- Send feedback through the reverse secured path.
- Parse sender-side RTCP feedback and verify every RTP packet has confirmation.

Done when:

- The test fails if any RTP packet is lost, reordered unexpectedly, missing TWCC, not delivered to SRTP stream, or not confirmed by RTCP feedback.

## Stage 7: Baseline Expansion

Status: planned

Tasks:

- Update E2E baseline required events after instrumentation lands.
- Add forbidden events:
  - `udp.datagram.failed`
  - `ice.packet_demux.failed`
  - `dtls.record.parse.failed`
  - `dtls.record.reconstruct.failed`
  - `srtp.rtp_encrypt.failed`
  - `srtp.rtp_decrypt.failed`
  - `srtp.rtcp_encrypt.failed`
  - `srtp.rtcp_decrypt.failed`
  - `srtp.stream.dropped`
  - `rtp.packet.send.failed`
  - `rtcp.feedback.send.failed`
- Add counters for full path:
  - UDP tx/rx
  - ICE demux RTP/RTCP/DTLS
  - SRTP encrypt/decrypt
  - RTP sent/received
  - RTCP feedback sent/received
  - TWCC confirmed packets
  - verified frames

Done when:

- Baseline catches missing trace coverage and packet-path regressions.

## Stage 8: CPU-Bound Optimization Plan

Status: planned

Candidate operations to measure first:

- SDP generation and codec matching.
- ICE candidate parsing and mDNS resolution.
- STUN attribute parse/encode under high packet rate.
- DTLS record parsing and handshake reconstruction.
- DTLS key derivation and certificate operations.
- SRTP RTP/RTCP crypto under burst.
- RTP packet serialization/parsing.
- AV1 packetization/depacketization.
- RTCP/TWCC feedback generation and parsing.

Offload rules:

- Keep event-loop work limited to socket callbacks, queue handoff, state transitions, and scheduling.
- Use `spawn_peer_task` for protocol loops and bounded peer operations.
- Use `PeerContext.offload_sync()` or runtime executor for CPU-bound synchronous work once measured.
- Prefer batch offload for bursts over one executor hop per packet.
- Preserve packet ordering when offloading RTP/RTCP work.
- Include trace metadata:
  - `bounded`
  - `component`
  - `operation`
  - `batch_size`
  - `ssrc`
  - `packet_count`

Done when:

- There is an evidence-backed list of operations to offload and a list of operations intentionally kept inline.

## Stage 9: Review Checklist

Status: planned

Review must verify:

- No packet-path trace creates heavy work in UDP callbacks.
- No long-running loop is measured as a completed phase.
- Every spawned peer task has component metadata.
- CPU-bound offload uses runtime/peer context, not ad hoc thread creation.
- Tests use public APIs where possible.
- Full E2E test proves socket-to-receive packet delivery, not only readiness.
- RTCP/TWCC confirms every sent RTP transport sequence.
- Baselines include forbidden failure/drop events.
- Existing Stage 7 isolated AV1/TWCC test remains useful as a unit-style performance guard.

## Immediate Next Task

Start with Stage 0 and produce the coverage matrix before touching runtime code. That matrix decides the exact implementation order and prevents adding trace events that are expensive or redundant.
