# Full Peer Connection E2E Trace Event Contract

## Status and scope

This is the Stage 1 contract for the packet path audited in
`performance_testing_tracing_full_peer_connection_e2e_coverage_matrix.md`.
It defines instrumentation to be added in later stages; it does not claim that
any listed event is currently emitted.  The contract covers one secured media
flow from RTP frame creation through UDP, ICE, DTLS/SRTP, remote track delivery,
and RTCP/TWCC feedback.

An event name is `component.phase.state`, matching `perf_mark(component, phase,
state)`.  `started`/`completed`/`failed` are one measured operation: a matching
terminal event carries `duration_ms`; the start event does not.  Instantaneous
boundary marks (for example `udp.datagram.tx`) do not carry `duration_ms`.

## Common rules

### Ownership and correlation

- The component that performs the boundary owns its event.  Callers must not
  duplicate a successful downstream event merely because they await it.
- `perf_mark` already adds available task context (`trace_id`,
  `parent_trace_id`, `task_name`, `task_kind`, `peer_id`, `bounded`, and
  `app_task`). Implementations must preserve that behavior and must not
  overwrite those keys.
- Every event must include `flow_direction` (`"tx"` or `"rx"`) when a direction
  exists. Events associated with selected ICE transport include `pair_id`.
- Packet identifiers are included only when available at that boundary:
  `ssrc`, `sequence_number`, and `transport_sequence_number`.  Values are
  integers. `packet_kind` is one of `"rtp"`, `"rtcp"`, `"dtls"`, `"stun"`, or
  `"unknown"`.
- Network endpoints use `local_address`, `local_port`, `remote_address`, and
  `remote_port`; packet sizes use `size_bytes`, `plaintext_size_bytes`, or
  `ciphertext_size_bytes`. Do not record payload bytes, SRTP keys, DTLS
  handshake contents, ICE credentials, or raw certificate material.
- Every `*.failed` event includes `error_stage` and `exception_class` when an
  exception exists. `error_code` is included when a protocol/library error code
  exists. Failure metadata must retain safe correlation fields known before the
  failure.
- Every lifecycle operation explicitly defined with `started`/`completed`/
  `failed` includes an opaque `operation_id`; terminal events reuse the start
  event's value. The identifier is unique within one recorder and contains no
  packet payload or credential. This is required even when the current
  implementation is serial: later batch or executor work may overlap
  operations. Stage 2+ must extend summary pairing to use `(component, phase,
  operation_id)` before concurrent operations are introduced. Events specified
  only as `completed`/`failed` (RTP receive, frame verification, RTCP feedback,
  and TWCC confirmation) are instantaneous boundary marks and do not have an
  `operation_id` requirement.

### Counter convention

- Counters are integer deltas in metadata keys beginning `counter.`. The
  summary strips that prefix and sums the values.
- A successful packet/unit counter is emitted once, on its canonical completed
  or instantaneous success event, never on `started`. A failure counter is
  emitted once on the corresponding `failed` event. A dropped packet is not a
  delivered/decrypted/received packet.
- `counter.rtp.packets_sent` means plaintext RTP packets accepted for secured
  transport (the successful `rtp.packet.send.completed` boundary), not UDP
  datagrams. `counter.rtp.packets_received` means packets delivered to the
  application-visible remote track, not merely placed on the ICE RTP queue.
- `counter.rtcp.feedback_sent` and `.feedback_received` count RTCP feedback
  packets at their secure send and sender-side parse boundaries respectively.
  `counter.rtcp.confirmed_packets` counts individual transport sequence numbers,
  so it can exceed the feedback-packet counters.
- `counter.udp.datagrams_*` counts every UDP datagram, including DTLS and
  encrypted RTP/RTCP. It is intentionally not expected to equal an RTP count.

## Event inventory

Required metadata in the table is in addition to the applicable common
metadata above. “Counter” names the only counter emitted by that event unless a
row explicitly lists more than one. Counts with a value derived from a batch
use the actual batch size; all per-packet rows use `1`.

| Event | Owner / boundary | Required metadata | Counter |
| --- | --- | --- | --- |
| `udp.datagram.tx` | `UDPMuxConn.sendto`: datagram handed to asyncio UDP transport | `flow_direction="tx"`, endpoints, `packet_kind`, `size_bytes`, `pair_id` when selected | `counter.udp.datagrams_tx: 1` |
| `udp.datagram.rx` | `InterfaceMuxUDPHandler.datagram_received`: accepted socket datagram before queue handoff | `flow_direction="rx"`, endpoints, `size_bytes` | `counter.udp.datagrams_rx: 1` |
| `udp.datagram.failed` | `UDPMuxConn.sendto` synchronous send failure, or `InterfaceMuxUDPHandler.error_received` asynchronous UDP transport failure | common failure fields, `failure_source` (`"sendto"` or `"error_received"`), endpoints/`size_bytes` when known, `flow_direction="tx"` when egress is known (omit it when `error_received` cannot identify a direction) | `counter.udp.datagrams_failed: 1` |
| `udp.datagram.unbound_dropped` | UDP mux rejects an unbound/unroutable received datagram | `flow_direction="rx"`, remote endpoint, `size_bytes`, `drop_reason="unbound"` | `counter.udp.datagrams_dropped: 1` |
| `ice.controller.loop_started` | `CandidatePairController.start`: ownership marker when the long-running packet loop starts | `pair_id`, `flow_direction="rx"`, `expected_long_running=true` | none |
| `ice.controller.packet_received` | controller dequeues a datagram, before STUN/non-STUN branching | `pair_id`, `flow_direction="rx"`, `size_bytes`, `packet_kind="stun"` or `"unknown"` before non-STUN classification | `counter.ice.controller_packets_received: 1` |
| `ice.controller.packet_routed` | controller completes handoff to STUN handling or the non-STUN transport pipe | `pair_id`, `flow_direction="rx"`, `route` (`"stun"` or `"transport"`), `size_bytes` | `counter.ice.controller_packets_routed: 1` |
| `ice.controller.packet_failed` | controller dequeue/branch/routing fails | common failure fields, `pair_id`, `flow_direction="rx"`, `size_bytes` when known | `counter.ice.controller_packets_failed: 1` |
| `ice.packet_demux.dtls` | `CandidatePairTransport.pipe` classifies and queues a DTLS datagram | `pair_id`, `flow_direction="rx"`, `packet_kind="dtls"`, `size_bytes` | `counter.ice.demux_dtls: 1` |
| `ice.packet_demux.rtp` | transport pipe classifies and queues encrypted RTP | `pair_id`, `flow_direction="rx"`, `packet_kind="rtp"`, `size_bytes`, `ssrc`/`sequence_number` only if already parsed | `counter.ice.demux_rtp: 1` |
| `ice.packet_demux.rtcp` | transport pipe classifies and queues encrypted RTCP | `pair_id`, `flow_direction="rx"`, `packet_kind="rtcp"`, `size_bytes`, `ssrc` when available | `counter.ice.demux_rtcp: 1` |
| `ice.packet_demux.failed` | empty, malformed, unsupported, or queue-rejected non-STUN datagram | common failure fields, `pair_id`, `flow_direction="rx"`, `size_bytes`, `demux_reason` | `counter.ice.demux_failed: 1` |
| `dtls.record.parse.started` / `.completed` / `.failed` | DTLS inbound record-batch parser | `pair_id`, `flow_direction="rx"`, `packet_kind="dtls"`, `input_size_bytes`; terminal events add `record_count` | completed: none (existing per-record `dtls.record.rx` remains the sole owner of `counter.dtls.records_rx`); failed: `counter.dtls.record_parse_failed: 1` |
| `dtls.record.reconstruct.started` / `.completed` / `.failed` | DTLS handshake record reconstructor | `pair_id`, `flow_direction="rx"`, `record_type`, `epoch`, `sequence_number` when available; completed adds `reconstructed_size_bytes` | completed: `counter.dtls.records_reconstructed: 1`; failed: `counter.dtls.record_reconstruct_failed: 1` |
| `dtls.fsm.dispatch.started` / `.completed` / `.failed` | DTLS receive FSM dispatch after parsing/reconstruction | `pair_id`, `flow_direction="rx"`, `record_type`, `epoch`, `sequence_number` when available, `fsm_state` | failed: `counter.dtls.fsm_dispatch_failed: 1` |
| `srtp.rtp_encrypt.started` / `.completed` / `.failed` | `Session.encrypt` called for outgoing RTP | `flow_direction="tx"`, `packet_kind="rtp"`, `ssrc`, `sequence_number`, `plaintext_size_bytes`; completed adds `ciphertext_size_bytes` | completed: `counter.srtp.rtp_encrypted: 1`; failed: `counter.srtp.rtp_encrypt_failed: 1` |
| `srtp.rtcp_encrypt.started` / `.completed` / `.failed` | `Session.encrypt` called for outgoing RTCP | `flow_direction="tx"`, `packet_kind="rtcp"`, `ssrc` when available, `plaintext_size_bytes`; completed adds `ciphertext_size_bytes` | completed: `counter.srtp.rtcp_encrypted: 1`; failed: `counter.srtp.rtcp_encrypt_failed: 1` |
| `srtp.rtp_decrypt.started` / `.completed` / `.failed` | `Session.write_incoming` decrypts ciphertext RTP | `flow_direction="rx"`, `packet_kind="rtp"`, `ciphertext_size_bytes`; completed adds `ssrc`, `sequence_number`, `plaintext_size_bytes` | completed: `counter.srtp.rtp_decrypted: 1`; failed: `counter.srtp.rtp_decrypt_failed: 1` |
| `srtp.rtcp_decrypt.started` / `.completed` / `.failed` | `Session.write_incoming` decrypts ciphertext RTCP | `flow_direction="rx"`, `packet_kind="rtcp"`, `ciphertext_size_bytes`; completed adds `ssrc` when available, `plaintext_size_bytes` | completed: `counter.srtp.rtcp_decrypted: 1`; failed: `counter.srtp.rtcp_decrypt_failed: 1` |
| `srtp.stream.created` | `Session._get_or_create_stream` creates the inbound SSRC stream | `flow_direction="rx"`, `packet_kind`, `ssrc`, `is_new=true` | `counter.srtp.streams_created: 1` |
| `srtp.stream.delivered` | `Stream.write` successfully queues a decrypted packet | `flow_direction="rx"`, `packet_kind`, `ssrc`, `sequence_number` for RTP, `plaintext_size_bytes`, `queue_size` when available | `counter.srtp.stream_packets_delivered: 1` |
| `srtp.stream.dropped` | `Stream.write` cannot queue a decrypted packet | `flow_direction="rx"`, `packet_kind`, `ssrc`, `sequence_number` for RTP, `plaintext_size_bytes`, `drop_reason`, `queue_size`/`queue_capacity` when known | `counter.srtp.stream_packets_dropped: 1` |
| `rtp.frame.packetize.started` / `.completed` / `.failed` | `TrackEncoding.write_frame` / AV1 packetizer turns one frame into RTP packets | `flow_direction="tx"`, `codec`, `frame_bytes`, `mtu`; completed adds `packet_count`, `ssrc`, `timestamp` | completed: `counter.rtp.frames_packetized: 1`, `counter.rtp.packets_packetized: packet_count`; failed: `counter.rtp.frame_packetize_failed: 1` |
| `rtp.packet.send.started` / `.completed` / `.failed` | public peer send path accepts one plaintext RTP packet and completes its secure transport send | `flow_direction="tx"`, `packet_kind="rtp"`, `ssrc`, `sequence_number`, `transport_sequence_number` when used, `plaintext_size_bytes`, `pair_id` when selected | completed: `counter.rtp.packets_sent: 1`; failed: `counter.rtp.packets_send_failed: 1` |
| `rtp.packet.receive.completed` / `.failed` | `TrackRemote` queue delivery makes an RTP packet application-visible | `flow_direction="rx"`, `packet_kind="rtp"`, `ssrc`, `sequence_number`, `transport_sequence_number` when present, `plaintext_size_bytes`; failed includes common failure fields and, for a non-exceptional queue rejection, `error_stage="track_queue_delivery"` plus `drop_reason` | completed: `counter.rtp.packets_received: 1`; failed: `counter.rtp.packets_receive_failed: 1` |
| `rtp.frame.verified` / `.failed` | E2E test/application AV1 depacketization verifies a complete frame | `flow_direction="rx"`, `codec`, `frame_bytes`, `packet_count`, `ssrc`, `timestamp` when known | verified: `counter.rtp.frames_verified: 1`; failed: `counter.rtp.frames_verify_failed: 1` |
| `rtcp.feedback.send.completed` / `.failed` | RTCP feedback has completed SRTP-protected transport send | `flow_direction="tx"`, `packet_kind="rtcp"`, `feedback_type`, `packet_count`, `pair_id`, `ciphertext_size_bytes` when available | completed: `counter.rtcp.feedback_sent: packet_count`; failed: `counter.rtcp.feedback_send_failed: packet_count` |
| `rtcp.feedback.receive.completed` / `.failed` | sender parses and accepts received RTCP feedback | `flow_direction="rx"`, `packet_kind="rtcp"`, `feedback_type`, `packet_count`, `plaintext_size_bytes` | completed: `counter.rtcp.feedback_received: packet_count`; failed: `counter.rtcp.feedback_receive_failed: 1` |
| `rtcp.twcc.confirmed` / `.failed` | parsed TWCC feedback confirms RTP transport sequence numbers | `flow_direction="rx"`, `feedback_type="twcc"`, `base_sequence_number`, `confirmed_packet_count`, `packet_count=1` | confirmed: `counter.rtcp.confirmed_packets: confirmed_packet_count`; failed: `counter.rtcp.twcc_confirm_failed: 1` |

## Baseline compatibility and failure policy

The existing baselines remain valid until their later-stage migration. The
following aliases are deliberately not silently substituted in a baseline:

| Existing isolated-baseline event | Contract event | Migration rule |
| --- | --- | --- |
| `rtp.packetize.started` / `.completed` | `rtp.frame.packetize.started` / `.completed` | Emit/require the contract name in the full E2E baseline; update the isolated baseline in the same intentional migration or temporarily emit both. |
| `media.frame.verified` | `rtp.frame.verified` | Same migration rule; the contract makes the RTP frame boundary explicit. |
| `rtcp.twcc.generated` | no replacement | Retained as feedback-construction instrumentation; it precedes `rtcp.feedback.send.completed`. |
| `dtls.record.tx` / `.rx` | no replacement | Retained record I/O events. `dtls.record.rx` remains the sole producer of `counter.dtls.records_rx`; parse/reconstruct/FSM phase events add timing and failure visibility without duplicating that count. |

The future full-E2E success baseline must forbid every failure event in this
contract. The current baseline checker matches exact event names rather than
wildcards, so it must list each of the following explicitly:
`udp.datagram.failed`, `ice.controller.packet_failed`,
`ice.packet_demux.failed`, `dtls.record.parse.failed`,
`dtls.record.reconstruct.failed`, `dtls.fsm.dispatch.failed`,
`srtp.rtp_encrypt.failed`, `srtp.rtcp_encrypt.failed`,
`srtp.rtp_decrypt.failed`, `srtp.rtcp_decrypt.failed`,
`rtp.frame.packetize.failed`, `rtp.packet.send.failed`,
`rtp.packet.receive.failed`, `rtp.frame.verified.failed`,
`rtcp.feedback.send.failed`, `rtcp.feedback.receive.failed`, and
`rtcp.twcc.confirmed.failed`. It must also forbid `srtp.stream.dropped` and,
in a loopback run that binds both peers, `udp.datagram.unbound_dropped`. It
should require only deterministic success events for the exercised
media/feedback path; DTLS handshake record batch counts remain threshold-based
because flight sizes vary.

## Timing and task boundaries

`CandidatePairController.start`, DTLS inbound receive, RTP receive, RTCP
receive, and remote-track receive are ownership loops. They may expose task
metadata and `expected_long_running=true`, but their lifetime is not a phase
latency metric. The measured phase events above are the latency boundaries.

SRTP crypto, DTLS record parsing/reconstruction, and frame packetization are
measured inline first. This contract does not authorize offloading them. A later
stage may introduce executor work only after burst measurements demonstrate
event-loop blocking; it must retain the same event owner, correlation metadata,
and single-count rules.
