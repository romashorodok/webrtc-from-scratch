# Full Peer Connection E2E CPU-Bound Optimization Plan

## Status

Stage 8 plan only. **No packet-path operation is approved for executor
offload yet.** The current secured AV1 loopback performance test passed on
2026-07-11 (`1 passed in 1.37s`), but its smoke thresholds cover total scenario
time and `rtp.packet.send` latency, not event-loop starvation or an inline vs.
executor comparison. That result proves the path and its trace coverage work;
it does not demonstrate that a CPU-bound bottleneck exists.

The event contract also explicitly requires DTLS parsing/reconstruction, SRTP
crypto, and frame packetization to be measured inline first. This document uses
that as the decision gate rather than treating synchronous implementation as
evidence that it must be offloaded.

## Evidence available now

| Evidence | What it establishes | Limitation |
| --- | --- | --- |
| `tests/performance/test_peer_connection_e2e_perf.py::test_peer_connection_loopback_av1_rtp_rtcp_twcc_e2e` passed in 1.37 s | Seven RTP packets and one RTCP/TWCC packet traverse the secured loopback path and meet the E2E baseline. | One small, local, seven-packet burst is not a saturation measurement. |
| `pc_e2e_loopback_av1_rtp_rtcp_twcc.json` | Per-operation `rtp.packet.send` smoke maximum is 250 ms; counters require all seven RTP packets and one RTCP packet. | It has no CPU time, loop-lag, queue-delay, percentile, or executor-overhead assertion. |
| DTLS `measure_perf` phases | Record batch parse, reconstruction, and FSM dispatch boundaries have duration events. | They need burst distributions and correlation with loop lag. |
| SRTP `measure_perf` phases | RTP/RTCP encrypt and decrypt durations are emitted around the synchronous Rust-backed calls. | Current metadata is per packet; it does not compare batching or executor handoff. |
| Public ordered RTP batch send | `PeerConnection.send_rtp_packets` serializes the ordered burst under one media-send lock and deliberately avoids per-packet spawned tasks. | It does not yet state a batch operation id or quantify CPU cost. |
| Runtime worker support | Worker-classified component methods route through the bounded serialized lane and preserve task tracing; aggregate groups are available. | Availability is not a performance justification. |

## Candidate operations and decision evidence

| Operation | Current execution boundary | Measure before deciding | Initial disposition |
| --- | --- | --- | --- |
| SDP generation and codec matching | Negotiation/lifecycle path | CPU duration and loop lag during concurrent offers; allocation/profile sample | Keep inline unless concurrent negotiation demonstrably delays media/control work. |
| ICE candidate parsing and mDNS resolution | Gathering and candidate handling | Candidate count, resolver latency, CPU duration, loop lag; distinguish network wait from CPU | Keep state transitions inline. Consider only synchronous parsing/resolution helpers proven to block. |
| STUN parse/encode | Candidate-pair controller packet loop | p50/p95/p99 duration, packets/s, loop lag, controller queue depth | Inline; hot-path parsing is small and ordering-sensitive. |
| DTLS record batch parse/reconstruct | DTLS inbound receive path | Existing parse/reconstruct phase percentiles by input size and record count, loop lag, queue depth | Inline initially; candidate for a *whole ordered record batch* only under burst evidence. |
| DTLS certificate/key operations | DTLS handshake | Key/certificate helper CPU duration separately from network wait; loop lag while handshake flights run | Candidate only for synchronous crypto helpers shown to block. FSM orchestration remains inline. |
| SRTP RTP/RTCP encrypt/decrypt | `Session.encrypt`/`decrypt`, synchronous Rust calls | Per-packet and burst CPU duration, packet size/count, loop lag, RTP/RTCP queue depth, loss/drop/reorder | Inline initially; strongest potential batch-offload candidate only after a burst regression is proven. |
| RTP serialization/parsing | Public send / remote track path | Duration by payload size and extension count, packet rate, loop lag | Inline for normal MTU-sized packets. |
| AV1 packetization/depacketization | Frame send/test-app boundary | Frame size, MTU, packet count, duration and loop lag per frame | Inline for small frames; candidate for a complete frame batch under sustained large-frame bursts. |
| RTCP/TWCC construction and parsing | Feedback boundary | Feedback packet size, confirmed sequence count, duration, feedback cadence, loop lag | Inline; normally compact and ordering/cadence-sensitive. |

## Measurements required for an offload decision

Run the secured E2E scenario at increasing sustained packet and frame bursts,
with representative payload sizes and concurrent ICE/DTLS control traffic where
applicable. Retain the current correctness assertions: no forbidden failure or
drop event, every RTP packet application-visible, and every transport sequence
confirmed by TWCC.

For each candidate, capture:

- Existing phase durations (`started`/terminal pairs) as p50, p95, p99, max,
  count, and bytes/records/packets per operation.
- Event-loop lag from a lightweight periodic loop probe, plus receive/control
  queue depth and time-to-dequeue. Do not infer CPU blocking from end-to-end
  duration alone.
- Throughput, packet/frame loss, reorder, SRTP stream drops, feedback latency,
  and memory/queue growth.
- A paired inline-versus-offloaded experiment with identical workload,
  executor capacity, and warm-up. Include executor wait time separately from
  worker CPU duration and include the same tracing overhead in both cases.

Offload is warranted only when the inline case repeatedly shows a meaningful
event-loop responsiveness or correctness/throughput regression attributable to
one synchronous operation, and a batch offload removes that regression without
increasing packet loss, reordering, queue growth, or tail latency. The exact
numeric budget belongs in the performance baseline after a stable workload is
recorded; no universal millisecond cutoff is justified by the current trace.

## Operations intentionally kept on the event loop

- UDP `datagram_received`/`sendto` bookkeeping, packet classification, and
  queue handoff. These callbacks must not parse complete RTP/RTCP payloads or
  await executor work.
- ICE controller scheduling, STUN/non-STUN branch selection, selected-pair
  state transitions, and queue routing.
- DTLS FSM orchestration, record-to-FSM ordering, handshake state changes, and
  readiness notifications. A worker may return a completed ordered CPU result;
  it must not mutate the FSM or peer state.
- SRTP stream lookup/creation, queue delivery, and application-visible track
  handoff.
- Single normal-size RTP/RTCP serialization, parse, encrypt, decrypt, and
  feedback processing until measurement proves a burst problem.
- Task/trace creation and performance marks; adding offload must not make
  tracing perform payload copies, serialization, or expensive aggregation in a
  socket callback.

## Approved shape if a candidate earns offload

Use a worker-classified `ObservedComponent` method, never ad hoc threads.
Invoke it from a bounded peer operation—not from the UDP callback
or a long-running receive loop itself. The executor callable must be pure with
respect to peer state: inputs in, ordered immutable results out. Apply results
and emit canonical packet-path events back on the owning event-loop boundary.
This excludes moving mutable protocol objects across the boundary by default:
the current SRTP contexts advance cryptographic/sequence state during
encrypt/decrypt, and the DTLS handshake reconstructor/FSM owns evolving
handshake state. A proposal involving either must first prove that its worker
owns isolated state for the entire ordered batch (or has an equivalent,
explicitly serialized ownership transfer). It must never call the same mutable
SRTP or DTLS object concurrently from the event loop and executor.

For bursts, submit one bounded operation per independently ordered flow:

1. The event loop assigns a monotonic `batch_sequence` for a flow key such as
   `(peer_id, direction, packet_kind, ssrc)` and snapshots a contiguous batch.
2. Offload one batch for parse, crypto, or packetization; never one executor
   hop per packet.
3. Await/apply batches in `batch_sequence` order for that flow before handing
   packets to SRTP streams, the DTLS FSM, UDP transport, or track queues.
4. Allow unrelated SSRCs/directions only when the implementation proves their
   protocol state is independent. RTP and RTCP have distinct ordering domains.
5. Bound in-flight batches and preserve backpressure. On cancellation, peer
   close, timeout, or executor failure, discard the unapplied batch atomically
   and emit the existing owning failure boundary once; never partially reorder
   a batch.

Do not use runtime aggregate grouping as a reordering mechanism. It can group
trace calls, but packet application still requires the per-flow sequence gate.

## Required task and trace metadata

Every proposed separately scheduled bounded wrapper must use `@task` with an
operation-specific name and metadata. An awaited worker method need not add a
redundant spawned task solely for tracing, but it must receive the same operation metadata
and retain its parent peer task context. Its task metadata must include at
least:

```text
bounded: true
component: dtls | srtp | rtp | rtcp | ice
operation: record_parse_batch | handshake_reconstruct_batch |
           srtp_encrypt_batch | srtp_decrypt_batch | av1_packetize_batch
batch_size: <actual input count>
packet_count: <actual RTP/RTCP count when applicable>
ssrc: <integer when a single-SSRC flow; omit for a mixed batch>
batch_sequence: <monotonic sequence within the flow>
flow_direction: tx | rx
packet_kind: dtls | rtp | rtcp
```

Add `pair_id`, byte sizes, record count, and executor queue/wait/worker timing
when instrumentation supplies those values. The current runtime bounds executor
submissions but does not expose those timings, so the benchmark/instrumentation
gate must add them before using them as an inline-versus-offloaded decision
metric. Preserve the event contract's `operation_id` for measured
phase pairs and do not overwrite task context fields supplied by `perf_mark`.
Long-running loops retain `expected_long_running=true` and are ownership
markers, not bounded phase measurements.

## Implementation gate

Before changing production packet execution, add a focused burst benchmark and
baseline assertions for loop lag, queue behavior, ordering, and worker versus
inline cost. The change proposal must identify the measured candidate, workload,
inline regression, offloaded improvement, batch/order design, and failure/
cancellation behavior. Until that evidence exists, retain the current inline
implementations.
