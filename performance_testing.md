# Performance Testing Plan

## Goals

Build an end-to-end performance test pipeline for the in-process WebRTC stack without FastAPI, browser signaling, or external services.

The first baseline covers:

- ICE gathering and candidate nomination.
- DTLS handshake.
- SRTP key/session readiness.
- Synthetic media setup only, with no RTP send/receive in the first version.

The default test should run as a normal pytest test without requiring a marker. It should produce a deterministic immutable event log, derive timing summaries from that log, and compare structural requirements against a stored baseline.

Timing assertions in the default test should be loose smoke thresholds only. Stricter timing regression checks should be opt-in because real loopback sockets and asyncio scheduling are deterministic in event order, not in exact milliseconds.

## User Decisions

- Scope: ICE nomination, DTLS, and SRTP. No RTP in the first implementation.
- Data model: immutable event log is the source of truth.
- Pytest execution: structural smoke test runs without special tags or markers.
- Execution model: deterministic asyncio loopback using real sockets and real tasks, not mocks.
- Tracing model: use the existing task logic and `TaskContext` tree to collect data.
- Measurement target: collect all major timings, not one primary number.
- Rewrite policy: extend current WebRTC APIs and task instrumentation where needed, without changing protocol behavior.
- Baseline: store baseline data in the repository and compare structure plus broad timing thresholds against it.
- Granularity: record every important stage, including DTLS handshake stages, plus packet counters.
- Media: use synthetic setup only for now.

## Current Architecture Fit

The repo already has most of the task infrastructure needed:

- `webrtc/tracing/models.py`
  - `TaskContext` already stores task identity, parent links, monotonic timestamps, duration, status, metadata, and transitions.
- `webrtc/runtime.py`
  - `TaskScheduler.spawn_factory()` owns autonomous task lifetime.
  - `Runtime.start(factory, ...)` starts genuinely dynamic application work.
  - The serialized worker lane measures worker-classified component calls.
- `webrtc/peer_connection.py`
  - `PeerConnection` owns the WebRTC domain lifecycle inside an active `Runtime`.
  - `ObservedMeta` attaches task and component metadata automatically.
  - Existing ICE readiness helpers provide a useful boundary, but should be consolidated behind a typed condition-based wait API.
- `webrtc/ice/agent.py`
  - ICE gather, candidate pair creation, connectivity checks, pair success, and nomination are all visible.
- `webrtc/dtls/dtlstransport.py` and `webrtc/dtls/fsm.py`
  - DTLS task and handshake state boundaries exist, but need better phase instrumentation.

The missing piece is a low-overhead performance event layer. Task tracing measures coroutine lifetime, but E2E performance needs protocol phase events inside long-running tasks.

Before adding the E2E performance test, fix the current lifecycle surface:

- Expose typed condition-based wait APIs on `Agent`, `ICEGatherer`, `DTLSTransport`, and `PeerConnection`.
- Use `wait(condition, timeout)` as the canonical readiness contract for ICE, DTLS, and SRTP.
- Keep method-specific wait wrappers optional and thin if they improve readability.
- Remove the obsolete DTLS dequeue bridge task from `PeerConnection`; the Python DTLS FSM sends records directly through `DTLSLocal.sendto()`, and `DTLSTransport.dequeue_record()` intentionally never returns.
- Replace protocol-path `print()` calls with structured logger calls so perf tests can run with quiet output.
- Stop swallowing protocol setup errors in SDP, ICE, and DTLS paths. Setup failures should fail the test directly instead of becoming missing events or timeouts.

## Implementation Improvements Required

These implementation changes should be completed before the performance pipeline is added. They are not benchmark features; they make the WebRTC lifecycle explicit enough for tests, application code, and tracing to share the same contract.

### 1. Fix Lifecycle APIs First

Add explicit readiness APIs instead of testing private internals. Prefer a typed, data-oriented wait interface as the primary contract:

```python
await peer.wait(PeerCondition.ICE_GATHERING_COMPLETE, timeout=...)
await peer.wait(PeerCondition.ICE_CANDIDATE_PAIR_SUCCEEDED, timeout=...)
await peer.wait(PeerCondition.ICE_NOMINATED, timeout=...)
await peer.wait(PeerCondition.NOMINATED_TRANSPORT_READY, timeout=...)
await peer.wait(PeerCondition.DTLS_HANDSHAKE_COMPLETE, timeout=...)
await peer.wait(PeerCondition.SRTP_READY, timeout=...)
```

Convenience wrappers may exist for common call sites, but they are optional aliases and must delegate to this same condition-based implementation.

Suggested shape:

- Add typed condition enums rather than passing raw strings:

```python
class ICECondition(StrEnum):
    GATHERING_COMPLETE = "ice.gathering_complete"
    CANDIDATE_PAIR_SUCCEEDED = "ice.candidate_pair_succeeded"
    NOMINATED = "ice.nominated"
    NOMINATED_TRANSPORT_READY = "ice.nominated_transport_ready"


class TransportCondition(StrEnum):
    HANDSHAKE_COMPLETE = "dtls.handshake_complete"
    SRTP_READY = "srtp.ready"


class PeerCondition(StrEnum):
    ICE_GATHERING_COMPLETE = "ice.gathering_complete"
    ICE_CANDIDATE_PAIR_SUCCEEDED = "ice.candidate_pair_succeeded"
    ICE_NOMINATED = "ice.nominated"
    NOMINATED_TRANSPORT_READY = "ice.nominated_transport_ready"
    DTLS_HANDSHAKE_COMPLETE = "dtls.handshake_complete"
    SRTP_READY = "srtp.ready"
```

- `Agent.wait(condition: ICECondition, timeout)` waits on ICE-specific lifecycle conditions.
- `ICEGatherer.wait(condition: ICECondition, timeout)` delegates to the active `Agent`.
- `DTLSTransport.wait(condition: TransportCondition, timeout)` waits on DTLS handshake and SRTP readiness conditions.
- `TransportCondition.SRTP_READY` waits for both RTP and RTCP SRTP sessions.
- `PeerConnection.wait(condition: PeerCondition, timeout)` routes to ICE, DTLS, or SRTP internals.
- Existing methods such as `DTLSTransport.wait_handshake()` may remain as compatibility wrappers, but should delegate to the condition-based wait path.

This makes tests, app code, and tracing use the same readiness contract.

The condition-based API is the cleaner core protocol because it avoids method growth as new states are added. Wrappers should be thin aliases for readability, not separate implementations.

### 2. Remove Obsolete DTLS Dequeue Task

`dtls_ice_pair_dequeue_handshake_routine()` should go away. The current FSM sends DTLS records directly through `DTLSLocal.sendto()`, and `DTLSTransport.dequeue_record()` blocks forever by design.

Keeping this task creates misleading traces and permanent running work. The nomination path should only start:

- DTLS transport handshake.
- Inbound DTLS queue routine.
- ICE candidate pair controller.

### 3. Stop Swallowing Protocol Errors

Several paths currently print and return on failure. For a protocol stack, this hides the actual bug and turns it into a timeout later.

Change these to raise or emit structured failure events:

- `ICEGatherer.gather()`
- `PeerConnection.set_local_description()`
- `PeerConnection.set_remote_description()`
- `PeerConnection.create_offer()`
- `PeerConnection.create_answer()`
- `DTLSTransport._run_handshake()`

For example:

```python
except SignalingStateTransitionError:
    raise
```

Do not silently continue after invalid SDP or signaling state.

### 4. Replace `print()` With Structured Logger

Replace protocol-path prints with structured logger calls:

```python
logger.debug(Component.ICE, "Candidate pair nominated", pair_id=pair.get_pair_id())
logger.info(Component.DTLS, "DTLS handshake completed", role=role.value)
logger.error(Component.SDP, "Invalid state transition", error=str(exc))
```

This gives controllable verbosity and avoids polluting pytest output.

### 5. Separate Long-Running Loops From Phase Measurements

Do not use task duration as protocol timing for receive loops. These loops are supposed to run forever:

- ICE pair controller loop.
- DTLS inbound record loop.
- RTP receive loop.
- RTCP receive loop.
- Log drain loop.

Use task tracing for ownership. Use explicit perf events for protocol phases:

```text
ice.gather.started
ice.gather.completed
ice.transport.nominated
dtls.handshake.started
dtls.handshake.completed
srtp.ready.completed
```

### 6. Add a Small No-Op Perf Helper

Avoid passing `PerformanceRecorder` everywhere. Add a helper module with:

```python
perf_mark("ice", "candidate_pair", "nominated", metadata={...})
```

If no recorder is installed, it does nothing. If a recorder exists on the runtime/current context, it records the event.

This keeps protocol code clean and makes instrumentation removable.

### 7. Make ICE State More Explicit

ICE currently relies on events and internal pair state. Add explicit state transitions/counters:

- Candidate gathered.
- Remote credentials set.
- Remote candidate added.
- Candidate pair created.
- STUN request sent.
- STUN response received.
- Candidate pair succeeded.
- Candidate pair nominated.
- Transport selected.

Avoid direct `_selected_pair` / `_nominated_pair` ambiguity where possible. Model selected and nominated as explicit properties or state transitions.

## Proposed Data Model

Add immutable performance events. They should be append-only and derived summaries should be computed after the run.

```python
@dataclass(frozen=True, slots=True)
class PerfEvent:
    run_id: str
    peer_id: str
    trace_id: str | None
    parent_trace_id: str | None
    component: str
    phase: str
    state: str
    monotonic_ns: int
    sequence: int
    metadata: Mapping[str, bool | int | float | str | None]
```

`metadata` must be frozen at record time. The recorder should copy and normalize metadata into JSON-safe scalar values before storing the event so later protocol mutations cannot change historical measurements.

Example events:

```python
{
    "run_id": "pc-loopback-ice-dtls-srtp",
    "peer_id": "offerer",
    "trace_id": "abc123",
    "component": "ice",
    "phase": "candidate_pair",
    "state": "succeeded",
    "monotonic_ns": 1234567890,
    "sequence": 42,
    "metadata": {
        "role": "controlling",
        "pair_id": "..."
    }
}
```

The summary should be data-first and generated from events:

```python
{
    "scenario": "pc_e2e_loopback_ice_dtls_srtp",
    "status": "completed",
    "total_ms": 143.7,
    "peers": {
        "offerer": {
            "setup_ms": 1.2,
            "create_offer_ms": 4.8,
            "set_local_offer_ms": 2.1,
            "ice_gather_ms": 3.8,
            "ice_nomination_ms": 24.5,
            "dtls_handshake_ms": 41.2,
            "srtp_ready_ms": 44.0
        },
        "answerer": {
            "set_remote_offer_ms": 3.0,
            "create_answer_ms": 4.1,
            "set_local_answer_ms": 2.4,
            "ice_nomination_ms": 25.0,
            "dtls_handshake_ms": 39.7,
            "srtp_ready_ms": 42.5
        }
    },
    "components": {
        "sdp": {
            "total_ms": 18.2,
            "operation_count": 6
        },
        "ice": {
            "gather_ms": 3.8,
            "nomination_ms": 24.5,
            "candidate_pairs": 1,
            "stun_tx": 8,
            "stun_rx": 8
        },
        "dtls": {
            "handshake_ms": 41.2,
            "flight_count": 6,
            "records_tx": 7,
            "records_rx": 7
        },
        "srtp": {
            "ready_ms": 44.0
        }
    }
}
```

## Performance Recorder

Create a separate class for performance instrumentation. It should depend on task context, but protocol logic must not depend on benchmark code or a concrete recorder implementation.

Suggested module:

```text
webrtc/tracing/performance.py
```

Suggested classes:

```python
class PerformanceRecorder:
    def mark(
        self,
        component: str,
        phase: str,
        state: str,
        *,
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        ...

    @contextmanager
    def measure(
        self,
        component: str,
        phase: str,
        *,
        peer_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ):
        ...

    def events(self) -> tuple[PerfEvent, ...]:
        ...
```

Suggested decorators:

```python
def perf_measure(component: str, phase: str):
    ...

def perf_async_measure(component: str, phase: str):
    ...
```

The decorator should only wrap timing and event emission. Removing it must not change WebRTC behavior.

Add a tiny no-op helper API for protocol code:

```python
perf_mark("ice", "candidate_pair", "succeeded", metadata={...})
```

If no recorder is active, this helper must do nothing. This keeps instrumentation optional and avoids threading a recorder through every protocol class.

`PerformanceRecorder.mark()` should use `current_execution_context()` to attach:

- `trace_id`
- `parent_trace_id`
- task name
- task kind
- existing component metadata where useful
- scope metadata from the active `Runtime`, when available

The recorder should also provide a run-level event:

```text
scenario.run.started
scenario.run.completed
scenario.run.failed
```

## Where To Instrument

### PeerConnection and SDP

Instrument high-level offer/answer phases:

- `PeerConnection.create_offer`
- `PeerConnection.create_answer`
- `PeerConnection.set_local_description`
- `PeerConnection.set_remote_description`

Events:

```text
sdp.create_offer.started
sdp.create_offer.completed
sdp.create_answer.started
sdp.create_answer.completed
sdp.set_local_description.started
sdp.set_local_description.completed
sdp.set_remote_description.started
sdp.set_remote_description.completed
sdp.create_offer.failed
sdp.create_answer.failed
sdp.set_local_description.failed
sdp.set_remote_description.failed
```

Metadata:

- description type: offer, answer, pranswer, rollback
- signaling state before
- signaling state after
- media section count
- transceiver count

### ICE

Instrument `webrtc/ice/agent.py` without changing behavior.

Events:

```text
ice.gather.started
ice.gather.completed
ice.local_candidate.created
ice.remote_credentials.set
ice.remote_candidate.added
ice.candidate_pair.created
ice.connect.called
ice.stun.tx
ice.stun.rx
ice.candidate_pair.succeeded
ice.candidate_pair.nominated
ice.transport.nominated
ice.gather.failed
ice.connect.failed
```

Counters:

- local candidates
- remote candidates
- candidate pairs
- STUN binding requests tx/rx
- STUN success responses tx/rx
- nomination count

Important locations:

- `Agent.gather_candidates()`
- `Agent._add_local_candidate()`
- `Agent._add_remote_candidate()`
- `Agent._add_candidate_pair()`
- `Agent.connect()`
- `ControllingSelector.send_ping_stun_message()`
- `ControlledSelector.send_ping_stun_message()`
- selector success handlers
- `CandidatePairController.__pair_nominate()`

ICE instrumentation should make selected and nominated state explicit. Avoid deriving nomination only from debug logs or task lifetime.

### DTLS

Instrument `webrtc/dtls/dtlstransport.py` and `webrtc/dtls/fsm.py`.

Events:

```text
dtls.start.called
dtls.role.selected
dtls.record.tx
dtls.record.rx
dtls.flight.started
dtls.flight.completed
dtls.state.changed
dtls.handshake.completed
dtls.handshake.failed
dtls.alert.rx
dtls.alert.tx
dtls.retransmit.tx
```

Counters:

- records tx/rx
- handshake messages tx/rx
- retransmits
- flight count
- alerts

Metadata:

- role: client/server
- flight number/name
- handshake state
- record content type
- record epoch
- record sequence
- error class/message for failed events

### SRTP

Instrument SRTP readiness, not media packet flow yet.

Events:

```text
srtp.keys.derived
srtp.rtp_session.ready
srtp.rtcp_session.ready
srtp.ready.completed
srtp.ready.failed
```

Counters:

- RTP protection profile
- RTP session count
- RTCP session count

### Runtime and Task Context

Keep `TaskContext` as the task ownership layer.

Make `PerformanceRecorder` available through the active execution context:

```python
use_performance_recorder(recorder)
```

Preferred path:

- Runtime owns the recorder for the whole test run.
- Runtime scope metadata supplies the peer identifier automatically.
- Protocol code calls a small helper:

```python
perf_mark("ice", "candidate_pair", "succeeded", metadata={...})
```

If no recorder is active, the helper is a no-op.

Task tracing remains the ownership layer. Do not use task duration as the protocol phase duration for long-running loops such as ICE candidate-pair controllers, DTLS inbound record handlers, RTP/RTCP receive loops, or log drains.

Expected long-running tasks should be marked in metadata, for example:

```python
metadata={"component": "dtls", "long_running": True}
```

The performance summary should ignore long-running task lifetime and use only explicit `PerfEvent` phase markers for timings.

## Required Implementation Cleanup

Complete these cleanup items before the E2E performance test is added:

- Remove `dtls_ice_pair_dequeue_handshake_routine()` usage from `PeerConnection` unless DTLS sending is redesigned to use an actual outbound queue.
- Add typed condition-based `wait(condition, timeout)` support for ICE gathering, candidate-pair success, nomination, nominated transport, DTLS handshake completion, and SRTP readiness.
- Ensure SRTP readiness waits for both RTP and RTCP SRTP sessions.
- Keep method-specific wrappers optional and implemented only as thin aliases over `wait(condition, timeout)`.
- Replace remaining `print()` calls in SDP, ICE, and DTLS protocol paths with structured logging.
- Convert swallowed setup errors into raised exceptions or explicit `*.failed` events.
- Make `PeerConnection.aclose()` produce predictable cleanup and allow the perf test to assert no unexpected managed tasks remain after close.

## Baseline Files

Add baseline data under:

```text
tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json
```

The baseline should not store every event. It should store summary thresholds and expected structural requirements.

Example:

```json
{
  "scenario": "pc_e2e_loopback_ice_dtls_srtp",
  "smoke_max_total_ms": 8000,
  "smoke_max_ice_nomination_ms": 2000,
  "smoke_max_dtls_handshake_ms": 5000,
  "smoke_max_srtp_ready_ms": 6000,
  "required_components": ["sdp", "ice", "dtls", "srtp"],
  "required_events": [
    "ice.gather.completed",
    "ice.transport.nominated",
    "dtls.handshake.completed",
    "srtp.ready.completed"
  ],
  "forbidden_events": [
    "scenario.run.failed",
    "sdp.create_offer.failed",
    "sdp.create_answer.failed",
    "sdp.set_local_description.failed",
    "sdp.set_remote_description.failed",
    "ice.gather.failed",
    "ice.connect.failed",
    "dtls.handshake.failed",
    "srtp.ready.failed"
  ],
  "min_counters": {
    "ice.stun_tx": 1,
    "ice.stun_rx": 1,
    "dtls.records_tx": 1,
    "dtls.records_rx": 1
  },
  "required_order": [
    ["scenario.run.started", "ice.gather.completed"],
    ["ice.transport.nominated", "dtls.start.called"],
    ["dtls.start.called", "dtls.handshake.completed"],
    ["dtls.handshake.completed", "srtp.ready.completed"],
    ["srtp.ready.completed", "scenario.run.completed"]
  ],
  "cleanup": {
    "allow_long_running_tasks_before_close": true,
    "require_no_unexpected_active_routines_after_close": true
  }
}
```

Keep timing thresholds loose at first. The value of the default baseline is not strict performance enforcement; it is making regressions visible and making missing stages fail clearly.

If strict timing regression checks are needed later, add a separate marked test or environment-gated assertion that compares against tighter thresholds generated on a controlled machine.

## Pytest Architecture

Suggested files:

```text
tests/performance/test_peer_connection_e2e_perf.py
tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json
tests/performance/helpers.py
```

Do not use FastAPI. Use in-memory signaling.

Test flow:

```text
1. Create runtime with active PerformanceRecorder.
2. Create two PeerConnection instances.
3. Enter one `Runtime` and one nested `PeerConnection` context per peer:
   - peer_id = "offerer"
   - peer_id = "answerer"
4. Start both peer connections.
5. Add minimal synthetic transceiver/media setup required to reach DTLS/SRTP.
6. Create offer on offerer.
7. Set local offer on offerer.
8. Set remote offer on answerer.
9. Create answer on answerer.
10. Set local answer on answerer.
11. Set remote answer on offerer.
12. Start offerer dial and answerer accept.
13. Await `PeerCondition.ICE_GATHERING_COMPLETE`, `ICE_CANDIDATE_PAIR_SUCCEEDED`, `ICE_NOMINATED`, and `NOMINATED_TRANSPORT_READY` on both peers.
14. Await `PeerCondition.DTLS_HANDSHAKE_COMPLETE` on both peers.
15. Await `PeerCondition.SRTP_READY` on both peers.
16. Build immutable event tuple.
17. Build summary dict from event tuple.
18. Compare summary structure and loose smoke thresholds to stored baseline.
19. Attach summary to pytest via record_property.
20. Close peer contexts and runtime.
```

The test should assert:

```python
assert summary["status"] == "completed"
assert "ice.transport.nominated" in event_names
assert "dtls.handshake.completed" in event_names
assert "srtp.ready.completed" in event_names
assert not any(name in event_names for name in baseline["forbidden_events"])
assert summary["total_ms"] <= baseline["smoke_max_total_ms"]
assert summary["components"]["ice"]["nomination_ms"] <= baseline["smoke_max_ice_nomination_ms"]
assert summary["components"]["dtls"]["handshake_ms"] <= baseline["smoke_max_dtls_handshake_ms"]
assert summary["components"]["srtp"]["ready_ms"] <= baseline["smoke_max_srtp_ready_ms"]
```

The test should also verify required ordering constraints from the baseline and assert cleanup after closing both peer contexts.

## Determinism Rules

This test is deterministic in structure, not in exact milliseconds.

Rules:

- Use one event loop.
- Use loopback UDP only.
- Use OS-assigned UDP ports.
- Avoid FastAPI, browser WebRTC, subprocesses, files, and codecs.
- Disable verbose print/log output during the perf test.
- Use monotonic timestamps only.
- Assert event order and broad maximum thresholds.
- Avoid asserting exact packet counts unless the protocol path is stable.
- Do not assert long-running task duration.
- Use explicit timeout values for every awaited readiness boundary.

## Event Naming Contract

Use this stable pattern:

```text
component.phase.state
```

Examples:

```text
ice.gather.started
ice.gather.completed
ice.candidate_pair.created
ice.candidate_pair.succeeded
ice.transport.nominated
dtls.flight.started
dtls.flight.completed
dtls.handshake.completed
srtp.ready.completed
```

The `PerfEvent` fields should remain separate:

```python
component="ice"
phase="gather"
state="completed"
```

The dotted name is derived only for summaries and baseline checks.

## Summary Builder

Add a pure summary builder. It should take events and return a dict.

Suggested module:

```text
webrtc/tracing/performance_summary.py
```

Function:

```python
def build_performance_summary(
    events: Sequence[PerfEvent],
    *,
    scenario: str,
) -> dict[str, Any]:
    ...
```

This must be pure and easy to test. It should not know about asyncio, sockets, PeerConnection, or pytest.

Responsibilities:

- Sort by sequence or monotonic timestamp.
- Compute total duration from first to last event.
- Compute phase durations from started/completed pairs.
- Compute per-peer metrics.
- Compute per-component metrics.
- Aggregate counters from event metadata.
- Report missing required events and forbidden events.
- Report ordering violations.
- Report missing phases as `"status": "incomplete"` with `missing_events`.
- Ignore long-running task lifetimes when computing protocol phase timing.

## Test Layers

Implement the performance work in layers:

1. Unit-test `PerformanceRecorder` event freezing, sequencing, peer attribution, and no-op behavior.
2. Unit-test `build_performance_summary()` with synthetic event tuples.
3. Add the E2E loopback structural smoke test for ICE, DTLS, and SRTP.
4. Add optional stricter timing regression checks only after the structural test is stable.

## Staged Task Plan

## Execution Status

- Stage 0: completed and reviewed.
- Stage 1: completed and reviewed.
- Stage 2: completed and reviewed.
- Stage 3: completed and reviewed.
- Stage 4: completed and reviewed.
- Stage 5: completed and reviewed.
- Stage 6: completed and reviewed.
- Stage 7: completed and reviewed with AV1 RTP packetization/depacketization and RTCP/TWCC confirmation.

### Stage 0: Lifecycle Contract Cleanup

**Goal:** Make readiness observable through public APIs before adding performance tests.

**Areas:** `Agent`, `ICEGatherer`, `DTLSTransport`, `PeerConnection`, lifecycle wait tests.

**Changes:**
- Add typed `wait(condition, timeout)` APIs for `Agent`, `ICEGatherer`, `DTLSTransport`, and `PeerConnection`.
- Add `ICECondition`, `TransportCondition`, and `PeerCondition`.
- Support waits for ICE gathering complete, candidate-pair succeeded, nomination, nominated transport ready, DTLS handshake complete, and SRTP ready.
- Ensure SRTP readiness waits for both RTP and RTCP SRTP sessions.
- Keep method-specific readiness wrappers only as thin aliases over typed waits.
- Require explicit timeouts for all lifecycle waits.

**Tests:**
- Add unit tests for each condition wait.
- Add a timeout test for an unmet condition.
- Add a peer-level test proving `PeerConnection.wait(PeerCondition.SRTP_READY)` delegates correctly.

**Done when:**
- Tests no longer depend on private internals for readiness.
- All lifecycle waits have explicit timeouts.

### Stage 1: Remove Misleading Runtime Work

**Goal:** Remove obsolete long-running work that pollutes traces.

**Areas:** `PeerConnection`, DTLS transport startup, nomination startup, runtime task metadata, trace/task tests.

**Changes:**
- Remove `dtls_ice_pair_dequeue_handshake_routine()` usage from `PeerConnection`.
- Confirm DTLS records are sent through `DTLSLocal.sendto()`.
- Keep only the DTLS handshake task, inbound DTLS queue routine, and ICE candidate-pair controller in nomination startup.
- Mark expected long-running tasks with metadata so traces can distinguish controllers from phase work.

**Tests:**
- Verify the existing DTLS handshake still completes.
- Add trace/task inspection proving the obsolete DTLS dequeue bridge task is absent.
- Add cleanup coverage confirming no unexpected active routines remain after close.

**Done when:**
- No permanent dequeue bridge task appears in traces.
- Nomination still reaches DTLS and SRTP readiness.

### Stage 2: Protocol Failure And Logging Cleanup

**Goal:** Make protocol setup failures fail directly instead of becoming timeouts.

**Areas:** SDP paths, ICE gather/setup paths, DTLS handshake paths, protocol logging, failure tests.

**Changes:**
- Replace protocol-path `print()` calls with structured logger calls.
- Stop swallowing errors in ICE gather, SDP offer/answer/local/remote description paths, and DTLS handshake.
- Preserve original exception types where possible.
- Plan for later `*.failed` performance events once the recorder exists, but do not silently continue before then.

**Tests:**
- Verify invalid signaling state raises immediately.
- Verify ICE gather/setup failure raises or emits structured failure.
- Verify DTLS handshake failure is visible as a failure, not a missing readiness timeout.
- Verify pytest output is quiet unless logging is enabled.

**Done when:**
- No hot-path `print()` remains in SDP, ICE, or DTLS protocol flow.
- Setup bugs fail at the source.

### Stage 3: Performance Infrastructure

**Goal:** Add the immutable event pipeline without changing protocol behavior.

**Areas:** Performance event model, recorder, no-op helper, measurement helpers, task/peer metadata, summary builder, baseline comparison helpers.

**Changes:**
- Add immutable `PerfEvent`.
- Add `PerformanceRecorder`.
- Add no-op `perf_mark(component, phase, state, metadata=...)`.
- Add sync and async measurement helpers.
- Attach task context and peer metadata automatically.
- Add pure `build_performance_summary(events, scenario=...)`.
- Add baseline comparison helpers for required events, forbidden events, ordering, counters, and loose smoke thresholds.

**Tests:**
- Verify recorder metadata is frozen.
- Verify events are sequenced deterministically.
- Verify the no-op helper has no side effects when a recorder is absent.
- Verify the summary builder handles completed, incomplete, forbidden, and out-of-order event sets.

**Done when:**
- Protocol code can call `perf_mark()` without depending on benchmark setup.
- Summary generation is pure and unit tested.

### Stage 4: Protocol Instrumentation

**Goal:** Emit stable events for SDP, ICE, DTLS, and SRTP phases.

**Areas:** PeerConnection SDP methods, ICE agent/gatherer/candidate-pair flow, DTLS transport, SRTP session setup, summary counters.

**Changes:**
- Emit SDP events for create offer/answer and set local/remote description started/completed/failed.
- Emit ICE events for gather, candidates, remote credentials, pair creation, STUN tx/rx, pair succeeded, pair nominated, and transport nominated.
- Emit DTLS events for start, role selection, records, flights, state changes, handshake completed/failed, alerts, and retransmits.
- Emit SRTP events for keys derived, RTP session ready, RTCP session ready, and SRTP ready completed/failed.
- Keep instrumentation no-op when the recorder is disabled.

**Tests:**
- Add unit or focused integration tests asserting key events are emitted.
- Verify event names follow `component.phase.state`.
- Verify long-running task duration is not used for phase timing.

**Done when:**
- Required baseline events can be produced from normal protocol execution.
- Counters for ICE STUN and DTLS records are available in summary data.

### Stage 5: E2E Performance Pytest

**Goal:** Add the first structural smoke performance test.

**Areas:** `tests/performance/test_peer_connection_e2e_perf.py`, `tests/performance/helpers.py`, `tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json`, pytest reporting.

**Changes:**
- Add `tests/performance/test_peer_connection_e2e_perf.py`.
- Add `tests/performance/helpers.py`.
- Add baseline JSON at `tests/performance/baselines/pc_e2e_loopback_ice_dtls_srtp.json`.
- Use two in-process peers, in-memory signaling, real loopback UDP, and synthetic media setup only.
- Await readiness using `PeerConnection.wait(PeerCondition, timeout)`.
- Assert required events, forbidden events, ordering, counters, loose timing thresholds, and cleanup.
- Attach the performance summary to pytest output through `record_property`.

**Tests:**
- Ensure the default pytest run includes this structural smoke test.
- Ensure the test fails clearly on missing ICE, DTLS, or SRTP phase.
- Ensure the summary is attached to pytest output through `record_property`.

**Done when:**
- One normal pytest test validates ICE nomination, DTLS handshake, and SRTP readiness end to end.
- No FastAPI, browser, subprocess, codec, or external signaling dependency is introduced.

### Stage 6: Baseline Refinement

**Goal:** Make the baseline useful without making it flaky.

**Areas:** E2E performance baseline JSON, local repeated-run notes, baseline comparison thresholds.

**Changes:**
- Run the E2E test multiple times locally.
- Set broad smoke thresholds from observed stable local numbers.
- Keep structural checks more important than exact timing.
- Decide later whether strict timing checks become a marked pytest, environment-gated assertion, or separate script.

**Tests:**
- Verify repeated local runs pass under normal machine load.
- Verify an artificial missing event causes a clear failure.
- Verify an artificial forbidden event causes a clear failure.

**Done when:**
- The baseline catches structural regressions.
- Timing thresholds are loose enough for normal developer machines.

### Stage 7: AV1 RTP Media Performance Test

**Status:** Completed.

**Goal:** Add deterministic RTP media coverage after the ICE/DTLS/SRTP baseline without changing the protocol runtime path.

**Areas:** `tests/performance/test_av1_rtp_media_perf.py`, `tests/performance/baselines/av1_rtp_packetization_twcc.json`.

**Changes:**
- Add a focused AV1 RTP packetization/depacketization performance test.
- Use `Av1Packetizer` from `webrtc/media/av1_payloader.py` with deterministic RTP sequence, timestamp, SSRC, MTU, and frame bytes.
- Serialize each RTP packet with `DEFAULT_EXT_MAP`, parse it back through `RtpPacket.parse(..., DEFAULT_EXT_MAP)`, and verify the transport-wide CC extension survives the wire round-trip.
- Reassemble the parsed AV1 RTP payload fragments and verify the original frame bytes round-trip exactly.
- Generate RTCP `TransportLayerCC` feedback for the parsed packet span and verify the feedback confirms every packet transport-wide CC sequence.
- Record RTP and RTCP performance events with the existing `PerformanceRecorder`/`perf_mark` pipeline and compare the summary to a new Stage 7 baseline.

**Tests:**
- `pytest -q tests/performance/test_av1_rtp_media_perf.py`
- `pytest -q tests/performance/test_peer_connection_e2e_perf.py`

**Done when:**
- The AV1 frame bytes round-trip through RTP packetize, serialize, parse, and reassembly.
- Every RTP packet has a transport-wide CC sequence number.
- Generated RTCP TWCC feedback confirms the complete packet sequence span.
- The new baseline catches missing RTP/RTCP events and counter regressions.
- The existing ICE/DTLS/SRTP baseline remains unchanged.

## Risks

- Current terminal trace pruning can remove completed `TaskContext`s from live trace storage. The performance recorder must keep its own immutable event list.
- `Agent.add_remote_candidate()` schedules asynchronous work and returns immediately. Tests should wait on events, not sleeps.
- Long-running tasks such as candidate pair controllers cannot be summarized by task duration. They need internal phase events.
- Existing `print()` calls in ICE, DTLS, and SDP hot paths can affect measurements and should be replaced before the first stable baseline.
- DTLS/SRTP readiness may not currently expose a clean public wait method. Add condition-based wait support without changing handshake behavior.

## Open Questions

- Should strict timing regression checks be a marked pytest test, an environment-gated assertion, or a separate script?
- Should the first synthetic transceiver be audio-only, video-only, or one of each?
- Should the E2E test create both peers with the default composition root or inject isolated runtime services?
- Should event artifacts be written to disk on failure for debugging, or only attached through pytest `record_property`?
- Should failure events include sanitized exception text, exception class only, or both?

## Expected First Baseline Shape

The first passing test should produce a compact summary like:

```python
{
    "scenario": "pc_e2e_loopback_ice_dtls_srtp",
    "status": "completed",
    "total_ms": 143.7,
    "setup_ms": 1.2,
    "sdp_ms": {
        "create_offer": 4.8,
        "set_local_offer": 2.1,
        "set_remote_offer": 3.0,
        "create_answer": 4.1,
        "set_local_answer": 2.4,
        "set_remote_answer": 2.2
    },
    "ice_ms": {
        "gather": 3.8,
        "candidate_exchange": 1.1,
        "nomination": 24.5
    },
    "dtls_ms": {
        "handshake": 41.2
    },
    "srtp_ms": {
        "ready": 44.0
    },
    "counters": {
        "ice.stun_tx": 8,
        "ice.stun_rx": 8,
        "dtls.records_tx": 7,
        "dtls.records_rx": 7
    }
}
```

This is the baseline for later work. Once this is stable, synthetic RTP can extend the same data model without changing the test architecture.
