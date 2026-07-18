# `ObservedComponent` Refactoring Audit

## Scope and executive verdict

This is an audit only. It does not contain or authorize an implementation
change.

The audit covers `ObservedMeta` and `ObservedComponent` in
`webrtc/performance.py`, all 13 direct production subclasses, their state
machine and Runtime relationships, and the schema-2 compact trace shown in the
request. Test-only subclasses are evidence for the instrumentation contract but
are not treated as production components.

The principal finding is that `ObservedComponent` is not an observability-only
abstraction. Class creation silently decides execution affinity, worker
submission, task scheduling, activity aggregation, metric extraction, capture
behavior, and worker ownership. Protocol components then compensate by knowing
about decorators, Runtime owner epochs, projection identities, facet metadata,
and generic machine snapshots. This is the SRP violation to remove.

The desired boundary is:

```text
WebRTC component -> domain command -> domain state/snapshot
                                      |
                                      +-> Runtime execution adapter
                                      +-> observation adapter -> schema 2 -> UI/export
```

The WebRTC component should know its protocol state and explicit scheduling
dependencies. It should not know operation IDs, observation detail, trace
groups, owner aliases, projection ordering, facet redaction, capture rules, or
schema-2 transport records.

The supplied trace is structurally valid and its counts reconcile, but it is
not yet a semantically correct compact WebRTC explanation. In particular, it
assigns component operations to the Runtime owner, exports private plumbing as
first-class work, cannot distinguish healthy long-running pumps from stuck
calls, leaks the shortened peer identifier through facet names, and removes the
only semantic distinction between the two attachment registries.

## What `ObservedMeta` currently hides

At class creation, `ObservedMeta` walks methods declared in the class namespace
and wraps every method except `__init__`, other double-underscore methods,
properties, non-functions, and explicitly `@unobserved` methods. The default
policy is aggregate observation. This makes private helpers observable by
default while properties and methods inherited from an ordinary mixin are not
observed at all.

More importantly, the wrapper changes execution semantics:

- an unmarked synchronous method defaults to `WORKER`, not to an ordinary
  direct call;
- `@event_loop` is therefore a correctness marker, not trace metadata;
- `@worker` submits through the Runtime and returns an awaitable dispatch;
- `@task` changes a method call into Runtime task creation;
- `@performance` and `@observe` control metric extraction, aggregation,
  diagnostic capture, and failure retention;
- worker calls consult mutable owner binding stored on the component.

Consequently, removing tracing or changing a trace policy can change where and
how WebRTC code runs. An observation mechanism should not have that authority.

`ObservedComponent` is also described as stateless, but it supplies mutable
per-instance worker ownership through `__worker_owner_binding__` and
`__runtime_root_worker_utility__`. Every new subclass begins as an ownerless
root utility. If a future synchronous method lacks `@event_loop` and the
component was never explicitly bound, it can be attributed to the Runtime root
instead of failing as an ownership error. Only `DTLSTransport`, `AsyncLogDrain`,
and the SRTP lifecycle mixin currently bind production instances explicitly.

### Inconsistent coverage caused by inheritance

The metaclass compiles methods in the new class namespace and merges already
compiled policies from bases. It does not compile methods inherited from a
non-observed mixin. This affects both mixed-in production designs:

- `Session(_LifecycleOwner, ObservedComponent)` observes methods declared on
  `Session`, but `_LifecycleOwner._init_lifecycle`, `_command`, and
  `_join_lifecycle` remain outside the metaclass contract.
- `RTPReceiver(ObservedComponent, _MachineComponent)` observes receiver methods,
  while machine lifecycle helpers inherited from `_MachineComponent` remain
  outside it.

That boundary is an MRO accident rather than an intentional operation policy.

## Separation required

Four concerns should become independent:

1. **Domain state.** ICE, DTLS, signaling, SRTP, RTP, and transceiver rules own
   typed commands and immutable domain snapshots. Generic machine epoch,
   projection order, aliases, and trace IDs are not part of these snapshots.
2. **Execution.** Event-loop assertions, worker dispatch, long-running pumps,
   and owned tasks belong to explicit Runtime services injected at composition
   time. Worker dispatch should be visible at the call site or behind a
   domain-named port such as an analyzer/crypto executor; it should not be a
   side effect of observation.
3. **Observation.** A Runtime-side registry binds object identity to an entity
   and operation policy. It observes calls and committed state without writing
   metadata fields onto protocol objects. Transition/facet publication is
   failure-isolated from the domain commit.
4. **Presentation.** Schema-2 normalization, redaction, owner labels,
   coalescing, and compact LLM formatting belong to the tracing/UI layer.

An external operation policy should be allowlisted by component API or domain
event. Private helpers should default to off. A small number of meaningful
internal workflows may be explicitly named by the adapter. This reverses the
current default, which automatically promotes every private async helper and
every explicitly loop-affine sync helper into an operation group.

## Production component inventory

### Summary table

| Component | Current hidden responsibility | State/property boundary | Audit disposition |
| --- | --- | --- | --- |
| `AudioAnalyzer` | `@worker` both schedules CPU work and observes it; the class defaults to Runtime-root ownership | FFT configuration is domain data; `frame_count` is logging/telemetry state | Remove the observation base. Inject an analyzer executor or explicit worker port. Keep configuration local; move the frame counter and periodic reporting to telemetry. |
| `DTLSTransport` | Owns Runtime binding, worker owner binding, machine registration, transition sink, facet publication, pumps, and protocol behavior | DTLS role, selected transport, handshake readiness, and SRTP readiness belong in one internal DTLS snapshot; machine epoch/revision and facet data do not belong in the public protocol API | Keep a DTLS state authority, but bind execution and observation externally. Replace generic `authoritative_snapshot()` metadata with a domain readiness view for consumers. |
| `FSM` | Mixes DTLS flight logic with Runtime/projection registration and aggregate observation of nearly every step/helper | Handshake phase and retransmission state are DTLS logic; `transition_revision` is infrastructure; polling completion is orchestration | Keep the handshake state machine. Hide its generic revision, use its state-change notification for completion, and let an observer consume committed phase changes. |
| `DTLSConn` | Becomes observed mainly because it contains the FSM and record pump; all async parsing branches become aggregate operations | Record queues, pending encrypted records, and cipher readiness are DTLS internals | Remove the base. Observe the enclosing handshake/record-pump boundaries, not parsing helpers. Queue health should come from the Runtime queue adapter. |
| `CandidatePairController` | Builds owner identity, registers a machine, emits exact nomination facets, and exposes every STUN branch as an aggregate operation | Pair checking, nomination, selected transport, and receive-pump lifecycle are ICE state; owner epoch, command IDs, and facet keys are not | Keep typed ICE controller state. Move machine binding and nomination projection to an ICE observation adapter. Observe connectivity-check outcomes, not each private parser/helper. |
| `Agent` | Owns observation IDs, projection registration, machine commands, transition causes, and many automatic operation groups | ICE role, credentials, candidates, pairs, selected transports, and connectivity state belong in an immutable agent snapshot | Keep ICE agent state. Hide Runtime/projection fields and generic command metadata in a state owner. Preserve a domain snapshot; do not expose trace ownership through `entity_id`. |
| `MultiUDPMux` | Observation inheritance wraps resource operations although lifecycle is already a synchronous reducer | Bound interfaces, bindings, and active/draining lifecycle are transport/resource state | Remove the base. Runtime resource ownership should observe socket lifecycle downstream. `inbound_handlers()` should remain an internal transport port, not an operation group. |
| `AsyncLogDrain` | Uses the same base to schedule the write worker, aggregate logging, bind owner epochs, and observe lifecycle | Intake/drain/failure state belongs to the logging service, not WebRTC protocol state | Move the whole service behind Runtime logging. A peer should depend only on a log sink/inbox. Its queue and lifecycle may appear in the trace through the Runtime adapter, without the peer or drain constructing metadata. |
| `PeerConnection` | Private validation, machine setup, command factories, facet publication, media-pump internals, and all public WebRTC methods are automatically grouped | Peer lifecycle, signaling, negotiation generation, selected transport readiness, and media admission are domain state; `_runtime`, machine handles, command IDs, owner epochs, and observability IDs are infrastructure | Remove the base last, after external call and state adapters exist. Consolidate public reads behind peer/signaling/media snapshots. Suppress private bookkeeping from the operation model. |
| `Session` | Worker crypto scheduling, tracing policy, lifecycle binding, facet publication, stream telemetry, and SRTP protocol behavior coexist | Keys-ready, admission, stream count, and drain state are SRTP state; generic `MachineSnapshot`, owner epoch, debug counters, and facet metadata are not | Keep an internal `SessionAdmissionSnapshot`. Replace public generic lifecycle snapshots with a narrow readiness view. Move crypto execution to an injected port and counters/facets to an SRTP observer. |
| `RTPReceiver` | Observation wraps receiver API while lifecycle helpers come from an unobserved mixin; the component also starts Runtime pumps directly | Bound transport, active/paused/stopped, and current track are RTP state | Keep one receiver state snapshot and the `track` domain read. Move pump ownership and lifecycle observation to a media runtime adapter; remove MRO-dependent instrumentation. |
| `RTPTransceiver` | Constructs observation identity, machine owner, operation metadata, transition facets, and Runtime task scheduling | Direction, MID, codecs, sender, receiver, and negotiated configuration are one domain snapshot; `observability_id`, machine epoch, and generic revision exposure are infrastructure | Make `NegotiatedTransceiverSnapshot` the sole authority. Remove duplicated compatibility fields where possible. Keep optimistic revision checks inside the state owner, not in public metadata-shaped calls. |

### Component-specific property and data findings

#### `AudioAnalyzer`

`sample_rate`, `fft_size`, precomputed FFT arrays, filter configuration, and the
analysis result are in scope. `frame_count` exists only to decide when to log.
It should not make the analyzer a stateful observed component. The two compute
functions are valid worker work, but execution and observation should be two
separate policies.

#### `DTLSTransport`, `FSM`, and `DTLSConn`

`DTLSTransportSnapshot` is the right direction because consumers need an atomic
answer to “which transport/role is authoritative and are DTLS/SRTP ready?” The
snapshot should be domain-named and internal. Its current machine revision is
useful for internal consistency, but exposing generic state-machine metadata to
callers couples WebRTC logic to the implementation.

`FSM.handshake_state` is a legitimate DTLS read. `FSM.transition_revision` is
not a WebRTC concept and should be hidden inside the state authority. The
handshake completion loop still polls at one millisecond; the runner already
provides revision/terminal notification, so polling is not needed.

`DTLSConn` should not be a second observed domain component. It is an internal
record/handshake transport owned by `DTLSTransport`. Its parsing helpers,
cipher-suite wait, and record queues should be hidden behind that boundary.

#### `CandidatePairController` and `Agent`

`nominated` is meaningful ICE state, but it should be read from the typed pair
or controller snapshot. The transport, nomination origin, and pair revision
form one committed ICE result. Exact projection facets can be derived from that
result after commit.

`Agent.protocol_snapshot()` is preferable to reading its many mutable lists and
maps, but its snapshot should remain an ICE model. Projection identity,
observation IDs, producer causes, and Runtime owner registration should be
sidecar data. Internal registries currently reach through controller `_pair`
fields; a typed controller/pair view would avoid that private cross-component
coupling.

#### `MultiUDPMux` and `AsyncLogDrain`

These are infrastructure services used by WebRTC, not WebRTC protocol objects.
They should not inherit a protocol-wide observation base. The mux needs a
resource lifecycle and the drain needs intake/drain/failure state, but Runtime
already owns the resources, queues, pumps, and trace projection needed to
observe them.

#### `PeerConnection`

The public `state`, `closed`, signaling descriptions, and negotiation
generation are legitimate peer reads. The compatibility properties `_closed`,
`_closing`, `_started`, and the separate signaling-description properties
should be projections of one peer/signaling snapshot rather than repeated
runner reads. `media_send_epoch` is purely Runtime ownership metadata and
should not be a peer property.

`_publish_peer`, `_publish_peer_configuration`, and
`_after_signaling_commit` are direct evidence of the SRP breach: the protocol
owner constructs facet names and observation detail. The state transition
should emit or return a domain effect; a Runtime observer should translate that
effect to schema 2.

The media-send mailbox/pump is already the admission authority. Its counters
and local lifecycle belong in one hidden media-send state object. They should
not become peer properties, and the peer should not publish their trace
metadata itself.

#### `Session`

`SessionAdmissionSnapshot` correctly groups the values that must change
atomically for packet and stream admission. Keep it internal and make WebRTC
decisions from it. `lifecycle_snapshot()` currently returns a generic
`MachineSnapshot`; consumers such as DTLS should receive a narrow SRTP readiness
view instead. `admission_snapshot()` should remain an internal diagnostic or
domain port rather than a trace-facing property.

`_decrypt_count`, `_decrypt_errors`, and `_ssrc_counters` are telemetry. They
should be maintained by a bounded/coalesced observer or metrics reducer, not by
the protocol object merely to decide what to log. The keyed SSRC aliasing is
good redaction behavior and belongs in that observer.

#### `RTPReceiver` and `RTPTransceiver`

`RTPReceiver.track` is a valid domain relationship. Runtime handles, machine
epochs, and pump metadata should be hidden. The component should change
receiver state; an external media adapter should own and join the pump.

For `RTPTransceiver`, `NegotiatedTransceiverSnapshot` should be the only
configuration authority. `_direction`, `_mid`, `_prefered_codecs`, `_sender`,
and `_receiver` are currently compatibility projections updated beside the
snapshot and can drift if any future path bypasses `_commit_configuration`.
Public `direction`, `kind`, `mid`, `sender`, `receiver`, and negotiated reads
may remain, but all should read the one snapshot. `observability_id` is not a
WebRTC property and should move to the Runtime registry.

## Audit of the supplied schema-2 compact trace

### What is correct

- The header count reconciles: 19 machine + 17 transition + 25 group + 27
  facet records equals 88.
- Transition records are grouped by owner, so nine displayed transition lines
  can correctly represent 17 individual transitions.
- It is valid for a registered machine to have no transition record yet. The
  `transport`, `dtls-transport`, `rtp-sender`, `media-track`, and transceiver
  initial states do not by themselves prove missing data.
- Repeated facet values are grouped without dropping values.
- Nested operations retain their hierarchy, including two calls to
  `_after_peer_commit` represented by one aggregate group.
- At this instant, `peer=negotiating`, `ice-gatherer=complete`,
  `ice-agent=waiting-remote`, and DTLS/selected transport still `new` is a
  plausible pre-remote-description snapshot.

### Semantic defects

#### 1. Operation ownership is wrong

Every root operation in the sample is shown under `[@1]`, the Runtime machine,
including `PeerConnection`, `AsyncLogDrain`, `MultiUDPMux`, `Agent`, and
`RTPTransceiver` work. This follows directly from `_aggregate_identity`: when
no worker binding is passed, it selects the Runtime entity. Async and inline
aggregate wrappers do not pass a component binding. Worker binding therefore
cannot fix ordinary component calls.

The result is a valid activity tree attached to the wrong semantic owner. It
prevents an LLM or operator from correlating transceiver work with `[@19]`, ICE
work with `[@15]`, or log work with `[@11]`.

Required correction: component-to-entity binding must be supplied by the
Runtime observation registry for every call kind, without storing trace
metadata on the component.

#### 2. Private plumbing dominates the operation tree

The export promotes `_require_runtime_bound_children`,
`_ensure_machine_owners`, `_set_media_send_state`, `_command`, `_publish_peer`,
`_submit_lifecycle`, `_next_transceiver_observability_id`, and `_next` to the
same status as `PeerConnection.start`, candidate gathering, and adding a
transceiver. These are implementation mechanics already reflected in machine
and facet records.

Required correction: default private methods to unobserved and explicitly
allowlist meaningful workflows. Do not use trace annotations inside those
components to achieve the allowlist; keep the policy in the observation
adapter.

#### 3. “Active” is ambiguous

`_run_media_send_pump`, `AsyncLogDrain._run`, and `AsyncLogDrain._next` are
expected to remain open. `add_transceiver_from_kind`,
`add_transceiver_from_track`, and `RTPTransceiver.wait_active` may be briefly
active while queued activation advances the transceiver from `inactive`.
Because the compact export removes duration, start age, task role, and
`expected_long_running`, it cannot distinguish healthy waiting from a hang.

The simultaneous `transceiver=inactive` and active `wait_active` is therefore
temporally possible, but the summary cannot establish whether it is normal or
stalled.

Required correction: label pumps/waits as long-running or waiting, include
bounded age for unexpectedly active request operations, and state that the
export is a live incomplete snapshot.

#### 4. Redaction is incomplete

Machine display names remove their raw entity IDs, but facet names retain
`peer-12b3d7d0f28e`. The renderer sanitizes UUIDs and hexadecimal strings of
24–64 characters; this peer suffix is only 12 hexadecimal characters and is
not removed. Arbitrary user-provided `peer_id` values would also survive.

Required correction: never derive redaction from identifier shape. Normalize
facet names relative to their owner and replace all registered entity IDs with
their aliases before applying generic text sanitization.

#### 5. Aliases remove necessary roles and invent an apparent machine

The two `attachment-registry` machines at `[@9]` and `[@10]` are
indistinguishable after raw IDs are stripped. They likely represent signaling
and media-source registries, but the export provides no role. Conversely,
facet owner `[@20]` has no machine row, so an operator may assume a missing
machine rather than a queue/resource owner.

Required correction: include bounded semantic roles assigned at registration,
for example attachment registry purpose and queue kind. Distinguish “machine
alias” from “resource owner alias,” or explicitly label facet-only owners.

#### 6. Cross-owner hierarchy cannot be represented reliably

The renderer prints an owner only for root operation rows. Nested rows suppress
their owner even if it differs. In the current sample this is masked because
all operations collapse to the Runtime owner. Once ownership is fixed, a peer
operation that invokes ICE, DTLS, or transceiver work will lose the ownership
change in the compact export.

Required correction: print an alias on a nested operation whenever its owner
differs from its displayed parent.

### Correctness conclusion for the sample

The sample is syntactically and arithmetically consistent with schema 2. It is
not sufficient as a correct compact explanation of the WebRTC runtime because
ownership, role, redaction, and active-work semantics are lossy in ways that
can lead to a wrong diagnosis. The most urgent correction is ownership; the
most visible privacy defect is facet-name redaction.

## Recommended refactoring sequence

This sequence describes boundaries and acceptance gates, not code changes.

1. **Freeze domain snapshots.** Identify the authoritative peer, signaling,
   ICE, DTLS, SRTP admission, receiver, and negotiated-transceiver snapshots.
   Remove observation fields from their contracts. Keep revision only where
   the domain state owner actually needs optimistic concurrency.
2. **Introduce a Runtime sidecar registry.** Bind object identity, semantic
   entity role, owner epoch, and operation policy at composition time. This is
   the sole source of trace owner identity and redacted role labels.
3. **Separate execution policy.** Replace `@event_loop`, `@worker`, and `@task`
   as metaclass behavior with explicit Runtime/domain execution ports. Preserve
   loop assertions and owner cancellation semantics independently of whether
   tracing is enabled.
4. **Observe state after commit.** State owners return or emit immutable domain
   commits/effects. Runtime observers translate them into machine, transition,
   and facet records. Projection failure remains diagnostic and cannot affect
   protocol progress.
5. **Move telemetry reducers.** Logging counters, analyzer frame counters,
   queue depth/high-water, worker load, SRTP packet delivery, and debug counters
   become Runtime-side bounded/coalesced reducers.
6. **Replace automatic operation discovery.** Use an external allowlist of
   meaningful public operations and named workflows. Private helpers default
   off; high-rate packet paths default off or aggregate at a deliberate
   cadence.
7. **Remove `ObservedComponent` per component.** Start with infrastructure and
   leaf components (`MultiUDPMux`, `DTLSConn`, `AudioAnalyzer`,
   `AsyncLogDrain`), then media/ICE components, and remove it from
   `PeerConnection` last after end-to-end parity is proven.
8. **Correct compact export semantics.** Resolve registered IDs to aliases in
   all text, retain semantic role labels, expose owner changes in nested work,
   and distinguish pumps/waits from request operations.

## Acceptance criteria

### Architecture

- No production WebRTC class inherits `ObservedComponent` or uses
  `ObservedMeta`.
- Enabling/disabling tracing cannot change call return type, worker dispatch,
  task scheduling, event-loop affinity, cancellation, or protocol state.
- Protocol modules do not construct operation IDs, observation groups, trace
  detail, producer dots, source order, facet IDs, owner aliases, or schema-2
  records.
- Projection and renderer failures are diagnostic-only and cannot fail a
  committed WebRTC state transition.
- Every state read used for admission/readiness comes from one authoritative
  domain snapshot, not from duplicated fields plus machine state.

### Trace behavior

- `PeerConnection.start` is owned by the peer entity, ICE work by the ICE
  entity, transceiver work by the transceiver entity, and infrastructure work
  by its service/resource owner.
- Nested operations display ownership exactly when it changes.
- No raw registered entity ID appears anywhere in the compact export,
  regardless of length or character set.
- Semantically duplicate machine types carry bounded role labels.
- Expected pumps and waits cannot be mistaken for stalled request operations.
- Record counts equal the complete normalized records represented by every
  section; grouping must not drop values.
- A single end-to-end fixture covers Python snapshot/patch production, WebSocket
  delivery, TypeScript normalization, and compact export. Isolated backend and
  renderer tests are not enough for ownership/redaction parity.

### Regression and performance

- Run the full Python suite with tracing enabled and disabled and compare
  protocol outcomes.
- Retain schema-2 snapshot/patch, slow-subscriber, terminal-drain, facet
  cardinality/redaction, capture, worker cancellation, and state authority
  tests.
- Add assertions that private plumbing does not appear in the default compact
  operation export.
- Measure call overhead and full-peer CPU before and after removal of the
  metaclass. The refactoring is incomplete if observation remains on the data
  path merely under a different name.

## Verification performed for this audit

- `python -m compileall -q webrtc`: passed.
- Full backend test suite: **265 passed**.
- Focused observability/state/transport subset: **56 passed**.
- Web trace renderer suite: **14 passed**.

Those results confirm the current isolated contracts. They do not invalidate
the architectural and semantic findings above because the current tests assert
the existing owner fallback and renderer behavior rather than the desired
component ownership and full-identifier redaction contract.
