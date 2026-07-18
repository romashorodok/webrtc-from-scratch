# Runtime-Owned State Machine Refactoring Plan

## Status

Implementation plan only. This plan builds on the completed
`live_tracing_performance_aggregation_plan.md` schema-2 observability work. It
replaces scattered mutable flags, locks, events, directly created tasks, and
facet-only lifecycle reporting with runtime-owned, single-writer state
machines for the complete peer-to-peer WebRTC lifecycle.

The motivating trace is not yet internally consistent:

- the peer machine remains `new` while the peer connection facet is
  `connected`;
- the ICE machine reaches `connected` while the ICE connection facet remains
  `checking`;
- the DTLS observable machine exposes internal `Preparing/Sending/Waiting`
  flight phases and ends in `Finished`, while the public DTLS machine contract
  in `machine_specs.py` expects `new/connecting/connected/...`;
- transport, transceiver, media session, media stream, queue, worker, and
  tracing lifecycles are represented by facets but not consistently by
  authoritative machines;
- some component-owned tasks are created with `asyncio.create_task` rather
  than through Runtime ownership.

These are correctness and ownership defects, not summary-format defects. The
compact LLM summary must be a projection of authoritative commits; it must
never infer protocol state by reconciling contradictory facets after the fact.

## Goals

- Make Runtime the owner of every long-lived coroutine, worker submission,
  queue pump, timer, protocol controller, and teardown barrier created by a
  peer connection.
- Give every bounded lifecycle-bearing component an explicit typed state
  machine, legal transition table, epoch, revision, command set, and terminal
  reconciliation rule.
- Use one event-loop writer for authoritative protocol state and observability
  projection. Workers return immutable results and never mutate component or
  tracing state.
- Remove component locks that compensate for multi-writer state mutation.
  Serialize commands through bounded mailboxes or explicit runtime lanes.
- Preserve high throughput: packet processing and crypto do not create a
  transition per packet, per frame, or per observed call.
- Produce a coherent schema-2 trace in which machines, transitions, activity
  groups, facets, and diagnostics share stable entity identity and revision
  ordering.
- Automatically offload synchronous work when its compiled execution policy is
  CPU-bound or potentially blocking, while retaining cheap atomic state
  mutation on the runtime loop.
- Make shutdown deterministic: reject new commands, drain or cancel owned work,
  reconcile children, commit one terminal state, flush final projection, and
  remove the entity epoch.

## Non-goals and precise meaning of “lock-free”

- CRDTs are used only for the observability replica and cross-producer result
  merging. They do not decide ICE, DTLS, SRTP, RTP, signaling, or peer behavior.
- “Lock-free” means no application-level shared mutex or shared mutable map on
  normal transition, tracing, packet, or worker-result paths. Runtime's event
  loop is the sole writer. It does not claim that CPython, `asyncio`, socket
  wakeups, or the physical thread-pool implementation contain no internal
  locks.
- Not every synchronous method should be offloaded. A tiny accessor, command
  validation, queue accounting update, or atomic state commit must execute on
  the owning loop. Offloading such work would add latency and break commit
  ordering.
- Packets, STUN transactions, RTP sequence numbers, RTCP reports, DTLS records,
  and individual media frames are bounded activities or protocol data, not
  independently replicated lifecycle machines.
- This plan does not introduce distributed control of one live peer across
  multiple Runtime processes. CRDT convergence is for retry, reordering,
  worker results, and frontend replication.

## Confirmed architecture decisions

These decisions were selected for this refactor and supersede recommendations
elsewhere in the original tracing plan when they conflict.

1. **All unannotated synchronous `ObservedComponent` methods are offloaded.**
   `ObservedMeta` compiles every eligible unannotated synchronous method as a
   Runtime worker call. State-machine validation/commit code is kept outside
   `ObservedComponent` wrappers in neutral runner primitives; explicitly
   annotated loop callbacks remain loop callbacks. This prevents a synchronous
   component method from unexpectedly blocking the event loop.
2. **Preserve sync-or-awaitable compatibility during the refactor.** A worker
   call in an active async Runtime context returns an awaitable; an explicitly
   loop-inline method can return its value. Call sites must use the common
   `maybe_await`/typed adapter until migration is complete. The ambiguity is a
   deliberate compatibility decision and must have type-check tests.
3. **Internal API breakage is allowed.** Update every repository caller and
   test with the owning component. Do not retain obsolete internal adapters.
4. **Deliver one atomic full refactor.** Component work may be developed in the
   dependency order below, but the new architecture is enabled only when all
   components, tests, and trace consumers have migrated. Do not ship a runtime
   with two lifecycle authorities.
5. **Remove EventEmitter completely.** Replace `EventEmitter` and
   `AsyncEventEmitter` inheritance, `.on()`, `.emit()`, decorator listeners,
   and listener locks with owned typed machine commands, reply ports, and
   bounded subscriber/output mailboxes.
6. **Every component is an observable machine.** Queues, bindings, candidate
   pairs, attachments, worker lanes, SRTP streams, inboxes, and other bounded
   component instances receive machine identity. Hot operations still update
   aggregate counters rather than transitioning per packet/call.
7. **Mailbox overload is class-specific.** Backpressure at safe async API
   boundaries; fail an owner when dropping a protocol/control command would
   violate correctness; drop and count only explicitly lossy media/log data.
8. **Maximize worker concurrency.** Under the selected CPython-with-GIL target,
   worker threads make blocking calls and Python work concurrent; they do not
   provide true parallel execution of Python bytecode. True CPU parallelism is
   available only when native/Rust code releases the GIL, through subprocess
   workers, or on a future validated free-threaded runtime. Do not serialize
   concurrent worker execution merely to preserve call order. Assign submission
   sequence numbers and commit results through the owning loop. Where a
   stateful foreign object cannot safely be called concurrently, use isolated
   per-call/per-shard state or move the minimal unsafe mutation to the owner;
   do not add a lock or global serialized lane. Network arrival order is not an
   execution-serialization requirement, but protocol invariants such as DTLS
   flight causality, SRTP replay state, packet sequence allocation, and machine
   revision order remain mandatory at commit.
9. **Observation failure is non-fatal in production and fatal in strict tests.**
10. **Target CPython with the GIL initially.** Immutable worker boundaries and
    wrong-thread assertions are still required; free-threaded Python is not an
    acceptance target for this refactor.
11. **Delete schema 1 and duplicate metric paths.** Schema 2 is the only trace
    authority; no permanent dual emission or compatibility event bus remains.
12. **No explicit locks or semaphores in project code.** Delete all
    `asyncio.Lock`, `threading.Lock`, `RLock`, and component/executor ordering
    semaphores. Internal synchronization inside CPython, asyncio queues, the
    event loop, socket implementation, Rust libraries, and the selected
    executor is outside this source-level rule.
13. **Use a bounded live journal plus snapshot/resync.** Do not retain an
    unbounded transition history.
14. **Derive numeric performance gates from the existing benchmark baseline.**
    Record the chosen values in the checked-in performance budgets before the
    atomic architecture switch.

## Required invariants

1. **One authoritative writer.** Only the Runtime loop may mutate a component
   machine, component-owned collection, readiness predicate, or schema-2
   projection store.
2. **Commands are not states.** Callers enqueue typed intent. Only the machine
   runner validates and commits a state edge.
3. **Commit is synchronous.** A commit validates the expected epoch/revision,
   updates the authoritative state and derived readiness bits, and emits one
   immutable transition operation without awaiting.
4. **No await inside an invariant.** Potentially suspending protocol work is
   performed before proposing a commit or after a committed checkpoint.
5. **One public machine per semantic lifecycle.** Internal phase machines use
   distinct types and entity IDs; they cannot masquerade as the public DTLS or
   peer state.
6. **Facets are derived.** A facet may add bounded detail but cannot carry a
   lifecycle value that conflicts with its owning machine revision.
7. **All work is registered before it can run.** No bare component-level
   `asyncio.create_task`, orphan future, untracked timer, or fire-and-forget
   callback may outlive its owner.
8. **Bounded ingress.** Every mailbox, worker lane, packet queue, transition
   journal, pending-op buffer, and diagnostic exemplar store has a capacity and
   an explicit overflow policy.
9. **Terminal means reconciled.** The terminal checkpoint occurs only after all
   owned children and worker barriers are joined and no producer can publish a
   later transition for that entity epoch.
10. **Tracing is downstream only.** Failure or overload in observability cannot
    change protocol decisions; it records a bounded diagnostic and requests a
    subscriber resynchronization if necessary.

## Core architecture

```text
application/API callers
        |
        v
typed bounded component mailbox --------+
        |                                |
        v                                | immutable worker result
Runtime-owned machine runner             |
        | prepare async work             |
        +------> Runtime worker lane -----+
        |
        | validate + synchronous commit
        v
authoritative component snapshot
        |
        +--> readiness/barrier notification
        +--> domain event compatibility adapter (temporary)
        `--> MachineTransitionOp + derived FacetOp
                    |
                    v
          loop-owned CRDT projection
                    |
                    v
          schema-2 journal and summary
```

### Generic machine contract

Extend `webrtc/state_machine.py` instead of creating a bespoke runner for each
component:

```python
@dataclass(frozen=True, slots=True)
class MachineCommand(Generic[P]):
    kind: CommandKind
    command_id: int
    expected_epoch: int
    cause_id: int | str | None
    payload: P
    reply: ReplyPort | None

@dataclass(frozen=True, slots=True)
class PreparedTransition(Generic[E]):
    expected_state: str
    proposed_state: str
    effects: E
    cause_id: int | str | None

@dataclass(frozen=True, slots=True)
class MachineCommit:
    entity_id: str
    machine_type: str
    epoch: int
    revision: int
    from_state: str
    to_state: str
    cause_id: int | str | None
    monotonic_ns: int
```

The reusable runner must provide:

- a bounded mailbox with `submit`, `try_submit`, and close/reject behavior;
- exactly one Runtime-owned runner task;
- duplicate command suppression by `(epoch, producer_id, producer_seq)` where
  retry is possible;
- `prepare(command)` for suspending I/O or worker work;
- `commit(prepared)` as a non-awaiting compare/validate/mutate operation;
- `after_commit(commit, effects)` for notifications and follow-up commands;
- terminal reconciliation and controller checkpoints;
- typed failure mapping rather than an implicit transition to a generic error;
- snapshots that can be read on-loop without a lock;
- a debug assertion for wrong-loop and wrong-epoch access.

`AsyncStateMachineRunner` currently supplies part of this contract. Refactor it
so `step()` cannot mutate public state, terminal commands can wake a runner
blocked on protocol input, mailbox capacity is configurable, and Runtime owns
the task handle. Remove direct projector callbacks that allow arbitrary
component code; inject a narrow Runtime transition sink instead.

### Hierarchical machine graph

Use these semantic parents. Parentage controls cancellation, final flushing,
and compact summary grouping, but child machines retain independent state and
revision.

```text
runtime
`-- peer
    |-- signaling
    |-- attachment:signaling
    |-- attachment:media-source[*]
    |-- ice-gatherer
    |   `-- ice-agent
    |       `-- candidate-pair[*]
    |           `-- candidate-pair-controller[*]
    |-- selected-transport
    |   `-- dtls-transport
    |       |-- dtls-handshake-phase
    |       |-- srtp-session:rtp
    |       `-- srtp-session:rtcp
    |           `-- srtp-stream[*]
    |-- transceiver[*]
    |   |-- rtp-sender
    |   |-- rtp-receiver
    |   `-- media-track[*]
    |-- queue[*]
    `-- worker-lane[*]
```

Runtime and tracing-service health are separate root machines, not peer
children, because they may outlive and observe multiple peers.

## Machine catalog and component plans

### Runtime and observability service

Machine type `runtime`:

```text
new -> starting -> active -> quiescing -> draining -> closed
                  \-> failed -> draining
```

- Runtime owns the root task context, scheduler, offloader, concurrent workers,
  transition ingress, schema-2 journal, subscriber dispatchers, and every peer
  scope.
- Replace `_close_lock` idempotence with a close command and one retained
  Runtime-owned close future. Concurrent closers await the same reply.
- `quiescing` rejects new roots and worker submissions. `draining` joins peer
  scopes, scheduler descendants, dispatched futures, journal flush, and owned
  resources in that order.
- Add an `observability` machine:
  `stopped -> starting -> active -> degraded -> draining -> stopped`, with
  facets for admission, journal depth, subscriber count, drops, resyncs, and
  observer failures. Diagnostics may move it to/from `degraded`; they must not
  fail Runtime.
- Runtime allocates stable numeric producer IDs and component entity IDs. All
  random/public IDs are allocated once per component epoch, never per packet or
  transition.

### PeerConnection

Machine type `peer`:

```text
new -> starting -> negotiating -> connecting -> connected
 |       |             |             |             |
 +-------+-------------+-------------+-----------> closing -> closed
         \------------- failure ----------------> failed -> closing
```

- Make the peer machine the authority for `_started`, `_closing`, `_closed`,
  `state`, connection readiness, and failure cleanup. Remove those independent
  flags after compatibility accessors read the snapshot.
- `__aenter__`, `dial`, `accept`, offer/answer operations, nominated transport,
  DTLS readiness, protocol failure, and `aclose` submit typed commands.
- Do not derive connection state merely from `_transport is not None`.
  `connected` requires selected ICE transport plus committed DTLS/SRTP readiness
  according to the peer's negotiated media requirements.
- Replace `_peer_connection_lock`, `_close_lock`, and ad hoc failure-close task
  with mailbox serialization and a Runtime-owned close workflow.
- Replace the media-send lock with a bounded concurrent `media-send` worker
  component. Tag submissions and reconcile results on the peer loop; preserve
  only protocol-required sequence allocation at commit. Its queue and running
  status have their own machines and facets.
- Commit `closed` only after attachments, transceivers, pair controllers, DTLS,
  selected transport, log drain, event emitter, worker barriers, and final
  observability flush reconcile.

### Signaling and SDP offer/answer

Machine type `signaling` uses WebRTC signaling states as real state identities:

```text
stable -> have-local-offer -> stable
stable -> have-remote-offer -> stable
offer states -> closed
any nonterminal -> failed -> closed
```

- Fold `_signaling_state`, pending/current descriptions, and
  `_signaling_lock` into one signaling machine snapshot.
- `create_offer` reads a stable snapshot. `set_local_description` and
  `set_remote_description` prepare parsing/validation first, then atomically
  commit description pointers and signaling state together.
- A stale prepared result carries its expected signaling revision and is
  rejected/retried rather than overwriting a newer description.
- SDP parsing or certificate/fingerprint validation that is CPU-heavy uses a
  worker result; the worker receives immutable bytes/strings and never sees the
  live PeerConnection.
- Redact SDP, ICE credentials, fingerprints, and addresses from facets. Trace
  only description type, negotiation generation, bounded media-section count,
  and outcome.

### AttachmentController, AsyncLogDrain, and peer inboxes

Machine type `attachment`:
`detached -> attached -> starting -> active -> stopping -> stopped`, with
`failed -> stopping`.

- Give the signaling attachment and each media source a stable entity. The
  controller is a registry machine; attachments are child machines.
- `start()` must be idempotent by command identity, not by duplicate tasks.
  Runtime owns attachment pumps and joins them before `stopped`.
- Model `AsyncLogDrain` as
  `stopped -> starting -> idle <-> draining -> stopping -> stopped`, with log
  count and queue high-water as facets/activity counters.
- `PeerEventInbox`, log inbox, and attachment inbox remain bounded queues, but
  queue lifecycle is a `queue` machine:
  `open -> closing -> drained -> closed`, plus depth/high-water/drop facets.
- Replace the two bare `asyncio.create_task` calls used to race drain input and
  stop wakeups with a Runtime-owned receive primitive or one runner mailbox.

### ICE gatherer and Agent

Split the overloaded ICE view into distinct machines:

- `ice-gatherer`: `new -> gathering -> complete -> closed`, with
  `gathering -> failed -> closed`;
- `ice-agent`: `new -> waiting-remote -> checking -> connected -> completed`,
  with reconnect path `connected/completed -> disconnected -> checking` and
  terminal `failed/closed`;
- `candidate-pair`: `frozen -> waiting -> in-progress -> succeeded ->
  nominated`, with failure and close edges;
- `candidate-pair-controller`: `new -> starting -> checking -> nominated ->
  forwarding -> stopping -> stopped`, with `failed -> stopping`.

Implementation rules:

- `ICEGatherer.__gather_lock`, candidate registries, controller registries,
  role, credentials, candidate lists, pair lists, and selected pair mutate only
  through the ICE runner on the Runtime loop.
- DNS resolution (`socket.gethostbyname`) is blocking and must use the Runtime
  offloader with a timeout and immutable result command.
- Candidate creation and STUN parsing remain ordinary activities unless they
  cross the measured CPU offload threshold. Never transition for every inbound
  STUN request.
- Nomination commits the pair and agent states before notifying PeerConnection.
  The selected pair ID facet must carry the exact nomination revision.
- Controller receive loops are Runtime-owned children. `start_managed` returns
  an owned handle, not a task created or stored by the component.
- Replace `CandidatePairController._close_task = asyncio.create_task(...)` with
  an idempotent stop command and Runtime-owned terminal reply.
- Controller failure maps once into pair/controller/agent states, then sends a
  causally linked peer failure command. It must not generate competing close
  tasks.

### UDP mux, interceptors, and selected CandidatePairTransport

Machine types:

- `udp-mux`: `new -> binding -> active -> draining -> closed`, with `failed`;
- `udp-binding`: `new -> bound -> active -> draining -> closed`;
- `transport`: `new -> selecting -> ready -> draining -> closed`, with
  `failed`;
- queue children use the common queue machine.

- Runtime owns socket transports and datagram protocols as resources with
  explicit close barriers.
- Datagram callbacks may only parse the minimum routing key and enqueue an
  immutable packet reference into a bounded loop-owned queue. They do not
  mutate ICE/DTLS/media machines.
- Define overflow per route: STUN/control overflow is diagnostic and may fail
  the affected controller; media overflow uses bounded drop accounting. Never
  block a UDP callback.
- A selected transport is `ready` only after a nominated pair commit. On close,
  stop ingress, drain/cancel consumers, close interceptors/bindings, then close
  the mux.
- Queue facets are updated at threshold/coalescing boundaries, not per packet
  schema-2 patches.

### DTLS transport and handshake phase FSM

Use two machines, fixing the current semantic collision:

- public `dtls-transport`:
  `new -> binding -> connecting -> connected -> closing -> closed`, with
  `connecting/connected -> failed -> closing`;
- internal `dtls-handshake-phase`:
  `preparing -> sending -> waiting -> preparing`, ending in `finished` or
  `errored`.

- Rename the current trace machine type from public `dtls` to
  `dtls-handshake-phase`. Project public `dtls` only from DTLSTransport
  lifecycle commits.
- Adapt `FSM` to the generic runner: one typed command mailbox, no state lock,
  no stale shadow state, explicit transition table, and one terminal commit.
- A phase prepares a flight or wait outcome; it cannot directly publish a
  state. Retransmit timers are Runtime-owned timer handles tied to the handshake
  epoch and ignored after epoch change.
- `DTLSTransport.start` becomes an async command/reply operation. It must not
  return merely because it scheduled `_run_handshake`.
- Record ingestion is bounded. The reconstructor is loop-owned; expensive
  certificate verification and cryptographic operations use a serialized DTLS
  worker lane when they cannot run in Rust without blocking the loop.
- Handshake `finished` causes key extraction and SRTP session creation. Commit
  public `connected` only after both SRTP sessions are installed and their
  readiness snapshots are visible. Never expose key material to tracing.
- Replace readiness events as authorities with revision predicates; events may
  remain temporary compatibility wait adapters.

### SRTP sessions and streams

Machine types:

- `srtp-session`: `new -> initializing -> ready -> draining -> closed`, with
  `failed -> draining`;
- `srtp-stream`: `new -> active -> draining -> closed`, with `failed`.

- Session keys and Rust contexts are immutable after initialization. Their
  existence is represented only by `keys_ready=true` and negotiated profile.
- Replace `_streams_lock` with loop-owned stream-map mutation. Concurrent
  decrypt calls return immutable `(ssrc, plaintext, crypto counters)` worker
  results; the loop performs get-or-create and delivery ordering.
- Allocate one bounded stream entity per admitted SSRC. Apply an explicit SSRC
  cardinality budget and overflow diagnostic; never create unbounded observed
  identities from hostile packets.
- Crypto sync methods are compiled worker operations and automatically
  offloaded when called from async component code. A call already inside the
  worker context executes inline to avoid recursive resubmission overhead.
- Preserve protocol commit order per session/direction where the cipher replay
  window requires it. Execute independent sessions concurrently; true CPU
  parallelism exists only when the Rust context releases the GIL or work is
  moved to subprocesses.
- Encrypt/decrypt calls stay aggregate activity groups. Session/stream state
  changes only on initialization, admission, failure, drain, and close.

### RTP transceiver, sender, receiver, tracks, packetizer, and jitter buffer

Machine types:

- `transceiver`: `inactive -> negotiating -> active -> stopping -> stopped`,
  with active/inactive renegotiation and `failed -> stopping`;
- `rtp-sender`: `new -> bound -> active -> paused -> stopping -> stopped`;
- `rtp-receiver`: same lifecycle;
- `media-track`: `new -> live -> muted -> ended`, with `failed -> ended`;
- optional `media-pipeline`: `new -> configured -> running -> draining ->
  stopped` for each admitted sender/receiver pipeline.

- Direction, MID, codec, sender, receiver, negotiated parameters, and lifecycle
  are committed atomically at a transceiver revision. Remove independent
  `_emit_transceiver_state` lifecycle guesses.
- `set_mid`, `set_preferred_codec`, and sender/receiver attachment submit
  commands or are private commit helpers invoked only by the runner.
- Replace `RTPSender.__transport_lock` with binding-state commands and revision
  checks. Send attempts wait for a `bound/active` predicate outside the commit.
- TrackRemote delivery uses its bounded queue machine. Drops and delivered
  counts are coalesced G-counters; the queue does not transition per packet.
- Packetizer, sequencer, RTP header extension, RTCP report builder, and jitter
  buffer are loop-owned data-plane helpers, not machines unless they own a
  long-lived pipeline. Their CPU-heavy sync work follows the execution policy.
- Codec/encode work and `WebSocketMediaWorker.invoke` use bounded concurrent
  workers based on codec thread-safety. Native codecs that release the GIL or
  subprocess codecs may run in true parallel. The 31k-call activity group
  remains aggregated and must not produce 31k state transitions.

### Worker lanes and automatic synchronous offload

Machine type `worker-lane`:
`idle -> queued -> running -> idle`, with `running -> failed -> idle` and any
nonterminal state to `closing -> closed`.

Compile one execution policy per observed method at class creation. Because
automatic offload was selected, `WORKER_CONCURRENT` is the default for every
unannotated synchronous `ObservedComponent` method:

```text
LOOP_INLINE       explicit loop callback/accessor exemption only
LOOP_ASYNC        coroutine orchestrating loop-owned state or I/O
WORKER_CONCURRENT default synchronous component method
BLOCKING_WORKER   potentially blocking filesystem/DNS/foreign call
```

- `@event_loop` explicitly selects `LOOP_INLINE`/`LOOP_ASYNC`; unannotated sync
  and `@worker` select `WORKER_CONCURRENT`; `@blocking` additionally selects the
  blocking-worker capacity class. There is no serialized-worker policy.
- For an async caller, invoking a worker-policy synchronous method returns an
  awaitable owned by Runtime and automatically dispatches it. Compatibility
  call sites accept a direct value or awaitable and normalize through one
  typed adapter, as selected above.
- For a synchronous caller without an active Runtime, worker-policy methods
  fail with `MissingExecutionScope`; they must not silently run blocking work
  on the event loop.
- Nested synchronous calls already inside a worker execute inline and append
  observation deltas to the submission-local buffer; they must not recursively
  resubmit to the executor.
- Worker functions receive immutable arguments/snapshots and return immutable
  results. Completion callbacks enqueue results to the owning loop; they never
  commit state from executor threads.
- Delete `SerializedWorkerLane`. Replace its semaphore and helper
  `create_task` cleanup with a concurrent Runtime worker pool, bounded command
  admission, submission sequence IDs, owned futures, and loop-side result
  reconciliation.
- Queue time, worker time, total time, cancellations, and errors merge into the
  activity CRDT once per submission.

Execution backends must be named accurately in code, traces, and benchmarks:

| Backend | Python bytecode behavior on target CPython | Intended work |
| --- | --- | --- |
| event loop | cooperative concurrency | machine ownership, async I/O, commit |
| thread executor | concurrent, normally not CPU-parallel under the GIL | blocking calls and native work |
| GIL-releasing Rust/native function | may execute truly in parallel | crypto/codec hot paths proven to release GIL |
| subprocess pool | true process parallelism with serialization cost | large pure-Python CPU jobs only |
| free-threaded Python | potentially true thread parallelism | future target, excluded from current acceptance |

Metrics must use `concurrent_in_flight`, `native_parallelism`, and
`subprocess_parallelism` rather than describing every worker thread as
parallel. Benchmarks must separately prove whether a native operation releases
the GIL before attributing throughput improvement to parallel execution.

### Common queue machine

Machine type `queue`: `open -> closing -> drained -> closed`, with `failed`.

- The lifecycle machine owns acceptance and close semantics. Depth,
  high-water, admitted, delivered, dropped, and rejected are facets/counters.
- Producers use `try_submit` for callback/hot paths and `submit` only at async
  backpressure-safe points. Every queue declares which is legal.
- Closing rejects new entries before suspension. `drained` means the last
  accepted entry was processed or explicitly cancelled.
- Publish depth changes only on zero/nonzero transitions, threshold crossings,
  health changes, or display cadence. Keep exact counters internally.

## CRDT and schema-2 projection

### Operation types

Every machine commit produces one immutable operation:

```text
(runtime_epoch, entity_id, entity_epoch, machine_type,
 revision, from_state, to_state, producer_dot, cause_id, monotonic_ns)
```

Derived facets use `(entity_id, entity_epoch, facet_revision, producer_dot)`.
Activity counters use per-producer G-counters/PN-counters. Entity membership is
an epoch-scoped observed-remove map. The loop reducer applies these rules:

- duplicate dot: ignore and increment duplicate diagnostic;
- future contiguous revision: validate and commit;
- bounded future gap: retain temporarily and request missing operation;
- stale epoch/revision: ignore;
- invalid edge or source mismatch: do not change visible state, retain one
  bounded exemplar, and increment diagnostic;
- removal: wins for the same/older entity epoch only;
- incompatible machine type for an existing entity epoch: reject.

### Facet coherence

- Machine state is emitted only in `machine:transition`/snapshot records. Do
  not duplicate it as an independently revised `state` facet.
- Connection, readiness, active, selected, direction, role, profile, queue
  depth, and counters may be facets. Each derived facet includes
  `source_machine_revision`.
- The reducer rejects or withholds a facet whose source revision is ahead of
  the machine and ignores one older than the installed facet revision.
- A snapshot is captured at one service revision. The compact summary is
  generated from that snapshot, never from live component objects.

### Compact LLM summary requirements

The summary must report:

- all nonterminal/failed machines and the final state of bounded terminal
  machines;
- legal transitions in runtime commit order with repeated phase cycles compacted
  as counts when causality would not be lost;
- aggregate operation call counts and bounded nesting;
- only latest coherent facets per entity;
- diagnostics for invalid transitions, stale/future revisions, drops,
  overflow, worker failures, resyncs, and untracked-work attempts.

Add consistency diagnostics to summary generation:

- `machine_facet_state_conflict`;
- `peer_connected_without_transport`;
- `peer_connected_without_srtp`;
- `ice_selected_pair_without_nomination`;
- `dtls_connected_without_keys`;
- `terminal_entity_with_live_children`;
- `untracked_runtime_work`;
- `wrong_loop_mutation`.

A consistency error makes an end-to-end trace test fail even when signaling and
media otherwise complete.

## Runtime ownership enforcement

- Add `Runtime.start_machine(...)`, `Runtime.start_pump(...)`,
  `Runtime.call_worker(...)`, and `Runtime.call_later_owned(...)`. Each requires
  an owner entity, failure policy, and terminal reconciliation barrier.
- Return opaque `OwnedTaskHandle`/`OwnedTimerHandle`, not raw tasks to component
  code. Handles support cancel, wait, and status but not task-tree mutation.
- In test/debug mode, install an event-loop task factory that records or rejects
  task creation not originating from TaskScheduler. Permit a tiny allowlist for
  asyncio internals and third-party libraries, with ownership adapters.
- Add a static repository check for `asyncio.create_task`,
  `loop.create_task`, `ensure_future`, raw executor submission, and unbounded
  `asyncio.Queue` outside approved runtime modules.
- Runtime shutdown reports `untracked_runtime_work` and fails tests if live
  tasks, worker futures, timers, transports, or machine entities remain.

## Aggressive lock deletion ledger

The target architecture does not preserve locks for compatibility. Delete each
lock below as soon as its protected fields have moved behind the named owner.
Do not replace an `asyncio.Lock` with a different mutex. Replace multi-writer
access with one writer, typed commands, immutable worker results, or an owned
serialized lane.

| Current lock | Protected concern | Replacement | Delete when |
| --- | --- | --- | --- |
| `ICEGatherer.__gather_lock` | duplicate gather/agent creation | `ice-gatherer` mailbox; concurrent callers share one command reply | gatherer machine lands |
| `ICETransport.__transport_lock` | selected transport pointer | transport machine commit and revisioned on-loop snapshot | ICE transport migration lands |
| `PeerConnection._signaling_lock` | SDP state/description mutation | signaling runner; descriptions and state commit atomically | signaling machine lands |
| `PeerConnection._close_lock` | idempotent teardown | one peer close command plus retained terminal reply | peer runner owns teardown |
| `PeerConnection._peer_connection_lock` | broad peer mutation serialization | typed peer/signaling/transceiver commands with distinct owners | all protected call sites are routed |
| `PeerConnection._media_send_lock` | ordered public media bursts | bounded concurrent media-send worker plus loop-owned sequence allocation/result reconciliation | send path no longer mutates shared state |
| `BindingRequestCacheRegistry._lock` | STUN transaction cache mutation | ICE-controller loop ownership; cache commands/timer expiry on same runner | selectors cannot mutate off-loop |
| `DTLSConn.recv_lock` | inbound record ordering | single DTLS receive pump and bounded mailbox | all records enter through pump |
| `Session._streams_lock` | SSRC stream map creation | SRTP-session loop-owned admission command; worker returns immutable SSRC result | decrypt workers cannot touch map |
| `RTPSender.__transport_lock` | transport bind/read | sender machine `bound` snapshot and revision predicate | sender migration lands |
| `Runtime._close_lock` | Runtime close idempotence | runtime close command and shared close reply | runtime machine lands |
| `SerializedWorkerLane._semaphore` | lane ordering | one owned lane runner consuming a bounded mailbox | new worker lane is enabled |
| `SyncOffloader._limiter` semaphore | physical worker capacity | bounded Runtime command queue plus explicit dispatch-credit messages | new offloader lands |
| `TaskRegistry._lock` | cross-thread task/barrier registry | Runtime-loop-only registry; executor threads enqueue immutable completion operations | no registry API is called off-loop |
| `MetricRecorder._lock` in `performance.py` | arbitrary-thread metric list | loop-owned aggregate store and worker-local delta merge | legacy per-call metric recorder is removed |
| operation interning lock in `performance.py` | dynamic global operation IDs | compile/intern operation IDs during class registration/startup; freeze table before Runtime active | no runtime dynamic registration remains |
| `TraceEventBus._lock` | subscriber set, pending batches, sequence | loop-owned schema-2 journal/cursors and immutable shared batch | legacy event bus is deleted |
| tracing performance recorder `RLock` | legacy retained perf events | loop-owned bounded diagnostic/activity reducers | compatibility recorder is deleted |
| `EventEmitter._lock` | listener registry across threads | delete emitter; typed machine commands and bounded output mailboxes | no emitter inheritance or call site remains |

There is no project-code exception for `SyncOffloader`: capacity control moves
to bounded Runtime command admission and explicit dispatch-credit messages.
The physical executor may synchronize internally, but project code neither
imports nor exposes that synchronization.

### Lock-removal procedure

For every ledger row:

1. List every field and call site previously protected by the lock.
2. Assign those fields to exactly one machine/Runtime-loop owner.
3. Convert external mutation to a command and external reads to an immutable
   snapshot, revision predicate, or command reply.
4. Route worker/thread callbacks through immutable ingress operations.
5. Add a wrong-loop assertion and a concurrency/race test.
6. Delete the lock and the old direct-mutator methods in the same change. Do
   not leave an unused compatibility lock or dual mutation path.
7. Run deterministic interleaving, cancellation, shutdown, and throughput
   tests before checking off the row.

The final repository check must reject `asyncio.Lock`, `threading.Lock`,
`RLock`, and ordering semaphores everywhere under `webrtc/`. External-library
bridges must communicate through immutable messages rather than wrapping the
library with a project-owned lock.

## Evidence-based component update inventory

This inventory is based on the current implementation, not only the desired
machine graph. Every row names concrete evidence that requires migration. A row
is complete only when its component uses owned commands, has a declared machine
spec, produces coherent schema-2 state, and leaves no event, lock, task, or
mutable lifecycle authority behind.

| Component/file | Current evidence | Required update |
| --- | --- | --- |
| `performance.py` — `ObservedMeta`, `ObservedComponent` | `_compile_sync_call` currently classifies affinity; worker wrappers create lane tasks; global operation interning and `MetricRecorder` use locks | Make unannotated sync methods concurrent-worker calls, preserve value-or-awaitable compatibility, remove wrapper-created tasks, freeze operation IDs, return worker-local CRDT deltas, delete metric locks |
| `state_machine.py` | generic runner has an unbounded `asyncio.Queue`, directly invokes a projector callback, and owns no Runtime task handle | Add bounded command ingress, epoch/expected-revision commands, prepared effects, owned runner handle, reply ports, terminal reconciliation, and transition sink |
| `machine_specs.py` | only peer/ICE/DTLS/transport/worker/transceiver/media specs exist; DTLS spec conflicts with the traced phase enum | Declare every catalog machine, separate `dtls-transport` from `dtls-handshake-phase`, compile parents/terminal rules/readiness predicates |
| `runtime.py` — `Runtime` | `_close_lock` protects close; Runtime owns tracing primitives but is not itself an observable lifecycle machine | Add runtime and observability machines, close command/reply, entity registry, owned timer/socket/future audit, remove close lock |
| `runtime_services.py` — `TaskRegistry` | registry uses `RLock`; `TaskScheduler` and reconciliation create raw asyncio tasks | Make registry loop-owned, route executor completions through ingress, make reconciliation an already-registered child/barrier, delete registry lock and raw task creation |
| `runtime_services.py` — `SyncOffloader`, `SerializedWorkerLane` | capacity and ordering use semaphores; lane dispatch and cancellation cleanup use `asyncio.create_task` | Replace with bounded concurrent command dispatcher, explicit credits, owned futures, sequence-tagged results and barriers; delete serialized lane |
| `observability.py` | projection stores already assert one owner and use dots/revisions, but component machines do not consistently feed them | Extend entity epochs/removal, source-machine facet revision checks, complete CRDT types, consistency diagnostics and all-component registration |
| `state_facets.py` | domain-event adapter currently synthesizes DTLS and other facet state independently | Derive facets only from machine commits/snapshots; remove duplicated lifecycle fields and eventually delete the domain-event compatibility adapter |
| `utils/event_emitter.py` | listener map is protected by `threading.Lock`; peer and ICE inherit its async form | Delete emitter implementation and replace every listener edge with typed command/reply/output mailboxes |
| `peer_connection.py` — `PeerConnection` | inherits `AsyncEventEmitter` and `ObservedComponent`; has signaling, close, broad peer and media-send locks; maintains `_started/_closing/_closed/state`; creates failure cleanup task; emits peer/transceiver state manually | Add peer/signaling machines, child readiness join, typed application output mailbox, owned failure command and close workflow, machine-owned transceiver updates; delete emitter, flags, locks, task and manual lifecycle emitters |
| `peer_connection.py` — `ICEGatherer` | inherits `AsyncEventEmitter`; uses gather lock; mutable gathering/connection strings; forwards controller through `.on/.emit` | Add gatherer machine and commands, shared gather reply, machine output to peer, remove lock/emitter/string authorities |
| `peer_connection.py` — `ICETransport` | transport pointer is guarded by a lock and exposed by async getter | Replace with selected-transport machine snapshot and revisioned bind command; delete lock |
| `peer_components.py` — inboxes | peer/log inboxes own queues, close flags/events and drop behavior but have no machines | Give each inbox a queue machine, bounded counters, typed close/drain commands and schema-2 identity |
| `peer_components.py` — `AsyncLogDrain` | `ObservedComponent`; races two raw tasks for input vs stop and owns stopping/wake events | Add log-drain machine and one owned mailbox pump; remove raw tasks/events; all sync methods auto-offload unless explicit loop callbacks |
| `peer_components.py` — attachment controllers | `ObservedComponent`; `start` schedules attachment work while lifecycle is held in controller collections | Create controller and per-attachment machines, typed attach/start/stop commands, Runtime-owned pumps and terminal joins |
| `ice/agent.py` — `CandidatePair` and registries | pair state is a directly settable enum; pair/controller registries are mutable dictionaries/lists | Make pair and registry machines loop-owned, replace public setter/direct collection mutation with commands and immutable snapshots |
| `ice/agent.py` — binding request cache | registry combines sync reads with an async locked writer and wall-clock expiry | Move cache to controller owner, use monotonic owned expiry timers and commands, remove lock and mixed access |
| `ice/agent.py` — selectors | controlling/controlled selectors inherit emitter and emit nomination callbacks | Convert selector outcomes to typed controller result commands; remove listener protocol and emitter inheritance |
| `ice/agent.py` — `CandidatePairController` | inherits emitter/ObservedComponent; listener-driven nomination; stores task handle; creates a close task; infinite packet loop | Add controller machine, bounded packet mailbox, owned receive child, nomination commit/output, terminal reconciliation; remove emitter and task handles |
| `ice/agent.py` — `Agent` | inherits emitter/ObservedComponent; mutable credentials/role/candidate/pair/controller/transport collections; emits new controller | Add agent machine and registry ownership, typed credential/candidate/connect commands, bounded child creation and causal nomination output |
| `ice/net/udp_mux.py` — interceptor/handler/connections | datagram callbacks route directly into mutable interceptor maps and queues | Give handler, interceptor, binding and connection machines; callback only submits immutable packets; define overflow and close barriers |
| `ice/net/udp_mux.py` — `MultiUDPMux` | `ObservedComponent`; accept/bind/inbound handler access and close are ordinary methods around socket resources | Add mux machine, Runtime-owned socket resources, typed bind/snapshot commands; automatic worker wrapping must explicitly exempt actual loop callbacks |
| `dtls/fsm.py` — `FSM` | current explicit `Preparing/Sending/Waiting/Finished` transitions use their own command queue and state/revision logic | Adapt to generic handshake-phase runner, bounded commands, epoch timers and one terminal commit; keep it distinct from public DTLS lifecycle |
| `dtls/fsm.py` — `DTLSConn` | `ObservedComponent`; owns `recv_lock`, unbounded handshake queue and receive-loop task path | Add connection/receive-pump machines, bounded record/message mailboxes, immutable crypto results; remove lock |
| `dtls/dtlstransport.py` | `ObservedComponent`; sync `start` schedules handshake; multiple task handles and readiness events; RTP/RTCP receive loops | Add public transport machine, typed start/bind/record/close commands, owned child machines, revision readiness, bounded ingress; remove direct task/event authority |
| `srtp/session.py` — `Session` | `ObservedComponent`; stream map uses lock; crypto sync methods use worker wrappers; new-stream queue is unbounded | Add session machine, loop-owned bounded stream admission, concurrent sequence-tagged crypto submissions, bounded output mailbox, remove stream lock |
| `srtp/session.py` — `Stream` | stream owns packet queue, activity counters and close/delivery semantics but only emits facets | Add visible stream and queue machines, admission budget, lossy overflow policy and terminal join |
| `transceiver.py` — `RTPTransceiver` | `ObservedComponent`; MID/direction/sender/receiver are mutated through ordinary methods and peer emits lifecycle separately | Add transceiver machine with atomic negotiated snapshot and typed configuration commands; remove peer-side lifecycle inference |
| `transceiver.py` — `RTPSender` | transport pointer uses `__transport_lock`; send lifecycle is not a machine | Add sender/binding machine, revision readiness and concurrent packet work with loop commit; remove lock |
| `transceiver.py` — `RTPReceiver`, `TrackRemote` | receiver is observed but lifecycle is incomplete; remote track owns bounded queue and direct drop logic | Add receiver, track and queue machines, typed packet delivery and terminal reconciliation |
| `media/packetizer.py`, payloaders, RTP/RTCP helpers | synchronous data-plane helpers are not `ObservedComponent`; some hold sequence/config state | Wrap stateful component instances in machines/ObservedComponent ownership; automatically offload sync calls; keep pure value functions outside wrapping |
| `media/jitterbuffer.py` | mutable buffer/frame state has no owner machine | Add jitter-buffer component and queue machine, immutable packet commands, bounded admission and concurrent parse results with loop commit |
| tracing event/performance modules | `TraceEventBus` and legacy performance recorder use `RLock` and retained event lists | Delete schema-1 bus and duplicate recorder; use only loop-owned schema-2 journal, cursors, activity CRDT and snapshot/resync |

### EventEmitter removal evidence and replacement routes

The following current event chains must be removed rather than wrapped:

```text
Agent --CANDIDATE_PAIR_CONTROLLER--> ICEGatherer --> PeerConnection
Selector --NOMINATE--> CandidatePairController
CandidatePairController --NOMINATE_TRANSPORT--> PeerConnection
PeerConnection --TRACK/STATE/etc.--> application listeners
```

Their replacements are:

```text
agent child-created commit -> gatherer/peer command
selector result command -> pair/controller nomination commit
nomination commit -> selected-transport command -> peer readiness command
peer output commit -> bounded application output mailbox / async iterator
```

Each replacement carries `cause_id`, owner/entity epoch, producer dot, command
ID, and reply/error policy. There is no arbitrary callback execution in a
machine commit or packet callback.

## Migration stages

### Stage 0 — Freeze contracts and establish baselines

- Capture the supplied 161-record trace as a regression fixture.
- Record throughput, event-loop lag, CPU, allocations, packet loss, media
  delivery, trace record count, patch rate, and shutdown duration with tracing
  off/on.
- Add an inventory of every lock, event, queue, task creation, timer, worker
  submission, mutable lifecycle flag, and domain state emitter.
- Define budgets before refactoring; do not accept “more state machines” if it
  causes per-packet transitions or materially regresses throughput.

Exit: reproducible full-peer loopback benchmark and ownership inventory exist.

### Stage 1 — Harden the generic runner and Runtime ownership APIs

- Implement bounded typed mailboxes, prepared transitions, epoch/revision
  compare, idempotent command replies, terminal reconciliation, owned timers,
  and opaque task handles.
- Refactor worker lanes to Runtime ownership and immutable result delivery.
- Add wrong-loop, wrong-epoch, untracked-task, and terminal-child assertions.

Exit: synthetic machine tests cover cancellation, duplicate/reordered commands,
worker completion after close, mailbox overflow, and deterministic checkpoints.

### Stage 2 — Separate public DTLS lifecycle from handshake phases

- Migrate the existing FSM first because it already exposes explicit phases.
- Rename its machine identity, remove stale duplicate state, bound its channels,
  and connect public DTLSTransport commits.
- Migrate SRTP session creation/readiness and ensure keys precede public DTLS
  `connected`.

Exit: trace shows two coherent DTLS machines and no `dtls=Finished` public
state.

### Stage 3 — Migrate ICE and transport ownership

- Migrate gatherer, agent, pair, controller, mux/binding, selected transport,
  DNS offload, and receive-loop ownership.
- Remove candidate/controller registry locks and bare close tasks.
- Make nomination the single causal source for selected transport.

Exit: ICE machine and facets agree; all controller tasks and socket resources
are Runtime-owned and reconciled.

### Stage 4 — Migrate peer and signaling

- Introduce peer and signaling mailboxes, replace lifecycle flags/locks, and
  make negotiation generation revisioned.
- Express child readiness as revision predicates and commit peer `connected`
  from coherent ICE+DTLS+SRTP snapshots.
- Replace failure cleanup scheduling with one failure command.

Exit: peer progresses from `new` to `connected` in the end-to-end trace and
closes without a competing cleanup task.

### Stage 5 — Migrate transceivers and media pipelines

- Migrate transceiver, sender, receiver, tracks, stream admission, media send
  lane, packet queues, packetizer/codec workers, and WebSocket media worker.
- Retain aggregate activities for packet/frame operations.

Exit: media begins only after committed transport readiness, stream entities
are bounded, and media throughput meets baseline budgets.

### Stage 6 — Migrate attachments, log drain, queues, and tracing service

- Remove remaining bare tasks and lifecycle flags from auxiliary components.
- Add queue and observability machines, coherent threshold-based facets, and
  final-flush reconciliation.
- Remove compatibility state emitters once all consumers read commits/facets.

Exit: repository ownership scan has no unexplained exception and every
lifecycle facet has an owning machine.

### Stage 7 — Remove locks and compatibility paths deliberately

- Remove each component lock only after its protected fields have one writer.
- Remove Event objects as sources of truth; retain lightweight wait adapters
  only where public API compatibility requires them.
- Remove “sync result or awaitable” call patterns and direct task handles.
- Delete legacy facet state duplication and deprecated machine mappings.

Exit: no application state lock remains on the normal peer/ICE/DTLS/SRTP/media
path; exceptions are documented with benchmark evidence and do not protect
multi-writer protocol state.

### Stage 8 — Full end-to-end validation and rollout

- Run deterministic checkpoint, failure injection, cancellation, overload,
  reconnect, renegotiation, shutdown, CRDT convergence, and schema-2 resync
  suites.
- Compare trace-off/on throughput and event-loop lag to budgets.
- Roll out behind per-component migration flags only while mixed-mode adapters
  are required; never allow two authorities for one lifecycle.

Exit: all acceptance criteria below pass and mixed-mode code is deleted.

## File-level change map

- `webrtc/state_machine.py`: prepared-transition runner, bounded mailbox,
  epochs, typed replies, reconciliation, loop assertions.
- `webrtc/machine_specs.py`: complete machine catalog, separate public DTLS and
  handshake-phase specs, parent and readiness metadata.
- `webrtc/runtime.py`: runtime/observability machines, owned work APIs, entity
  registry, shutdown audit.
- `webrtc/runtime_services.py`: opaque handles, owned timers, worker execution
  policies and lanes, task-factory audit.
- `webrtc/observability.py`: epoch-scoped CRDT reducers, coherent facet/source
  revisions, consistency diagnostics.
- `webrtc/state_facets.py`: derive facets from commits; remove duplicated state
  authority and compatibility emitters at the end.
- `webrtc/performance.py`: compile execution plus observation policy, automatic
  async offload, immutable worker delta collection.
- `webrtc/peer_connection.py`: peer/signaling runners, readiness joins,
  Runtime-owned close and media lane.
- `webrtc/peer_components.py`: attachment/log/queue machines and owned pumps.
- `webrtc/ice/agent.py`: gatherer/agent/pair/controller runners and registries.
- `webrtc/ice/net/udp_mux.py`: mux/binding/queue lifecycle and callback ingress.
- `webrtc/dtls/fsm.py`: internal handshake-phase runner and owned timers.
- `webrtc/dtls/dtlstransport.py`: public DTLS lifecycle, bounded ingestion,
  SRTP child readiness.
- `webrtc/srtp/session.py`: session/stream machines, loop-owned stream map,
  ordered crypto result delivery.
- `webrtc/transceiver.py`: transceiver/sender/receiver/track machines.
- `webrtc/media/*`: immutable worker inputs/results, pipeline ownership, bounded
  queue integration; keep stateless parsers/helpers out of machine catalog.
- `webrtc/tracing/*`: schema-2 consistency checks and compact summary sourcing.
- `tests/*`: unit, lifecycle, ownership, convergence, failure, and deterministic
  checkpoint coverage.
- `tests/performance/*`: throughput, latency, allocation, trace-overhead, and
  overload gates.

## Test plan

### Machine contract tests

- every declared state is reachable or explicitly terminal-only;
- every valid edge commits once and increments revision once;
- invalid, stale, duplicate, reordered, wrong-epoch, and wrong-loop operations
  have specified outcomes and diagnostics;
- cancellation at before/after/terminal checkpoints preserves invariants;
- terminal commit occurs after children, timers, queues, and worker barriers;
- mailbox close and overflow cannot strand a reply waiter.

### Component tests

- peer offer/answer, dial/accept, renegotiation, protocol failure, concurrent
  close, and close during connection;
- ICE gather success/failure, delayed remote credentials, nomination,
  disconnect/recheck, multiple pairs, controller failure, and DNS timeout;
- DTLS loss/reorder/retransmit, client/server flights, invalid record,
  certificate failure, duplicate start, and close mid-handshake;
- SRTP initialization, ordered encrypt/decrypt, replay failure, SSRC admission
  limit, close with worker result in flight, and key redaction;
- transceiver direction changes, bind/unbind, sender/receiver stop, queue
  overflow, codec worker failure, and media shutdown;
- attachment/log drain start/stop races and bounded inbox behavior.

### Ownership tests

- no component-created task, timer, executor future, socket transport, or worker
  result remains after Runtime close;
- a child cannot publish after owner epoch removal;
- repeated `aclose` calls await one workflow;
- Runtime rejects new work from `quiescing` onward;
- failure propagation retains original exception and one causal transition
  chain.

### CRDT and trace tests

- randomized duplicate/reorder/drop-then-resync streams converge to the same
  snapshot;
- transition/facet source revisions never conflict;
- old-epoch updates cannot resurrect removed entities;
- summary generation is deterministic from a snapshot;
- the motivating trace becomes coherent: peer connected, ICE selected and
  connected/completed, public DTLS connected with keys ready, internal DTLS
  phase finished, transport ready, and media children active;
- packet and media call volume changes aggregate counters but not machine or
  facet cardinality.

### Performance gates

Measure tracing disabled, tracing enabled without subscriber, and tracing with
one normal plus one slow subscriber. Gate on:

- peer setup p50/p95/p99;
- media packets/frames per second and end-to-end loss;
- event-loop lag p95/p99;
- CPU time and allocations per packet/frame;
- worker queue time, utilization, and saturation;
- machine transitions and patches per connection;
- schema-2 records, patch bytes, journal depth, and resync count;
- shutdown duration and remaining owned-work count.

Initial rule: a packet/frame load increase may raise aggregate counters, but it
must not linearly raise machine transitions, state facets, UUID allocation, or
transport patches. Final numeric budgets must be copied from the Stage 0
baseline and checked into the existing performance baseline files.

## Final acceptance criteria

- The full peer-to-peer WebRTC run has an authoritative, causally linked state
  machine graph from Runtime through peer, ICE, transport, DTLS, SRTP,
  transceiver, and media terminal reconciliation.
- Schema-2 snapshot and compact LLM summary contain no machine/facet
  contradiction and no missing required lifecycle machine.
- Peer reaches `connected` only after selected ICE transport and required
  DTLS/SRTP readiness; shutdown reaches terminal states in dependency order.
- Every long-lived task, worker submission, timer, queue pump, socket resource,
  and close barrier is Runtime-owned and accounted for at shutdown.
- Component state has one loop writer. Workers use immutable inputs/results and
  cannot mutate component or observability stores.
- No shared application mutex exists on normal transition, tracing, packet, or
  media hot paths. Any retained lock is documented, outside authoritative
  state, and justified by measurement or an external API contract.
- All unannotated synchronous `ObservedComponent` operations invoked by async
  component code are automatically and boundedly offloaded. Cheap machine
  commits/accessors stay inline only as neutral runner primitives or explicit
  loop callbacks outside automatic component wrapping.
- CRDT projection converges under duplicate and reordered delivery, remains
  epoch-safe, and never feeds merged state back into protocol behavior.
- Packet/frame volume affects bounded aggregate statistics, not lifecycle
  machine cardinality or per-call trace-node allocation.
- Correctness, ownership, consistency, overload, failure-injection, resync, and
  performance suites pass with no unexplained diagnostics.
