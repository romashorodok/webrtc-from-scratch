# Async State Machine Audit

## Scope and conclusion

This document audits the current implementation of
`AsyncStateMachineRunner` in `webrtc/state_machine.py` and every production
component that subclasses it. It is an audit only; it does not prescribe an
implementation patch.

The repository currently defines 22 production runner subclasses. Only the
DTLS handshake-phase runner performs genuinely asynchronous work in `step()`.
Every other `step()` is synchronous logic declared `async` to satisfy the base
class. Some owners do need asynchronous orchestration or teardown, but that
does not require every state reduction to have a permanent task, mailbox,
reply future, retry cache, tracing identity, and async checkpoint chain.

The state-machine implementation is not an idle busy loop: an idle runner is
blocked in `BoundedMailbox.receive()`. The excessive CPU comes from active-path
amplification and explicit polling:

1. State waiters repeatedly use `await asyncio.sleep(0)`, keeping themselves
   runnable and spinning until another task changes a state.
2. The global worker-lane machine can receive up to three state publications
   for every worker call: queued, running, and completion/idle.
3. Every accepted command pays for command and reply objects, mailbox wakeups,
   an async `step`, async production no-op checkpoints, transition allocation,
   retry-cache bookkeeping, projection allocation, producer-dot allocation,
   and often a facet merge.
4. Queue and SRTP stream facets are published on every packet enqueue and
   dequeue. This is adjacent to, rather than inherent in, the runner, but it is
   part of the same machine/metadata design and is likely a larger steady-state
   data-plane cost than lifecycle transitions.
5. A full peer creates a permanent runner task for runtime, observability,
   worker lane, peer, signaling, media send, gatherer, agent, candidate pair,
   pair controller, selected transport, UDP mux/bindings and interceptor
   queues, DTLS transport and phase, two SRTP sessions, streams and packet
   queues, transceivers, senders, receivers, tracks, attachments, and inboxes.
   Sleeping tasks do not burn CPU by themselves, but they increase scheduling,
   ownership, shutdown, and metadata work.

The main architectural finding is that four responsibilities have been merged:

- WebRTC/domain state validation;
- event-loop serialization and task ownership;
- retry/reply transport semantics;
- observability and deterministic test metadata.

That violates SRP and makes components understand infrastructure metadata that
is irrelevant to their protocol behavior. Meaningful WebRTC states should be
retained, but most do not need `AsyncStateMachineRunner`.

## Evidence and confidence

This is a static source audit, not a profiler report. The CPU causes above are
directly visible in the control flow, but their percentages cannot be claimed
without a full-peer profile.

The state-machine commit (`4353bac`) removed the existing backend live-tracing
benchmark, full peer performance tests, and JSON baselines in the same change
that introduced the broad runner use. The repository still documents a target
of at most 5% aggregate tracing CPU overhead, but there is no current benchmark
that enforces or even reports that target. Consequently:

- the polling loops and per-call amplification are confirmed mechanisms;
- the ordering of their real-world cost is a strong source-based assessment;
- numeric CPU attribution remains unverified until the deleted benchmark
  coverage is restored or replaced.

## What one transition currently costs

For a typical component lifecycle move:

1. The component increments its own command ID and often formats a cause ID.
2. It allocates `ReplyPort`, which allocates an `asyncio.Future`.
3. It allocates a nine-field `MachineCommand` carrying epoch, revision,
   producer/deduplication and causality concerns.
4. `BoundedMailbox` appends the command and replaces its `asyncio.Event` on
   every signal (`state_machine.py:160-162`).
5. The runner wakes, performs dedupe lookup, awaits `prepare()`, and awaits an
   `async step()` even when the step has no suspension.
6. It allocates a preview `TransitionCommit`.
7. It allocates a checkpoint and awaits `NullTransitionController.before_commit()`;
   production therefore still crosses an async function boundary for a no-op.
8. It validates again, allocates the authoritative `TransitionCommit`, and
   reads the monotonic clock.
9. It invokes a component-owned transition sink, which usually converts the
   commit to a second `MachineTransitionOp`, allocates a producer dot, and
   updates the projection.
10. It allocates another checkpoint and awaits the production no-op
    `after_commit()` checkpoint, then awaits the usually empty component
    `after_commit()` hook.
11. It inserts the result into the per-runner dedupe dictionary/deque even for
    commands that are never retried.
12. It resolves the reply future; the caller performs another shielded await.

Terminal transitions add reconciliation, mailbox rejection, a terminal
checkpoint, task joining, and owner removal. This machinery is defensible for
rare externally retryable orchestration commands. It is disproportionate for
local queue close flags, attachment status, worker load, and simple resource
lifecycle changes.

## Confirmed CPU amplification

### 1. Zero-delay state polling

The following state waiters repeatedly yield and immediately become runnable:

- `peer_components.py:301-304`: log-inbox close waits for `open`/`closing`;
- `peer_components.py:467-468`: attachment work waits for `detached` to change;
- `srtp/session.py:337-344`: stream close waits for activation and terminal;
- `srtp/session.py:426-427`: session readiness;
- `srtp/session.py:452-454`: terminal reconciliation waits for in-flight work;
- `srtp/session.py:724-725`: session close waits for terminal;
- `ice/agent.py:1189`: controller start waits for its receive handle;
- `ice/agent.py:1217-1218`: controller close waits for terminal;
- `runtime_services.py:1031`: child reconciliation retries when registry state
  exists but exposes no waitable handle.

`asyncio.sleep(0)` is a fairness yield, not a blocking notification. These
loops can execute thousands of times while waiting and are the clearest direct
explanation for CPU spikes during startup, state convergence, and shutdown.
They also compete with the runner that must make the condition true.

The state owner already has reply futures and task handles, so polling is not
necessary. A state change should resolve a retained revision/terminal waiter;
in-flight counters should have a zero-count barrier.

### 2. Worker-lane transition churn

`ConcurrentWorkerLane.run_observed()` publishes load at admission, dispatch,
and completion (`runtime_services.py:746-764`). `Runtime._worker_state_changed()`
turns changes in those counters into machine commands and exact facet updates
(`runtime.py:376-406`). Thus a packet crypto worker, codec worker, or any other
observed synchronous call can indirectly cause up to three complete state
machine/projection cycles.

This is a model error as well as a performance error. A concurrent lane can be
queued and running at the same time; `idle | queued | running` is not a valid
state model for two independent counters. The producer-side
`_worker_desired_state` can also advance before the runner commits earlier
commands. Under concurrency it can request edges the spec does not allow, for
example `running -> queued`, and it uses `try_submit()` into a capacity-32
mailbox. Load reporting can therefore raise `MailboxFull` in the work path or
silently cache invalid-transition failures when no reply port was supplied.

Worker queued/running/high-water values are metrics, not lifecycle states.
Only `accepting/closing/closed` is a useful lane lifecycle.

### 3. Exact data-plane facet publication

The following paths publish projection values for ordinary packet queue
traffic:

- `RuntimeOwnedQueue.put/get/put_nowait/get_nowait()` in
  `queue_machine.py:67-83`;
- UDP `Interceptor.put/get()` in `ice/net/udp_mux.py:116-151`;
- SRTP `Stream.write/read()` via `_publish_queue_facets()` in
  `srtp/session.py`.

Each publication allocates a producer dot and value mapping and merges it into
the projection. This happens even though queue depth is not a state transition.
For RTP/SRTP traffic, coalesced counters or threshold/high-water updates are
appropriate; exact depth per packet is not.

### 4. Per-entity runner/task multiplication

One SRTP stream creates both an `srtp-stream` runner and a `queue` runner. A
track creates a media-track runner; a sender and receiver each create another.
Each UDP interceptor creates a queue runner. Each attachment creates a runner.
This produces many permanent task registry entries and terminal reconciliation
edges for objects whose behavior is already serialized on one event loop.

This is mostly task, allocation, and shutdown overhead rather than idle CPU.
It becomes CPU overhead when all entities start or close together and when
their projections/facets are updated.

## Async necessity and state-authority inventory

“Keep state” below means the state has useful domain or admission semantics.
It does not mean the current async runner should be retained.

| Component / runner | Current use | Actually async? | State authority and verdict |
| --- | --- | --- | --- |
| Runtime `_LifecycleRunner` (`runtime`) | Startup and shutdown stages | Reduction: no; shutdown workflow: yes | Keep a small runtime lifecycle, but a mailbox task is unnecessary because Runtime already owns the loop and close task. |
| Runtime `_LifecycleRunner` (`worker-lane`) | Converts queued/running counts to enum transitions | No | Remove this state model. Keep counters plus `accepting/closing/closed`. |
| `_ObservabilityRunner` | Tracing service start/degrade/drain | No | Keep service health as a snapshot/metric. It must not require tracing metadata to report tracing metadata. |
| `RuntimeOwnedQueue._QueueRunner` | `open -> closing -> drained -> closed` | No | Remove the runner. Queue close/admission must be enforced by the queue primitive itself; observe it downstream. |
| `peer_components._LifecycleRunner` | Peer/log inboxes, log drain, attachment registry and each attachment | No reduction; some start/stop work awaits | Keep explicit close/start workflows where useful, but not a generic caller-selected `MOVE` machine. |
| `_GathererRunner` | Gathering lifecycle and launch | Reduction: no; gather operation: yes | Keep `new/gathering/complete/failed/closed`; use one gather task/result. |
| `_SelectedTransportRunner` | Records selecting/ready/draining/closed | No | Keep selected-transport readiness, preferably as an atomic selected binding snapshot rather than a separate runner task. |
| `_PeerRunner` | Peer lifecycle, child-readiness gate, role and teardown | Reduction: no; effects/teardown: yes | Keep. This is a legitimate aggregate WebRTC lifecycle, but use a synchronous reducer inside the peer's existing serialized orchestration. |
| `_SignalingRunner` | Offer/answer validation and atomic descriptions | No; SDP capture/materialization is synchronous | Keep. This is the strongest state-machine use because WebRTC signaling has normative states. The reducer should be synchronous and metadata-free. |
| `_MediaSendRunner` | Active/draining/failed/closed around a separate media mailbox/pump | No | Remove runner; the media-send pump already owns admission, jobs, credits and drain. |
| `_CandidatePairRunner` | ICE checklist pair state | No | Keep. Pair state is real ICE logic and should gate checks/nomination, but it needs no dedicated task per pair. |
| `_CandidatePairControllerRunner` | Starts/checks/nominates/forwards and closes receive pump | Reduction: no; packet pump/close: yes | Keep only meaningful controller phase or derive it from pair/pump status. Do not dedicate a second state authority to the same pair lifecycle. |
| `_AgentRunner` | ICE agent connectivity state | No | Keep. Agent states are useful for connection/reconnect decisions, but current registry/role/candidate mutation is still outside the runner. |
| `_InterceptorQueueRunner` | Queue failure and close sequence | No | Remove. Queue failure/admission must be direct queue behavior; coalesce metrics. |
| `_UDPRunner` (`udp-mux`, `udp-binding`) | Resource bind/active/drain/close | No; socket bind/close awaits | Keep resource readiness if consumers use it, but one resource task/result is sufficient. Per-binding runner tasks add little value. |
| `_DTLSTransportRunner` | Bind, handshake readiness/failure, SRTP-ready gate, close | Reduction: no; handshake and reconciliation: yes | Keep public DTLS state. It is useful to gate media, but state reduction need not be async. |
| `_HandshakePhaseRunner` | Calls `await owner._step(current)` for flights/retransmission | Yes | Retain asynchronous orchestration. This is the only runner whose `step()` genuinely suspends. Consider separating the synchronous phase transition from the flight I/O workflow. |
| SRTP `_LifecycleRunner` (`srtp-session`) | Key readiness, stream admission, drain/close | Reduction: no; draining streams awaits | Keep session readiness/admission state; use direct notification instead of readiness polling. |
| SRTP `_LifecycleRunner` (`srtp-stream`) | Active/draining/closed | No; optional close callback awaits | Simplify to queue/admission close state. A separate stream runner plus queue runner is redundant. |
| SRTP `_PacketQueueRunner` | Queue close/drain/closed | No | Remove; fold into the stream queue. |
| Transceiver `_ComponentRunner` | Track, sender and receiver lifecycle | No; terminal child close awaits | Keep sender/receiver/track readiness where it gates media. Do not create a runner task for every small media object. |
| `_TransceiverRunner` | Negotiation lifecycle and configuration mutation | No | Keep negotiated state/snapshot. Configuration commands should update one negotiation snapshot, not create lifecycle self-transitions. |

## SRP and metadata coupling findings

### Components know infrastructure details they should not know

Nearly every owner currently knows how to:

- allocate monotonically increasing command IDs;
- copy the runner epoch and sometimes revision;
- decide whether revision checking is enabled by passing `None`;
- generate textual cause IDs;
- create and await `ReplyPort` futures;
- choose mailbox and dedupe capacities;
- register machine specs and owner epochs with Runtime;
- start and join the runner task;
- convert `TransitionCommit` to `MachineTransitionOp`;
- allocate producer dots and projection source order;
- merge machine-linked facets;
- remove the owner after terminal completion.

None of those concerns computes ICE nomination, signaling legality, DTLS
readiness, SRTP admission, or RTP behavior. Repeating them across components is
the concrete SRP violation.

### The generic command is over-specified

`MachineCommand` has nine fields. Most local lifecycle callers need only an
event kind and optional payload/result. `producer_id` and `producer_seq` are
used only by a small subset of commands; `expected_epoch`, `command_id`, and
`cause_id` are nevertheless mandatory everywhere. Every command is entered in
the dedupe cache, even if it originated locally and cannot be retried.

Epoch, producer sequence, and causal trace identity belong at an external
retry/observability boundary. Revision belongs only on operations that truly
perform optimistic concurrency. They should not be part of the protocol
component's everyday command vocabulary.

### Observability is injected into the state owner

The supposedly neutral runner invokes `_transition_sink` synchronously inside
its authoritative post-commit path (`state_machine.py:655-660`). Every
component implements nearly identical projection glue. Projection failure can
terminate the runner after the state is already committed. This means
observability is not purely downstream and forces protocol owners to know
projection types and source metadata.

### Test control affects production shape

Every transition allocates checkpoints and awaits three controller methods in
the terminal case, even though the production controller is a no-op. Test
pause/failure injection is useful, but the production transition algorithm
should not require async no-op hooks at each edge.

### Generic `MOVE` moves policy to callers

The auxiliary lifecycle runner accepts a payload containing the desired state.
It does not map a domain event to a state; callers select the target directly.
Legal-edge validation remains, but state policy is distributed across log,
inbox, and attachment code. That is an observable state register, not an
encapsulated state machine.

## State-model correctness audit

### States currently used correctly or worth retaining

- WebRTC signaling: `stable`, `have-local-offer`, `have-remote-offer`.
- ICE gatherer and agent connectivity states.
- ICE candidate-pair progress and nomination.
- Selected transport readiness tied to exact nomination provenance.
- Public DTLS transport readiness tied to handshake and both SRTP sessions.
- Internal DTLS flight/handshake phases.
- SRTP session readiness as a gate for crypto and stream admission.
- Peer aggregate connection state with exact child epoch/revision readiness.
- RTP sender/receiver/track readiness when it actually gates packet admission.
- Transceiver negotiation state and one atomic negotiated snapshot.

These states can make WebRTC processing safer: reject media before DTLS/SRTP
readiness, reject nomination without pair success, reject invalid signaling
edges, reject stale negotiated snapshots, and make teardown stop admission
before resources are released.

### States that currently act mainly as tracing labels

- worker-lane `idle/queued/running`;
- per-queue `open/closing/drained/closed` runners;
- observability service runner;
- attachment registry and per-attachment runners;
- media-send runner layered over its own mailbox/pump/job state;
- many UDP binding/interceptor lifecycle runners;
- the second queue runner attached to every SRTP stream.

For these, ordinary owned-resource state, counters, and completion futures are
clearer and cheaper.

### Commands are being recorded as false state changes

`_PeerRunner` maps `DIAL` and `ACCEPT` to the current state
(`peer_connection.py:821-822`). `_TransceiverRunner` maps MID, codec, sender,
receiver, and snapshot updates to `active`, creating `active -> active`
transitions (`transceiver.py:984-988`). The machine spec explicitly permits
some self-edges to support this.

Those are operations or snapshot revisions, not lifecycle changes. Treating
them as state transitions inflates transition revisions and projection work
and makes the trace claim that a lifecycle transition occurred when it did
not.

### Queue state does not consistently control queue behavior

`RuntimeOwnedQueue.put()` and `put_nowait()` do not consult the queue runner's
state. The runner can report closing/closed while the underlying queue still
accepts items. Similar queue wrappers publish lifecycle and depth separately.
This proves the machine is not the queue's authoritative behavior; it is an
observational companion.

### Several authoritative fields remain outside machine commits

Examples include ICE agent credentials/role/candidate and controller
registries, selected transport pointers and revisions, UDP binding maps,
media-send job/result maps, and multiple transceiver fields. Some mutations
are carefully sequenced around commits, but the runner's “single writer” claim
only protects `_state`, `_revision`, and `epoch`. It cannot detect mutation of
the owner's actual protocol fields during `step()` or from another method.

The strongest exception is signaling, where the immutable description snapshot
is committed with the lifecycle edge. That pattern should be the standard for
states that remain.

### Fire-and-forget failures can be silent

When a `MachineCommand` has no reply, preparation or validation failures are
cached and the loop continues (`state_machine.py:621-646`). The caller is not
notified. Many automatic follow-up and worker-state commands omit replies.
Invalid edges can therefore leave producer-side desired state different from
committed state without a direct failure signal.

### Terminal and restart semantics are awkward

`log-drain` and `observability` use `stopped` as both initial and terminal.
The base runner special-cases revision zero so it will accept the first
command. Once it returns to `stopped`, the runner exits and cannot represent a
second start. This is acceptable only if these objects are strictly one-shot;
the specs otherwise look restartable.

### Long reconciliation blocks the only command consumer

Terminal reconciliation occurs before the terminal commit while the runner is
the only mailbox consumer. Some reconciliation closes multiple descendants or
waits for in-flight work. New close/failure commands remain queued until it
finishes. This provides serialization, but it also couples state progress to
potentially slow I/O and makes shutdown depend on the polling loops described
above.

## Does the runner need to be async?

Not as a general abstraction.

All components already run on one asyncio event loop and the runner asserts
that loop ownership. A synchronous reducer can validate and atomically update
state in the same event-loop turn without a lock. Async work can be launched or
awaited by the owning workflow before/after that reducer. A permanent mailbox
task is justified only where multiple independent producers need backpressure,
ordering, cancellation, and reply semantics that are not already supplied by
the component's existing pump or Runtime task.

Recommended separation of concerns:

1. **Synchronous domain reducer** — current snapshot plus typed event yields
   the next immutable domain snapshot and effects. It knows no task IDs,
   producer dots, trace cause IDs, or reply futures.
2. **Optional command serializer** — used only by genuinely multi-producer
   owners. It handles bounded admission and completion, without pretending
   every command is a state transition.
3. **Async workflow/task owner** — performs socket, handshake, worker, child
   join, and teardown work through Runtime.
4. **State notification** — revision/terminal futures or a condition that
   wakes only on change; never `sleep(0)` polling.
5. **Observability adapter** — consumes a small domain transition after commit
   and adds entity IDs, epochs, cause IDs, producer dots, timestamps, and
   projection ordering outside the component.
6. **Optional retry envelope** — adds command identity/dedupe only at API or
   transport boundaries that can actually retry.
7. **Test interception** — wraps selected reducer commits in tests without
   imposing async no-op checkpoints on production transitions.

The DTLS handshake phase is the one clear special case. It is an async workflow
whose next phase depends on network/timer/flight work. Even there, separating
the flight I/O from the synchronous phase commit would make the state easier
to reason about.

## Refactoring priorities

### P0: remove confirmed CPU spinners

- Replace every state-related `await asyncio.sleep(0)` loop with a reply,
  revision waiter, terminal future, task handle, or counter barrier.
- Ensure notification is resolved after the authoritative change and on every
  failure/cancellation path.

### P0: remove worker calls from the transition hot path

- Stop translating queued/running counts into lifecycle transitions.
- Keep coalesced counters and high-water metrics.
- Keep only admission lifecycle (`accepting`, `closing`, `closed`) if needed.
- Make metrics incapable of failing worker admission through `MailboxFull` or
  an invalid lifecycle edge.

### P1: remove exact per-packet projection updates

- Coalesce queue depth and delivery counters by time, count, or threshold.
- Publish high-water, drops, failures, and bounded diagnostics.
- Keep packet processing independent of tracing availability.

### P1: retain only meaningful domain machines

Prioritize synchronous reducers for signaling, peer readiness, ICE pair/agent,
selected transport, DTLS transport/phase, SRTP session admission, and
transceiver negotiation. Fold queue, worker-load, attachment, media-send, and
duplicated stream lifecycle machines into their existing owner primitives.

### P1: move metadata out of components

Components should emit a minimal domain event/snapshot. Runtime/observability
should attach identity, epoch, timestamps, producer ordering and causal trace
metadata. Retry identity and optimistic revision checks should be opt-in.

### P2: make state authoritative

For each retained machine, list the exact fields protected by its commit and
move them into one immutable snapshot. Reads and admission decisions must use
that snapshot. Delete observational states that do not control behavior.

### P2: restore performance evidence

Restore or replace the deleted worker/mixed/full-peer benchmarks. Measure at
least:

- process CPU and event-loop lag with tracing off and on;
- worker calls/second with worker-state projection disabled/enabled;
- state commands, commits, rejected commands, mailbox high-water, projection
  merges, and producer-dot allocations;
- runnable task count during steady media and shutdown;
- SRTP/RTP packets per second with exact versus coalesced queue facets;
- startup and close CPU with polling waiters removed.

Use sampling profiles to confirm time in runner/checkpoint/projection code and
event-loop scheduling. Do not treat reduced wall time from worker threads as
proof of reduced process CPU.

## Acceptance criteria for a future implementation

- No state waiter polls with `asyncio.sleep(0)`.
- Idle lifecycle observation creates no permanent task unless the owner needs a
  command serializer.
- A worker call does not create a lifecycle transition.
- Packet enqueue/dequeue does not synchronously merge exact tracing facets.
- Observability failure cannot terminate a committed protocol state owner.
- Queue/transport/session “closed” state rejects new admission in the same
  authoritative primitive.
- Configuration changes do not appear as lifecycle self-transitions.
- Each retained state has at least one protocol decision, admission rule, or
  public WebRTC semantic that depends on it.
- Local commands that cannot retry do not enter a dedupe cache.
- Components do not construct producer dots, trace ordering, or projection
  operations.
- Full-peer tracing CPU overhead is measured against an unobserved baseline and
  meets a checked-in budget.

## Final assessment

The current state machine is useful in a few places, especially signaling,
ICE nomination, peer child-readiness, public DTLS readiness, and the DTLS
handshake phase. The broad application of `AsyncStateMachineRunner` to queues,
worker load, attachments, media-send status, UDP resources, and every media
child is not justified by their behavior.

The high CPU is not caused by an idle runner loop. It is caused by busy-yield
polling plus high-frequency command/projection amplification, with the worker
lane and exact packet queue facets as the most important steady-state suspects.
The architectural remedy is to keep WebRTC domain states, make their reducers
synchronous and authoritative, use async only for workflows that truly wait,
and move retry/test/observability metadata out of the components.
