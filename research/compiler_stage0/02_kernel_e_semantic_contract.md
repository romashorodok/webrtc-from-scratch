# Kernel E semantic contract

Status: first review draft for work item 0.2. The success path is concrete. The
malformed-input exception table and the authoritative executable specification
remain open, so this contract is not frozen.

The final executable specification will be an ordinary Python function written
within the Python Meta-Language contract. The same function must execute under
CPython when no compiled artifact exists. This document describes that future
function's observable behavior; it does not make the paper C ABI or a
handwritten C oracle authoritative.

## Normative observable behavior

This section defines behavior without reference to an implementation strategy.

### Operation

The operation accepts one encoded AV1 frame, a fragmentation limit, an RTP
timestamp, an SSRC, the current RTP sequence number, and the current
transport-wide sequence number. It returns an ordered sequence of complete RTP
packet byte strings and the two updated sequence numbers.

The operation is deterministic for identical accepted inputs and initial
state. It performs no I/O, reads no clock or random source, and does not retain
the frame or any returned packet after it returns.

### Accepted inputs

| Input | Accepted value |
| --- | --- |
| frame | immutable `bytes` containing one AV1 temporal unit in the OBU form accepted by the reference packetizer |
| fragmentation limit | integer in the frozen range; current application value is 1200 |
| RTP timestamp | integer from 0 through 4,294,967,295 inclusive |
| SSRC | integer from 0 through 4,294,967,295 inclusive |
| current RTP sequence | integer from 0 through 65,535 inclusive |
| current transport-wide sequence | integer from 0 through 65,535 inclusive |

The maximum accepted frame length and the final fragmentation-limit range are
open decisions. Until fixed, callers may rely only on the workload sizes
listed by the future golden-vector manifest.

### Success result

The frame is split into AV1 RTP payloads in reference order. For `N` payloads,
the result contains exactly `N` packet byte strings in the same order.

For packet index `i`, starting at zero:

- RTP version is 2; padding is false; the CSRC count is zero.
- RTP payload type is 45.
- RTP sequence is `(initial_rtp_sequence + i + 1) modulo 65,536`.
- RTP timestamp and SSRC equal their inputs.
- marker is one only when `i` is `N - 1`; otherwise it is zero.
- the only header extension is transport-wide sequence number, extension id 4,
  with value `(initial_transport_sequence + i + 1) modulo 65,536`.
- the extension uses the one-byte header form with profile `0xBEDE` and is
  padded to a four-byte extension body.
- the packet payload is the corresponding AV1 RTP payload.

All multibyte RTP fields and extension values are serialized most-significant
byte first. With the current extension map, the byte layout is:

```text
12-byte RTP header
0xBE 0xDE 0x00 0x01
0x41 TWCC-high TWCC-low 0x00
AV1 RTP payload
```

On success, both returned sequence values equal their respective initial value
plus `N`, modulo 65,536. An empty frame that produces no AV1 payloads returns
an empty packet sequence and leaves both sequence values unchanged.

Each returned packet is independently owned immutable bytes. Mutating or
discarding the input after return cannot affect a result. No result aliases
another result.

### Ordering, rollover, and state

Packet order is fragmentation order and cannot be changed. Sequence rollover
does not reorder packets. Timestamp does not advance inside this operation and
is identical in every packet from the frame. The operation is reentrant when
all state is supplied independently; simultaneous calls sharing sequence
state require serialization by the caller.

### Rejected inputs and failure ordering

The final contract must name the exact exception class and message policy for
every rejected input. Validation order is provisionally:

1. container/type validation;
2. scalar range validation in argument order;
3. frame-size and fragmentation-limit validation;
4. AV1 OBU validation;
5. result-size validation.

Failure is intended to produce no packet result and leave both sequence values
unchanged. This transactional rule does **not** yet match every failure mode of
the current composed Python path, which creates packet objects and advances
sequences before serialization can reject an out-of-range scalar. The behavior
owner must either freeze current partial mutation or approve prevalidation as
the source behavior before this section becomes normative.

## Reference mapping (informative)

The current behavior is composed by `examples/examples/ws.py`,
`webrtc/media/av1_payloader.py`, `webrtc/media/packetizer.py`,
`webrtc/media/rtp_packet.py`, and `webrtc/media/rtp_extensions.py`.

The AV1 payload behavior is currently supplied by a PyO3 wrapper over Rust.
Its public wrapper calls `.unwrap()` on packetization errors, so the precise
Python exception behavior for malformed AV1 input is not an adequate frozen
language contract. The Rust tests are seed vectors only.

Before Stage 1, this composition must be represented by a project-owned
ordinary Python region whose body contains the reference behavior. PyMeta
annotations may describe widths, bounds, buffers, ownership, effects, and the
compilation boundary, but they may not contain generated C or replace the
callable Python behavior.

## Exception-equivalence table to freeze

| Case | Required exception | Current evidence | State |
| --- | --- | --- | --- |
| wrong frame type | exact class/message policy unknown | PyO3 conversion | Open |
| negative or oversized fragmentation limit | exact class/message policy unknown | PyO3 `usize` conversion | Open |
| timestamp outside unsigned 32-bit range | `struct.error` occurs during current serialization, after packet creation | source inspection | Open mutation rule |
| SSRC outside unsigned 32-bit range | `struct.error` occurs during current serialization, after packet creation | source inspection | Open mutation rule |
| sequence state outside unsigned 16-bit range | proposed explicit range error | current `Sequencer` does not enforce constructor input | Open |
| truncated OBU extension header | current Rust error is unwrapped by the PyO3 wrapper | source inspection | Open |
| missing/truncated OBU size | current Rust error/panic behavior is not a stable contract | source inspection | Open |
| declared OBU size exceeds frame | bounds behavior is not suitable as a language contract | source inspection | Open |
| frame exceeds maximum | maximum and exception are not defined | no current guard | Open |

## Contract review gates

This document can be frozen only after:

- a single ordinary Python callable is named as the executable specification;
- that callable is ordinary executable Python conforming to the Python
  Meta-Language specification and has no native-only dependency;
- the accepted AV1 form and maximum frame size are fixed;
- the fragmentation-limit/MTU meaning is fixed;
- every failure row has an exact exception class and state result;
- golden vectors confirm exact bytes, packet order, empty behavior, and both
  rollovers without relying on the future implementation.
