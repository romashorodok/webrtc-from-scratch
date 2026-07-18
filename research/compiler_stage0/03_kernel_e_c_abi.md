# Kernel E paper C ABI

Status: proposed interface for work item 0.3. This is a design excerpt, not a
compilable header. Names and numeric constants become binding only after the
semantic contract is frozen.

This ABI is a generated-backend boundary, not the kernel source language. The
maintained kernel is an ordinary Python Meta-Language function. A future
compiler derives generated C and bindings from that function and the frozen
ABI contract. The handwritten C oracle may implement this ABI for Stage 1
measurement, but it is not shipped as the authoritative kernel and is never
compiler input.

## Design excerpt

```c
/* DESIGN EXCERPT ONLY -- intentionally incomplete and non-compiling. */

#define WRTC_KERNEL_E_ABI_VERSION_V1 UINT32_C(1)
#define WRTC_KERNEL_E_MAX_FRAME_SIZE_V1 (16u * 1024u * 1024u) /* provisional */

typedef struct wrtc_kernel_e_config_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t timestamp;
    uint32_t ssrc;
    uint16_t current_rtp_sequence;
    uint16_t current_twcc_sequence;
    uint16_t fragmentation_limit;
    uint16_t reserved_zero;
} wrtc_kernel_e_config_v1;

typedef struct wrtc_packet_span_v1 {
    size_t offset;
    size_t length;
} wrtc_packet_span_v1;

enum-like status constants represented by int32_t:
    WRTC_OK = 0
    WRTC_E_NULL = 1
    WRTC_E_ABI_VERSION = 2
    WRTC_E_STRUCT_SIZE = 3
    WRTC_E_RESERVED = 4
    WRTC_E_RANGE = 5
    WRTC_E_FRAME_TOO_LARGE = 6
    WRTC_E_MALFORMED_AV1 = 7
    WRTC_E_PACKET_CAPACITY = 8
    WRTC_E_ARENA_CAPACITY = 9
    WRTC_E_OVERLAP = 10
    WRTC_E_SIZE_OVERFLOW = 11

uint32_t wrtc_kernel_e_abi_version(void);

int32_t wrtc_kernel_e_packetize_v1(
    const wrtc_kernel_e_config_v1 *config,       /* non-null */
    const uint8_t *frame,                        /* nullable iff frame_len == 0 */
    size_t frame_len,
    uint8_t *packet_arena,                       /* nullable iff arena_capacity == 0 */
    size_t arena_capacity,
    wrtc_packet_span_v1 *packet_spans,           /* nullable iff span_capacity == 0 */
    size_t span_capacity,
    size_t *out_arena_length,                    /* non-null */
    size_t *out_packet_count,                    /* non-null */
    uint16_t *out_current_rtp_sequence,          /* non-null */
    uint16_t *out_current_twcc_sequence          /* non-null */
);
```

No C enum is part of the ABI; the status names above denote fixed `int32_t`
constants. The real header will include `<stdint.h>` and `<stddef.h>`, define
symbol visibility/calling convention explicitly, and use compile-time layout
checks for every public structure.

## Result representation

All serialized packets occupy one caller-owned byte arena. `packet_spans[i]`
identifies packet `i` by byte offset and length within that arena. Spans are in
packet order, are nonempty, do not overlap, and exactly partition the written
prefix when the semantic contract does not require inter-packet alignment.

The interface never returns an interior pointer. The caller creates Python
`bytes` results, if required, by copying each span before reusing the arena.
This makes the unavoidable output conversion visible and measurable.

## Success and failure invariants

On success:

- `out_arena_length` is the number of initialized arena bytes;
- `out_packet_count` is the number of initialized spans;
- both output sequence values contain the committed post-call state;
- no bytes beyond the reported arena prefix and no spans beyond the reported
  count are read or written by the operation.

On every failure:

- all four scalar outputs are set to zero before return;
- no sequence state is committed because state is passed by value;
- contents of the byte arena and span array are unspecified and must be
  ignored by the caller;
- no partial packet result is exposed.

For capacity errors, a later revision may report required capacities through a
separate sizing operation. V1 deliberately does not overload zeroed result
fields with two meanings.

## Validation order

The operation validates, in order:

1. non-null scalar output pointers, then initializes them to zero;
2. config pointer, ABI version, exact `struct_size`, and reserved-zero fields;
3. pointer/length consistency for frame, arena, and span array;
4. scalar and maximum-size ranges, including all `size_t` arithmetic;
5. disallowed overlap among the frame, arena, span array, config, and outputs;
6. AV1 syntax;
7. packet-count capacity;
8. arena capacity;
9. serialization.

All address-range overlap checks must avoid pointer arithmetic overflow.
Passing unrelated invalid pointers is outside what portable C can diagnose;
every non-null pointer must designate storage of the stated size.

## Ownership and lifetime table

| Object | Owner | Mutable during call | Retained after return | Required lifetime |
| --- | --- | --- | --- | --- |
| config | caller | no | no | entire call |
| frame bytes | caller | no | no | entire call |
| packet arena | caller | yes | no | entire call and until caller finishes consuming success result |
| packet span array | caller | yes | no | entire call and until caller finishes consuming success result |
| scalar outputs | caller | yes | no | entire call and until caller reads result |
| native internal temporaries | operation | yes | no | call only |
| Python result bytes | Python caller | immutable | not applicable | normal Python ownership |

The caller must not mutate input or output storage concurrently with the call.
Independent calls with disjoint storage and value state are reentrant and may
execute concurrently. The operation uses no global mutable state, callbacks,
network I/O, hidden allocation, or synchronization and makes no assumption
about an interpreter lock.

## Fixed-layout review

`wrtc_kernel_e_config_v1` has an intended field order but its byte size and
offsets are not yet frozen in this draft. Before approval, the ABI document
must record `sizeof`, alignment, and every `offsetof` value for each primary
target and either prove they are identical or replace the structure with
individual scalar parameters.

`wrtc_packet_span_v1` intentionally uses `size_t`; therefore its layout differs
between 32-bit and 64-bit processes. Artifact validation must require matching
pointer width. Stage 1 primary targets are 64-bit only.

## Portability

- Numeric packet fields are written byte-by-byte or with explicitly defined
  endian conversion; host endianness cannot affect output.
- No bitfield, compiler enum, flexible array member, packing pragma, C++, Rust,
  CPython type, or platform `long` appears in the public ABI.
- All shifts use unsigned operands and bounded counts. Every addition and
  multiplication involving lengths is checked before evaluation.
- macOS arm64 and Linux x86-64 are the first implementation targets.
- Windows requires an explicit export macro and fixed calling convention. DLL
  discovery and MSVC runtime policy belong to the loading/build contracts; the
  function data model remains unchanged.

## Copy and allocation account

| Step | Required bytes copied | Allocation owner | Included in full-boundary timing |
| --- | --- | --- | --- |
| Obtain contiguous read-only frame view | zero if the accepted Python object exports a contiguous byte buffer; otherwise input is rejected rather than copied silently | Python binding | yes |
| Foreign call argument conversion | scalar only; no frame copy | Python binding | yes |
| Construct RTP packets in arena | each AV1 payload byte is copied once into its final serialized location; headers/extensions are written once | caller preallocates arena | yes |
| Produce span metadata | one fixed span record per packet | caller preallocates span array | yes |
| Convert spans to public Python packet bytes | every complete serialized packet byte is copied once | Python allocates one `bytes` per packet | yes |
| Downstream SRTP | excluded from Kernel E; its existing input/output copies are end-to-end costs | downstream owner | end-to-end benchmark only |

There is no native heap allocation in the proposed contract. A future
implementation may use bounded stack scratch space only after the maximum is
reviewed; otherwise scratch storage must become another caller-provided
buffer. ABI validation and artifact discovery costs are accounted for by the
loading and benchmark contracts, not hidden from results.

## Semantic-to-ABI mapping

| Semantic fact | ABI representation |
| --- | --- |
| frame bytes and length | `frame`, `frame_len` |
| fragmentation limit | `config.fragmentation_limit` |
| timestamp and SSRC | exact-width config fields |
| initial RTP/TWCC state | two `current_*` config fields |
| ordered packet bytes | written arena prefix plus ordered spans |
| committed sequence state | two `out_current_*` values |
| empty success | zero arena length/count; unchanged sequence outputs |
| malformed input | fixed status; zero scalar outputs |
| ownership and aliasing | caller storage plus explicit overlap rejection |
| unsupported contract | ABI/structure-size statuses before frame parsing |

The compiler must produce a trace showing how each Python parameter,
annotation, operation, result, mutation, and exception path maps to these ABI
fields and statuses. ABI convenience cannot weaken or redefine the Python
behavior.

## Open ABI decisions

- Freeze the maximum frame size from workload evidence rather than the
  provisional 16 MiB value.
- Decide whether `fragmentation_limit` constrains AV1 payload bytes or complete
  serialized packet bytes.
- Freeze the exact accepted limit range.
- Decide whether a separate sizing call is worth a second parse or whether the
  caller uses a proven worst-case arena formula.
- Freeze structure layout or replace the config structure with scalars.
- Map every status to the exact exception required by the final semantic
  contract.
