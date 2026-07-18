# Python Meta-Language Specification

## Status and Scope

This is the single normative source-language contract for all compiler research
tracks in this repository. The CPython-extension, Python-independent CDLL, and
meta-compiler experiments may support different regions and lower them through
different ABIs, but they must not define different application languages.

The terms **must**, **must not**, **required**, **should**, and **may** are used
normatively. A backend capability is not a language rule: valid Python that a
backend cannot compile remains valid Python.

## Terminology

- **Source module:** an ordinary executable `.py` module.
- **Reference implementation:** the behavior of that module under the declared
  CPython version.
- **Compilation region:** a function marked in place with a PyMeta region
  descriptor for possible native compilation.
- **Kernel:** a compilation region that satisfies the portable, Python-
  independent value and effect restrictions defined under Backend Eligibility.
- **Manifest:** the normalized metadata graph constructed from in-place PyMeta
  declarations plus optional external build and target policy.
- **Policy sidecar:** an ordinary Python module containing reproducible target,
  build, search, artifact, or deployment choices that do not change source
  meaning.
- **Embedded DSL:** the PyMeta object model and syntax sugar, written entirely
  with Python grammar and evaluated by CPython into immutable metadata values.
- **Semantic descriptor:** an immutable PyMeta value stored directly in
  `Annotated` and available through normal Python introspection.
- **Native operation:** a separately specified ABI service with an executable
  Python reference path.
- **Backend:** a lowering target such as a CPython extension, a plain C ABI
  shared library, LLVM/MLIR, or target machine code.
- **Capability report:** the source-correlated result of eligibility, lowering,
  optimization, and verification.

Sections from Design Principles through Compiler and IR Requirements form the
normative core. Source-Level Design Patterns and Advanced Source-Level Patterns
are advisory examples. Execution and Concurrency Model is normative for regions
that request non-sequential execution. Machine IR and Assembly is normative only
for a backend that exposes or emits machine-level code.

## Design Principles

1. **CPython is the language definition.** A source module may use the full
   syntax and semantics of its declared CPython version. It must parse, import,
   and execute without compiler rewriting, compiler import hooks, or a generated
   native artifact.
2. **One source has one meaning.** Native execution must preserve all observable
   CPython behavior promised for the compiled region. An optimization may not
   replace Python integer, exception, aliasing, mutation, or cancellation
   semantics merely because C behaves differently.
3. **Typing describes facts; it does not create syntax.** Application source
   uses normal Python annotations, including standard `typing` facilities.
   Mypy is a frontend and developer tool, not the authority for runtime
   semantics.
4. **Low-level facts live with the code.** Annotations and decorators carry
   region boundaries, representation, layout, ownership, bounds, effects, and
   specialization facts. Backend, target, artifact, and deployment policy may
   remain in an external Python sidecar.
5. **Low-level control uses Python operations.** The compiler recognizes and
   lowers ordinary, explicit Python operations and calls into eligible project
   Python modules. PyMeta descriptors provide control where inference is
   insufficient while retaining genuine CPython behavior and introspection.
6. **Failure is visible.** A requested native region is either compiled in full
   or rejected with source locations and reasons. There is no hidden transition
   to Python inside a region reported as native.
7. **CPython hosts the metalanguage.** Region, type, effect, transformation,
   target, and native-operation descriptions are Python code. The DSL may use
   calls, keyword arguments, indexing, context managers, and operator
   overloading, and deterministic standard-library helpers, but no token or
   evaluation rule outside Python is permitted.

## Source and Compatibility Contract

Compiler input is an ordinary `.py` module. It may use every construct accepted
by its declared CPython language version. The module must not contain a custom
grammar, compiler-only tokens, or embedded generated C.

Application modules have normal access to CPython built-ins and the standard
library and may import ordinary project or third-party Python modules. A
native-compilation candidate must not depend on a third-party native extension,
generated native binding, or compiler intrinsic package that has no genuine
Python behavior. The pure-Python PyMeta package is a normal source dependency.
Such a dependency is either left on the interpreted CPython path or exposed by
an in-place native-operation declaration with a portable Python reference path;
platform symbol resolution remains in a Python policy sidecar.

A project-owned, pure-Python semantic API is allowed when its classes and
functions are useful and correct under CPython—for example PyMeta descriptors,
a buffer protocol, an execution-context protocol, or a lock-backed atomic
reference. It must not be a bag of compiler no-ops. Decorators attach frozen
metadata visible through `inspect`; semantic operations execute a Python
reference implementation when no compiled artifact exists.

This restriction does not ban imports. It keeps native implementation details
out of application source and ensures the same source remains meaningful when
no generated artifact exists.

“Fully compatible with CPython” means source compatibility and behavioral
equivalence, not that every Python program must be natively compilable. Each
backend publishes a capability report for every compilation region:

- `compiled`: the complete region was lowered;
- `interpreted`: compilation was not requested and CPython executes it;
- `rejected`: compilation was requested but the backend cannot prove a correct
  lowering; or
- `guarded`: a CPython-dependent backend compiled a documented guarded path and
  preserves exact fallback or deoptimization behavior.

A Python-independent CDLL backend may use only `compiled`, `interpreted`, and
`rejected`; it must not call back into Python from a native region.

The interpreted implementation is the executable specification. Native and
interpreted variants must pass the same tests. Public signatures, return
values, mutations, exception types and ordering, resource cleanup, and relevant
introspection must agree.

## Type and Representation Model

Ordinary annotations keep their Python meaning. `TypeAlias`, `NewType`,
`Annotated`, `Literal`, `Final`, unions, protocols, generic classes, and other
standard typing constructs are available. Unannotated or `Any` values are valid
Python but normally prevent unboxed CDLL lowering.

`Annotated` metadata may contain immutable PyMeta descriptors. For example,
`Annotated[int, uint[16] | wrap]` describes a Python `int` represented as an
unsigned wrapping 16-bit value in an eligible native region. CPython retains
the underlying `int`; `typing.get_type_hints(..., include_extras=True)` exposes
the descriptor. Application source must not encode target names, C pointer
layouts, artifact paths, or compiler flags in these descriptors.

Representation constraints are in-place descriptor values normalized into the
manifest. They support these categories:

- integer representation: width, signedness, and checked or wrapping overflow;
- floating-point representation: width and required IEEE behavior;
- buffer representation: element, access, lifetime, contiguity, and alignment;
- record layout: ABI name, size, alignment, fields, and version;
- value bounds: inclusive or exclusive minimum and maximum; and
- ownership and effects: owner, escape policy, aliasing, and thread affinity.

These descriptors do not change CPython values. For example, a parameter whose
PyMeta representation is a 16-bit integer is still a Python `int` when
interpreted. A compiler must insert checks where needed to preserve the policy;
it must not silently use C overflow or truncation.

Use normal classes, dataclasses, tuples, and protocols in source. A backend may
unbox them only when it can preserve their observable contract. ABI-facing
fixed records require an explicit, versioned `@record(...)` descriptor; native
layout must never be inferred from incidental CPython object layout.

A repository may keep reusable semantic aliases, protocols, and executable
fallback stubs in ordinary `.py` modules. Those modules run under CPython and
are the reference behavior for lowered operations. Optional `.pyi` stubs may
improve mypy and editor support but are never executed or treated as layout
authority. Both forms use standard Python typing constructs. Facts that typing
cannot express use immutable PyMeta descriptors; they do not introduce native
objects into application source.

Native-operation decorators refer to stable symbolic IDs and must not import a
native module to discover addresses or layouts. The build resolves each ID to a
versioned ABI declaration and target library; the in-place declaration supplies
its ownership, effects, Python fallback, and verification requirements.

The canonical in-place structure combines annotations and a region decorator:

```python
from typing import Annotated, TypeAlias

from pymeta import (
    buffer,
    contiguous,
    effects,
    lifetime,
    read,
    region,
    required,
    u8,
    uint,
    wrap,
    write,
)


SequenceNumber: TypeAlias = Annotated[int, uint[16] | wrap]
ReadableBytes: TypeAlias = Annotated[
    bytes | bytearray | memoryview,
    buffer[u8] | read | lifetime.call | contiguous,
]
WritableBytes: TypeAlias = Annotated[
    bytearray | memoryview,
    buffer[u8] | write | lifetime.call | contiguous,
]


@region(
    required,
    effects=effects(
        reads={"source", "offset"},
        writes={"target"},
        noescape={"source", "target"},
    ),
)
def copy_sequence(
    source: ReadableBytes,
    target: WritableBytes,
    offset: int,
) -> SequenceNumber:
    ...
```

The signature is the low-level interface and the function body remains the
executable specification. The decorator stores a frozen `RegionSpec` on the
function and returns a normally callable Python function. It does not compile
at import time. A frontend validates declared facts against the body.

## Operations and Control Flow

Normal Python operators retain CPython semantics. This rule includes arbitrary
precision integers, floor division and modulo, negative shifts, comparison
dispatch, short-circuit evaluation, evaluation order, and exception timing.

A backend may lower an operation directly only after proving the operands and
result fit the selected representation, or after emitting the checks required
by its overflow policy. C integer overflow, out-of-bounds access, invalid
shifts, pointer arithmetic, and data races are never source-level semantics.

The source expresses byte order, checks, and wrapping with standard operations:

```python
from typing import Annotated, Final, TypeAlias

from pymeta import uint, wrap


SequenceNumber: TypeAlias = Annotated[int, uint[16] | wrap]
ReadableBuffer: TypeAlias = bytes | bytearray | memoryview
WritableBuffer: TypeAlias = bytearray | memoryview

SEQUENCE_BYTES: Final = 2
OUTPUT_BYTES: Final = 4
MAX_SEQUENCE: Final = (1 << 16) - 1


def copy_sequence(
    source: ReadableBuffer,
    target: WritableBuffer,
    offset: int,
) -> SequenceNumber:
    sequence_end = offset + SEQUENCE_BYTES

    if offset < 0 or sequence_end > len(source):
        raise IndexError("sequence is outside source")
    if len(target) < OUTPUT_BYTES:
        raise BufferError("target is too small")

    sequence_bytes = source[offset:sequence_end]
    sequence = int.from_bytes(sequence_bytes, byteorder="big")
    target[:OUTPUT_BYTES] = sequence.to_bytes(OUTPUT_BYTES, byteorder="big")

    next_sequence: SequenceNumber = (sequence + 1) & MAX_SEQUENCE
    return next_sequence
```

The compiler may recognize `int.from_bytes`, `int.to_bytes`, masks, shifts,
`len`, indexing, slicing, and explicit checks as typed IR operations. Pattern
recognition must preserve evaluation and exception order and must produce a
report showing which operations were recognized. Unrecognized operations are a
backend eligibility failure when native compilation is required.

Readability is part of the source contract. Compiler recognition must tolerate
named constants, intermediate variables, helper functions, keyword arguments,
semantic type aliases, standard annotations, and conventional formatting.
Application authors must not be forced to inline expressions, repeat literals,
encode operations in unusual spellings, or write code shaped like generated C
merely to make a region compilable. Normal refactoring must either preserve
eligibility or produce a precise diagnostic.

SIMD, sockets, arenas, cryptography, and externally owned memory are ordinary
Python library boundaries, backend IR operations, or services declared with
`@native_operation(...)`. They are not new application syntax. If a future
operation cannot
be expressed clearly with Python, it requires a separate specification decision;
it must not arrive through an ad hoc compiler-specific import.

`if`, `match`, loops, comprehensions, exceptions, context managers, calls, and
`async` remain ordinary Python. A backend may restrict which forms are eligible.
Loop bounds may come from PyMeta bounds or analysis; special loop syntax is
forbidden. Calls between compiled regions are ordinary calls and may be inlined.

## The Python-Native PyMeta DSL

PyMeta is a CPython-hosted embedded language and pure-Python declarative API.
Its structure has four layers:

- `Annotated[T, descriptor]` describes representation and value constraints;
- `@region(...)` describes a compilation boundary, effects, and execution;
- class decorators such as `@record(...)` describe stable field layout; and
- context managers and callable semantic objects express scoped low-level
  operations with a real Python reference behavior.

These forms construct immutable metadata attached to normal Python objects.
They do not compile at import time, replace Python semantics, or require a
generated artifact. `inspect`, `typing.get_type_hints`, and PyMeta's public
inspection API expose the same descriptors seen by the compiler.

The normalized surface uses exactly these structural forms:

| Purpose | Canonical Python form |
| --- | --- |
| Value representation | `Annotated[T, descriptor]` |
| Descriptor composition | `descriptor | qualifier` |
| Compilation region | `@region(policy, ...)` |
| Fixed record | `@record(...)` over a class or dataclass |
| Native boundary | `@native_operation(...)` over a Python fallback |
| Typed operation | `load[descriptor](value, ...)` |
| Runtime data flow | `value | semantic_stage(...)` |
| Compiler-side ordered composition | `first >> second` |
| Target/deployment choice | calls in a Python policy sidecar |

Alternative spellings must normalize to these forms before they appear in
documentation, diagnostics, generated stubs, or capability reports.

### Syntax normalization rules

1. Closed vocabularies use exported immutable values such as `required`,
   `big_endian`, or `lifetime.call`, not strings. Strings are reserved for
   qualified source names, semantic operation IDs, ABI names, field/place
   expressions, error text, and other genuinely open data.
2. Descriptor chains are written in semantic order: representation, access,
   lifetime, layout, ownership, then constraints. Normalization is order
   independent, but generated source and diagnostics use this order.
3. Sets contain unordered facts such as effects or required proofs. Tuples
   contain ordered choices such as lane widths or pass sequences. Lists are
   used only when mutation or source order is itself meaningful.
4. Decorators carrying PyMeta metadata are outermost. A structural Python
   decorator such as `@dataclass` runs first; `@record` or `@region` then sees
   the final Python object and attaches one frozen specification.
5. `|` composes descriptor values when both operands are descriptors. When the
   left operand is runtime data, a semantic stage's `__ror__` executes the
   Python operation. Mixing these domains is a `TypeError`.
6. `>>` is restricted to compiler-side ordered values such as patterns and
   transformations. It never changes application arithmetic or control flow.
7. Public PyMeta objects have stable `repr`, equality, hashing, and normalized
   serialization. Equivalent sugar produces byte-identical normalized data.

Purity and effects should still be inferred first. Explicit declarations are
contracts checked against the body, not assertions that allow unsafe lowering.
Incorrect metadata is a compile error or checked guard, never permission for
undefined behavior.

The visual model is deliberately compact:

```python
Value = Annotated[PythonType, representation | qualifier]


@region(
    required,
    effects=effects(
        reads={"place"},
        writes={"place"},
        noescape={"parameter"},
    ),
)
def operation(value: Value) -> Value:
    ...
```

Calls show declaration boundaries, keyword arguments name parameters, `[]`
applies type arguments, and `|` composes independent facts from left to right.
Thus `buffer[u8] | write | lifetime.call | contiguous` reads as a phrase while
remaining normal Python. The operands are immutable descriptor values and `|`
returns a new validated descriptor; it is not a compiler-recognized fake
operation.

The API includes `sint[width]`, `uint[width]`, `float_[width]`, `buffer[element]`,
and `layout[name]`; `checked` or `wrap`; `read`, `write`, or `readwrite`;
`contiguous`, alignment, bounds, ownership, escape, effects, variants,
execution, and native-operation declarations. Function forms must also exist
for values that are dynamic or clearer with labels, such as
`aligned(32)`, `owned_by("peer")`, and `bounded(min=0, max=1500)`.

Fixed records use a class decorator without replacing the ordinary dataclass:

```python
@record(abi="webrtc.packet.v1", packed=True)
@dataclass(frozen=True, slots=True)
class PacketHeader:
    sequence: Annotated[int, uint[16]]
    timestamp: Annotated[int, uint[32]]
    ssrc: Annotated[int, uint[32]]
```

Scoped control uses context managers whose fallback behavior is real Python:

```python
with borrowed(packet, read | contiguous) as view:
    sequence = load[uint[16] | big_endian](view, at=2)
```

`borrowed` acquires and releases a `memoryview`; `load` performs checked Python
buffer access. Native lowering may replace them only with equivalent behavior.

### Expressive low-level operations

PyMeta may use Python's data-model hooks to create a compact operation language,
provided every expression has unsurprising executable behavior under CPython.

Typed memory operations use subscription for static facts and calls for runtime
operands:

```python
with borrowed(packet, read | contiguous) as source:
    sequence = load[uint[16] | big_endian](source, at=2)
    timestamp = load[uint[32] | big_endian](source, at=4)

with borrowed(output, write | contiguous) as target:
    store[uint[16] | big_endian](target, sequence + 1, at=0)
    store[uint[32] | big_endian](target, timestamp, at=2)
```

`load[spec]` and `store[spec]` return immutable callable operation objects.
Their calls perform bounds, mutability, conversion, and overflow checks in
Python. The compiler sees the same resolved specification.

Semantic pipelines use `|` as readable left-to-right data flow:

```python
written = (
    packet
    | decode[RtpHeader]
    | require(version=2)
    | protect_with(srtp_context)
    | write_into(output)
)
```

Each stage implements `__ror__` and immediately executes its Python reference
behavior. A pipeline is not lazy unless its public return type explicitly says
so. The compiler may fuse adjacent stages only after preserving their exception
order and partial mutations.

Bit-packed protocols use decorated dataclasses and slice-shaped field metadata:

```python
@bitfield(uint[8], bitorder="msb0")
@dataclass(frozen=True, slots=True)
class RtpFirstByte:
    version: Annotated[int, bits[0:2]]
    padding: Annotated[bool, bit[2]]
    extension: Annotated[bool, bit[3]]
    csrc_count: Annotated[int, bits[4:8]]
```

The class remains constructible and comparable as a normal dataclass.
`RtpFirstByte.from_bytes(...)` and `.to_bytes()` are checked Python methods
installed by the decorator and are the reference behavior for native packing.

Vector intent uses an ordinary iterable rather than magical lane variables:

```python
for index in lanes[8](range(length)):
    output[index] = left[index] + right[index]
```

Under CPython, `lanes[8]` yields exactly the original indices in order. The
width is a lowering request, not permission to reorder exceptions or overlap
writes. Tail handling is part of the iterable contract.

Operator sugar is deliberately small: `|` composes descriptors or executes
semantic pipelines, `[]` binds static operation arguments, and `>>` composes
compiler transformations. PyMeta must not overload ordinary numeric operators
on application values merely to smuggle target intrinsics into source.

PyMeta protocols and operation stubs are executable Python, not declarations
that disappear at runtime:

```python
from threading import Lock
from typing import Generic, Protocol, TypeVar


T = TypeVar("T")


class AtomicValue(Protocol[T]):
    def load(self) -> T: ...
    def compare_exchange(self, expected: T, desired: T) -> tuple[T, bool]: ...


class LockedAtomic(Generic[T]):
    """CPython reference implementation used without native lowering."""

    def __init__(self, value: T) -> None:
        self._value = value
        self._lock = Lock()

    def load(self) -> T:
        with self._lock:
            return self._value

    def compare_exchange(self, expected: T, desired: T) -> tuple[T, bool]:
        with self._lock:
            previous = self._value
            if previous == expected:
                self._value = desired
                return previous, True
            return previous, False
```

The compiler may recognize calls through `AtomicValue` and lower a supported
implementation to native atomics. Ordinary CPython executes `LockedAtomic`.
Every intrinsic-like protocol must have at least one conforming Python
implementation used by differential tests.

All public constructors return frozen dataclasses or equivalent immutable
values with useful `repr`, equality, and serialization behavior. Composition
rejects contradictions immediately—for example `read | write` must either
normalize explicitly to `readwrite` or raise a documented error. Names use
lower-case snake case within each dotted component. Python source names are
fully qualified. Unknown keyword arguments and duplicate declarations are
errors. Sugar has one context-independent normalization: `uint[16] | wrap`,
for example, becomes an integer with width 16, `signed = False`, and overflow
policy `"wrap"`.

External Python sidecars are reserved for target and deployment policy that
should not alter source meaning. They may import PyMeta, constants, other
sidecars, and deterministic standard-library helpers. Environment reads,
clocks, randomness, filesystem or network I/O, and imports with mutable side
effects are invalid during policy evaluation because they are not reproducible.

## Backend Eligibility

The common portable kernel core consists of scalars with proven representation,
contiguous buffers with explicit access and lifetime, fixed-layout records,
local control flow, calls to eligible functions, and explicit results. This is
a portability target, not a restriction on Python source.

Backend-specific eligibility is layered on that contract:

- A CPython-native backend may retain Python objects, exceptions, and guarded
  calls through version-pinned CPython APIs.
- A CDLL backend accepts only Python-independent values and cannot let Python
  exceptions, objects, borrowed lifetimes, or callbacks cross its C ABI.
- A meta-compiler may choose either backend and search transformations, but may
  not alter source semantics or add application syntax.

Dynamic attributes, reflection, generators, closures, arbitrary containers,
and async suspension remain valid Python. They may be backend rejection reasons.

## Errors, Effects, and Concurrency

Within CPython-native code, exceptions must match the reference path in type,
ordering, cleanup, and externally relevant traceback policy. Across a C ABI,
generated bindings translate versioned status records into those same Python
exceptions; temporary native error-string pointers are forbidden.

Buffer access checks length, capacity, alignment when required, overlap policy,
mutability, and lifetime before native work. Writable buffers require exclusive
access for the call unless synchronization is explicit. Borrowed views do not
escape their declared lifetime.

The GIL is not an ownership annotation. Code that may execute without it, or
under free-threaded CPython, must be data-race-free through ownership, atomics,
or synchronization expressed in IR and the binding contract. Native threads
must not invoke Python callbacks from CDLL kernels.

## Compiler and IR Requirements

All tracks share a semantic typed IR before backend lowering. It records:

- CPython evaluation and exception order;
- exact scalar representations and overflow policies;
- buffer shape, bounds, alias sets, ownership, and lifetime;
- reads, writes, allocation, I/O, suspension, and synchronization effects;
- guards and their failure behavior; and
- source spans for every operation and diagnostic.

Optimization passes consume proven IR facts rather than decorator names.
Potentially reusable ideas for other compilers include capability reports as a
first-class artifact, effects on SSA values, proof-carrying bounds elimination,
explicit ABI and lifetime manifests, differential execution against a language
reference, and separate semantic IR from backend and search IR.

Generated artifacts must include the source hash, declared CPython semantics
version, resolved types, normalized IR, backend and compiler versions, target,
flags, ABI version, guards, selected pass schedule, and verification results.

## Source-Level Design Patterns

This section is advisory. The following patterns borrow useful ideas from
systems languages, staged compilers, and transpilers without importing their
syntax into Python.

### Semantic types with in-place `Annotated`

Use the `Annotated` form demonstrated under Operations and Control Flow: an
ordinary underlying Python type plus an immutable semantic descriptor, never
an inline C declaration. This follows PEP 593: ordinary type checkers may use
the underlying type while CPython and the compiler can inspect the metadata.
Keeping target and ABI policy out of the descriptor prevents annotations from
becoming a target-specific C type language.

### Nominal protocol values with `NewType`

Use `NewType` when two runtime-compatible values must not be mixed accidentally:

```python
from typing import NewType


PeerId = NewType("PeerId", int)
TransportSequence = NewType("TransportSequence", int)
```

`NewType` is useful for identity, units, handles, and protocol domains. It does
not imply a native width; a PyMeta descriptor supplies representation. Prefer
`Annotated` when representation is the main fact and `NewType` when static
separation is the main fact. A shared pure-Python typing module may combine
these into reusable aliases.

### Compile-time values with `Final` and `Literal`

Borrow Zig's `comptime` and staged-compilation idea without adding an evaluator:

```python
from typing import Final, Literal


RTP_VERSION: Final = 2


def header_size(
    extension: Literal[False, True],
) -> int:
    return 16 if extension else 12
```

`Final` identifies constants that analysis may fold. `Literal` defines a finite
specialization domain. The region decorator chooses which values are static,
sets a variant limit, and defines fallback behavior. A value outside an AOT variant
must use the generic implementation rather than trigger production compilation.

### Structural capabilities with `Protocol`

Borrow trait/interface constraints without forcing inheritance:

```python
from typing import Protocol


class WritablePacket(Protocol):
    def __len__(self) -> int: ...
    def __setitem__(self, key: slice, value: bytes) -> None: ...
```

Protocols describe the readable Python interface. For a CDLL kernel, the
region metadata narrows accepted runtime implementations to representations it
can prove contiguous, writable, and call-scoped. Structural typing is not proof of
memory layout, so the compiler must keep those two questions separate.

### Shape relationships with generics and `Literal`

Borrow dependent/shape typing only where standard typing can express it. Use
generic parameters, `Literal` dimensions, and `TypeVarTuple` for relationships
such as “output has the same packet count as input.” Concrete byte capacity,
stride, alignment, and alias rules remain checked PyMeta facts. This retains
useful static relationships without pretending Python's type system proves
memory safety.

### Explicit lifetime scopes with `memoryview`

Use the standard buffer protocol and lexical scopes for borrowed memory:

```python
def read_sequence(packet: bytes | bytearray) -> int:
    with memoryview(packet) as view:
        if len(view) < 4:
            raise BufferError("RTP packet is too small")
        return int.from_bytes(view[2:4], byteorder="big")
```

This resembles a borrow scope while retaining real CPython behavior. The
compiler may prove that derived views do not escape the `with` block. It must
still check contiguity, format, mutability, aliasing, and concurrent mutation;
Python `memoryview` alone is not a Rust borrow checker.

### Declarative binary layouts with `struct`

Use the standard `struct` module as a readable executable layout description:

```python
from struct import Struct
from typing import Final


RTP_FIXED_HEADER: Final = Struct("!BBHII")
```

The compiler may constant-fold a `Struct`, validate its size against an
in-place record descriptor, and lower `pack_into` or `unpack_from` directly. This is preferable
to handwritten shifts when a wire layout is fixed; explicit arithmetic remains
appropriate for conditional or bit-packed fields. Native in-memory record
layout still requires an explicit `@record(...)` descriptor because wire format
and host ABI layout are different contracts.

### Effects and ownership as a second signature

Borrow Rust ownership and MLIR memory-effect modeling, but place it beside the
Python signature in `@region(...)`:

```python
@region(
    preferred,
    effects=effects(
        reads={"header"},
        writes={"output"},
        noescape={"output"},
        owner="peer",
        allocate=never,
        suspend=never,
    ),
)
def write_header(header: Header, output: WritableBytes) -> None:
    ...
```

Effects should be inferred first and declared only at public native boundaries
or where inference is incomplete. The frontend compares declared and inferred
effects. A declaration may restrict behavior but never hide an observed effect.
This produces low-level scheduling, fusion, interpreter-release, and alias
information in a declaration beside the function.

### Separate transformation programs

Borrow MLIR's Transform dialect distinction between payload IR and transform
IR. Python source states behavior; a separate Python sidecar selects operations
with ordinary calls such as `transform.inline(...)`,
`transform.specialize(...)`, `transform.fuse(...)`, `transform.tile(...)`,
`transform.vectorize(...)`, `transform.bufferize(...)`, or
`transform.lower_to_cdll(...)`. Each
transformation has legality predicates, effects, a bounded search space, and an
auditable rejection reason. Optimization directives never change Python
meaning and never execute on a live request path.

### Capability reports instead of syntax restrictions

Borrow Cython's annotated compilation report and staged-compiler lowering
inspection. Generate a source-correlated report showing boxed values, native
representations, bounds checks, copies, allocations, Python calls, guards,
fusion decisions, and rejection reasons. This lets authors write attractive
Python first and optimize from evidence instead of memorizing compiler-shaped
idioms.

### Approaches deliberately not adopted

- Cython-style target-specific scalar names are not used; PyMeta descriptors
  describe semantic facts and retain Python values at runtime.
- One structured `@region(...)` decorator replaces unordered stacks of JIT,
  purity, no-GIL, inline, and specialization markers.
- Rust-like lifetime parameters are not simulated in Python syntax. Ownership
  is inferred, checked, and reported through IR and manifests.
- JAX-like tracing does not define program semantics. It may collect shapes or
  profiles offline, but CPython execution remains the reference.
- Target intrinsics, raw pointers, unchecked indexing, and undefined overflow
  are never disguised as harmless Python functions.

## Advanced Source-Level Patterns

This section is advisory. These profiles extend the preceding patterns to
GPU-like kernels, SIMD, packet processing, and cross-compilation while keeping
the source executable Python.

### Typed buffers and address spaces

The attractive `Buffer[element, address_space]` spelling can be retained in a
central pure-Python typing API. Address-space names are semantic marker types;
their hardware mapping lives in the target-policy sidecar:

```python
from typing import Annotated, Protocol, TypeAlias, TypeVar

from pymeta import address_space, float_


Element = TypeVar("Element")


class ReadableBuffer(Protocol[Element]):
    def __len__(self) -> int: ...
    def __getitem__(self, index: int) -> Element: ...


class WritableBuffer(ReadableBuffer[Element], Protocol[Element]):
    def __setitem__(self, index: int, value: Element) -> None: ...


F32: TypeAlias = Annotated[float, float_[32]]
GlobalF32: TypeAlias = Annotated[
    WritableBuffer[F32],
    address_space.global_,
]
```

This is more Pythonic than making `Global` and `Shared` runtime wrapper objects.
The protocol describes operations; `Annotated` selects a semantic
representation; in-place descriptors define alignment, contiguity, aliasing,
and lifetime, while target policy maps the semantic address space to hardware.

For simple CPU kernels, prefer `memoryview` directly. Use a custom buffer
protocol only when the same source must describe device, mapped, shared, or
remote memory with a meaningful Python simulator.

### Explicit execution context instead of magical globals

Names such as `thread.x` and `block.x` look concise but hide inputs. Pass an
execution context explicitly so testing, simulation, effects, and specialization
remain visible:

```python
from typing import Protocol


class KernelContext(Protocol):
    def global_id(self, dimension: int) -> int: ...
    def global_size(self, dimension: int) -> int: ...
    def barrier(self) -> None: ...


def vector_add(
    context: KernelContext,
    left: GlobalF32,
    right: GlobalF32,
    output: GlobalF32,
    length: int,
) -> None:
    index = context.global_id(0)
    if index < length:
        output[index] = left[index] + right[index]
```

A pure-Python context executes or simulates the function. GPU, SIMD, or CPU
backends lower the protocol calls to their execution model. The region
descriptor marks the context parameter as implicit in the native ABI if needed.

### Grid-stride loops with ordinary `range`

Avoid a compiler-only `parallel_range`. Express the actual work partition with
normal Python control flow:

```python
def scale(
    context: KernelContext,
    values: GlobalF32,
    factor: F32,
    length: int,
) -> None:
    start = context.global_id(0)
    stride = context.global_size(0)

    for index in range(start, length, stride):
        values[index] *= factor
```

This exposes indexing and bounds to both readers and the compiler. A
transformation file may map an ordinary outer `range` loop to CPU threads,
SIMD lanes, GPU work items, or distributed shards after proving independence.

### Atomics as typed objects with real fallback behavior

Use method calls whose names match standard atomic concepts instead of an
`with atomic()` block whose scope is ambiguous:

```python
from typing import Protocol, TypeVar


Value = TypeVar("Value")


class AtomicReference(Protocol[Value]):
    def load(self) -> Value: ...
    def store(self, value: Value) -> None: ...
    def fetch_add(self, value: Value) -> Value: ...
    def compare_exchange(
        self,
        expected: Value,
        desired: Value,
    ) -> tuple[Value, bool]: ...
```

The CPython implementation can use a lock. Metadata selects width, alignment,
memory order, scope, and target instruction. If memory order matters to source
correctness, expose it as a standard `Literal` argument rather than an optimizer
hint.

### Fixed-size vectors and matrices

Use tuples for small immutable values and attach a semantic layout descriptor:

```python
from typing import Annotated, TypeAlias

from pymeta import float_, vector


Float4: TypeAlias = Annotated[
    tuple[float, float, float, float],
    vector[float_[32], 4],
]


def dot4(left: Float4, right: Float4) -> float:
    return sum(a * b for a, b in zip(left, right, strict=True))
```

The compiler may lower this to SIMD after proving the tuple length and scalar
representation. For variable-rank tensors, use generics and shape metadata;
do not embed strings such as `("M", "N")` into runtime indexing rules without
a separately validated shape environment.

### Shared or scratch memory through explicit resources

Context managers are appropriate when they express real lifetime and cleanup,
not merely optimization wishes:

```python
from contextlib import AbstractContextManager
from typing import Protocol


class ScratchAllocator(Protocol):
    def bytes(self, size: int) -> AbstractContextManager[memoryview]: ...


def stage_header(scratch: ScratchAllocator, packet: bytes) -> bytes:
    with scratch.bytes(12) as header:
        header[:] = packet[:12]
        return bytes(header)
```

The Python implementation allocates and releases storage. A GPU backend may map
the resource to shared memory and a CPU backend to stack or arena storage when
escape analysis proves the lifetime. `with unroll()`, `with fast_math()`, and
`with bounds_check(False)` are rejected because they do not describe portable
runtime resource semantics.

### Operations as tagged data

Use `Literal`, `Enum`, or `match` for a finite operation family instead of
stringly typed compiler calls:

```python
from enum import Enum, auto


class Reduction(Enum):
    SUM = auto()
    MAXIMUM = auto()


def combine(operation: Reduction, left: float, right: float) -> float:
    match operation:
        case Reduction.SUM:
            return left + right
        case Reduction.MAXIMUM:
            return max(left, right)

    raise AssertionError("unreachable reduction")
```

The compiler can prove exhaustiveness, specialize finite variants, and retain a
generic dispatch path. The enum remains an ordinary Python API.

### Generated launch handles on the host side

The bracket launch form is valid Python but should belong to a generated host
launcher, not replace the source function object:

```python
grid = (block_count, 1, 1)
block = (256, 1, 1)
compiled["vector_add"][grid, block](left, right, output, length)
```

The original `vector_add(...)` stays callable with a Python `KernelContext`.
The generated `compiled` registry validates geometry and arguments before
dispatch. A conventional `.launch(..., grid=grid, block=block)` method should
also exist because it is clearer for dynamic configuration and error messages.

### Compile-time specialization with region metadata

Use `Literal` and `Final` in the signature and select static parameters in the
in-place region declaration:

```python
@region(
    preferred,
    variants=variants(limit=8, fallback=generic),
    specialize=specialize(operation="sum", width=4),
)
def scale(values: Values, operation: Operation, width: int) -> Values:
    ...
```

This adopts the useful part of `Const[int]` and `.specialize(...)` while keeping
build policy out of function signatures. The compiler produces an ordinary
callable per accepted variant plus a deterministic dispatcher.

### Structured unsafe operations only at reviewed boundaries

Do not provide a general `unsafe` context in application Python. Put raw
pointers, unchecked loads, target barriers, vector intrinsics, and foreign calls
behind a separately specified native operation. Its metadata declares preconditions,
effects, ABI, reference Python callable, fuzz tests, and sanitizer requirements.
This makes the unsafe boundary small and reviewable rather than visually elegant
but semantically misleading.

The declaration itself is Python code:

```python
@native_operation(
    "webrtc.crypto.protect_packet",
    abi=c_abi(version=1),
    effects=effects(reads={"context", "packet"}, writes={"output"}),
    verifies={fuzz, address_sanitizer, undefined_behavior_sanitizer},
)
def protect_packet(context: Context, packet: ReadableBytes) -> bytes:
    return reference_protect_packet(context, packet)
```

The decorated function is the reference implementation. A target-policy
sidecar maps `"webrtc.crypto.protect_packet"` to a library and exported symbol;
application source does not contain platform symbol names.

## Execution and Concurrency Model

### Do not add a parallel grammar

The compiler needs an explicit concurrency model, but application Python does
not need new keywords. Use structured region decorators, ordinary functions,
`async def`, `await`, `for`, `range`, context managers, locks, queues, and typed execution
contexts. Region metadata selects a legal native execution strategy after IR
analysis proves its requirements.

`async` describes cooperative suspension and concurrency; it does not imply CPU
parallelism. A normal `for` loop is sequential unless a region transformation
requests parallelization and the compiler proves that iterations are
independent or recognizes a declared reduction.

### Supported execution models

Every compiled region has exactly one primary model:

- **Sequential:** the default. One invocation executes in program order on the
  calling thread.
- **SIMD:** one thread evaluates multiple independent lanes. Observable results
  and exception choice must remain defined.
- **Parallel-for:** a finite iteration space is divided into bounded chunks.
  The source loop still has ordinary sequential CPython behavior.
- **SPMD:** each invocation represents one work item and receives an explicit
  `KernelContext`; barriers and shared memory are part of that context.
- **Owned shard:** mutable state belongs to one peer, session, worker, or event
  loop. Other threads communicate through bounded messages or immutable input.
- **Pipeline:** different stages may run concurrently, but each item has an
  explicit ownership transfer and bounded queue between stages.

These models may be nested only when their region descriptors permit it and
sets a global parallelism budget. Otherwise a nested region executes
sequentially to prevent thread-pool oversubscription.

### Parallel loops remain readable Python

Write a normal range kernel with explicit inputs and outputs:

```python
def scale_range(
    values: memoryview,
    factor: float,
    start: int,
    stop: int,
) -> None:
    if start < 0 or stop > len(values) or start > stop:
        raise IndexError("invalid scale range")

    for index in range(start, stop):
        values[index] *= factor
```

CPython calls it sequentially. The compiler may generate a bounded
parallel-for wrapper because each iteration writes a distinct element. The
source does not import `parallel_range`, and a reader can understand its work
partition without knowing compiler syntax.

### Execution policy belongs on the region

```python
@region(
    preferred,
    execute=parallel_for(
        "index",
        schedule=static,
        minimum_grain=4096,
        maximum_workers=4,
        errors=ordered,
        nested=sequential,
    ),
    effects=effects(
        reads={"values[start:stop]", "factor"},
        writes={"values[start:stop]"},
        disjoint_by="index",
        suspend=never,
        block=never,
    ),
)
def scale_range(
    values: memoryview,
    factor: float,
    start: int,
    stop: int,
) -> None:
    ...
```

The region descriptor is a request, not proof. Alias, bounds, escape, effect, and
dependence analysis must validate it. If independence cannot be proved, a
required parallel build is rejected and an optional one stays sequential.

### Ownership is more important than threads

For mutable protocol state, prefer single-owner shards over locks. Assign each
peer or transport context to one owner. Compile pure frame or feedback batches
in parallel only when they do not mutate the same sequence-number, SRTP, pacing,
or congestion-control state. Transfer results back through a bounded completion
record with an owner generation number.

The IR tracks each value as one of:

- immutable and freely shareable;
- call-scoped borrowed read-only;
- exclusively borrowed writable;
- moved to a new owner;
- atomic shared state; or
- synchronized shared state.

The GIL is not an ownership category. The same rules apply to generated CDLL
code and free-threaded CPython.

### Reductions require explicit semantics

Parallel floating-point reductions can change rounding because reassociation
changes operation order. Integer reductions can change overflow or error
selection. A reduction declaration therefore specifies:

- operation and identity;
- input and accumulator representations;
- overflow and NaN policy;
- deterministic tree or implementation-defined grouping;
- whether reassociation is legal; and
- which exception wins when more than one lane fails.

The portable default preserves sequential order. A faster unordered reduction
is a separately named semantic operation or explicit region contract, not an
automatic optimization hidden behind `sum()`.

### Cancellation and failure are part of execution semantics

For every parallel region, define:

- the point after which submitted native work cannot be cancelled;
- whether cancellation stops admission, requests cooperative stop, or only
  discards the result;
- whether partial writes are possible and how they are reported;
- deterministic selection or aggregation of concurrent failures;
- cleanup and ownership return for every started chunk; and
- a join barrier before buffers, arenas, or owners can be reused.

Cancelling an awaiting coroutine must not claim that physical native work has
stopped. A completion arriving after owner shutdown is immutable evidence and
must not mutate a replacement owner.

### Event-loop affinity remains explicit

Socket transports, asyncio tasks, and most event-loop objects remain owned by
their loop thread. Native workers return completion records; they do not invoke
Python callbacks or touch loop-owned objects. Cross-thread delivery uses the
event loop's documented thread-safe scheduling mechanism.

Do not create a worker submission per RTP packet merely because a function is
native. Use frame-level or feedback-batch boundaries large enough to amortize
scheduling and foreign-call costs. Direct nonblocking UDP operations should
remain on the event-loop thread unless measurement proves a native fused-send
is beneficial and preserves pacing.

### WebRTC default execution plan

For this repository, begin with:

1. One event-loop owner for signaling, transports, timers, and pacing.
2. One mutable owner per peer for RTP/TWCC/SRTP sequence-dependent state.
3. Sequential packet operations inside an owned peer unless analysis proves
   independence.
4. SIMD inside serialization, parsing, copying, and media math where profitable.
5. Bounded frame-level workers for expensive independent codec or image work.
6. Optional parallel-for inside a sufficiently large frame or feedback batch.
7. SPMD/GPU execution only for substantial media kernels, not header-sized
   packet operations.

This plan minimizes synchronization and preserves packet order while leaving
large computation regions available for real parallel speedup.

### Required compiler diagnostics

The source-correlated report must show execution model, owner, thread or loop
affinity, chunk size, worker limit, shared values, synchronization, atomics,
barriers, possible races, false-sharing risks, cancellation points, and why a
requested loop was or was not parallelized.

## Machine IR and Assembly

### Assembly is an exceptional backend, not the starting point

The compiler should first lower portable typed IR through generated C, LLVM IR,
or MLIR. Those backends already solve instruction selection, register
allocation, scheduling, instruction encoding, relocations, unwind information,
debug data, and platform calling conventions. Writing assembly too early would
turn each supported CPU and ABI into a separate compiler project.

Assembly is justified only after measurement identifies a small operation for
which at least one of these is true:

- the backend cannot select a required instruction or addressing mode;
- verified handwritten code materially beats optimized generated code;
- context switching, syscall entry, or another ABI boundary requires exact
  register control;
- cryptographic code requires reviewed constant-time instruction sequences; or
- a new or custom target does not have a usable mature backend.

Before accepting assembly, compare generated C, portable vector IR, target
intrinsics isolated behind metadata, and assembly. Keep assembly only when its
end-to-end gain pays for target, ABI, testing, and maintenance costs.

### Use three instruction levels

Borrow LLVM Generic MIR's progressive constraint model rather than lowering
Python directly to mnemonic strings:

1. **Portable low-level IR** contains typed arithmetic, loads, stores, branches,
   atomics, vectors, and explicit effects. It has virtual values but no physical
   registers.
2. **Target machine IR** selects an instruction family, register bank,
   addressing form, feature predicate, and clobbers while retaining virtual
   registers.
3. **Allocated machine IR** assigns physical registers and stack slots. Only
   then does an emitter produce assembly text or object bytes.

Every transition produces a readable dump and preserves source spans. Assembly
text is an output/debug format, not the compiler's internal data structure.

### Typed Python instruction records

Compiler-internal machine descriptions can use standard dataclasses, enums,
unions, `Literal`, and pattern matching:

```python
from dataclasses import dataclass
from enum import Enum, auto
from typing import Literal, TypeAlias


BitWidth: TypeAlias = Literal[8, 16, 32, 64]


class MemoryOrder(Enum):
    RELAXED = auto()
    ACQUIRE = auto()
    RELEASE = auto()
    ACQUIRE_RELEASE = auto()
    SEQUENTIALLY_CONSISTENT = auto()


@dataclass(frozen=True, slots=True)
class VirtualRegister:
    number: int
    width: BitWidth


@dataclass(frozen=True, slots=True)
class Add:
    result: VirtualRegister
    left: VirtualRegister
    right: VirtualRegister


@dataclass(frozen=True, slots=True)
class Load:
    result: VirtualRegister
    address: VirtualRegister
    alignment: int


@dataclass(frozen=True, slots=True)
class AtomicAdd:
    address: VirtualRegister
    value: VirtualRegister
    order: MemoryOrder


Instruction: TypeAlias = Add | Load | AtomicAdd
```

This resembles LLVM TableGen and GCC machine descriptions, but uses normal
Python tooling. Records describe semantics and constraints rather than
preformatted assembly. Frozen, slotted values make rewrites explicit and keep
instruction objects predictable.

### A builder for readable compiler passes

Use a typed builder for creating SSA-like machine IR so passes read like
operations rather than object construction:

```python
def lower_wrapping_increment(
    builder: "MachineBuilder",
    value: VirtualRegister,
) -> VirtualRegister:
    one = builder.constant(1, width=value.width)
    incremented = builder.add(value, one)
    return builder.truncate(incremented, width=16)
```

The builder checks widths, creates virtual registers, records def-use edges,
and attaches source locations. It must not overload ordinary arithmetic in a
way that confuses IR construction with Python calculation; explicit methods
make effects and invalid combinations easier to diagnose.

### Declarative instruction descriptions

Target definitions should follow the TableGen/GCC lesson: declare instruction
facts once and generate the encoder, decoder, disassembler, verifier, scheduler
tables, and selection helpers. A separate Python target-policy module can contain records
such as:

```python
target.instruction(
    "aarch64.add.shifted_register",
    lowers=integer.add[32, 64],
    operands={
        "destination": gpr,
        "left": gpr,
        "right": gpr,
        "amount": shift,
    },
    defines={"destination"},
    uses={"left", "right"},
    requires={baseline},
    effects=none,
    encoding="aarch64.add_shifted_register.v1",
)
```

Complex encodings should use structured bit-field records, not Python string
concatenation. The schema validates nonoverlapping fields, fixed bits, operand
ranges, sign extension, relocation kinds, feature gates, and reserved values.

### Instruction selection with typed pattern matching

Python `match` works well for a small selection layer:

```python
def select_add(
    instruction: Add,
    target: "TargetDescription",
) -> "MachineInstruction":
    width = instruction.result.width

    match target.architecture, width:
        case "aarch64", 32 | 64:
            return target.make(
                "aarch64.add.shifted_register",
                destination=instruction.result,
                left=instruction.left,
                right=instruction.right,
                shift=0,
            )
        case "x86_64", 32 | 64:
            return target.make(
                "x86.add.register",
                destination=instruction.result,
                source=instruction.right,
                tied_to=instruction.left,
            )
        case _:
            raise SelectionError(instruction, target)
```

For a large target, generate these matchers from declarative patterns rather
than maintaining thousands of handwritten cases. Legality predicates must be
pure and separately testable. Selection failures include the source operation,
types, demanded features, attempted patterns, and rejection reasons.

### Model registers and flags explicitly

Machine IR must represent facts that textual assembly often hides:

- virtual and physical register classes;
- subregister reads and partial-register writes;
- implicit inputs, outputs, flags, and clobbers;
- tied operands and early-clobber constraints;
- stack alignment, red zones, shadow space, and callee-saved registers;
- memory size, alignment, volatility, atomic order, and alias identity;
- control-flow successors, exceptional exits, and calls; and
- target feature requirements.

These facts drive liveness, allocation, scheduling, verification, and ABI
correctness. An instruction that cannot state its effects is not eligible for
automatic scheduling or fusion.

### Keep inline assembly outside application Python

Do not add `asm("...")`, multiline assembly strings, or mnemonic functions to
compiled application modules. When reviewed handwritten assembly is necessary,
store it in a target-specific `.S` file and reference its exported symbol from
an in-place native-operation decorator. The decorator declares its ABI,
features, clobbers, alignment, unwind behavior, effects, reference Python
implementation, and supported targets.

This makes assembly visible to platform assemblers, linters, disassemblers,
debuggers, and code review. It also prevents arbitrary strings from bypassing
the compiler's type, ownership, and effect analysis.

### Python-native golden tests

Golden tests use the same Python instruction records as the compiler. A compact
text rendering may appear in diagnostics or snapshots, but it is output—not a
second input language. Tests construct expected blocks with ordinary builders:

```python
expected = block(
    "entry",
    add("%2", "%0", "%1", register=gpr32),
    store("output", "%2", width=32, alignment=4),
    return_(status=ok),
)
```

Record construction rejects missing widths, unknown effects, invalid register
classes, and illegal target features using ordinary Python exceptions.

### Assembly verification gates

Every accepted assembly path requires:

- differential tests against the Python reference and portable backend;
- encode/decode/disassemble/re-encode round trips;
- ABI tests for every OS, architecture, and calling convention claimed;
- register-clobber, stack-alignment, unwind, and sanitizer harnesses;
- emulation or hardware testing for each required feature set;
- malformed-input, boundary, alias, and concurrency tests;
- constant-time analysis where claimed; and
- benchmarks including dispatch and data-conversion overhead.

Generated code should retain a portable fallback unless the operation is
inherently target-specific. A compiler upgrade must re-run these gates rather
than treating old assembly measurements as permanent evidence.

## Conformance

A frontend conforms when CPython accepts every input module using normal Python
imports without requiring a generated native artifact, diagnostics contain
source spans, and mypy, stubs, or the manifest do not redefine runtime
meaning.

A compiled region conforms only after differential tests cover normal results,
mutation and aliasing, every reachable error boundary, integer limits, malformed
buffers, concurrency and cancellation where applicable, and regular plus
free-threaded CPython where claimed. Native builds additionally require
sanitizers and ABI mismatch tests.

No performance result relaxes conformance. A faster result with different
observable behavior is a compiler bug, not a language variant.

## References

- [PEP 593: `Annotated`](https://peps.python.org/pep-0593/)
- [Python `typing` documentation](https://docs.python.org/3/library/typing.html)
- [PEP 646: variadic generics](https://peps.python.org/pep-0646/)
- [PEP 695: type-parameter syntax](https://peps.python.org/pep-0695/)
- [Python support for free threading](https://docs.python.org/3/howto/free-threading-python.html)
- [CPython free-threaded extension guidance](https://docs.python.org/3/howto/free-threading-extensions.html)
- [Asyncio and free-threaded Python](https://docs.python.org/3/library/asyncio-threading.html)
- [Cython pure Python mode and augmenting files](https://cython.readthedocs.io/en/stable/src/tutorial/pure.html)
- [Cython source annotation reports](https://cython.readthedocs.io/en/stable/src/userguide/source_files_and_compilation.html)
- [MLIR Transform dialect](https://mlir.llvm.org/docs/Dialects/Transform/)
- [MLIR data-layout modeling](https://mlir.llvm.org/docs/DataLayout/)
- [LLVM Generic Machine IR](https://llvm.org/docs/GlobalISel/GMIR.html)
- [LLVM Machine IR format](https://llvm.org/docs/MIRLangRef.html)
- [LLVM TableGen programmer's reference](https://llvm.org/docs/TableGen/ProgRef.html)
- [MLIR vector dialect](https://mlir.llvm.org/docs/Dialects/Vector/)
- [GCC machine descriptions](https://gcc.gnu.org/onlinedocs/gccint/Machine-Desc.html)
- [JAX ahead-of-time lowering](https://docs.jax.dev/en/latest/aot.html)
- [Rust ownership example and diagnostics](https://doc.rust-lang.org/stable/error_codes/E0507.html)
- [Zig compile-time and ABI-layout concepts](https://ziglang.org/documentation/master/)
