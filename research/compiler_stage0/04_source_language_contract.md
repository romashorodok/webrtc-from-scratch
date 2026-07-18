# Kernel E source-language and artifact contract

Status: architecture rule frozen; concrete source function remains a Stage 0
design deliverable and is not implemented here.

## Authoritative source

Kernel E is authored and maintained as an ordinary `.py` module conforming to
`research/python_metalanguage_spec.md`. Its function body is the executable
specification and must work when imported and called by the pinned CPython
runtime with no compiler and no compiled artifact present.

The source may use normal Python annotations and the pure-Python PyMeta API to
declare:

- the compilation-region boundary;
- integer widths and checked or wrapping behavior;
- contiguous buffer access, bounds, ownership, aliasing, and call lifetime;
- purity, allocation, mutation, and reentrancy facts;
- fixed result records whose Python behavior and introspection remain real.

Those declarations describe facts about Python code. They do not embed C,
spell C types in application source, import generated bindings, or act as
compiler-only no-ops.

## Required source-to-artifact chain

```text
ordinary Python Meta-Language module
        | executes directly under CPython (reference behavior)
        | validated and lowered by the future compiler
        v
generated C implementation + generated ctypes binding
        | built by the frozen CMake graph
        v
versioned shared library loaded into the pinned CPython runtime
```

The normal Python module API exposes the callable in both modes. Native-required
configuration must prove the generated symbol ran; development fallback may
execute the same Python function.

## Role of handwritten C

Handwritten ISO C is allowed only as a Stage 1 oracle implementing the same
paper ABI. It answers whether the boundary has enough performance headroom and
whether generated code approaches a competent native implementation.

The oracle:

- is not the kernel source;
- is not parsed or wrapped as Python Meta-Language input;
- does not define Python semantics or exception order;
- cannot introduce behavior absent from the Python reference;
- cannot become a handwritten escape hatch used by generated code;
- may be removed without removing the authoritative implementation.

If useful performance requires maintaining the handwritten oracle instead of
compiling the Python kernel, the compiler proposal fails its maintenance-value
gate; the project must record that as a separate implementation decision.

## Generated native implementation

The future compiler, not the application developer, generates C conforming to
the paper ABI. Generated output is a reproducible build artifact associated
with the Python source hash, normalized PyMeta metadata, compiler version, ABI
version, target, and toolchain identity.

Generated C is never edited as source. A manual edit invalidates the artifact.
Reproduction starts from the Python module and compiler inputs.

The generated binding validates the artifact before the first call and maps
native results and statuses back to the public Python signature, values,
mutations, ownership, and exception ordering.

## Kernel E eligibility implications

The current `Av1Packetizer.packetize` path is not yet eligible as the source
region because AV1 fragmentation calls the native `webrtc_rs.Av1Payloader`.
The future reference region must express the complete selected boundary in
ordinary Python:

1. accepted AV1 OBU parsing and validation;
2. AV1 fragmentation and aggregation-header construction;
3. RTP sequence and marker assignment;
4. TWCC sequence and extension construction;
5. final ordered packet serialization;
6. success-state commitment and exact failure behavior.

Helper calls are allowed only when they lead to project-owned Python functions
that are themselves executable and eligible for the same compiled region. A
call back into Rust, C, a Python callback from native code, or an interpreted
fallback inside a region reported as compiled is not allowed.

## Stage boundaries

Stage 0 freezes the source signature, behavior, metadata requirements, ABI,
and validation rules on paper. It does not add the Python kernel, PyMeta
runtime, compiler, generated C, binding, loader, or handwritten C oracle.

Stage 1 begins with the approved Python reference fixtures and region, then the
handwritten C oracle experiment. Compiler construction remains gated on oracle
correctness, sanitizer results, full-boundary measurements, end-to-end value,
and the comparison with simply maintaining the small C library.

## Acceptance rules

The source/artifact relationship is acceptable only if:

- deleting all generated files still leaves a correct importable Python
  implementation;
- deleting the handwritten C oracle does not remove the language definition;
- regeneration from the Python source is deterministic;
- differential tests invoke the same public function in interpreted and
  required-native modes;
- required-native tests prove the generated native symbol executed;
- the compiler rejects the complete region with a source-located diagnostic
  rather than silently calling Python or the handwritten oracle.

