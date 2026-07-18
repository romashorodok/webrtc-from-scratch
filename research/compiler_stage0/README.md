# Compiler Stage 0 working set

These documents implement the evidence and contract work authorized by
[`compiler_stage0_c_only_plan.md`](../../compiler_stage0_c_only_plan.md). They
do not authorize Stage 1 and intentionally contain no CMake project, C source,
Python binding, loader, or compiler implementation.

Current artifacts:

- [`01_baseline_and_source_inventory.md`](./01_baseline_and_source_inventory.md)
  records the repository, host-runtime, toolchain, workload, and source
  boundary evidence required by work item 0.1.
- [`02_kernel_e_semantic_contract.md`](./02_kernel_e_semantic_contract.md)
  is the first review draft of the observable behavior required by work item
  0.2. Its normative section is deliberately independent of a native ABI.
- [`03_kernel_e_c_abi.md`](./03_kernel_e_c_abi.md) is the non-compiling paper
  interface, lifetime table, and copy/allocation account required by work item
  0.3.
- [`04_source_language_contract.md`](./04_source_language_contract.md) freezes
  the relationship between the Python Meta-Language source, generated native
  artifact, and handwritten C oracle.

## Status legend

- **Frozen**: supported by an exact repository revision or an explicit Stage 0
  decision.
- **Provisional**: concrete enough to review, but still requires an owner to
  accept it.
- **Open**: missing evidence; Stage 0 cannot complete until it is resolved.

## Current decision

Kernel E remains the sole candidate, but is **provisional**, not frozen. The
repository does not currently contain a pure-Python AV1 frame packetizer: the
Python send path calls `webrtc_rs.Av1Payloader`, whose packetization logic is
implemented in Rust. Stage 0 must decide whether to create a Python executable
specification as the future maintained kernel source, narrow the candidate, or
reject Kernel E. The intended production source is not handwritten C. No such
implementation is added here because Stage 0 forbids it.
