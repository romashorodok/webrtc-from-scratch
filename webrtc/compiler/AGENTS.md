# Compiler optimization rules

These rules apply to `webrtc/compiler/**`.

- Keep Python source authoritative; generated C is an artifact.
- Lower generically from IR operations, representations, ownership, storage
  proofs, annotations, exact types, and resolved call edges. Never recognize
  application class, method, or field names in the general compiler.
- Keep proven scalars in C (`Py_ssize_t`, `int64_t`, `double`, `int`). Track
  ownership only for owned `PyObject *` locals and materialize scalars only at
  genuine Python boundaries.
- Preserve arbitrary-precision integer and mixed numeric semantics unless a
  range/type proof permits native arithmetic.
- Emit native storage truth, length, iteration, compaction, and mutation
  directly. Never materialize a native container for internal observation.
- Use a guarded public wrapper and a guard-free internal status ABI. Borrow
  existing frame arguments; pass `out == NULL` for unused results.
- Guard exact types and pinned type versions once at graph entry. On mismatch,
  deopt before mutation; after mutation continue from a safe point and never
  restart the operation.
- Cache only module-owned unbound descriptors, interned names, constants,
  types, and call targets. Include every cache in traverse, clear, and free.
- Use `PyObject_GetAttr`/`PyObject_SetAttr` with interned names and
  `PyObject_VectorcallMethod` to avoid bound-method objects.
- Under an exact type/version proof, borrow generated object fields and invoke
  cached descriptors directly. Retain dynamic Python fallback.
- Use indexed access for exact list/tuple iteration and unpacking; preserve the
  iterator fallback for other objects.
- Unbox heap keys only with an explicit `key_type` contract and runtime storage
  guards. Unknown key or external-call return types remain boxed.
- Put external result proofs on call edges with `call_returns`. Use native call
  ABIs only for explicit `pinned_semantics`; keep all other calls checked and
  boxed, and reject unmatched contracts.
- Inline only measured leaf/internal ABI paths. Do not force all expression
  helpers inline; code growth has regressed performance.
- Pause compiler allocation accounting around selectors, callbacks, logging,
  and other external Python execution.
- A direct hot graph must not reference the boxed executor, expression-hook
  dispatch, bound-method binding, or `aot_pyobject` edges.
- Build the compiler and production extension, run a short paired preflight,
  and check `git diff --check`. Run the 15-triple acceptance suite only when
  the short run makes the required `1.20x` one-sided bound plausible.
