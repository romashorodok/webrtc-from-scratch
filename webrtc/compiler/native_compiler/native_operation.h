#ifndef WRTC_NATIVE_OPERATION_H
#define WRTC_NATIVE_OPERATION_H

#include <stddef.h>

#include "native_class.h"

/*
 * Storage operations are semantic sites, not emitted C.  A backend may consume
 * a complete table in evaluation_order, but must reject an incomplete field.
 */
typedef enum {
    WRTC_NATIVE_OP_ALIAS_BIND = 0,
    WRTC_NATIVE_OP_SCALAR_READ,
    WRTC_NATIVE_OP_SCALAR_WRITE,
    WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE,
    WRTC_NATIVE_OP_LENGTH,
    WRTC_NATIVE_OP_TRUTH,
    WRTC_NATIVE_OP_ROOT_READ,
    WRTC_NATIVE_OP_ITERATE,
    WRTC_NATIVE_OP_SLICE_ASSIGN,
    WRTC_NATIVE_OP_FIFO_APPEND,
    WRTC_NATIVE_OP_FIFO_POPLEFT,
    WRTC_NATIVE_OP_HEAPIFY,
    WRTC_NATIVE_OP_HEAP_PUSH,
    WRTC_NATIVE_OP_HEAP_POP,
    WRTC_NATIVE_OP_ATOMIC_LOAD,
    WRTC_NATIVE_OP_ATOMIC_STORE,
    WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE,
    WRTC_NATIVE_OP_MPSC_PUT_NOWAIT,
    WRTC_NATIVE_OP_MPSC_GET_NOWAIT,
    WRTC_NATIVE_OP_MPSC_QSIZE,
    WRTC_NATIVE_OP_MPSC_EMPTY,
    WRTC_NATIVE_OP_MPSC_CLOSE,
    WRTC_NATIVE_OP_SPSC_PUT_NOWAIT,
    WRTC_NATIVE_OP_SPSC_GET_NOWAIT,
    WRTC_NATIVE_OP_SPSC_QSIZE,
    WRTC_NATIVE_OP_SPSC_EMPTY,
    WRTC_NATIVE_OP_SPSC_CLOSE,
    WRTC_NATIVE_OP_BOXED_WRITE,
    WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE
} WrtcNativeOperationKind;

typedef struct {
    WrtcNativeOperationKind kind;
    WrtcSourceSpan span;
    size_t evaluation_order;
    size_t region_class_index;
    size_t region_index;
    size_t field_proof_index;
    char *alias_name;
    char *detail;
} WrtcNativeOperationIR;

typedef struct {
    size_t class_index;
    size_t field_index;
    size_t first_operation;
    size_t operation_count;
    unsigned touched : 1;
    unsigned complete : 1;
} WrtcNativeFieldOperationProof;

typedef struct {
    WrtcNativeFieldOperationProof *fields;
    size_t field_count;
    WrtcNativeOperationIR *operations;
    size_t operation_count;
    unsigned complete : 1;
} WrtcNativeOperationTable;

/*
 * Resolve native-field operations in required regions.  A zero result means
 * analysis completed; consult complete and each field's complete bit before
 * lowering.  Unsupported exposure is retained as a source-correlated table
 * entry instead of being silently ignored.
 */
int wrtc_native_operation_prove(const WrtcNativeClassProgram *program,
                                WrtcNativeOperationTable **out);
const char *wrtc_native_operation_kind_name(WrtcNativeOperationKind kind);
void wrtc_native_operation_table_free(WrtcNativeOperationTable *table);

#endif
