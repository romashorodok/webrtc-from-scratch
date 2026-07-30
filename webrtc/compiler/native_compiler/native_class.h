#ifndef WRTC_NATIVE_CLASS_H
#define WRTC_NATIVE_CLASS_H

#include <Python.h>
#include <stddef.h>

#include "compiler_core.h"
#include "statement_ir.h"

typedef enum {
    WRTC_REGION_UNSPECIFIED = 0,
    WRTC_REGION_PREFERRED,
    WRTC_REGION_REQUIRED
} WrtcRegionPolicy;

enum {
    WRTC_REGION_READ = 1u << 0,
    WRTC_REGION_WRITE = 1u << 1,
    WRTC_REGION_ALLOCATE = 1u << 2,
    WRTC_REGION_RAISE = 1u << 3,
    WRTC_REGION_FIFO = 1u << 4,
    WRTC_REGION_MIN_HEAP = 1u << 5,
    WRTC_REGION_CALL = 1u << 6,
    WRTC_REGION_SELECTOR_POLL = 1u << 7,
    WRTC_REGION_SELECTOR_DISPATCH = 1u << 8,
    WRTC_REGION_SOCKET_RECEIVE = 1u << 9,
    WRTC_REGION_RECEIVE_INTO = 1u << 10,
    WRTC_REGION_BOUNDED_LOOP = 1u << 11,
    WRTC_REGION_PACKET_BUDGET = 1u << 12,
    WRTC_REGION_TIME_BUDGET = 1u << 13,
    WRTC_REGION_PACKET_POOL = 1u << 14,
    WRTC_REGION_DELIVERY = 1u << 15,
    WRTC_REGION_RESCHEDULE = 1u << 16,
    WRTC_REGION_NOESCAPE = 1u << 17,
    WRTC_REGION_NO_ALLOCATE = 1u << 18,
    WRTC_REGION_NO_SUSPEND = 1u << 19,
    WRTC_REGION_SELECTOR_EVENT_MASK = 1u << 20,
    WRTC_REGION_SELECTOR_KEY_DATA = 1u << 21,
    WRTC_REGION_ATOMIC = 1u << 22,
    WRTC_REGION_COMPARE_EXCHANGE = 1u << 23,
    WRTC_REGION_SPSC = 1u << 24,
    WRTC_REGION_MPSC = 1u << 25,
    WRTC_REGION_BOUNDED_QUEUE = 1u << 26,
    WRTC_REGION_COALESCED_NOTIFICATION = 1u << 27,
    WRTC_REGION_OWNED_SHARD = 1u << 28,
    WRTC_REGION_TYPED_RECORD = 1u << 29,
    WRTC_REGION_SHUTDOWN = 1u << 30,
    WRTC_REGION_HANDLE_RUN = 1u << 31
};

typedef enum {
    WRTC_QUEUE_NONE = 0,
    WRTC_QUEUE_SPSC,
    WRTC_QUEUE_MPSC
} WrtcQueueTopology;

typedef enum {
    WRTC_NATIVE_FIELD_PYOBJECT = 0,
    WRTC_NATIVE_FIELD_SCALAR,
    WRTC_NATIVE_FIELD_FIFO,
    WRTC_NATIVE_FIELD_MIN_HEAP,
    WRTC_NATIVE_FIELD_ATOMIC_UINT32,
    WRTC_NATIVE_FIELD_MPSC,
    WRTC_NATIVE_FIELD_SPSC
} WrtcNativeStorageKind;

typedef struct {
    char *target;
    WrtcSourceSpan span;
    size_t target_class;
    size_t target_region;
    unsigned resolved : 1;
    unsigned required_callee : 1;
    unsigned exact_receiver : 1;
    unsigned fused : 1;
} WrtcNativeCallEdgeIR;

typedef struct {
    char *name;
    WrtcSourceSpan span;
    WrtcTypeKind type;
    char *declared_type;
    char *owner;
    char *heap_key;
    char *heap_ordering;
    char *queue_capacity;
    char *queue_item_type;
    char *atomic_memory_order;
    char *atomic_scope;
    char *atomic_linearization;
    unsigned atomic_width;
    WrtcQueueTopology queue_topology;
    WrtcNativeStorageKind storage_kind;
    unsigned native_storage : 1;
    unsigned atomic : 1;
    unsigned coalesced_notification : 1;
    unsigned typed_queue_payload : 1;
    unsigned payload_representation_proven : 1;
    unsigned producer_admission_proven : 1;
    unsigned producer_quiescence_proven : 1;
    unsigned reactor_dequeue_proven : 1;
    unsigned close_drain_order_proven : 1;
    unsigned notification_rearm_proven : 1;
    unsigned lifecycle_shutdown_proven : 1;
    unsigned mpsc_memory_ordering_proven : 1;
    unsigned reactor_reclamation_proven : 1;
    unsigned spsc_producer_proven : 1;
    unsigned spsc_consumer_proven : 1;
    unsigned spsc_close_drain_proven : 1;
    unsigned spsc_memory_ordering_proven : 1;
    unsigned spsc_reclamation_proven : 1;
    unsigned exact_type : 1;
} WrtcNativeFieldIR;

typedef struct {
    char *name;
    WrtcSourceSpan span;
    char *owner;
    char *shard_key;
    char *shard_workers;
    char *result_type;
    char *direct_call_target;
    WrtcPySuiteIR *body;
    WrtcPySignatureIR *signature;
    WrtcNativeCallEdgeIR *calls;
    WrtcRegionPolicy policy;
    unsigned capabilities;
    size_t call_count;
    size_t loop_count;
    size_t bounded_loop_count;
    unsigned fusion_requested : 1;
    unsigned selector_shape_validated : 1;
    unsigned packet_order_preserved : 1;
    unsigned pool_lifetime_checked : 1;
    unsigned bounded_interleaving : 1;
    unsigned shard_ordered : 1;
    unsigned atomic_linearization_proven : 1;
    unsigned queue_linearization_proven : 1;
    unsigned producer_admission_proven : 1;
    unsigned producer_quiescence_proven : 1;
    unsigned reactor_dequeue_proven : 1;
    unsigned close_drain_order_proven : 1;
    unsigned memory_ordering_proven : 1;
    unsigned ownership_transfer_proven : 1;
    unsigned reclamation_proven : 1;
    unsigned full_queue_behavior_proven : 1;
    unsigned wakeup_coalescing_proven : 1;
    unsigned shutdown_interaction_proven : 1;
    unsigned worker_python_free : 1;
    unsigned typed_worker_records : 1;
    unsigned direct_callee_resolved : 1;
    unsigned direct_callee_fused : 1;
} WrtcNativeRegionIR;

typedef struct {
    char *name;
    char *filename;
    char *target_class;
    WrtcSourceSpan span;
    WrtcPySuiteIR *body;
    WrtcPySignatureIR *signature;
} WrtcNativeFactoryIR;

typedef struct {
    char *name;
    char *filename;
    WrtcSourceSpan span;
    size_t field_count;
    size_t boxed_field_count;
    unsigned abi_declared : 1;
    unsigned representation_proven : 1;
    unsigned boxed_ownership_proven : 1;
    unsigned exact_runtime_type_guard : 1;
} WrtcTypedRecordIR;

typedef struct {
    char *name;
    char *base;
    char *filename;
    WrtcSourceSpan span;
    WrtcNativeFieldIR *fields;
    size_t field_count;
    WrtcNativeRegionIR *regions;
    size_t region_count;
    unsigned compact_object : 1;
    unsigned gc_tracked : 1;
    unsigned weakrefs : 1;
    unsigned custom_constructor : 1;
} WrtcNativeClassIR;

typedef struct {
    char *factory_name;
    WrtcNativeFactoryIR *factories;
    size_t factory_count;
    WrtcNativeClassIR *classes;
    size_t class_count;
    WrtcTypedRecordIR *records;
    size_t record_count;
} WrtcNativeClassProgram;

/*
 * Build source-correlated capability IR from ordinary Python syntax and
 * immutable PyMeta declarations.  Returns zero for both empty and populated
 * programs; metadata errors are diagnosed with source spans.
 */
int wrtc_native_class_analyze(const char *source, size_t source_length,
                              const char *filename,
                              WrtcNativeClassProgram **out);
int wrtc_native_class_merge(WrtcNativeClassProgram *destination,
                            WrtcNativeClassProgram *source);
void wrtc_native_class_resolve_calls(WrtcNativeClassProgram *program);
/*
 * Return a new-reference, source-correlated report.  Regions are reported as
 * rejected until a backend proves and emits their complete native lowering.
 */
PyObject *wrtc_native_class_capability_report(
    const WrtcNativeClassProgram *program, const char *filename);
void wrtc_native_class_free(WrtcNativeClassProgram *program);
int wrtc_native_class_requires_lowering(const WrtcNativeClassProgram *program);

#endif
