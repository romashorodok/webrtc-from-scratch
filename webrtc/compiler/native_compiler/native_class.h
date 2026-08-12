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
    WRTC_NATIVE_FIELD_SPSC,
    WRTC_NATIVE_FIELD_SELECTOR,
    WRTC_NATIVE_FIELD_PACKET_POOL
} WrtcNativeStorageKind;

typedef enum {
    WRTC_REACTOR_HOOK_NONE = 0,
    WRTC_REACTOR_HOOK_SELECTOR_REMOVE_READER,
    WRTC_REACTOR_HOOK_SELECTOR_REMOVE_WRITER,
    WRTC_REACTOR_HOOK_DATAGRAM_GENERATION_CHECK,
    WRTC_REACTOR_HOOK_DATAGRAM_DELIVERY,
    WRTC_REACTOR_HOOK_RESCHEDULE
} WrtcReactorHookKind;

typedef struct {
    char *target;
    WrtcSourceSpan span;
    size_t target_class;
    size_t target_region;
    size_t positional_count;
    size_t keyword_count;
    unsigned resolved : 1;
    unsigned required_callee : 1;
    unsigned exact_receiver : 1;
    unsigned fused : 1;
    WrtcReactorHookKind reactor_hook;
    unsigned reactor_hook_shape_proven : 1;
    unsigned attribute_call : 1;
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
    char *reactor_capacity;
    char *packet_buffer_size;
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
    char *worker_rejection_reason;
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
    unsigned descriptor_generation_validated : 1;
    unsigned selector_runtime_lowering_available : 1;
    unsigned datagram_runtime_lowering_available : 1;
    unsigned reactor_hook_emission_complete : 1;
    unsigned selector_remove_reader_hook : 1;
    unsigned selector_remove_writer_hook : 1;
    unsigned datagram_generation_hook : 1;
    unsigned datagram_delivery_hook : 1;
    unsigned bounded_reschedule_hook : 1;
    unsigned reactor_thread_serialized : 1;
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
    unsigned worker_record_abi_proven : 1;
    unsigned worker_reachability_proven : 1;
    unsigned worker_emission_complete : 1;
    unsigned worker_executor_emission_complete : 1;
    unsigned worker_bounded_channels_proven : 1;
    unsigned worker_typed_error_proven : 1;
    unsigned worker_shutdown_proven : 1;
    unsigned worker_thread_python_api_free : 1;
    unsigned kernel_emission_complete : 1;
    unsigned kernel_python_free : 1;
    unsigned direct_callee_resolved : 1;
    unsigned direct_callee_fused : 1;
    size_t kernel_statement_count;
    size_t kernel_emitted_statement_count;
    size_t kernel_call_count;
    size_t kernel_emitted_call_count;
    char *kernel_rejection_reason;
    WrtcSourceSpan kernel_rejection_span;
    char *reactor_hook_rejection_reason;
    WrtcSourceSpan reactor_hook_rejection_span;
} WrtcNativeRegionIR;

typedef struct {
    char *name;
    char *filename;
    char *target_class;
    WrtcSourceSpan span;
    WrtcPySuiteIR *body;
    WrtcPySignatureIR *signature;
} WrtcNativeFactoryIR;

typedef enum {
    WRTC_WORKER_FIELD_UNSUPPORTED = 0,
    WRTC_WORKER_FIELD_UINT,
    WRTC_WORKER_FIELD_SINT,
    WRTC_WORKER_FIELD_FLOAT,
    WRTC_WORKER_FIELD_READONLY_BUFFER
} WrtcWorkerRecordFieldKind;

typedef struct {
    char *name;
    char *declared_type;
    WrtcSourceSpan span;
    WrtcWorkerRecordFieldKind kind;
    unsigned width;
    unsigned noescape : 1;
    unsigned immutable : 1;
} WrtcWorkerRecordFieldIR;

typedef struct {
    char *name;
    char *abi;
    char *filename;
    WrtcSourceSpan span;
    WrtcWorkerRecordFieldIR *fields;
    size_t field_count;
    size_t boxed_field_count;
    unsigned abi_declared : 1;
    unsigned representation_proven : 1;
    unsigned boxed_ownership_proven : 1;
    unsigned exact_runtime_type_guard : 1;
    unsigned worker_abi_eligible : 1;
} WrtcTypedRecordIR;

typedef struct {
    char *name;
    char *base;
    char *filename;
    WrtcSourceSpan span;
    WrtcPySuiteIR *constructor_body;
    WrtcPySignatureIR *constructor_signature;
    char *constructor_rejection_reason;
    WrtcSourceSpan constructor_rejection_span;
    WrtcNativeFieldIR *fields;
    size_t field_count;
    WrtcNativeRegionIR *regions;
    size_t region_count;
    unsigned compact_object : 1;
    unsigned gc_tracked : 1;
    unsigned weakrefs : 1;
    unsigned custom_constructor : 1;
    unsigned custom_new : 1;
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
