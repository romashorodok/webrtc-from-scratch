#include "native_storage_codegen.h"

#include <string.h>

#include "native_storage_source.h"

int wrtc_native_storage_emit_runtime(FILE *output) {
    static const char marker[] = "static int missing(const char *name)";
    static const char declarations[] =
        "#include <stdint.h>\n#include <stddef.h>\n#include <stdatomic.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "typedef enum{WRTC_TYPE_UNKNOWN=0,WRTC_TYPE_NONE,WRTC_TYPE_BOOL,"
        "WRTC_TYPE_INT}WrtcTypeKind;"
        "typedef enum{WRTC_NATIVE_FIELD_PYOBJECT=0,"
        "WRTC_NATIVE_FIELD_SCALAR,WRTC_NATIVE_FIELD_FIFO,"
        "WRTC_NATIVE_FIELD_MIN_HEAP,WRTC_NATIVE_FIELD_ATOMIC_UINT32,"
        "WRTC_NATIVE_FIELD_MPSC,WRTC_NATIVE_FIELD_SPSC,"
        "WRTC_NATIVE_FIELD_SELECTOR,WRTC_NATIVE_FIELD_PACKET_POOL}"
        "WrtcNativeStorageKind;"
        "typedef enum{WRTC_QUEUE_NONE=0,WRTC_QUEUE_SPSC,WRTC_QUEUE_MPSC}"
        "WrtcQueueTopology;"
        "typedef struct{const char*declared_type,*owner,*heap_ordering;"
        "const char*queue_capacity,*queue_item_type,*reactor_capacity;"
        "const char*packet_buffer_size;"
        "const char*atomic_memory_order,*atomic_scope,*atomic_linearization;"
        "unsigned atomic_width;unsigned atomic;unsigned typed_queue_payload;"
        "WrtcQueueTopology queue_topology;"
        "WrtcTypeKind type;WrtcNativeStorageKind storage_kind;}"
        "WrtcNativeFieldIR;"
        "typedef enum{WRTC_STORAGE_EMPTY=0,WRTC_STORAGE_NATIVE,"
        "WRTC_STORAGE_BOXED}WrtcStorageMode;"
        "typedef enum{WRTC_SCALAR_NONE=0,WRTC_SCALAR_INT64,"
        "WRTC_SCALAR_DOUBLE,WRTC_SCALAR_BOOL,WRTC_SCALAR_BOXED}"
        "WrtcScalarTag;"
        "typedef struct{WrtcScalarTag tag;union{int64_t integer;"
        "double floating;int boolean;PyObject*boxed;}value;}"
        "WrtcNativeScalar;"
        "typedef struct{WrtcStorageMode mode;PyObject*boxed;PyObject**items;"
        "size_t capacity,head,size;}WrtcNativeFifo;"
        "typedef struct{WrtcStorageMode mode;PyObject*boxed;PyObject**items;"
        "size_t capacity,size;}WrtcNativeMinHeap;\n"
        "typedef struct{_Atomic uint_least32_t value;int initialized;}"
        "WrtcNativeAtomicUint32;"
        "typedef struct{_Atomic size_t sequence;_Atomic(void*)item;}"
        "WrtcNativeMpscCell;"
        "typedef struct{WrtcNativeMpscCell*cells;size_t capacity;"
        "_Atomic size_t enqueue_position;_Atomic size_t dequeue_position;"
        "_Atomic size_t producer_admission;"
        "_Atomic unsigned notified;}WrtcNativeMpsc;"
        "typedef struct{WrtcNativeMpsc*queue;WrtcNativeMpscCell*cell;"
        "size_t position;unsigned active;}WrtcNativeMpscTicket;"
        "typedef enum{WRTC_MPSC_OK=0,WRTC_MPSC_EMPTY,WRTC_MPSC_FULL,"
        "WRTC_MPSC_CLOSED}WrtcNativeMpscStatus;"
        "typedef void(*WrtcNativeMpscRelease)(void*,void*);\n"
        "typedef struct{_Atomic(void*)*items;size_t capacity;"
        "_Atomic size_t producer_position;_Atomic size_t consumer_position;"
        "_Atomic size_t producer_admission;}WrtcNativeSpsc;"
        "typedef enum{WRTC_SPSC_OK=0,WRTC_SPSC_EMPTY,WRTC_SPSC_FULL,"
        "WRTC_SPSC_CLOSED}WrtcNativeSpscStatus;"
        "typedef void(*WrtcNativeSpscRelease)(void*,void*);\n";
    const char *source = (const char *)wrtc_native_storage_source;
    const char *implementation = strstr(source, marker);
    size_t length;
    if (output == NULL || implementation == NULL ||
        fputs(declarations, output) < 0)
        return -1;
    length = strlen(implementation);
    return fwrite(implementation, 1u, length, output) == length ? 0 : -1;
}
