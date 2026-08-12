#ifndef WRTC_NATIVE_WORKER_ABI_H
#define WRTC_NATIVE_WORKER_ABI_H

#include <stddef.h>
#include <stdint.h>

/* Pure C ABI shared by generated kernels and the reactor-side CPython bridge. */
typedef enum {
    WRTC_WORKER_ABI_UINT = 1,
    WRTC_WORKER_ABI_SINT,
    WRTC_WORKER_ABI_FLOAT,
    WRTC_WORKER_ABI_READONLY_BYTES
} WrtcNativeWorkerAbiKind;

typedef struct {
    const char *name;
    WrtcNativeWorkerAbiKind kind;
    unsigned width;
} WrtcNativeWorkerAbiField;

typedef struct {
    const char *abi;
    const WrtcNativeWorkerAbiField *fields;
    size_t field_count;
} WrtcNativeWorkerAbi;

typedef struct {
    WrtcNativeWorkerAbiKind kind;
    union {
        uint64_t uint_value;
        int64_t sint_value;
        double float_value;
        struct {
            const unsigned char *data;
            size_t size;
            /* Opaque on worker threads; owned and released by the reactor. */
            void *reactor_owner;
        } bytes_value;
    } as;
} WrtcNativeWorkerValue;

typedef struct {
    const WrtcNativeWorkerAbi *abi;
    WrtcNativeWorkerValue *values;
    size_t value_count;
} WrtcNativeWorkerRecord;

#endif
