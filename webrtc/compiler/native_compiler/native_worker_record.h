#ifndef WRTC_NATIVE_WORKER_RECORD_H
#define WRTC_NATIVE_WORKER_RECORD_H

#include <Python.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The reactor packs and releases these records while it may use the Python
 * C API.  A native worker only reads scalar/buffer values and moves the
 * record.  The retained immutable-bytes owner is opaque to worker code.
 */
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
            PyObject *reactor_owner;
        } bytes_value;
    } as;
} WrtcNativeWorkerValue;

typedef struct {
    const WrtcNativeWorkerAbi *abi;
    WrtcNativeWorkerValue *values;
    size_t value_count;
} WrtcNativeWorkerRecord;

int wrtc_native_worker_record_pack(
    PyObject *value, PyTypeObject *exact_type,
    const WrtcNativeWorkerAbi *abi, WrtcNativeWorkerRecord *out);
PyObject *wrtc_native_worker_record_materialize(
    const WrtcNativeWorkerRecord *record, PyTypeObject *exact_type);
void wrtc_native_worker_record_move(
    WrtcNativeWorkerRecord *destination,
    WrtcNativeWorkerRecord *source);
void wrtc_native_worker_record_release(WrtcNativeWorkerRecord *record);

#endif
