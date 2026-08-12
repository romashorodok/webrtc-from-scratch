#ifndef WRTC_NATIVE_WORKER_RECORD_H
#define WRTC_NATIVE_WORKER_RECORD_H

#include <Python.h>
#include "native_worker_abi.h"

/*
 * The reactor packs and releases these records while it may use the Python
 * C API.  A native worker only reads scalar/buffer values and moves the
 * record.  The retained immutable-bytes owner is opaque to worker code.
 */
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
