#ifndef WRTC_NATIVE_WORKER_CODEGEN_H
#define WRTC_NATIVE_WORKER_CODEGEN_H

#include <stdio.h>

/* Emit the proven worker ABI/record/executor runtime into one extension TU. */
int wrtc_native_worker_emit_runtime(FILE *file);
int wrtc_native_worker_emit_cpython_adapter(FILE *file);

#endif
