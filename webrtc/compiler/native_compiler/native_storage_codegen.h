#ifndef WRTC_NATIVE_STORAGE_CODEGEN_H
#define WRTC_NATIVE_STORAGE_CODEGEN_H

#include <stdio.h>

/* Emit a self-contained artifact-local copy of the storage runtime. */
int wrtc_native_storage_emit_runtime(FILE *output);

#endif
