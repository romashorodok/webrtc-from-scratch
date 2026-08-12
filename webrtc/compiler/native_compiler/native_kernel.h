#ifndef WRTC_NATIVE_KERNEL_H
#define WRTC_NATIVE_KERNEL_H

#include <stdio.h>

#include "native_class.h"

/*
 * Portable, Python-independent kernel lowering.  The accepted scalar domain
 * is bool and unsigned 8/16/32/64-bit integers.  Arithmetic is checked unless
 * an Annotated representation contains the ``wrap`` descriptor.  Generated
 * functions return a status value; no Python object, exception, allocation,
 * import, or callback is reachable from the emitted translation unit.
 */
typedef enum {
    WRTC_NATIVE_KERNEL_OK = 0,
    WRTC_NATIVE_KERNEL_OVERFLOW,
    WRTC_NATIVE_KERNEL_DIVISION_BY_ZERO,
    WRTC_NATIVE_KERNEL_INVALID_ARGUMENT,
    WRTC_NATIVE_KERNEL_UNSUPPORTED
} WrtcNativeKernelStatus;

void wrtc_native_kernel_prove(WrtcNativeClassProgram *program);

/* Emit all completely proven scalar kernels as one freestanding C17 unit. */
int wrtc_native_kernel_emit(FILE *file,
                            const WrtcNativeClassProgram *program,
                            const char *symbol_prefix);

#endif
