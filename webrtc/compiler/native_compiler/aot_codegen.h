#ifndef WRTC_AOT_CODEGEN_H
#define WRTC_AOT_CODEGEN_H

#include <stdio.h>

#include "native_class.h"
#include "native_operation.h"

int wrtc_aot_region_supported(const WrtcNativeRegionIR *region);
int wrtc_aot_region_direct_supported(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations, size_t class_index,
    size_t region_index);
int wrtc_aot_program_has_regions(const WrtcNativeClassProgram *program);
int wrtc_aot_program_complete(const WrtcNativeClassProgram *program);
int wrtc_aot_program_direct_complete(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations);
int wrtc_aot_emit_runtime(FILE *file);
int wrtc_aot_emit_region(FILE *file, size_t class_index, size_t region_index,
                         const WrtcNativeRegionIR *region,
                         const WrtcNativeClassProgram *program,
                         const WrtcNativeOperationTable *operations,
                         const char *globals_symbol, int has_hooks);

#endif
