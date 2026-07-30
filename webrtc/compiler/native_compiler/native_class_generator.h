#ifndef WRTC_NATIVE_CLASS_GENERATOR_H
#define WRTC_NATIVE_CLASS_GENERATOR_H

#include <stdio.h>

#include "native_class.h"

/*
 * Eligibility is deliberately narrower than analysis.  A class is emitted
 * only when every part of its representation has a complete generic lowering.
 */
int wrtc_native_class_can_emit(const WrtcNativeClassProgram *program);

int wrtc_emit_native_class_extension(
    FILE *file, const char *module, const WrtcNativeClassProgram *program,
    const char *source_hash, const char *semantic_hash, const char *revision,
    const char *target, const char *architecture,
    const char *extension_suffix, PyObject *artifact_metadata);

#endif
