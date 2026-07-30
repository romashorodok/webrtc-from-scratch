#ifndef WRTC_GENERATOR_H
#define WRTC_GENERATOR_H

#include <stdio.h>

#include "lowering.h"

int wrtc_emit_extension(FILE *file, const char *module,
                        const WrtcLoweringProgram *program,
                        const char *source_hash, const char *semantic_hash,
                        const char *revision, const char *target,
                        const char *architecture, const char *extension_suffix,
                        PyObject *artifact_metadata);

#endif
