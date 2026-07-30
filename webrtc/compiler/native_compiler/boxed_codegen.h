#ifndef WRTC_BOXED_CODEGEN_H
#define WRTC_BOXED_CODEGEN_H

#include <stdio.h>

#include "statement_ir.h"

/*
 * Emit the artifact-local boxed runtime and recursively serialized IR tables.
 * The runtime must be emitted once per generated translation unit, before any
 * suite.  symbol must be a valid C identifier and becomes a static
 * WrtcPySuiteIR object addressable by generated method wrappers.
 */
int wrtc_boxed_emit_runtime(FILE *output);
int wrtc_boxed_emit_suite(FILE *output, const char *symbol,
                          const WrtcPySuiteIR *suite);
int wrtc_boxed_emit_signature(FILE *output, const char *symbol,
                              const WrtcPySignatureIR *signature);
int wrtc_boxed_emit_module_globals(FILE *output, const char *symbol,
                                   const char *module_name);

#endif
