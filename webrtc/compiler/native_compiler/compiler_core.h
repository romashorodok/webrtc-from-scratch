#ifndef WRTC_COMPILER_CORE_H
#define WRTC_COMPILER_CORE_H

#include <Python.h>
#include <stddef.h>

typedef struct {
    int line;
    int column;
    int end_line;
    int end_column;
} WrtcSourceSpan;

typedef enum {
    WRTC_TYPE_UNKNOWN = 0,
    WRTC_TYPE_NONE,
    WRTC_TYPE_BOOL,
    WRTC_TYPE_INT,
    WRTC_TYPE_STR,
    WRTC_TYPE_BYTES,
    WRTC_TYPE_BYTE_VECTOR,
    WRTC_TYPE_BUFFER,
    WRTC_TYPE_RECORD,
    WRTC_TYPE_TUPLE,
    WRTC_TYPE_LIST,
    WRTC_TYPE_OBJECT
} WrtcTypeKind;

typedef struct {
    char *name;
    WrtcSourceSpan span;
    WrtcTypeKind type;
    unsigned is_public : 1;
    unsigned is_reachable : 1;
    unsigned owns_result : 1;
    size_t call_count;
    size_t block_count;
    size_t exception_edge_count;
} WrtcFunctionIR;

typedef struct {
    char *name;
    WrtcSourceSpan span;
    WrtcTypeKind type;
    unsigned has_default : 1;
} WrtcRecordFieldIR;

typedef struct {
    char *name;
    WrtcSourceSpan span;
    size_t field_count;
    WrtcRecordFieldIR *fields;
    size_t property_count;
} WrtcRecordIR;

typedef struct WrtcCompilerCore {
    char *filename;
    char *lowered_source;
    PyObject *tree;
    PyObject *exports;
    PyObject *constant_names;
    PyObject *constant_values;
    WrtcFunctionIR *functions;
    size_t function_count;
    WrtcRecordIR *records;
    size_t record_count;
} WrtcCompilerCore;

/* Parse and validate without executing source or metadata declarations. */
int wrtc_compiler_core_analyze(const char *source, size_t source_length,
                               const char *filename, WrtcCompilerCore **out);
void wrtc_compiler_core_free(WrtcCompilerCore *core);
const WrtcFunctionIR *wrtc_compiler_core_find_function(
    const WrtcCompilerCore *core, const char *name);

#endif
