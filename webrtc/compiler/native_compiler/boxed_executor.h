#ifndef WRTC_BOXED_EXECUTOR_H
#define WRTC_BOXED_EXECUTOR_H

#include <Python.h>

#include "statement_ir.h"

typedef struct {
    const char *name;
    WrtcPyParameterKind kind;
    const char *default_expression;
    unsigned has_default : 1;
} WrtcBoxedParameterSpec;

typedef struct {
    const char *name;
    const WrtcBoxedParameterSpec *parameters;
    size_t parameter_count;
    PyObject **defaults;
} WrtcBoxedSignature;

typedef PyObject *(*WrtcBoxedNativeEvaluate)(
    void *context, const WrtcPyExprIR *expression, void *frame,
    int *handled);
typedef int (*WrtcBoxedNativeAssign)(
    void *context, const WrtcPyExprIR *target, PyObject *value,
    void *frame, int *handled);
typedef struct {
    void *context;
    WrtcBoxedNativeEvaluate evaluate;
    WrtcBoxedNativeAssign assign;
} WrtcBoxedNativeHooks;

typedef enum {
    WRTC_NATIVE_ALLOC_REGION_FRAME = 0,
    WRTC_NATIVE_ALLOC_LOCALS_DICTIONARY,
    WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE,
    WRTC_NATIVE_ALLOC_TEMPORARY_LIST,
    WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY,
    WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW,
    WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD,
    WRTC_NATIVE_ALLOC_BOXED_TEMPORARY,
    WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER,
    WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION,
    WRTC_NATIVE_ALLOC_SCHEDULER_CONTAINER_GROWTH,
    WRTC_NATIVE_ALLOC_NATIVE_MATERIALIZATION,
    WRTC_NATIVE_ALLOC_CATEGORY_COUNT
} WrtcNativeAllocationCategory;

/*
 * Execute a lowered native-region suite with ordinary CPython PyObject
 * operations.  globals and locals must be dictionaries containing the
 * resolved module symbols and already-bound function parameters.  On success
 * result receives a new reference (Py_None for fallthrough).
 */
int wrtc_boxed_execute(const WrtcPySuiteIR *suite, PyObject *globals,
                       PyObject *locals, PyObject **result);
int wrtc_boxed_execute_with_hooks(
    const WrtcPySuiteIR *suite, PyObject *globals, PyObject *locals,
    const WrtcBoxedNativeHooks *hooks, PyObject **result);
PyObject *wrtc_boxed_hook_evaluate(
    const WrtcPyExprIR *expression, void *frame);
PyObject *wrtc_boxed_hook_local(const char *name, void *frame);
int wrtc_boxed_signature_initialize(WrtcBoxedSignature *signature,
                                    PyObject *globals);
void wrtc_boxed_signature_clear(WrtcBoxedSignature *signature);
int wrtc_boxed_bind(const WrtcBoxedSignature *signature, PyObject *args,
                    PyObject *kwargs, PyObject **locals);
int wrtc_boxed_bind_method(const WrtcBoxedSignature *signature, PyObject *self,
                           PyObject *const *args, Py_ssize_t nargs,
                           PyObject *keyword_names, PyObject **locals);
int wrtc_boxed_suite_initialize(WrtcPySuiteIR *suite, PyObject *globals);
void wrtc_boxed_suite_clear(WrtcPySuiteIR *suite);
void wrtc_native_allocation_region_enter(const char *name);
void wrtc_native_allocation_region_leave(void);
void wrtc_native_allocation_pause(void);
void wrtc_native_allocation_resume(void);
void wrtc_native_allocation_alloc(WrtcNativeAllocationCategory category);
void wrtc_native_allocation_free(WrtcNativeAllocationCategory category);
void wrtc_native_allocation_release_locals(PyObject *locals);
PyObject *wrtc_native_allocation_counters(PyObject *self, PyObject *unused);
PyObject *wrtc_native_reset_allocation_counters(PyObject *self,
                                                PyObject *unused);

#endif
