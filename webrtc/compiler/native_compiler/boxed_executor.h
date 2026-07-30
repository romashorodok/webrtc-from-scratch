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

#endif
