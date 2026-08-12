#ifndef WRTC_STATEMENT_IR_H
#define WRTC_STATEMENT_IR_H

#include <Python.h>
#include <stddef.h>

#include "compiler_core.h"

/*
 * Generic boxed-Python IR.  The IR records evaluation structure and source
 * order without selecting an unboxed representation or a backend operation.
 * Every expression therefore denotes an ordinary PyObject-producing Python
 * operation until a later proof-backed lowering says otherwise.
 */
typedef enum {
    WRTC_PY_EXPR_NAME = 0,
    WRTC_PY_EXPR_ATTRIBUTE,
    WRTC_PY_EXPR_CONSTANT,
    WRTC_PY_EXPR_CALL,
    WRTC_PY_EXPR_BINARY,
    WRTC_PY_EXPR_UNARY,
    WRTC_PY_EXPR_BOOLEAN,
    WRTC_PY_EXPR_COMPARE,
    WRTC_PY_EXPR_TUPLE,
    WRTC_PY_EXPR_LIST,
    WRTC_PY_EXPR_DICT,
    WRTC_PY_EXPR_JOINED_STRING,
    WRTC_PY_EXPR_FORMATTED_VALUE,
    WRTC_PY_EXPR_LAMBDA,
    WRTC_PY_EXPR_SUBSCRIPT,
    WRTC_PY_EXPR_SLICE
} WrtcPyExprKind;

typedef struct WrtcPyExprIR {
    WrtcPyExprKind kind;
    WrtcSourceSpan span;
    char *text;
    char *operation;
    char **operations;
    size_t operation_count;
    char **keyword_names;
    struct WrtcPyExprIR *children;
    size_t child_count;
    size_t positional_count;
    size_t keyword_count;
} WrtcPyExprIR;

typedef enum {
    WRTC_PY_STMT_EXPR = 0,
    WRTC_PY_STMT_ASSIGN,
    WRTC_PY_STMT_AUGMENTED_ASSIGN,
    WRTC_PY_STMT_IF,
    WRTC_PY_STMT_WHILE,
    WRTC_PY_STMT_FOR,
    WRTC_PY_STMT_TRY,
    WRTC_PY_STMT_TRY_FINALLY,
    WRTC_PY_STMT_EXCEPT_HANDLER,
    WRTC_PY_STMT_RETURN,
    WRTC_PY_STMT_RAISE,
    WRTC_PY_STMT_BREAK,
    WRTC_PY_STMT_CONTINUE,
    WRTC_PY_STMT_PASS
} WrtcPyStmtKind;

typedef struct WrtcPyStmtIR {
    WrtcPyStmtKind kind;
    WrtcSourceSpan span;
    char *operation;
    WrtcPyExprIR *expressions;
    size_t expression_count;
    struct WrtcPyStmtIR *body;
    size_t body_count;
    struct WrtcPyStmtIR *orelse;
    size_t orelse_count;
    struct WrtcPyStmtIR *finalbody;
    size_t finalbody_count;
    struct WrtcPyStmtIR *handlers;
    size_t handler_count;
    unsigned iterator_is_range : 1;
} WrtcPyStmtIR;

typedef struct {
    WrtcPyStmtIR *statements;
    size_t statement_count;
    char **local_names;
    size_t local_count;
} WrtcPySuiteIR;

typedef enum {
    WRTC_PY_PARAM_POSITIONAL_ONLY = 0,
    WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD,
    WRTC_PY_PARAM_VAR_POSITIONAL,
    WRTC_PY_PARAM_KEYWORD_ONLY,
    WRTC_PY_PARAM_VAR_KEYWORD
} WrtcPyParameterKind;

typedef struct {
    char *name;
    char *annotation;
    char *default_expression;
    WrtcSourceSpan span;
    WrtcPyParameterKind kind;
    unsigned has_default : 1;
} WrtcPyParameterIR;

typedef struct {
    char *name;
    WrtcPyParameterIR *parameters;
    size_t parameter_count;
} WrtcPySignatureIR;

int wrtc_py_ir_lower_suite(PyObject *statements, const char *filename,
                           WrtcPySuiteIR **out);
int wrtc_py_ir_lower_signature(PyObject *function, const char *filename,
                               WrtcPySignatureIR **out);
int wrtc_py_suite_validate_lambdas(const WrtcPySuiteIR *suite,
                                   const WrtcPySignatureIR *signature,
                                   const char *filename);
void wrtc_py_expr_ir_clear(WrtcPyExprIR *expression);
void wrtc_py_stmt_ir_clear(WrtcPyStmtIR *statement);
void wrtc_py_suite_ir_free(WrtcPySuiteIR *suite);
void wrtc_py_signature_ir_free(WrtcPySignatureIR *signature);

#endif
