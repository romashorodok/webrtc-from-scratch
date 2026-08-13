#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boxed_executor.h"

#define WRTC_ALLOCATION_REGION_LIMIT 256u
#define WRTC_ALLOCATION_REGION_DEPTH 64u

typedef struct {
    uint64_t allocations;
    uint64_t frees;
    uint64_t live;
    uint64_t peak_live;
} WrtcNativeAllocationValues;

typedef struct {
    const char *name;
    WrtcNativeAllocationValues values[WRTC_NATIVE_ALLOC_CATEGORY_COUNT];
} WrtcNativeAllocationRegion;

static WrtcNativeAllocationValues
    wrtc_native_allocation_totals[WRTC_NATIVE_ALLOC_CATEGORY_COUNT];
static WrtcNativeAllocationRegion
    wrtc_native_allocation_regions[WRTC_ALLOCATION_REGION_LIMIT];
static size_t wrtc_native_allocation_region_count;
static WrtcNativeAllocationRegion *
    wrtc_native_allocation_region_stack[WRTC_ALLOCATION_REGION_DEPTH];
static size_t wrtc_native_allocation_region_depth;
static unsigned wrtc_native_allocation_pause_depth;

static const char *const wrtc_native_allocation_category_names[] = {
    "region_frame", "locals_dictionary", "temporary_tuple",
    "temporary_list", "keyword_dictionary", "argument_vector_overflow",
    "attribute_name_or_bound_method", "boxed_temporary",
    "compiler_scratch_buffer", "fallback_deoptimization",
    "scheduler_container_growth", "native_materialization"
};

static void allocation_values_alloc(WrtcNativeAllocationValues *values) {
    values->allocations++;
    values->live++;
    if (values->live > values->peak_live) values->peak_live = values->live;
}

static void allocation_values_free(WrtcNativeAllocationValues *values) {
    values->frees++;
    if (values->live != 0u) values->live--;
}

void wrtc_native_allocation_alloc(WrtcNativeAllocationCategory category) {
    WrtcNativeAllocationRegion *region;
    if (wrtc_native_allocation_pause_depth != 0u || category < 0 ||
        category >= WRTC_NATIVE_ALLOC_CATEGORY_COUNT)
        return;
    allocation_values_alloc(&wrtc_native_allocation_totals[(size_t)category]);
    region = wrtc_native_allocation_region_depth == 0u
                 ? NULL
                 : wrtc_native_allocation_region_stack[
                       wrtc_native_allocation_region_depth - 1u];
    if (region != NULL)
        allocation_values_alloc(&region->values[(size_t)category]);
}

void wrtc_native_allocation_free(WrtcNativeAllocationCategory category) {
    WrtcNativeAllocationRegion *region;
    if (wrtc_native_allocation_pause_depth != 0u || category < 0 ||
        category >= WRTC_NATIVE_ALLOC_CATEGORY_COUNT)
        return;
    allocation_values_free(&wrtc_native_allocation_totals[(size_t)category]);
    region = wrtc_native_allocation_region_depth == 0u
                 ? NULL
                 : wrtc_native_allocation_region_stack[
                       wrtc_native_allocation_region_depth - 1u];
    if (region != NULL)
        allocation_values_free(&region->values[(size_t)category]);
}

void wrtc_native_allocation_region_enter(const char *name) {
    WrtcNativeAllocationRegion *region = NULL;
    size_t index;
    if (name == NULL) return;
    for (index = 0u; index < wrtc_native_allocation_region_count; index++)
        if (strcmp(wrtc_native_allocation_regions[index].name, name) == 0) {
            region = &wrtc_native_allocation_regions[index];
            break;
        }
    if (region == NULL &&
        wrtc_native_allocation_region_count < WRTC_ALLOCATION_REGION_LIMIT) {
        region = &wrtc_native_allocation_regions[
            wrtc_native_allocation_region_count++];
        region->name = name;
    }
    if (wrtc_native_allocation_region_depth < WRTC_ALLOCATION_REGION_DEPTH)
        wrtc_native_allocation_region_stack[
            wrtc_native_allocation_region_depth++] = region;
}

void wrtc_native_allocation_region_leave(void) {
    if (wrtc_native_allocation_region_depth != 0u)
        wrtc_native_allocation_region_depth--;
}

void wrtc_native_allocation_pause(void) {
    wrtc_native_allocation_pause_depth++;
}

void wrtc_native_allocation_resume(void) {
    if (wrtc_native_allocation_pause_depth != 0u)
        wrtc_native_allocation_pause_depth--;
}

static int allocation_dict_value(PyObject *result, const char *prefix,
                                 const char *category, const char *field,
                                 uint64_t value) {
    char key[512];
    PyObject *number;
    int written, status;
    written = snprintf(key, sizeof key, "%s%s%s.%s", prefix,
                       prefix[0] == '\0' ? "" : ".", category, field);
    if (written < 0 || (size_t)written >= sizeof key) {
        PyErr_SetString(PyExc_RuntimeError,
                        "native allocation counter key is too long");
        return -1;
    }
    number = PyLong_FromUnsignedLongLong((unsigned long long)value);
    if (number == NULL) return -1;
    status = PyDict_SetItemString(result, key, number);
    Py_DECREF(number);
    return status;
}

static int allocation_dict_values(PyObject *result, const char *prefix,
                                  size_t category,
                                  const WrtcNativeAllocationValues *values) {
    const char *name = wrtc_native_allocation_category_names[category];
    return allocation_dict_value(result, prefix, name, "allocations",
                                 values->allocations) < 0 ||
                   allocation_dict_value(result, prefix, name, "frees",
                                         values->frees) < 0 ||
                   allocation_dict_value(result, prefix, name, "live",
                                         values->live) < 0 ||
                   allocation_dict_value(result, prefix, name, "peak_live",
                                         values->peak_live) < 0
               ? -1 : 0;
}

PyObject *wrtc_native_allocation_counters(PyObject *self, PyObject *unused) {
    PyObject *result;
    size_t category, region;
    (void)self;
    (void)unused;
    wrtc_native_allocation_pause();
    result = PyDict_New();
    if (result == NULL) goto done;
    for (category = 0u; category < WRTC_NATIVE_ALLOC_CATEGORY_COUNT;
         category++)
        if (allocation_dict_values(result, "", category,
                                   &wrtc_native_allocation_totals[category]) < 0)
            goto error;
    for (region = 0u; region < wrtc_native_allocation_region_count; region++) {
        char prefix[384];
        int written = snprintf(prefix, sizeof prefix, "region.%s",
                               wrtc_native_allocation_regions[region].name);
        if (written < 0 || (size_t)written >= sizeof prefix) {
            PyErr_SetString(PyExc_RuntimeError,
                            "native allocation region name is too long");
            goto error;
        }
        for (category = 0u; category < WRTC_NATIVE_ALLOC_CATEGORY_COUNT;
             category++)
            if (allocation_dict_values(
                    result, prefix, category,
                    &wrtc_native_allocation_regions[region].values[category]) < 0)
                goto error;
    }
    goto done;
error:
    Py_CLEAR(result);
done:
    wrtc_native_allocation_resume();
    return result;
}

PyObject *wrtc_native_reset_allocation_counters(PyObject *self,
                                                PyObject *unused) {
    size_t category, region;
    (void)self;
    (void)unused;
    wrtc_native_allocation_pause();
    for (category = 0u; category < WRTC_NATIVE_ALLOC_CATEGORY_COUNT;
         category++) {
        WrtcNativeAllocationValues *values =
            &wrtc_native_allocation_totals[category];
        values->allocations = values->frees = 0u;
        values->peak_live = values->live;
    }
    for (region = 0u; region < wrtc_native_allocation_region_count; region++)
        for (category = 0u; category < WRTC_NATIVE_ALLOC_CATEGORY_COUNT;
             category++) {
            WrtcNativeAllocationValues *values =
                &wrtc_native_allocation_regions[region].values[category];
            values->allocations = values->frees = 0u;
            values->peak_live = values->live;
        }
    wrtc_native_allocation_resume();
    Py_RETURN_NONE;
}

void wrtc_native_allocation_release_locals(PyObject *locals) {
    if (locals == NULL) return;
    wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_LOCALS_DICTIONARY);
    Py_DECREF(locals);
}

typedef enum {
    WRTC_FLOW_NORMAL = 0,
    WRTC_FLOW_RETURN,
    WRTC_FLOW_BREAK,
    WRTC_FLOW_CONTINUE
} WrtcFlow;

typedef struct WrtcBoxedFrame WrtcBoxedFrame;
typedef PyObject *(*WrtcExternalFrameEvaluate)(
    void *, const WrtcPyExprIR *);
typedef PyObject *(*WrtcExternalFrameLocal)(void *, const char *);

struct WrtcBoxedFrame {
    PyObject *globals;
    PyObject *locals;
    PyObject *return_value;
    char **local_names;
    size_t local_count;
    const WrtcBoxedNativeHooks *hooks;
    void *external_frame;
    WrtcExternalFrameEvaluate external_evaluate;
    WrtcExternalFrameLocal external_local;
};

static PyObject *evaluate(const WrtcPyExprIR *expression,
                          WrtcBoxedFrame *frame);
static PyObject *evaluate_impl(const WrtcPyExprIR *expression,
                              WrtcBoxedFrame *frame);
static int execute_statements(const WrtcPyStmtIR *statements, size_t count,
                              WrtcBoxedFrame *frame, WrtcFlow *flow);

static PyObject *tracked_get_attr_string(PyObject *owner, const char *name) {
    PyObject *result = PyObject_GetAttrString(owner, name);
    if (result != NULL) {
        /* Ownership leaves the compiler immediately through the expression
         * result; live therefore measures compiler-owned objects, not the
         * lifetime of objects retained by application code. */
        wrtc_native_allocation_alloc(
            WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);
    }
    return result;
}

static PyObject *lookup_name(WrtcBoxedFrame *frame, const char *name) {
    PyObject *value = PyDict_GetItemString(frame->locals, name);
    PyObject *builtins;
    if (value != NULL) return Py_NewRef(value);
    if (PyErr_Occurred()) return NULL;
    value = PyDict_GetItemString(frame->globals, name);
    {
        size_t index;
        for (index = 0u; index < frame->local_count; index++)
            if (strcmp(frame->local_names[index], name) == 0) {
                PyErr_Format(
                    PyExc_UnboundLocalError,
                    "cannot access local variable '%s' where it is "
                    "not associated with a value",
                    name);
                return NULL;
            }
    }
    if (value != NULL) return Py_NewRef(value);
    if (PyErr_Occurred()) return NULL;
    builtins = PyDict_GetItemString(frame->globals, "__builtins__");
    if (builtins == NULL) builtins = PyEval_GetBuiltins();
    if (builtins != NULL && PyDict_Check(builtins))
        value = PyDict_GetItemString(builtins, name);
    else if (builtins != NULL)
        value = PyObject_GetAttrString(builtins, name);
    if (value != NULL)
        return PyDict_Check(builtins) ? Py_NewRef(value) : value;
    if (PyErr_Occurred()) return NULL;
    PyErr_Format(PyExc_NameError, "name '%s' is not defined", name);
    return NULL;
}

static PyObject *evaluate_constant(const WrtcPyExprIR *expression,
                                   WrtcBoxedFrame *frame) {
    if (strcmp(expression->text, "None") == 0) return Py_NewRef(Py_None);
    if (strcmp(expression->text, "True") == 0) return Py_NewRef(Py_True);
    if (strcmp(expression->text, "False") == 0) return Py_NewRef(Py_False);
    /*
     * text is produced exclusively by ast.unparse(Constant), so evaluation
     * cannot resolve names, call objects, or execute application operations.
     * CPython's own literal parser preserves exact integer, float, bytes,
     * string, complex, and ellipsis construction semantics.
     */
    if (expression->cached_constant != NULL)
        return Py_NewRef(expression->cached_constant);
    return PyRun_StringFlags(expression->text, Py_eval_input,
                             frame->globals, frame->locals, NULL);
}

static int initialize_expression(WrtcPyExprIR *expression,
                                 PyObject *globals) {
    size_t index;
    if (expression->kind == WRTC_PY_EXPR_CONSTANT &&
        expression->cached_constant == NULL) {
        expression->cached_constant = PyRun_StringFlags(
            expression->text, Py_eval_input, globals, globals, NULL);
        if (expression->cached_constant == NULL) return -1;
    }
    if (expression->kind == WRTC_PY_EXPR_CALL &&
        expression->keyword_count != 0u &&
        expression->cached_keyword_names == NULL) {
        expression->cached_keyword_names =
            PyTuple_New((Py_ssize_t)expression->keyword_count);
        if (expression->cached_keyword_names == NULL) return -1;
        for (index = 0u; index < expression->keyword_count; index++) {
            PyObject *name = PyUnicode_InternFromString(
                expression->keyword_names[index]);
            if (name == NULL) return -1;
            PyTuple_SET_ITEM(expression->cached_keyword_names,
                             (Py_ssize_t)index, name);
        }
    }
    for (index = 0u; index < expression->child_count; index++)
        if (initialize_expression(&expression->children[index], globals) < 0)
            return -1;
    return 0;
}

static int initialize_statements(WrtcPyStmtIR *statements, size_t count,
                                 PyObject *globals) {
    size_t statement_index, expression_index;
    for (statement_index = 0u; statement_index < count; statement_index++) {
        WrtcPyStmtIR *statement = &statements[statement_index];
        for (expression_index = 0u;
             expression_index < statement->expression_count;
             expression_index++)
            if (initialize_expression(
                    &statement->expressions[expression_index], globals) < 0)
                return -1;
        if (initialize_statements(statement->body, statement->body_count,
                                  globals) < 0 ||
            initialize_statements(statement->orelse, statement->orelse_count,
                                  globals) < 0 ||
            initialize_statements(statement->finalbody,
                                  statement->finalbody_count, globals) < 0 ||
            initialize_statements(statement->handlers,
                                  statement->handler_count, globals) < 0)
            return -1;
    }
    return 0;
}

static void clear_expression(WrtcPyExprIR *expression) {
    size_t index;
    Py_CLEAR(expression->cached_constant);
    Py_CLEAR(expression->cached_keyword_names);
    for (index = 0u; index < expression->child_count; index++)
        clear_expression(&expression->children[index]);
}

static void clear_statements(WrtcPyStmtIR *statements, size_t count) {
    size_t statement_index, expression_index;
    for (statement_index = 0u; statement_index < count; statement_index++) {
        WrtcPyStmtIR *statement = &statements[statement_index];
        for (expression_index = 0u;
             expression_index < statement->expression_count;
             expression_index++)
            clear_expression(&statement->expressions[expression_index]);
        clear_statements(statement->body, statement->body_count);
        clear_statements(statement->orelse, statement->orelse_count);
        clear_statements(statement->finalbody, statement->finalbody_count);
        clear_statements(statement->handlers, statement->handler_count);
    }
}

void wrtc_boxed_suite_clear(WrtcPySuiteIR *suite);

int wrtc_boxed_suite_initialize(WrtcPySuiteIR *suite, PyObject *globals) {
    if (suite == NULL || globals == NULL) {
        PyErr_SetString(PyExc_SystemError, "boxed suite initialization is invalid");
        return -1;
    }
    if (initialize_statements(
            suite->statements, suite->statement_count, globals) < 0) {
        wrtc_boxed_suite_clear(suite);
        return -1;
    }
    return 0;
}

void wrtc_boxed_suite_clear(WrtcPySuiteIR *suite) {
    if (suite != NULL)
        clear_statements(suite->statements, suite->statement_count);
}

WrtcPyBinaryOp wrtc_py_binary_from_name(const char *name) {
    if (name == NULL) return WRTC_PY_BINARY_INVALID;
#define WRTC_BINARY_NAME(ast_name, value) \
    if (strcmp(name, ast_name) == 0) return value
    WRTC_BINARY_NAME("Add", WRTC_PY_BINARY_ADD);
    WRTC_BINARY_NAME("Sub", WRTC_PY_BINARY_SUBTRACT);
    WRTC_BINARY_NAME("Mult", WRTC_PY_BINARY_MULTIPLY);
    WRTC_BINARY_NAME("MatMult", WRTC_PY_BINARY_MATRIX_MULTIPLY);
    WRTC_BINARY_NAME("Div", WRTC_PY_BINARY_TRUE_DIVIDE);
    WRTC_BINARY_NAME("TrueDiv", WRTC_PY_BINARY_TRUE_DIVIDE);
    WRTC_BINARY_NAME("FloorDiv", WRTC_PY_BINARY_FLOOR_DIVIDE);
    WRTC_BINARY_NAME("Mod", WRTC_PY_BINARY_REMAINDER);
    WRTC_BINARY_NAME("Pow", WRTC_PY_BINARY_POWER);
    WRTC_BINARY_NAME("LShift", WRTC_PY_BINARY_LEFT_SHIFT);
    WRTC_BINARY_NAME("RShift", WRTC_PY_BINARY_RIGHT_SHIFT);
    WRTC_BINARY_NAME("BitAnd", WRTC_PY_BINARY_AND);
    WRTC_BINARY_NAME("BitXor", WRTC_PY_BINARY_XOR);
    WRTC_BINARY_NAME("BitOr", WRTC_PY_BINARY_OR);
#undef WRTC_BINARY_NAME
    return WRTC_PY_BINARY_INVALID;
}

const char *wrtc_py_binary_name(WrtcPyBinaryOp operation) {
    static const char *const names[] = {
        NULL, "Add", "Sub", "Mult", "MatMult", "TrueDiv", "FloorDiv",
        "Mod", "Pow", "LShift", "RShift", "BitAnd", "BitXor", "BitOr"
    };
    return operation > WRTC_PY_BINARY_INVALID &&
                   operation <= WRTC_PY_BINARY_OR
               ? names[(size_t)operation] : NULL;
}

static PyObject *binary_operation(WrtcPyBinaryOp operation, PyObject *left,
                                  PyObject *right, int inplace) {
#define BINARY(value, regular, in_place) \
    case value: return inplace ? in_place(left, right) : regular(left, right)
    switch (operation) {
        BINARY(WRTC_PY_BINARY_ADD, PyNumber_Add, PyNumber_InPlaceAdd);
        BINARY(WRTC_PY_BINARY_SUBTRACT, PyNumber_Subtract, PyNumber_InPlaceSubtract);
        BINARY(WRTC_PY_BINARY_MULTIPLY, PyNumber_Multiply, PyNumber_InPlaceMultiply);
        BINARY(WRTC_PY_BINARY_MATRIX_MULTIPLY, PyNumber_MatrixMultiply, PyNumber_InPlaceMatrixMultiply);
        BINARY(WRTC_PY_BINARY_TRUE_DIVIDE, PyNumber_TrueDivide, PyNumber_InPlaceTrueDivide);
        BINARY(WRTC_PY_BINARY_FLOOR_DIVIDE, PyNumber_FloorDivide, PyNumber_InPlaceFloorDivide);
        BINARY(WRTC_PY_BINARY_REMAINDER, PyNumber_Remainder, PyNumber_InPlaceRemainder);
        BINARY(WRTC_PY_BINARY_LEFT_SHIFT, PyNumber_Lshift, PyNumber_InPlaceLshift);
        BINARY(WRTC_PY_BINARY_RIGHT_SHIFT, PyNumber_Rshift, PyNumber_InPlaceRshift);
        BINARY(WRTC_PY_BINARY_AND, PyNumber_And, PyNumber_InPlaceAnd);
        BINARY(WRTC_PY_BINARY_XOR, PyNumber_Xor, PyNumber_InPlaceXor);
        BINARY(WRTC_PY_BINARY_OR, PyNumber_Or, PyNumber_InPlaceOr);
        case WRTC_PY_BINARY_POWER:
            return inplace ? PyNumber_InPlacePower(left, right, Py_None)
                           : PyNumber_Power(left, right, Py_None);
        default: break;
    }
#undef BINARY
    PyErr_SetString(PyExc_SystemError, "unknown boxed binary operation");
    return NULL;
}

static PyObject *compare_operation(const char *operation, PyObject *left,
                                   PyObject *right) {
    int answer;
#define RICH(name, opcode) \
    if (strcmp(operation, name) == 0) \
        return PyObject_RichCompare(left, right, opcode)
    RICH("Eq", Py_EQ);
    RICH("NotEq", Py_NE);
    RICH("Lt", Py_LT);
    RICH("LtE", Py_LE);
    RICH("Gt", Py_GT);
    RICH("GtE", Py_GE);
#undef RICH
    if (strcmp(operation, "Is") == 0)
        return PyBool_FromLong(left == right);
    if (strcmp(operation, "IsNot") == 0)
        return PyBool_FromLong(left != right);
    if (strcmp(operation, "In") == 0 ||
        strcmp(operation, "NotIn") == 0) {
        answer = PySequence_Contains(right, left);
        if (answer < 0) return NULL;
        if (strcmp(operation, "NotIn") == 0) answer = !answer;
        return PyBool_FromLong(answer);
    }
    PyErr_Format(PyExc_SystemError, "unknown boxed comparison %s", operation);
    return NULL;
}

static PyObject *evaluate_call(const WrtcPyExprIR *expression,
                               WrtcBoxedFrame *frame) {
    PyObject *callable = evaluate(&expression->children[0], frame);
    PyObject *small_stack[8], **stack = small_stack, *result = NULL;
    const size_t argument_count =
        expression->positional_count + expression->keyword_count;
    size_t index;
    if (callable == NULL) return NULL;
    memset(small_stack, 0, sizeof small_stack);
    if (expression->keyword_count != 0u &&
        expression->cached_keyword_names == NULL) {
        PyErr_SetString(PyExc_SystemError,
                        "boxed call keyword cache is uninitialized");
        goto done;
    }
    if (argument_count > sizeof small_stack / sizeof small_stack[0]) {
        stack = PyMem_Malloc(argument_count * sizeof(*stack));
        if (stack == NULL) {
            PyErr_NoMemory();
            goto done;
        }
        wrtc_native_allocation_alloc(
            WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);
        memset(stack, 0, argument_count * sizeof(*stack));
    }
    for (index = 0u; index < argument_count; index++) {
        PyObject *value = evaluate(&expression->children[1u + index], frame);
        if (value == NULL) goto done;
        stack[index] = value;
    }
    wrtc_native_allocation_pause();
    result = PyObject_Vectorcall(
        callable, stack, expression->positional_count,
        expression->cached_keyword_names);
    wrtc_native_allocation_resume();
done:
    for (index = 0u; index < argument_count; index++) Py_XDECREF(stack[index]);
    if (stack != small_stack) {
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);
        PyMem_Free(stack);
    }
    Py_DECREF(callable);
    return result;
}

static PyObject *evaluate_boolean(const WrtcPyExprIR *expression,
                                  WrtcBoxedFrame *frame) {
    PyObject *value = NULL;
    size_t index;
    const int is_and = strcmp(expression->operation, "And") == 0;
    if (!is_and && strcmp(expression->operation, "Or") != 0) {
        PyErr_SetString(PyExc_SystemError, "unknown boxed boolean operation");
        return NULL;
    }
    for (index = 0u; index < expression->child_count; index++) {
        int truth;
        Py_XDECREF(value);
        value = evaluate(&expression->children[index], frame);
        if (value == NULL) return NULL;
        if (index + 1u == expression->child_count) return value;
        truth = PyObject_IsTrue(value);
        if (truth < 0) {
            Py_DECREF(value);
            return NULL;
        }
        if ((is_and && !truth) || (!is_and && truth)) return value;
    }
    PyErr_SetString(PyExc_SystemError, "empty boxed boolean operation");
    return NULL;
}

static PyObject *evaluate_comparison(const WrtcPyExprIR *expression,
                                     WrtcBoxedFrame *frame) {
    PyObject *left;
    size_t index;
    if (expression->child_count != expression->operation_count + 1u) {
        PyErr_SetString(PyExc_SystemError, "invalid boxed comparison IR");
        return NULL;
    }
    left = evaluate(&expression->children[0], frame);
    if (left == NULL) return NULL;
    for (index = 0u; index < expression->operation_count; index++) {
        PyObject *right =
            evaluate(&expression->children[index + 1u], frame);
        PyObject *answer;
        int truth;
        if (right == NULL) {
            Py_DECREF(left);
            return NULL;
        }
        answer = compare_operation(
            expression->operations[index], left, right);
        Py_DECREF(left);
        if (answer == NULL) {
            Py_DECREF(right);
            return NULL;
        }
        if (index + 1u == expression->operation_count) {
            Py_DECREF(right);
            return answer;
        }
        truth = PyObject_IsTrue(answer);
        if (truth < 0) {
            Py_DECREF(answer);
            Py_DECREF(right);
            return NULL;
        }
        if (!truth) {
            Py_DECREF(right);
            return answer;
        }
        Py_DECREF(answer);
        left = right;
    }
    Py_DECREF(left);
    return Py_NewRef(Py_True);
}

static PyObject *evaluate_collection(const WrtcPyExprIR *expression,
                                     WrtcBoxedFrame *frame, int tuple) {
    PyObject *result = tuple
                           ? PyTuple_New((Py_ssize_t)expression->child_count)
                           : PyList_New((Py_ssize_t)expression->child_count);
    size_t index;
    if (result == NULL) return NULL;
    wrtc_native_allocation_alloc(
        tuple ? WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE
              : WRTC_NATIVE_ALLOC_TEMPORARY_LIST);
    for (index = 0u; index < expression->child_count; index++) {
        PyObject *value = evaluate(&expression->children[index], frame);
        if (value == NULL) {
            wrtc_native_allocation_free(
                tuple ? WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE
                      : WRTC_NATIVE_ALLOC_TEMPORARY_LIST);
            Py_DECREF(result);
            return NULL;
        }
        if (tuple)
            PyTuple_SET_ITEM(result, (Py_ssize_t)index, value);
        else
            PyList_SET_ITEM(result, (Py_ssize_t)index, value);
    }
    wrtc_native_allocation_free(
        tuple ? WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE
              : WRTC_NATIVE_ALLOC_TEMPORARY_LIST);
    return result;
}

static PyObject *evaluate_dict(const WrtcPyExprIR *expression,
                               WrtcBoxedFrame *frame) {
    PyObject *result = PyDict_New();
    size_t index;
    if (result == NULL) return NULL;
    wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
    if (expression->child_count % 2u != 0u) {
        wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
        Py_DECREF(result);
        PyErr_SetString(PyExc_SystemError, "invalid boxed dictionary IR");
        return NULL;
    }
    for (index = 0u; index < expression->child_count; index += 2u) {
        PyObject *key = evaluate(&expression->children[index], frame);
        PyObject *value = key == NULL
                              ? NULL
                              : evaluate(&expression->children[index + 1u],
                                         frame);
        if (key == NULL || value == NULL ||
            PyDict_SetItem(result, key, value) < 0) {
            Py_XDECREF(value);
            Py_XDECREF(key);
            wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
            Py_DECREF(result);
            return NULL;
        }
        Py_DECREF(value);
        Py_DECREF(key);
    }
    wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
    return result;
}

static PyObject *evaluate_joined_string(const WrtcPyExprIR *expression,
                                        WrtcBoxedFrame *frame) {
    PyObject *parts = PyTuple_New((Py_ssize_t)expression->child_count);
    PyObject *separator = NULL, *result = NULL;
    size_t index;
    if (parts == NULL) return NULL;
    wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);
    for (index = 0u; index < expression->child_count; index++) {
        PyObject *part = evaluate(&expression->children[index], frame);
        if (part == NULL) goto done;
        PyTuple_SET_ITEM(parts, (Py_ssize_t)index, part);
    }
    separator = PyUnicode_FromString("");
    if (separator != NULL) result = PyUnicode_Join(separator, parts);
done:
    Py_XDECREF(separator);
    wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);
    Py_DECREF(parts);
    return result;
}

static PyObject *evaluate_formatted_value(const WrtcPyExprIR *expression,
                                          WrtcBoxedFrame *frame) {
    PyObject *value, *converted = NULL, *format = NULL, *result = NULL;
    if (expression->child_count != 2u || expression->operation == NULL) {
        PyErr_SetString(PyExc_SystemError, "invalid formatted-value IR");
        return NULL;
    }
    value = evaluate(&expression->children[0], frame);
    if (value == NULL) return NULL;
    if (strcmp(expression->operation, "115") == 0)
        converted = PyObject_Str(value);
    else if (strcmp(expression->operation, "114") == 0)
        converted = PyObject_Repr(value);
    else if (strcmp(expression->operation, "97") == 0)
        converted = PyObject_ASCII(value);
    else if (strcmp(expression->operation, "-1") == 0)
        converted = Py_NewRef(value);
    else
        PyErr_SetString(PyExc_SystemError,
                        "invalid formatted-value conversion");
    Py_DECREF(value);
    if (converted == NULL) return NULL;
    format = evaluate(&expression->children[1], frame);
    if (format != NULL) result = PyObject_Format(converted, format);
    Py_XDECREF(format);
    Py_DECREF(converted);
    return result;
}

typedef struct {
    const WrtcPyExprIR *lambda;
    PyObject *globals;
} WrtcBoxedLambda;

static void boxed_lambda_capsule_clear(PyObject *capsule) {
    WrtcBoxedLambda *lambda = PyCapsule_GetPointer(
        capsule, "wrtc.boxed_lambda");
    if (lambda == NULL) {
        PyErr_Clear();
        return;
    }
    Py_CLEAR(lambda->globals);
    wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER);
    PyMem_Free(lambda);
}

static PyObject *invoke_boxed_lambda(PyObject *capsule, PyObject *args,
                                     PyObject *kwargs) {
    WrtcBoxedLambda *lambda = PyCapsule_GetPointer(
        capsule, "wrtc.boxed_lambda");
    PyObject *locals = NULL, *result = NULL;
    WrtcBoxedFrame frame;
    Py_ssize_t positional, keyword_count = 0;
    size_t index;
    memset(&frame, 0, sizeof frame);
    if (lambda == NULL || lambda->lambda == NULL ||
        lambda->lambda->child_count != 1u)
        return NULL;
    positional = PyTuple_GET_SIZE(args);
    if (kwargs != NULL) keyword_count = PyDict_Size(kwargs);
    if (positional < 0 || keyword_count < 0) return NULL;
    if ((size_t)positional > lambda->lambda->keyword_count) {
        PyErr_Format(PyExc_TypeError,
                     "<lambda>() takes %zu positional arguments but %zd "
                     "were given", lambda->lambda->keyword_count,
                     positional);
        return NULL;
    }
    locals = PyDict_New();
    if (locals == NULL) return NULL;
    wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_LOCALS_DICTIONARY);
    for (index = 0u; index < (size_t)positional; index++)
        if (PyDict_SetItemString(
                locals, lambda->lambda->keyword_names[index],
                PyTuple_GET_ITEM(args, (Py_ssize_t)index)) < 0)
            goto done;
    if (kwargs != NULL) {
        PyObject *key, *value;
        Py_ssize_t position = 0;
        while (PyDict_Next(kwargs, &position, &key, &value)) {
            const char *name = PyUnicode_AsUTF8(key);
            size_t parameter;
            if (name == NULL) goto done;
            for (parameter = 0u;
                 parameter < lambda->lambda->keyword_count; parameter++)
                if (strcmp(lambda->lambda->keyword_names[parameter], name) == 0)
                    break;
            if (parameter == lambda->lambda->keyword_count) {
                PyErr_Format(PyExc_TypeError,
                             "<lambda>() got an unexpected keyword argument "
                             "'%s'", name);
                goto done;
            }
            if (parameter < (size_t)positional ||
                PyDict_Contains(locals, key) == 1) {
                PyErr_Format(PyExc_TypeError,
                             "<lambda>() got multiple values for argument "
                             "'%s'", name);
                goto done;
            }
            if (PyDict_SetItem(locals, key, value) < 0) goto done;
        }
    }
    for (index = 0u; index < lambda->lambda->keyword_count; index++)
        if (PyDict_GetItemString(
                locals, lambda->lambda->keyword_names[index]) == NULL) {
            PyErr_Format(PyExc_TypeError,
                         "<lambda>() missing required argument: '%s'",
                         lambda->lambda->keyword_names[index]);
            goto done;
        }
    frame.globals = lambda->globals;
    frame.locals = locals;
    frame.return_value = NULL;
    frame.local_names = lambda->lambda->keyword_names;
    frame.local_count = lambda->lambda->keyword_count;
    frame.hooks = NULL;
    result = evaluate(&lambda->lambda->children[0], &frame);
done:
    wrtc_native_allocation_release_locals(locals);
    return result;
}

static PyMethodDef boxed_lambda_method = {
    "<lambda>",
    (PyCFunction)(void (*)(void))invoke_boxed_lambda,
    METH_VARARGS | METH_KEYWORDS,
    NULL
};

static PyObject *evaluate_lambda(const WrtcPyExprIR *expression,
                                 WrtcBoxedFrame *frame) {
    WrtcBoxedLambda *lambda = PyMem_Calloc(1u, sizeof(*lambda));
    PyObject *capsule, *callable;
    if (lambda == NULL) return PyErr_NoMemory();
    wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER);
    lambda->lambda = expression;
    lambda->globals = Py_NewRef(frame->globals);
    capsule = PyCapsule_New(
        lambda, "wrtc.boxed_lambda", boxed_lambda_capsule_clear);
    if (capsule == NULL) {
        Py_DECREF(lambda->globals);
        wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER);
        PyMem_Free(lambda);
        return NULL;
    }
    callable = PyCFunction_New(&boxed_lambda_method, capsule);
    Py_DECREF(capsule);
    return callable;
}

static PyObject *evaluate(const WrtcPyExprIR *expression,
                          WrtcBoxedFrame *frame) {
    PyObject *result = evaluate_impl(expression, frame);
    if (result != NULL) {
        wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_BOXED_TEMPORARY);
        wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_BOXED_TEMPORARY);
    }
    return result;
}

static PyObject *evaluate_impl(const WrtcPyExprIR *expression,
                               WrtcBoxedFrame *frame) {
    PyObject *first, *second, *result;
    if (frame->hooks != NULL && frame->hooks->evaluate != NULL) {
        int handled = 0;
        result = frame->hooks->evaluate(
            frame->hooks->context, expression, frame, &handled);
        if (handled || (result == NULL && PyErr_Occurred())) return result;
    }
    switch (expression->kind) {
        case WRTC_PY_EXPR_NAME:
            return lookup_name(frame, expression->operation);
        case WRTC_PY_EXPR_ATTRIBUTE:
            first = evaluate(&expression->children[0], frame);
            if (first == NULL) return NULL;
            result = tracked_get_attr_string(first, expression->operation);
            Py_DECREF(first);
            return result;
        case WRTC_PY_EXPR_CONSTANT:
            return evaluate_constant(expression, frame);
        case WRTC_PY_EXPR_CALL:
            return evaluate_call(expression, frame);
        case WRTC_PY_EXPR_BINARY:
            first = evaluate(&expression->children[0], frame);
            if (first == NULL) return NULL;
            second = evaluate(&expression->children[1], frame);
            if (second == NULL) {
                Py_DECREF(first);
                return NULL;
            }
            result =
                binary_operation(expression->binary_operation, first, second, 0);
            Py_DECREF(second);
            Py_DECREF(first);
            return result;
        case WRTC_PY_EXPR_UNARY:
            first = evaluate(&expression->children[0], frame);
            if (first == NULL) return NULL;
            if (strcmp(expression->operation, "Not") == 0) {
                int truth = PyObject_IsTrue(first);
                Py_DECREF(first);
                return truth < 0 ? NULL : PyBool_FromLong(!truth);
            }
            if (strcmp(expression->operation, "USub") == 0)
                result = PyNumber_Negative(first);
            else if (strcmp(expression->operation, "UAdd") == 0)
                result = PyNumber_Positive(first);
            else if (strcmp(expression->operation, "Invert") == 0)
                result = PyNumber_Invert(first);
            else {
                PyErr_SetString(PyExc_SystemError,
                                "unknown boxed unary operation");
                result = NULL;
            }
            Py_DECREF(first);
            return result;
        case WRTC_PY_EXPR_BOOLEAN:
            return evaluate_boolean(expression, frame);
        case WRTC_PY_EXPR_COMPARE:
            return evaluate_comparison(expression, frame);
        case WRTC_PY_EXPR_TUPLE:
            return evaluate_collection(expression, frame, 1);
        case WRTC_PY_EXPR_LIST:
            return evaluate_collection(expression, frame, 0);
        case WRTC_PY_EXPR_DICT:
            return evaluate_dict(expression, frame);
        case WRTC_PY_EXPR_JOINED_STRING:
            return evaluate_joined_string(expression, frame);
        case WRTC_PY_EXPR_FORMATTED_VALUE:
            return evaluate_formatted_value(expression, frame);
        case WRTC_PY_EXPR_LAMBDA:
            return evaluate_lambda(expression, frame);
        case WRTC_PY_EXPR_SUBSCRIPT:
            first = evaluate(&expression->children[0], frame);
            if (first == NULL) return NULL;
            second = evaluate(&expression->children[1], frame);
            if (second == NULL) {
                Py_DECREF(first);
                return NULL;
            }
            result = PyObject_GetItem(first, second);
            Py_DECREF(second);
            Py_DECREF(first);
            return result;
        case WRTC_PY_EXPR_SLICE: {
            PyObject *values[3] = {NULL, NULL, NULL};
            size_t index;
            for (index = 0u; index < 3u; index++) {
                values[index] =
                    evaluate(&expression->children[index], frame);
                if (values[index] == NULL) {
                    size_t previous;
                    for (previous = 0u; previous < index; previous++)
                        Py_DECREF(values[previous]);
                    return NULL;
                }
            }
            result = PySlice_New(values[0], values[1], values[2]);
            for (index = 0u; index < 3u; index++) Py_DECREF(values[index]);
            return result;
        }
    }
    PyErr_SetString(PyExc_SystemError, "unknown boxed expression kind");
    return NULL;
}

static int assign_target(const WrtcPyExprIR *target, PyObject *value,
                         WrtcBoxedFrame *frame);

static int unpack_target(const WrtcPyExprIR *target, PyObject *value,
                         WrtcBoxedFrame *frame) {
    PyObject *iterator = PyObject_GetIter(value);
    size_t index;
    if (iterator == NULL) {
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_Clear();
            PyErr_Format(PyExc_TypeError,
                         "cannot unpack non-iterable %.200s object",
                         Py_TYPE(value)->tp_name);
        }
        return -1;
    }
    for (index = 0u; index < target->child_count; index++) {
        PyObject *item = PyIter_Next(iterator);
        if (item == NULL) {
            Py_DECREF(iterator);
            if (!PyErr_Occurred())
                PyErr_Format(
                    PyExc_ValueError,
                    "not enough values to unpack (expected %zu, got %zu)",
                    target->child_count, index);
            return -1;
        }
        if (assign_target(&target->children[index], item, frame) < 0) {
            Py_DECREF(item);
            Py_DECREF(iterator);
            return -1;
        }
        Py_DECREF(item);
    }
    {
        PyObject *extra = PyIter_Next(iterator);
        Py_DECREF(iterator);
        if (extra != NULL) {
            Py_DECREF(extra);
            PyErr_Format(PyExc_ValueError,
                         "too many values to unpack (expected %zu)",
                         target->child_count);
            return -1;
        }
        if (PyErr_Occurred()) return -1;
    }
    return 0;
}

static int assign_target(const WrtcPyExprIR *target, PyObject *value,
                         WrtcBoxedFrame *frame) {
    PyObject *owner, *key;
    int status;
    if (frame->hooks != NULL && frame->hooks->assign != NULL) {
        int handled = 0;
        status = frame->hooks->assign(
            frame->hooks->context, target, value, frame, &handled);
        if (handled || status < 0) return status;
    }
    switch (target->kind) {
        case WRTC_PY_EXPR_NAME:
            return PyDict_SetItemString(
                frame->locals, target->operation, value);
        case WRTC_PY_EXPR_ATTRIBUTE:
            owner = evaluate(&target->children[0], frame);
            if (owner == NULL) return -1;
            status = PyObject_SetAttrString(owner, target->operation, value);
            Py_DECREF(owner);
            return status;
        case WRTC_PY_EXPR_SUBSCRIPT:
            owner = evaluate(&target->children[0], frame);
            if (owner == NULL) return -1;
            key = evaluate(&target->children[1], frame);
            if (key == NULL) {
                Py_DECREF(owner);
                return -1;
            }
            status = PyObject_SetItem(owner, key, value);
            Py_DECREF(key);
            Py_DECREF(owner);
            return status;
        case WRTC_PY_EXPR_TUPLE:
        case WRTC_PY_EXPR_LIST:
            return unpack_target(target, value, frame);
        default:
            PyErr_SetString(PyExc_SystemError,
                            "invalid boxed assignment target");
            return -1;
    }
}

typedef struct {
    const WrtcPyExprIR *target;
    PyObject *owner;
    PyObject *key;
    PyObject *value;
} WrtcLValue;

static void lvalue_clear(WrtcLValue *lvalue) {
    Py_XDECREF(lvalue->value);
    Py_XDECREF(lvalue->key);
    Py_XDECREF(lvalue->owner);
    memset(lvalue, 0, sizeof(*lvalue));
}

static int lvalue_load(const WrtcPyExprIR *target, WrtcBoxedFrame *frame,
                       WrtcLValue *lvalue) {
    memset(lvalue, 0, sizeof(*lvalue));
    lvalue->target = target;
    if (target->kind == WRTC_PY_EXPR_NAME) {
        lvalue->value = lookup_name(frame, target->operation);
    } else if (target->kind == WRTC_PY_EXPR_ATTRIBUTE) {
        lvalue->owner = evaluate(&target->children[0], frame);
        if (lvalue->owner != NULL)
            lvalue->value = tracked_get_attr_string(
                lvalue->owner, target->operation);
    } else if (target->kind == WRTC_PY_EXPR_SUBSCRIPT) {
        lvalue->owner = evaluate(&target->children[0], frame);
        if (lvalue->owner != NULL)
            lvalue->key = evaluate(&target->children[1], frame);
        if (lvalue->key != NULL)
            lvalue->value = PyObject_GetItem(lvalue->owner, lvalue->key);
    } else {
        PyErr_SetString(PyExc_SystemError,
                        "invalid augmented-assignment target");
    }
    if (lvalue->value == NULL) {
        lvalue_clear(lvalue);
        return -1;
    }
    return 0;
}

static int lvalue_store(WrtcLValue *lvalue, PyObject *value,
                        WrtcBoxedFrame *frame) {
    if (lvalue->target->kind == WRTC_PY_EXPR_NAME)
        return PyDict_SetItemString(
            frame->locals, lvalue->target->operation, value);
    if (lvalue->target->kind == WRTC_PY_EXPR_ATTRIBUTE)
        return PyObject_SetAttrString(
            lvalue->owner, lvalue->target->operation, value);
    return PyObject_SetItem(lvalue->owner, lvalue->key, value);
}

static int raise_value(PyObject *exception, PyObject *cause) {
    PyObject *instance = NULL;
    PyObject *type;
    if (exception == NULL) {
        PyObject *handled = PyErr_GetHandledException();
        if (handled == NULL) {
            PyErr_SetString(PyExc_RuntimeError,
                            "No active exception to reraise");
            return -1;
        }
        PyErr_SetObject((PyObject *)Py_TYPE(handled), handled);
        Py_DECREF(handled);
        return -1;
    }
    if (PyExceptionClass_Check(exception)) {
        instance = PyObject_CallNoArgs(exception);
        if (instance == NULL) return -1;
    } else if (PyExceptionInstance_Check(exception)) {
        instance = Py_NewRef(exception);
    } else {
        PyErr_SetString(PyExc_TypeError,
                        "exceptions must derive from BaseException");
        return -1;
    }
    type = (PyObject *)Py_TYPE(instance);
    if (cause != NULL) {
        PyObject *cause_instance = NULL;
        if (cause == Py_None) {
            cause_instance = Py_NewRef(Py_None);
        } else if (PyExceptionClass_Check(cause)) {
            cause_instance = PyObject_CallNoArgs(cause);
        } else if (PyExceptionInstance_Check(cause)) {
            cause_instance = Py_NewRef(cause);
        } else {
            Py_DECREF(instance);
            PyErr_SetString(PyExc_TypeError,
                            "exception causes must derive from BaseException");
            return -1;
        }
        if (cause_instance == NULL) {
            Py_DECREF(instance);
            return -1;
        }
        if (cause_instance == Py_None) {
            Py_DECREF(cause_instance);
            PyException_SetCause(instance, NULL);
        } else {
            PyException_SetCause(instance, cause_instance);
        }
    }
    PyErr_SetObject(type, instance);
    Py_DECREF(instance);
    return -1;
}

static int valid_exception_match(PyObject *match) {
    Py_ssize_t index, count;
    if (PyExceptionClass_Check(match)) return 1;
    if (PyTuple_Check(match)) {
        count = PyTuple_GET_SIZE(match);
        for (index = 0; index < count; index++)
            if (!valid_exception_match(
                    PyTuple_GET_ITEM(match, index)))
                return 0;
        return 1;
    }
    PyErr_SetString(PyExc_TypeError,
                    "catching classes that do not inherit from "
                    "BaseException is not allowed");
    return 0;
}

static int execute_try(const WrtcPyStmtIR *statement, WrtcBoxedFrame *frame,
                       WrtcFlow *flow) {
    PyObject *saved_type = NULL, *saved_value = NULL, *saved_traceback = NULL;
    WrtcFlow pending_flow = WRTC_FLOW_NORMAL;
    int status = execute_statements(
        statement->body, statement->body_count, frame, &pending_flow);
    if (status < 0 && statement->handler_count != 0u) {
        size_t index;
        PyErr_Fetch(&saved_type, &saved_value, &saved_traceback);
        PyErr_NormalizeException(
            &saved_type, &saved_value, &saved_traceback);
        for (index = 0u; index < statement->handler_count; index++) {
            const WrtcPyStmtIR *handler = &statement->handlers[index];
            PyObject *match_type = NULL;
            int matches = 1;
            if (handler->expression_count != 0u) {
                match_type = evaluate(&handler->expressions[0], frame);
                if (match_type == NULL) {
                    Py_XDECREF(saved_traceback);
                    Py_XDECREF(saved_value);
                    Py_XDECREF(saved_type);
                    return -1;
                }
                if (!valid_exception_match(match_type)) {
                    Py_DECREF(match_type);
                    Py_XDECREF(saved_traceback);
                    Py_XDECREF(saved_value);
                    Py_XDECREF(saved_type);
                    return -1;
                }
                matches = PyErr_GivenExceptionMatches(
                    saved_value, match_type);
                Py_DECREF(match_type);
            }
            if (!matches) continue;
            {
                PyObject *previous = PyErr_GetHandledException();
                PyErr_SetHandledException(Py_NewRef(saved_value));
                if (handler->operation != NULL &&
                    PyDict_SetItemString(
                        frame->locals, handler->operation,
                        saved_value) < 0) {
                    PyErr_SetHandledException(previous);
                    Py_XDECREF(saved_traceback);
                    Py_DECREF(saved_value);
                    Py_DECREF(saved_type);
                    return -1;
                }
                status = execute_statements(
                    handler->body, handler->body_count,
                    frame, &pending_flow);
                if (handler->operation != NULL) {
                    if (PyDict_DelItemString(
                            frame->locals, handler->operation) < 0 &&
                        PyErr_ExceptionMatches(PyExc_KeyError))
                        PyErr_Clear();
                }
                PyErr_SetHandledException(previous);
            }
            Py_XDECREF(saved_traceback);
            Py_DECREF(saved_value);
            Py_DECREF(saved_type);
            saved_type = saved_value = saved_traceback = NULL;
            break;
        }
        if (saved_type != NULL) {
            PyErr_Restore(saved_type, saved_value, saved_traceback);
            status = -1;
        }
    } else if (status == 0 && pending_flow == WRTC_FLOW_NORMAL &&
               statement->orelse_count != 0u) {
        status = execute_statements(
            statement->orelse, statement->orelse_count,
            frame, &pending_flow);
    }
    if (statement->finalbody_count != 0u) {
        PyObject *error_type = NULL, *error_value = NULL, *error_trace = NULL;
        PyObject *pending_return = NULL;
        WrtcFlow final_flow = WRTC_FLOW_NORMAL;
        int final_status;
        if (status < 0)
            PyErr_Fetch(&error_type, &error_value, &error_trace);
        if (pending_flow == WRTC_FLOW_RETURN) {
            pending_return = frame->return_value;
            frame->return_value = NULL;
        }
        final_status = execute_statements(
            statement->finalbody, statement->finalbody_count,
            frame, &final_flow);
        if (final_status < 0 || final_flow != WRTC_FLOW_NORMAL) {
            Py_XDECREF(error_trace);
            Py_XDECREF(error_value);
            Py_XDECREF(error_type);
            Py_XDECREF(pending_return);
            *flow = final_flow;
            return final_status;
        }
        if (status < 0) {
            PyErr_Restore(error_type, error_value, error_trace);
            *flow = WRTC_FLOW_NORMAL;
            return -1;
        }
        if (pending_flow == WRTC_FLOW_RETURN) {
            frame->return_value = pending_return;
            pending_return = NULL;
        }
        Py_XDECREF(pending_return);
    }
    *flow = pending_flow;
    return status;
}

static int execute_statement(const WrtcPyStmtIR *statement,
                             WrtcBoxedFrame *frame, WrtcFlow *flow) {
    PyObject *value = NULL;
    size_t index;
    *flow = WRTC_FLOW_NORMAL;
    switch (statement->kind) {
        case WRTC_PY_STMT_EXPR:
            value = evaluate(&statement->expressions[0], frame);
            if (value == NULL) return -1;
            Py_DECREF(value);
            return 0;
        case WRTC_PY_STMT_ASSIGN:
            value = evaluate(&statement->expressions[0], frame);
            if (value == NULL) return -1;
            for (index = 1u; index < statement->expression_count; index++)
                if (assign_target(
                        &statement->expressions[index], value, frame) < 0) {
                    Py_DECREF(value);
                    return -1;
                }
            Py_DECREF(value);
            return 0;
        case WRTC_PY_STMT_AUGMENTED_ASSIGN: {
            WrtcLValue lvalue;
            PyObject *right, *updated;
            if (lvalue_load(
                    &statement->expressions[0], frame, &lvalue) < 0)
                return -1;
            right = evaluate(&statement->expressions[1], frame);
            if (right == NULL) {
                lvalue_clear(&lvalue);
                return -1;
            }
            updated = binary_operation(
                statement->binary_operation, lvalue.value, right, 1);
            Py_DECREF(right);
            if (updated == NULL) {
                lvalue_clear(&lvalue);
                return -1;
            }
            if (lvalue_store(&lvalue, updated, frame) < 0) {
                Py_DECREF(updated);
                lvalue_clear(&lvalue);
                return -1;
            }
            Py_DECREF(updated);
            lvalue_clear(&lvalue);
            return 0;
        }
        case WRTC_PY_STMT_IF:
        case WRTC_PY_STMT_WHILE:
            for (;;) {
                int truth;
                value = evaluate(&statement->expressions[0], frame);
                if (value == NULL) return -1;
                truth = PyObject_IsTrue(value);
                Py_DECREF(value);
                if (truth < 0) return -1;
                if (!truth) {
                    if (statement->kind == WRTC_PY_STMT_WHILE)
                        return execute_statements(
                            statement->orelse, statement->orelse_count,
                            frame, flow);
                    return execute_statements(
                        statement->orelse, statement->orelse_count,
                        frame, flow);
                }
                if (execute_statements(
                        statement->body, statement->body_count,
                        frame, flow) < 0)
                    return -1;
                if (statement->kind == WRTC_PY_STMT_IF) return 0;
                if (*flow == WRTC_FLOW_BREAK) {
                    *flow = WRTC_FLOW_NORMAL;
                    return 0;
                }
                if (*flow == WRTC_FLOW_RETURN) return 0;
                *flow = WRTC_FLOW_NORMAL;
            }
        case WRTC_PY_STMT_FOR: {
            PyObject *iterable =
                evaluate(&statement->expressions[1], frame);
            PyObject *iterator;
            int broke = 0;
            if (iterable == NULL) return -1;
            iterator = PyObject_GetIter(iterable);
            Py_DECREF(iterable);
            if (iterator == NULL) return -1;
            for (;;) {
                PyObject *item = PyIter_Next(iterator);
                if (item == NULL) {
                    Py_DECREF(iterator);
                    if (PyErr_Occurred()) return -1;
                    break;
                }
                if (assign_target(
                        &statement->expressions[0], item, frame) < 0) {
                    Py_DECREF(item);
                    Py_DECREF(iterator);
                    return -1;
                }
                Py_DECREF(item);
                if (execute_statements(
                        statement->body, statement->body_count,
                        frame, flow) < 0) {
                    Py_DECREF(iterator);
                    return -1;
                }
                if (*flow == WRTC_FLOW_BREAK) {
                    *flow = WRTC_FLOW_NORMAL;
                    broke = 1;
                    Py_DECREF(iterator);
                    break;
                }
                if (*flow == WRTC_FLOW_RETURN) {
                    Py_DECREF(iterator);
                    return 0;
                }
                *flow = WRTC_FLOW_NORMAL;
            }
            if (!broke)
                return execute_statements(
                    statement->orelse, statement->orelse_count,
                    frame, flow);
            return 0;
        }
        case WRTC_PY_STMT_TRY:
        case WRTC_PY_STMT_TRY_FINALLY:
            return execute_try(statement, frame, flow);
        case WRTC_PY_STMT_RETURN:
            value = statement->expression_count == 0u
                        ? Py_NewRef(Py_None)
                        : evaluate(&statement->expressions[0], frame);
            if (value == NULL) return -1;
            Py_XSETREF(frame->return_value, value);
            *flow = WRTC_FLOW_RETURN;
            return 0;
        case WRTC_PY_STMT_RAISE: {
            PyObject *cause = NULL;
            value = statement->expression_count == 0u
                        ? NULL : evaluate(&statement->expressions[0], frame);
            if (statement->expression_count != 0u && value == NULL)
                return -1;
            if (statement->expression_count > 1u) {
                cause = evaluate(&statement->expressions[1], frame);
                if (cause == NULL) {
                    Py_XDECREF(value);
                    return -1;
                }
            }
            (void)raise_value(value, cause);
            Py_XDECREF(cause);
            Py_XDECREF(value);
            return -1;
        }
        case WRTC_PY_STMT_BREAK:
            *flow = WRTC_FLOW_BREAK;
            return 0;
        case WRTC_PY_STMT_CONTINUE:
            *flow = WRTC_FLOW_CONTINUE;
            return 0;
        case WRTC_PY_STMT_PASS:
            return 0;
        case WRTC_PY_STMT_EXCEPT_HANDLER:
            PyErr_SetString(PyExc_SystemError,
                            "except handler executed outside try");
            return -1;
    }
    PyErr_SetString(PyExc_SystemError, "unknown boxed statement kind");
    return -1;
}

static int execute_statements(const WrtcPyStmtIR *statements, size_t count,
                              WrtcBoxedFrame *frame, WrtcFlow *flow) {
    size_t index;
    *flow = WRTC_FLOW_NORMAL;
    for (index = 0u; index < count; index++) {
        if (execute_statement(&statements[index], frame, flow) < 0)
            return -1;
        if (*flow != WRTC_FLOW_NORMAL) return 0;
    }
    return 0;
}

int wrtc_boxed_execute_with_hooks(
    const WrtcPySuiteIR *suite, PyObject *globals, PyObject *locals,
    const WrtcBoxedNativeHooks *hooks, PyObject **result) {
    WrtcBoxedFrame frame;
    WrtcFlow flow = WRTC_FLOW_NORMAL;
    int status;
    memset(&frame, 0, sizeof frame);
    if (suite == NULL || !PyDict_Check(globals) ||
        !PyDict_Check(locals) || result == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "boxed executor requires suite and dict environments");
        return -1;
    }
    wrtc_native_allocation_alloc(
        WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);
    frame.globals = globals;
    frame.locals = locals;
    frame.return_value = NULL;
    frame.local_names = suite->local_names;
    frame.local_count = suite->local_count;
    frame.hooks = hooks;
    status = execute_statements(
        suite->statements, suite->statement_count, &frame, &flow);
    if (status < 0) {
        Py_XDECREF(frame.return_value);
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);
        return -1;
    }
    if (flow == WRTC_FLOW_BREAK || flow == WRTC_FLOW_CONTINUE) {
        Py_XDECREF(frame.return_value);
        PyErr_SetString(PyExc_SyntaxError,
                        "loop control escaped native region");
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);
        return -1;
    }
    *result = frame.return_value == NULL
                  ? Py_NewRef(Py_None) : frame.return_value;
    wrtc_native_allocation_free(
        WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);
    return 0;
}

int wrtc_boxed_execute(const WrtcPySuiteIR *suite, PyObject *globals,
                       PyObject *locals, PyObject **result) {
    return wrtc_boxed_execute_with_hooks(
        suite, globals, locals, NULL, result);
}

PyObject *wrtc_boxed_hook_evaluate(
    const WrtcPyExprIR *expression, void *frame) {
    WrtcBoxedFrame *boxed = (WrtcBoxedFrame *)frame;
    if (boxed->external_evaluate != NULL)
        return boxed->external_evaluate(boxed->external_frame, expression);
    return evaluate(expression, boxed);
}

PyObject *wrtc_boxed_hook_local(const char *name, void *frame) {
    WrtcBoxedFrame *boxed = (WrtcBoxedFrame *)frame;
    if (boxed->external_local != NULL)
        return boxed->external_local(boxed->external_frame, name);
    return lookup_name(boxed, name);
}

int wrtc_boxed_signature_initialize(WrtcBoxedSignature *signature,
                                    PyObject *globals) {
    size_t index;
    if (signature == NULL || !PyDict_Check(globals) ||
        signature->defaults != NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "boxed signature initialization is invalid");
        return -1;
    }
    signature->defaults =
        calloc(signature->parameter_count, sizeof(*signature->defaults));
    if (signature->parameter_count != 0u &&
        signature->defaults == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    if (signature->parameter_count != 0u)
        wrtc_native_allocation_alloc(
            WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER);
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcBoxedParameterSpec *parameter =
            &signature->parameters[index];
        if (!parameter->has_default) continue;
        if (parameter->default_expression == NULL) {
            PyErr_Format(PyExc_RuntimeError,
                         "%s() has an unresolved default for '%s'",
                         signature->name, parameter->name);
            wrtc_boxed_signature_clear(signature);
            return -1;
        }
        signature->defaults[index] = PyRun_StringFlags(
            parameter->default_expression, Py_eval_input,
            globals, globals, NULL);
        if (signature->defaults[index] == NULL) {
            wrtc_boxed_signature_clear(signature);
            return -1;
        }
    }
    return 0;
}

void wrtc_boxed_signature_clear(WrtcBoxedSignature *signature) {
    size_t index;
    if (signature == NULL || signature->defaults == NULL) return;
    for (index = 0u; index < signature->parameter_count; index++)
        Py_XDECREF(signature->defaults[index]);
    if (signature->parameter_count != 0u)
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_COMPILER_SCRATCH_BUFFER);
    free(signature->defaults);
    signature->defaults = NULL;
}

static int bind_missing(const WrtcBoxedSignature *signature,
                        const char *name, const char *kind) {
    PyErr_Format(PyExc_TypeError,
                 "%s() missing 1 required %s argument: '%s'",
                 signature->name, kind, name);
    return -1;
}

static Py_ssize_t vector_keyword_index(PyObject *names, const char *wanted) {
    Py_ssize_t index, count = names == NULL ? 0 : PyTuple_GET_SIZE(names);
    for (index = 0; index < count; index++) {
        PyObject *name = PyTuple_GET_ITEM(names, index);
        int equal = PyUnicode_Check(name)
                        ? PyUnicode_CompareWithASCIIString(name, wanted) == 0
                        : 0;
        if (equal || PyErr_Occurred()) return equal ? index : -2;
    }
    return -1;
}

int wrtc_boxed_bind_method(const WrtcBoxedSignature *signature, PyObject *self,
                           PyObject *const *args, Py_ssize_t nargs,
                           PyObject *keyword_names, PyObject **locals) {
    unsigned char small_consumed[16] = {0}, *consumed = small_consumed;
    PyObject *bound = NULL;
    Py_ssize_t keyword_count =
        keyword_names == NULL ? 0 : PyTuple_GET_SIZE(keyword_names);
    Py_ssize_t position = 0, index;
    size_t parameter;
    int has_var_keyword = 0;
    if (signature == NULL || self == NULL || nargs < 0 || locals == NULL ||
        signature->defaults == NULL ||
        (keyword_names != NULL && !PyTuple_Check(keyword_names))) {
        PyErr_SetString(PyExc_TypeError, "invalid vector signature binding");
        return -1;
    }
    if (keyword_count > (Py_ssize_t)sizeof small_consumed) {
        consumed = PyMem_Calloc((size_t)keyword_count, sizeof(*consumed));
        if (consumed == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        wrtc_native_allocation_alloc(
            WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);
    }
    *locals = NULL;
    bound = PyDict_New();
    if (bound == NULL) goto error;
    wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_LOCALS_DICTIONARY);
    for (parameter = 0u; parameter < signature->parameter_count; parameter++)
        if (signature->parameters[parameter].kind == WRTC_PY_PARAM_VAR_KEYWORD)
            has_var_keyword = 1;
    for (parameter = 0u; parameter < signature->parameter_count; parameter++) {
        const WrtcBoxedParameterSpec *spec = &signature->parameters[parameter];
        PyObject *value = NULL;
        Py_ssize_t keyword = -1;
        const Py_ssize_t available = nargs + 1;
        if (spec->kind == WRTC_PY_PARAM_POSITIONAL_ONLY ||
            spec->kind == WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD) {
            if (position < available) {
                value = position++ == 0 ? self : args[position - 2];
                if (spec->kind == WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD) {
                    keyword = vector_keyword_index(keyword_names, spec->name);
                    if (keyword == -2) goto error;
                    if (keyword >= 0) {
                        PyErr_Format(PyExc_TypeError,
                                     "%s() got multiple values for argument '%s'",
                                     signature->name, spec->name);
                        goto error;
                    }
                }
            } else if (spec->kind == WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD &&
                       (keyword = vector_keyword_index(keyword_names,
                                                       spec->name)) >= 0) {
                value = args[nargs + keyword];
                consumed[keyword] = 1u;
            } else if (keyword == -2) {
                goto error;
            } else if (signature->defaults[parameter] != NULL) {
                value = signature->defaults[parameter];
            } else if (bind_missing(signature, spec->name, "positional") < 0) {
                goto error;
            }
            if (value != NULL && PyDict_SetItemString(bound, spec->name, value) < 0)
                goto error;
        } else if (spec->kind == WRTC_PY_PARAM_VAR_POSITIONAL) {
            Py_ssize_t tail_count = available - position;
            PyObject *tail = PyTuple_New(tail_count);
            Py_ssize_t tail_index;
            if (tail == NULL) goto error;
            wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);
            for (tail_index = 0; tail_index < tail_count; tail_index++) {
                Py_ssize_t source = position + tail_index;
                PyObject *value_at = source == 0 ? self : args[source - 1];
                PyTuple_SET_ITEM(tail, tail_index, Py_NewRef(value_at));
            }
            if (PyDict_SetItemString(bound, spec->name, tail) < 0) {
                wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);
                Py_DECREF(tail);
                goto error;
            }
            wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);
            Py_DECREF(tail);
            position = available;
        } else if (spec->kind == WRTC_PY_PARAM_KEYWORD_ONLY) {
            keyword = vector_keyword_index(keyword_names, spec->name);
            if (keyword == -2) goto error;
            if (keyword >= 0) {
                value = args[nargs + keyword];
                consumed[keyword] = 1u;
            } else if (signature->defaults[parameter] != NULL) {
                value = signature->defaults[parameter];
            } else if (bind_missing(signature, spec->name, "keyword-only") < 0) {
                goto error;
            }
            if (value != NULL && PyDict_SetItemString(bound, spec->name, value) < 0)
                goto error;
        } else if (spec->kind == WRTC_PY_PARAM_VAR_KEYWORD) {
            PyObject *remaining = PyDict_New();
            if (remaining == NULL) goto error;
            wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
            for (index = 0; index < keyword_count; index++) {
                if (consumed[index]) continue;
                if (PyDict_SetItem(remaining, PyTuple_GET_ITEM(keyword_names, index),
                                   args[nargs + index]) < 0) {
                    wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
                    Py_DECREF(remaining);
                    goto error;
                }
                consumed[index] = 1u;
            }
            if (PyDict_SetItemString(bound, spec->name, remaining) < 0) {
                wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
                Py_DECREF(remaining);
                goto error;
            }
            wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
            Py_DECREF(remaining);
        }
    }
    if (position < nargs + 1) {
        PyErr_Format(PyExc_TypeError,
                     "%s() takes %zd positional arguments but %zd were given",
                     signature->name, position, nargs + 1);
        goto error;
    }
    for (index = 0; index < keyword_count; index++) {
        if (!consumed[index] && !has_var_keyword) {
            PyObject *name = PyTuple_GET_ITEM(keyword_names, index);
            PyErr_Format(PyExc_TypeError,
                         "%s() got an unexpected keyword argument '%U'",
                         signature->name, name);
            goto error;
        }
    }
    if (consumed != small_consumed) {
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);
        PyMem_Free(consumed);
    }
    *locals = bound;
    return 0;
error:
    if (consumed != small_consumed) {
        wrtc_native_allocation_free(
            WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);
        PyMem_Free(consumed);
    }
    if (bound != NULL) wrtc_native_allocation_release_locals(bound);
    return -1;
}

int wrtc_boxed_bind(const WrtcBoxedSignature *signature, PyObject *args,
                    PyObject *kwargs, PyObject **locals) {
    PyObject *bound = NULL, *remaining = NULL;
    Py_ssize_t positional_count, position = 0;
    size_t index;
    int has_var_keyword = 0;
    if (signature == NULL || !PyTuple_Check(args) ||
        (kwargs != NULL && !PyDict_Check(kwargs)) || locals == NULL ||
        signature->defaults == NULL) {
        PyErr_SetString(PyExc_TypeError, "invalid boxed signature binding");
        return -1;
    }
    *locals = NULL;
    positional_count = PyTuple_GET_SIZE(args);
    bound = PyDict_New();
    if (bound != NULL)
        wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_LOCALS_DICTIONARY);
    remaining = kwargs == NULL ? PyDict_New() : PyDict_Copy(kwargs);
    if (remaining != NULL)
        wrtc_native_allocation_alloc(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
    if (bound == NULL || remaining == NULL) goto error;
    for (index = 0u; index < signature->parameter_count; index++)
        if (signature->parameters[index].kind ==
            WRTC_PY_PARAM_VAR_KEYWORD)
            has_var_keyword = 1;
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcBoxedParameterSpec *parameter =
            &signature->parameters[index];
        PyObject *value = NULL;
        if (parameter->kind == WRTC_PY_PARAM_POSITIONAL_ONLY ||
            parameter->kind == WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD) {
            if (position < positional_count) {
                value = PyTuple_GET_ITEM(args, position++);
                if (parameter->kind ==
                        WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD &&
                    PyDict_GetItemString(remaining, parameter->name) != NULL) {
                    PyErr_Format(
                        PyExc_TypeError,
                        "%s() got multiple values for argument '%s'",
                        signature->name, parameter->name);
                    goto error;
                }
            } else if (parameter->kind ==
                           WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD &&
                       (value = PyDict_GetItemString(
                            remaining, parameter->name)) != NULL) {
                if (PyDict_DelItemString(
                        remaining, parameter->name) < 0)
                    goto error;
            } else if (signature->defaults[index] != NULL) {
                value = signature->defaults[index];
            } else if (bind_missing(
                           signature, parameter->name,
                           "positional") < 0) {
                goto error;
            }
            if (value != NULL &&
                PyDict_SetItemString(
                    bound, parameter->name, value) < 0)
                goto error;
        } else if (parameter->kind == WRTC_PY_PARAM_VAR_POSITIONAL) {
            PyObject *tail = PyTuple_GetSlice(
                args, position, positional_count);
            if (tail == NULL ||
                PyDict_SetItemString(
                    bound, parameter->name, tail) < 0) {
                Py_XDECREF(tail);
                goto error;
            }
            Py_DECREF(tail);
            position = positional_count;
        } else if (parameter->kind == WRTC_PY_PARAM_KEYWORD_ONLY) {
            value = PyDict_GetItemString(remaining, parameter->name);
            if (value != NULL) {
                if (PyDict_DelItemString(
                        remaining, parameter->name) < 0)
                    goto error;
            } else if (signature->defaults[index] != NULL) {
                value = signature->defaults[index];
            } else if (bind_missing(
                           signature, parameter->name,
                           "keyword-only") < 0) {
                goto error;
            }
            if (value != NULL &&
                PyDict_SetItemString(
                    bound, parameter->name, value) < 0)
                goto error;
        } else if (parameter->kind == WRTC_PY_PARAM_VAR_KEYWORD) {
            if (PyDict_SetItemString(
                    bound, parameter->name, remaining) < 0)
                goto error;
            wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
            Py_CLEAR(remaining);
        }
    }
    if (position < positional_count) {
        PyErr_Format(PyExc_TypeError,
                     "%s() takes %zd positional arguments but %zd were given",
                     signature->name, position, positional_count);
        goto error;
    }
    if (remaining != NULL && PyDict_Size(remaining) != 0) {
        PyObject *key = NULL, *unused = NULL;
        Py_ssize_t cursor = 0;
        (void)PyDict_Next(remaining, &cursor, &key, &unused);
        const char *name = key == NULL ? "" : PyUnicode_AsUTF8(key);
        if (!has_var_keyword)
            PyErr_Format(PyExc_TypeError,
                         "%s() got an unexpected keyword argument '%s'",
                         signature->name, name == NULL ? "" : name);
        goto error;
    }
    if (remaining != NULL) {
        wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
        Py_DECREF(remaining);
    }
    *locals = bound;
    return 0;
error:
    if (remaining != NULL) {
        wrtc_native_allocation_free(WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);
        Py_DECREF(remaining);
    }
    if (bound != NULL) wrtc_native_allocation_release_locals(bound);
    return -1;
}
