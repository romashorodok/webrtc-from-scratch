#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "boxed_executor.h"

typedef enum {
    WRTC_FLOW_NORMAL = 0,
    WRTC_FLOW_RETURN,
    WRTC_FLOW_BREAK,
    WRTC_FLOW_CONTINUE
} WrtcFlow;

typedef struct {
    PyObject *globals;
    PyObject *locals;
    PyObject *return_value;
    char **local_names;
    size_t local_count;
    const WrtcBoxedNativeHooks *hooks;
} WrtcBoxedFrame;

static PyObject *evaluate(const WrtcPyExprIR *expression,
                          WrtcBoxedFrame *frame);
static int execute_statements(const WrtcPyStmtIR *statements, size_t count,
                              WrtcBoxedFrame *frame, WrtcFlow *flow);

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
    return PyRun_StringFlags(expression->text, Py_eval_input,
                             frame->globals, frame->locals, NULL);
}

static PyObject *binary_operation(const char *operation, PyObject *left,
                                  PyObject *right, int inplace) {
#define BINARY(name, regular, in_place) \
    if (strcmp(operation, name) == 0) \
        return inplace ? in_place(left, right) : regular(left, right)
    BINARY("Add", PyNumber_Add, PyNumber_InPlaceAdd);
    BINARY("Sub", PyNumber_Subtract, PyNumber_InPlaceSubtract);
    BINARY("Mult", PyNumber_Multiply, PyNumber_InPlaceMultiply);
    BINARY("MatMult", PyNumber_MatrixMultiply, PyNumber_InPlaceMatrixMultiply);
    BINARY("TrueDiv", PyNumber_TrueDivide, PyNumber_InPlaceTrueDivide);
    BINARY("FloorDiv", PyNumber_FloorDivide, PyNumber_InPlaceFloorDivide);
    BINARY("Mod", PyNumber_Remainder, PyNumber_InPlaceRemainder);
    BINARY("LShift", PyNumber_Lshift, PyNumber_InPlaceLshift);
    BINARY("RShift", PyNumber_Rshift, PyNumber_InPlaceRshift);
    BINARY("BitAnd", PyNumber_And, PyNumber_InPlaceAnd);
    BINARY("BitXor", PyNumber_Xor, PyNumber_InPlaceXor);
    BINARY("BitOr", PyNumber_Or, PyNumber_InPlaceOr);
#undef BINARY
    if (strcmp(operation, "Pow") == 0)
        return inplace
                   ? PyNumber_InPlacePower(left, right, Py_None)
                   : PyNumber_Power(left, right, Py_None);
    PyErr_Format(PyExc_SystemError, "unknown boxed binary operation %s",
                 operation);
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
    PyObject *arguments = NULL, *keywords = NULL, *result = NULL;
    size_t index;
    if (callable == NULL) return NULL;
    arguments = PyTuple_New((Py_ssize_t)expression->positional_count);
    keywords = PyDict_New();
    if (arguments == NULL || keywords == NULL) goto done;
    for (index = 0u; index < expression->positional_count; index++) {
        PyObject *value = evaluate(&expression->children[1u + index], frame);
        if (value == NULL) goto done;
        PyTuple_SET_ITEM(arguments, (Py_ssize_t)index, value);
    }
    for (index = 0u; index < expression->keyword_count; index++) {
        PyObject *value = evaluate(
            &expression->children[1u + expression->positional_count + index],
            frame);
        if (value == NULL ||
            PyDict_SetItemString(
                keywords, expression->keyword_names[index], value) < 0) {
            Py_XDECREF(value);
            goto done;
        }
        Py_DECREF(value);
    }
    result = PyObject_Call(callable, arguments, keywords);
done:
    Py_XDECREF(keywords);
    Py_XDECREF(arguments);
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
    for (index = 0u; index < expression->child_count; index++) {
        PyObject *value = evaluate(&expression->children[index], frame);
        if (value == NULL) {
            Py_DECREF(result);
            return NULL;
        }
        if (tuple)
            PyTuple_SET_ITEM(result, (Py_ssize_t)index, value);
        else
            PyList_SET_ITEM(result, (Py_ssize_t)index, value);
    }
    return result;
}

static PyObject *evaluate_dict(const WrtcPyExprIR *expression,
                               WrtcBoxedFrame *frame) {
    PyObject *result = PyDict_New();
    size_t index;
    if (result == NULL) return NULL;
    if (expression->child_count % 2u != 0u) {
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
            Py_DECREF(result);
            return NULL;
        }
        Py_DECREF(value);
        Py_DECREF(key);
    }
    return result;
}

static PyObject *evaluate_joined_string(const WrtcPyExprIR *expression,
                                        WrtcBoxedFrame *frame) {
    PyObject *parts = PyTuple_New((Py_ssize_t)expression->child_count);
    PyObject *separator = NULL, *result = NULL;
    size_t index;
    if (parts == NULL) return NULL;
    for (index = 0u; index < expression->child_count; index++) {
        PyObject *part = evaluate(&expression->children[index], frame);
        if (part == NULL) goto done;
        PyTuple_SET_ITEM(parts, (Py_ssize_t)index, part);
    }
    separator = PyUnicode_FromString("");
    if (separator != NULL) result = PyUnicode_Join(separator, parts);
done:
    Py_XDECREF(separator);
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
    Py_DECREF(locals);
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
    lambda->lambda = expression;
    lambda->globals = Py_NewRef(frame->globals);
    capsule = PyCapsule_New(
        lambda, "wrtc.boxed_lambda", boxed_lambda_capsule_clear);
    if (capsule == NULL) {
        Py_DECREF(lambda->globals);
        PyMem_Free(lambda);
        return NULL;
    }
    callable = PyCFunction_New(&boxed_lambda_method, capsule);
    Py_DECREF(capsule);
    return callable;
}

static PyObject *evaluate(const WrtcPyExprIR *expression,
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
            result = PyObject_GetAttrString(first, expression->operation);
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
                binary_operation(expression->operation, first, second, 0);
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
            lvalue->value = PyObject_GetAttrString(
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
                statement->operation, lvalue.value, right, 1);
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
    if (suite == NULL || !PyDict_Check(globals) ||
        !PyDict_Check(locals) || result == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "boxed executor requires suite and dict environments");
        return -1;
    }
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
        return -1;
    }
    if (flow == WRTC_FLOW_BREAK || flow == WRTC_FLOW_CONTINUE) {
        Py_XDECREF(frame.return_value);
        PyErr_SetString(PyExc_SyntaxError,
                        "loop control escaped native region");
        return -1;
    }
    *result = frame.return_value == NULL
                  ? Py_NewRef(Py_None) : frame.return_value;
    return 0;
}

int wrtc_boxed_execute(const WrtcPySuiteIR *suite, PyObject *globals,
                       PyObject *locals, PyObject **result) {
    return wrtc_boxed_execute_with_hooks(
        suite, globals, locals, NULL, result);
}

PyObject *wrtc_boxed_hook_evaluate(
    const WrtcPyExprIR *expression, void *frame) {
    return evaluate(expression, (WrtcBoxedFrame *)frame);
}

PyObject *wrtc_boxed_hook_local(const char *name, void *frame) {
    return lookup_name((WrtcBoxedFrame *)frame, name);
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
    remaining = kwargs == NULL ? PyDict_New() : PyDict_Copy(kwargs);
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
    Py_XDECREF(remaining);
    *locals = bound;
    return 0;
error:
    Py_XDECREF(remaining);
    Py_XDECREF(bound);
    return -1;
}
