#include "lowering.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static PyObject *attribute(PyObject *object, const char *name) {
    return PyObject_GetAttrString(object, name);
}

static const char *node_kind(PyObject *node) {
    return Py_TYPE(node)->tp_name;
}

static int is_kind(PyObject *node, const char *expected) {
    const char *actual = node_kind(node);
    const char *dot = strrchr(actual, '.');
    if (dot != NULL) actual = dot + 1;
    return strcmp(actual, expected) == 0;
}

static WrtcSourceSpan span_of(PyObject *node) {
    WrtcSourceSpan span = {1, 1, 1, 1};
    PyObject *value = attribute(node, "lineno");
    if (value != NULL) { span.line = (int)PyLong_AsLong(value); Py_DECREF(value); }
    else PyErr_Clear();
    value = attribute(node, "col_offset");
    if (value != NULL) { span.column = (int)PyLong_AsLong(value) + 1; Py_DECREF(value); }
    else PyErr_Clear();
    value = attribute(node, "end_lineno");
    if (value != NULL) { span.end_line = (int)PyLong_AsLong(value); Py_DECREF(value); }
    else PyErr_Clear();
    value = attribute(node, "end_col_offset");
    if (value != NULL) { span.end_column = (int)PyLong_AsLong(value) + 1; Py_DECREF(value); }
    else PyErr_Clear();
    return span;
}

static char *copy_string(const char *value) {
    size_t length = strlen(value) + 1u;
    char *result = malloc(length);
    if (result != NULL) memcpy(result, value, length);
    return result;
}

static char *identifier(PyObject *node) {
    PyObject *name = attribute(node, "id");
    const char *text;
    char *result;
    if (name == NULL) return NULL;
    text = PyUnicode_AsUTF8(name);
    result = text == NULL ? NULL : copy_string(text);
    Py_DECREF(name);
    return result;
}

static char *definition_name(PyObject *node) {
    PyObject *name = attribute(node, "name");
    const char *text;
    char *result;
    if (name == NULL) return NULL;
    text = PyUnicode_AsUTF8(name);
    result = text == NULL ? NULL : copy_string(text);
    Py_DECREF(name);
    return result;
}

static WrtcTypeKind annotation_type(PyObject *annotation) {
    char *name;
    WrtcTypeKind result = WRTC_TYPE_UNKNOWN;
    if (annotation == NULL || annotation == Py_None) return WRTC_TYPE_UNKNOWN;
    if (is_kind(annotation, "Subscript")) {
        PyObject *value = attribute(annotation, "value");
        result = annotation_type(value);
        Py_XDECREF(value);
        return result;
    }
    if (!is_kind(annotation, "Name")) return WRTC_TYPE_UNKNOWN;
    name = identifier(annotation);
    if (name == NULL) return WRTC_TYPE_UNKNOWN;
    if (strcmp(name, "None") == 0) result = WRTC_TYPE_NONE;
    else if (strcmp(name, "bool") == 0) result = WRTC_TYPE_BOOL;
    else if (strcmp(name, "int") == 0) result = WRTC_TYPE_INT;
    else if (strcmp(name, "object") == 0) result = WRTC_TYPE_OBJECT;
    else if (strcmp(name, "str") == 0) result = WRTC_TYPE_STR;
    else if (strcmp(name, "bytes") == 0) result = WRTC_TYPE_BYTES;
    else if (strcmp(name, "bytearray") == 0) result = WRTC_TYPE_BYTE_VECTOR;
    else if (strcmp(name, "memoryview") == 0) result = WRTC_TYPE_BUFFER;
    else if (strcmp(name, "tuple") == 0) result = WRTC_TYPE_TUPLE;
    else if (strcmp(name, "list") == 0) result = WRTC_TYPE_LIST;
    free(name);
    return result;
}

static int operation_append(WrtcLoweredFunction *function,
                            WrtcLoweringOpKind kind, PyObject *node,
                            size_t target) {
    size_t count = function->operation_count + 1u;
    WrtcLoweringOp *operations;
    if (count < function->operation_count) return PyErr_NoMemory(), -1;
    operations = realloc(function->operations, count * sizeof(*operations));
    if (operations == NULL) return PyErr_NoMemory(), -1;
    function->operations = operations;
    operations[count - 1u].kind = kind;
    operations[count - 1u].span = span_of(node);
    operations[count - 1u].target_function = target;
    operations[count - 1u].syntax_kind = copy_string(node_kind(node));
    operations[count - 1u].symbol = NULL;
    operations[count - 1u].type = WRTC_TYPE_UNKNOWN;
    operations[count - 1u].parent = SIZE_MAX;
    operations[count - 1u].subtree_end = count;
    operations[count - 1u].owns_value = kind == WRTC_LOWER_OP_ALLOCATE ||
                                        kind == WRTC_LOWER_OP_RECORD_CONSTRUCT;
    operations[count - 1u].role = NULL;
    operations[count - 1u].role_index = SIZE_MAX;
    operations[count - 1u].operands = NULL;
    operations[count - 1u].operand_count = 0u;
    operations[count - 1u].literal = NULL;
    operations[count - 1u].record_index = SIZE_MAX;
    operations[count - 1u].element_type = WRTC_TYPE_UNKNOWN;
    operations[count - 1u].element_record_index = SIZE_MAX;
    operations[count - 1u].bit_width = 0u;
    operations[count - 1u].is_signed = 0u;
    operations[count - 1u].wraps = 0u;
    if (operations[count - 1u].syntax_kind == NULL) return PyErr_NoMemory(), -1;
    function->operation_count = count;
    return 0;
}

static int add_operand(WrtcLoweringOp *operation, size_t operand) {
    size_t count = operation->operand_count + 1u;
    size_t *operands;
    if (count < operation->operand_count) return PyErr_NoMemory(), -1;
    operands = realloc(operation->operands, count * sizeof(*operands));
    if (operands == NULL) return PyErr_NoMemory(), -1;
    operation->operands = operands;
    operation->operands[operation->operand_count] = operand;
    operation->operand_count = count;
    return 0;
}

static int set_node_payload(WrtcLoweringOp *operation, PyObject *node) {
    PyObject *value = NULL;
    if (is_kind(node, "Name")) value = attribute(node, "id");
    else if (is_kind(node, "Attribute")) value = attribute(node, "attr");
    else if (is_kind(node, "arg") || is_kind(node, "keyword"))
        value = attribute(node, "arg");
    else if (is_kind(node, "FunctionDef")) value = attribute(node, "name");
    if (value != NULL && value != Py_None) {
        const char *text = PyUnicode_AsUTF8(value);
        if (text == NULL) { Py_DECREF(value); return -1; }
        if (operation->symbol == NULL) operation->symbol = copy_string(text);
        Py_DECREF(value);
        if (operation->symbol == NULL) return PyErr_NoMemory(), -1;
    } else Py_XDECREF(value);
    if (is_kind(node, "Constant")) {
        PyObject *constant = attribute(node, "value");
        PyObject *representation = constant == NULL ? NULL : PyObject_Repr(constant);
        const char *text = representation == NULL ? NULL : PyUnicode_AsUTF8(representation);
        if (text == NULL) { Py_XDECREF(representation); Py_XDECREF(constant); return -1; }
        operation->literal = copy_string(text);
        Py_DECREF(representation); Py_DECREF(constant);
        if (operation->literal == NULL) return PyErr_NoMemory(), -1;
    }
    return 0;
}

static int function_index(const WrtcCompilerCore *core, const char *name,
                          size_t *index) {
    size_t item;
    for (item = 0u; item < core->function_count; item++) {
        if (strcmp(core->functions[item].name, name) == 0) {
            *index = item;
            return 1;
        }
    }
    return 0;
}

static int record_index(const WrtcCompilerCore *core, const char *name,
                        size_t *index) {
    size_t item;
    for (item = 0u; item < core->record_count; item++)
        if (strcmp(core->records[item].name, name) == 0) {
            *index = item;
            return 1;
        }
    return 0;
}

static WrtcLoweredParameter *find_parameter(WrtcLoweredFunction *function,
                                            const char *name);

static int supported_leaf(PyObject *node) {
    static const char *const names[] = {
        "Load", "Store", "Del", "Add", "Sub", "Mult", "Div", "FloorDiv",
        "Mod", "Pow", "LShift", "RShift", "BitOr", "BitXor", "BitAnd",
        "MatMult", "Invert", "Not", "UAdd", "USub", "Eq", "NotEq", "Lt",
        "LtE", "Gt", "GtE", "Is", "IsNot", "In", "NotIn", "And", "Or",
        "Pass", "Break", "Continue", "keyword", "arguments", "arg",
        "comprehension", "Constant", "Name", "Tuple", "List", "Set", "Dict",
        "BinOp", "UnaryOp", "BoolOp", "Compare", "IfExp", "Attribute",
        "Subscript", "Starred", "JoinedStr", "FormattedValue", "Assign",
        "AnnAssign", "AugAssign", "Expr", NULL
    };
    size_t index;
    for (index = 0u; names[index] != NULL; index++)
        if (is_kind(node, names[index])) return 1;
    return 0;
}

static void set_last_type(WrtcLoweredFunction *function, WrtcTypeKind type) {
    if (function->operation_count != 0u)
        function->operations[function->operation_count - 1u].type = type;
}

static WrtcTypeKind constant_type(PyObject *node) {
    PyObject *value = attribute(node, "value");
    WrtcTypeKind type = WRTC_TYPE_UNKNOWN;
    if (value == Py_None) type = WRTC_TYPE_NONE;
    else if (value != NULL && PyBool_Check(value)) type = WRTC_TYPE_BOOL;
    else if (value != NULL && PyLong_CheckExact(value)) type = WRTC_TYPE_INT;
    else if (value != NULL && PyUnicode_CheckExact(value)) type = WRTC_TYPE_STR;
    else if (value != NULL && PyBytes_CheckExact(value)) type = WRTC_TYPE_BYTES;
    Py_XDECREF(value);
    return type;
}

static int classify(PyObject *node, const WrtcCompilerCore *core,
                    WrtcLoweredFunction *function) {
    if (is_kind(node, "If") || is_kind(node, "IfExp")) {
        int status = operation_append(function, WRTC_LOWER_OP_BRANCH, node, SIZE_MAX);
        if (status == 0 && is_kind(node, "If")) set_last_type(function, WRTC_TYPE_NONE);
        return status;
    }
    if (is_kind(node, "For"))
        return operation_append(function, WRTC_LOWER_OP_FOR, node, SIZE_MAX);
    if (is_kind(node, "While"))
        return operation_append(function, WRTC_LOWER_OP_WHILE, node, SIZE_MAX);
    if (is_kind(node, "Raise"))
        return operation_append(function, WRTC_LOWER_OP_RAISE, node, SIZE_MAX);
    if (is_kind(node, "Return"))
        return operation_append(function, WRTC_LOWER_OP_RETURN, node, SIZE_MAX);
    if (is_kind(node, "GeneratorExp") || is_kind(node, "ListComp") ||
        is_kind(node, "SetComp") || is_kind(node, "DictComp")) {
        function->cleanup_slot_count++;
        return operation_append(function, WRTC_LOWER_OP_ANY_GENERATOR, node,
                                SIZE_MAX);
    }
    if (is_kind(node, "Slice"))
        return operation_append(function, WRTC_LOWER_OP_SLICE, node, SIZE_MAX);
    if (is_kind(node, "List") || is_kind(node, "Dict") ||
        is_kind(node, "Set")) {
        int status;
        function->cleanup_slot_count++;
        status = operation_append(function, WRTC_LOWER_OP_ALLOCATE, node, SIZE_MAX);
        if (status == 0 && is_kind(node, "List"))
            set_last_type(function, WRTC_TYPE_LIST);
        return status;
    }
    if (is_kind(node, "Call")) {
        PyObject *callable = attribute(node, "func");
        if (callable == NULL) return -1;
        if (is_kind(callable, "Name")) {
            char *name = identifier(callable);
            size_t target;
            int status = 0;
            if (name == NULL) { Py_DECREF(callable); return -1; }
            if (function_index(core, name, &target)) {
                status = operation_append(function, WRTC_LOWER_OP_DIRECT_CALL,
                                          node, target);
                if (status == 0) set_last_type(function, core->functions[target].type);
            }
            else if (record_index(core, name, &target)) {
                function->cleanup_slot_count++;
                status = operation_append(function, WRTC_LOWER_OP_RECORD_CONSTRUCT,
                                          node, SIZE_MAX);
                if (status == 0) {
                    set_last_type(function, WRTC_TYPE_RECORD);
                    function->operations[function->operation_count - 1u].record_index =
                        target;
                }
            } else if (strcmp(name, "any") == 0)
                status = operation_append(function, WRTC_LOWER_OP_ANY_GENERATOR,
                                          node, SIZE_MAX);
            else if (strcmp(name, "bytes") == 0 || strcmp(name, "bytearray") == 0 ||
                     strcmp(name, "list") == 0 || strcmp(name, "tuple") == 0 ||
                     strcmp(name, "memoryview") == 0) {
                function->cleanup_slot_count++;
                status = operation_append(function, WRTC_LOWER_OP_ALLOCATE, node,
                                          SIZE_MAX);
                if (status == 0) {
                    if (strcmp(name, "bytes") == 0)
                        set_last_type(function, WRTC_TYPE_BYTES);
                    else if (strcmp(name, "bytearray") == 0)
                        set_last_type(function, WRTC_TYPE_BYTE_VECTOR);
                    else if (strcmp(name, "list") == 0) set_last_type(function, WRTC_TYPE_LIST);
                    else if (strcmp(name, "tuple") == 0) set_last_type(function, WRTC_TYPE_TUPLE);
                    else set_last_type(function, WRTC_TYPE_BUFFER);
                }
            } else if (strcmp(name, "len") == 0 || strcmp(name, "range") == 0 ||
                       strcmp(name, "enumerate") == 0 || strcmp(name, "bool") == 0 ||
                       strcmp(name, "min") == 0 || strcmp(name, "max") == 0 ||
                       strcmp(name, "type") == 0 || strcmp(name, "ValueError") == 0 ||
                       strcmp(name, "TypeError") == 0) {
                status = operation_append(function, WRTC_LOWER_OP_BUILTIN_CALL,
                                          node, SIZE_MAX);
            } else {
                PyErr_Format(PyExc_ValueError,
                             "%s:%d:%d: error: unsupported call target %s",
                             core->filename, span_of(node).line,
                             span_of(node).column, name);
                status = -1;
            }
            if (status == 0 && function->operation_count != 0u)
                function->operations[function->operation_count - 1u].symbol =
                    copy_string(name);
            free(name);
            Py_DECREF(callable);
            return status;
        }
        if (is_kind(callable, "Attribute")) {
            PyObject *attribute_name = attribute(callable, "attr");
            const char *name = attribute_name == NULL ? NULL :
                               PyUnicode_AsUTF8(attribute_name);
            WrtcLoweringOpKind kind = WRTC_LOWER_OP_PROPERTY;
            if (name == NULL) { Py_XDECREF(attribute_name); Py_DECREF(callable); return -1; }
            if (strcmp(name, "append") == 0) kind = WRTC_LOWER_OP_COLLECTION_APPEND;
            else if (strcmp(name, "extend") == 0) kind = WRTC_LOWER_OP_COLLECTION_EXTEND;
            else if (strcmp(name, "pop") == 0) kind = WRTC_LOWER_OP_COLLECTION_POP;
            else if (strcmp(name, "to_bytes") == 0) kind = WRTC_LOWER_OP_ENDIAN_WRITE;
            else {
                PyErr_Format(PyExc_ValueError,
                             "%s:%d:%d: error: unsupported method call %s",
                             core->filename, span_of(node).line,
                             span_of(node).column, name);
                Py_DECREF(attribute_name); Py_DECREF(callable); return -1;
            }
            Py_DECREF(attribute_name);
            Py_DECREF(callable);
            return operation_append(function, kind, node, SIZE_MAX);
        }
        Py_DECREF(callable);
        return PyErr_Format(PyExc_ValueError,
                            "%s:%d:%d: error: indirect calls are not supported",
                            core->filename, span_of(node).line,
                            span_of(node).column), -1;
    }
    if (is_kind(node, "FunctionDef"))
        return operation_append(function, WRTC_LOWER_OP_FUNCTION, node, SIZE_MAX);
    if (is_kind(node, "Assign") || is_kind(node, "AnnAssign") ||
        is_kind(node, "AugAssign"))
        return operation_append(function, WRTC_LOWER_OP_ASSIGN, node, SIZE_MAX);
    if (is_kind(node, "BinOp") || is_kind(node, "BoolOp"))
        return operation_append(function, WRTC_LOWER_OP_BINARY, node, SIZE_MAX);
    if (is_kind(node, "UnaryOp"))
        return operation_append(function, WRTC_LOWER_OP_UNARY, node, SIZE_MAX);
    if (is_kind(node, "Compare")) {
        int status = operation_append(function, WRTC_LOWER_OP_COMPARE, node, SIZE_MAX);
        if (status == 0) set_last_type(function, WRTC_TYPE_BOOL);
        return status;
    }
    if (is_kind(node, "Attribute"))
        return operation_append(function, WRTC_LOWER_OP_ATTRIBUTE, node, SIZE_MAX);
    if (is_kind(node, "Subscript"))
        return operation_append(function, WRTC_LOWER_OP_SUBSCRIPT, node, SIZE_MAX);
    if (supported_leaf(node)) {
        int status = operation_append(function, WRTC_LOWER_OP_SCALAR, node, SIZE_MAX);
        if (status == 0) {
            if (is_kind(node, "Constant")) {
                WrtcTypeKind literal_type = constant_type(node);
                set_last_type(function, literal_type);
                if (literal_type == WRTC_TYPE_INT) {
                    PyObject *literal_value = attribute(node, "value");
                    unsigned long long raw = literal_value == NULL ? 0u :
                                             PyLong_AsUnsignedLongLongMask(literal_value);
                    unsigned width = 1u;
                    while (width < 64u && (raw >> width) != 0u) width++;
                    function->operations[function->operation_count - 1u].bit_width = width;
                    function->operations[function->operation_count - 1u].is_signed = 1u;
                    Py_XDECREF(literal_value);
                }
            }
            else if (is_kind(node, "Tuple")) set_last_type(function, WRTC_TYPE_TUPLE);
            else if (is_kind(node, "List")) set_last_type(function, WRTC_TYPE_LIST);
            else if (is_kind(node, "Name")) {
                char *name = identifier(node);
                WrtcLoweredParameter *parameter = name == NULL ? NULL :
                                                    find_parameter(function, name);
                if (parameter != NULL) set_last_type(function, parameter->boxed_type);
                free(name);
            }
        }
        return status;
    }
    return PyErr_Format(PyExc_ValueError,
                        "%s:%d:%d: error: untranslated reachable node %s",
                        core->filename, span_of(node).line, span_of(node).column,
                        node_kind(node)), -1;
}

static int walk(PyObject *node, const WrtcCompilerCore *core,
                WrtcLoweredFunction *function, size_t parent,
                const char *role, size_t role_index) {
    PyObject *fields;
    Py_ssize_t index, count;
    size_t operation_index = function->operation_count;
    if (classify(node, core, function) < 0) return -1;
    if (function->operation_count != operation_index + 1u) {
        PyErr_SetString(PyExc_RuntimeError, "lowering must emit exactly one IR node");
        return -1;
    }
    function->operations[operation_index].parent = parent;
    function->operations[operation_index].role = role == NULL ? NULL : copy_string(role);
    function->operations[operation_index].role_index = role_index;
    if ((role != NULL && function->operations[operation_index].role == NULL) ||
        set_node_payload(&function->operations[operation_index], node) < 0) return -1;
    fields = attribute(node, "_fields");
    if (fields == NULL) { PyErr_Clear(); return 0; }
    count = PySequence_Size(fields);
    for (index = 0; index < count; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attribute(node, name);
        Py_XDECREF(field);
        if (value == NULL) { Py_DECREF(fields); return -1; }
        if ((is_kind(node, "FunctionDef") &&
             (strcmp(name, "decorator_list") == 0 || strcmp(name, "returns") == 0 ||
              strcmp(name, "type_comment") == 0 || strcmp(name, "type_params") == 0)) ||
            (is_kind(node, "arg") && strcmp(name, "annotation") == 0)) {
            Py_DECREF(value);
            continue;
        }
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child_index, child_count = PySequence_Size(value);
            for (child_index = 0; child_index < child_count; child_index++) {
                PyObject *child = PySequence_GetItem(value, child_index);
                size_t child_operation = function->operation_count;
                if (child == NULL || (PyObject_HasAttrString(child, "_fields") &&
                                      walk(child, core, function, operation_index,
                                           name, (size_t)child_index) < 0)) {
                    Py_XDECREF(child); Py_DECREF(value); Py_DECREF(fields); return -1;
                }
                if (PyObject_HasAttrString(child, "_fields") &&
                    add_operand(&function->operations[operation_index], child_operation) < 0) {
                    Py_DECREF(child); Py_DECREF(value); Py_DECREF(fields); return -1;
                }
                Py_DECREF(child);
            }
        } else if (PyObject_HasAttrString(value, "_fields")) {
            size_t child_operation = function->operation_count;
            if (walk(value, core, function, operation_index, name, 0u) < 0 ||
                add_operand(&function->operations[operation_index], child_operation) < 0) {
                Py_DECREF(value); Py_DECREF(fields); return -1;
            }
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    function->operations[operation_index].subtree_end = function->operation_count;
    return 0;
}

static PyObject *annotation_descriptor(PyObject *node) {
    PyObject *left = NULL, *right = NULL, *result = NULL;
    if (node == NULL || node == Py_None) return PyUnicode_FromString("");
    if (is_kind(node, "Name")) return attribute(node, "id");
    if (is_kind(node, "Attribute")) {
        PyObject *value = attribute(node, "value");
        PyObject *name = attribute(node, "attr");
        left = value == NULL ? NULL : annotation_descriptor(value);
        Py_XDECREF(value);
        if (left != NULL && name != NULL)
            result = PyUnicode_FromFormat("%U.%U", left, name);
        Py_XDECREF(left); Py_XDECREF(name);
        return result;
    }
    if (is_kind(node, "Subscript")) {
        PyObject *value = attribute(node, "value");
        PyObject *slice = attribute(node, "slice");
        left = value == NULL ? NULL : annotation_descriptor(value);
        right = slice == NULL ? NULL : annotation_descriptor(slice);
        Py_XDECREF(value); Py_XDECREF(slice);
        if (left != NULL && right != NULL)
            result = PyUnicode_FromFormat("%U[%U]", left, right);
        Py_XDECREF(left); Py_XDECREF(right);
        return result;
    }
    if (is_kind(node, "Tuple")) {
        PyObject *elements = attribute(node, "elts");
        PyObject *parts = elements == NULL ? NULL : PyList_New(0);
        PyObject *separator = NULL;
        Py_ssize_t index, count = elements == NULL ? 0 : PySequence_Size(elements);
        for (index = 0; parts != NULL && index < count; index++) {
            PyObject *element = PySequence_GetItem(elements, index);
            PyObject *part = element == NULL ? NULL : annotation_descriptor(element);
            Py_XDECREF(element);
            if (part == NULL || PyList_Append(parts, part) < 0) {
                Py_XDECREF(part); Py_CLEAR(parts); break;
            }
            Py_DECREF(part);
        }
        separator = parts == NULL ? NULL : PyUnicode_FromString(", ");
        result = separator == NULL ? NULL : PyUnicode_Join(separator, parts);
        Py_XDECREF(separator); Py_XDECREF(parts); Py_XDECREF(elements);
        return result;
    }
    if (is_kind(node, "Constant")) {
        PyObject *value = attribute(node, "value");
        if (value == Py_Ellipsis) result = PyUnicode_FromString("...");
        else if (value == Py_None) result = PyUnicode_FromString("None");
        Py_XDECREF(value);
        if (result != NULL) return result;
    }
    if (is_kind(node, "BinOp")) {
        PyObject *operator_node = attribute(node, "op");
        int is_union = operator_node != NULL && is_kind(operator_node, "BitOr");
        Py_XDECREF(operator_node);
        if (is_union) {
            PyObject *left_node = attribute(node, "left");
            PyObject *right_node = attribute(node, "right");
            left = left_node == NULL ? NULL : annotation_descriptor(left_node);
            right = right_node == NULL ? NULL : annotation_descriptor(right_node);
            Py_XDECREF(left_node); Py_XDECREF(right_node);
            if (left != NULL && right != NULL)
                result = PyUnicode_FromFormat("%U | %U", left, right);
            Py_XDECREF(left); Py_XDECREF(right);
            return result;
        }
    }
    PyErr_Format(PyExc_ValueError, "unsupported annotation node %s", node_kind(node));
    return NULL;
}

static char *annotation_text(PyObject *node) {
    PyObject *descriptor = annotation_descriptor(node);
    const char *text = descriptor == NULL ? NULL : PyUnicode_AsUTF8(descriptor);
    char *copy = text == NULL ? NULL : copy_string(text);
    Py_XDECREF(descriptor);
    return copy;
}

static void type_shape_clear(WrtcTypeShape *shape) {
    size_t index;
    for (index = 0u; index < shape->item_count; index++)
        type_shape_clear(&shape->items[index]);
    free(shape->items);
    memset(shape, 0, sizeof(*shape));
}

static int type_shape_build(PyObject *node, const WrtcCompilerCore *core,
                            WrtcTypeShape *shape) {
    size_t record;
    memset(shape, 0, sizeof(*shape));
    shape->record_index = SIZE_MAX;
    shape->kind = annotation_type(node);
    if (is_kind(node, "Name")) {
        char *name = identifier(node);
        for (record = 0u; name != NULL && record < core->record_count; record++)
            if (strcmp(core->records[record].name, name) == 0) {
                shape->kind = WRTC_TYPE_RECORD;
                shape->record_index = record;
                break;
            }
        free(name);
        return 0;
    }
    if (is_kind(node, "Subscript")) {
        PyObject *base = attribute(node, "value");
        PyObject *slice = attribute(node, "slice");
        PyObject *elements = slice != NULL && is_kind(slice, "Tuple") ?
                             attribute(slice, "elts") : NULL;
        Py_ssize_t index, count = elements == NULL ? 1 : PySequence_Size(elements);
        shape->kind = annotation_type(base);
        if (shape->kind != WRTC_TYPE_TUPLE && shape->kind != WRTC_TYPE_LIST) {
            Py_XDECREF(elements); Py_XDECREF(slice); Py_XDECREF(base);
            PyErr_SetString(PyExc_ValueError,
                            "only tuple and list structural annotations are supported");
            return -1;
        }
        if (count > 0) {
            shape->items = calloc((size_t)count, sizeof(*shape->items));
            if (shape->items == NULL) {
                Py_XDECREF(elements); Py_XDECREF(slice); Py_XDECREF(base);
                return PyErr_NoMemory(), -1;
            }
        }
        for (index = 0; index < count; index++) {
            PyObject *item = elements == NULL ? Py_NewRef(slice) :
                             PySequence_GetItem(elements, index);
            PyObject *constant = item != NULL && is_kind(item, "Constant") ?
                                 attribute(item, "value") : NULL;
            if (constant == Py_Ellipsis) {
                shape->variadic = 1u;
                Py_DECREF(constant); Py_DECREF(item);
                continue;
            }
            Py_XDECREF(constant);
            if (item == NULL || type_shape_build(item, core,
                                                 &shape->items[shape->item_count]) < 0) {
                Py_XDECREF(item); Py_XDECREF(elements); Py_XDECREF(slice);
                Py_XDECREF(base); type_shape_clear(shape); return -1;
            }
            shape->item_count++;
            Py_DECREF(item);
        }
        Py_XDECREF(elements); Py_XDECREF(slice); Py_XDECREF(base);
    }
    return 0;
}

static char *function_docstring(PyObject *node) {
    PyObject *body = attribute(node, "body");
    PyObject *statement = body == NULL || PySequence_Size(body) == 0 ? NULL :
                          PySequence_GetItem(body, 0);
    PyObject *value_node = statement != NULL && is_kind(statement, "Expr") ?
                           attribute(statement, "value") : NULL;
    PyObject *value = value_node != NULL && is_kind(value_node, "Constant") ?
                      attribute(value_node, "value") : NULL;
    PyObject *inspect = value != NULL && PyUnicode_CheckExact(value) ?
                        PyImport_ImportModule("inspect") : NULL;
    PyObject *clean = inspect == NULL ? NULL :
                      PyObject_CallMethod(inspect, "cleandoc", "O", value);
    if (clean != NULL && value != NULL) {
        Py_ssize_t raw_length = PyUnicode_GetLength(value);
        Py_ssize_t tail = raw_length;
        while (tail > 0) {
            Py_UCS4 character = PyUnicode_ReadChar(value, tail - 1);
            if (character != ' ' && character != '\t') break;
            tail--;
        }
        if (tail > 0 && PyUnicode_ReadChar(value, tail - 1) == '\n') {
            PyObject *with_newline = PyUnicode_FromFormat("%U\n", clean);
            if (with_newline != NULL) { Py_DECREF(clean); clean = with_newline; }
        }
    }
    const char *text = clean != NULL ? PyUnicode_AsUTF8(clean) :
                       (value != NULL && PyUnicode_CheckExact(value) ?
                        PyUnicode_AsUTF8(value) : "");
    char *copy = text == NULL ? NULL : copy_string(text);
    Py_XDECREF(clean); Py_XDECREF(inspect); Py_XDECREF(value);
    Py_XDECREF(value_node); Py_XDECREF(statement); Py_XDECREF(body);
    return copy;
}

static size_t declared_record_index(const WrtcCompilerCore *core,
                                    const char *annotation) {
    size_t index;
    if (annotation == NULL) return SIZE_MAX;
    for (index = 0u; index < core->record_count; index++)
        if (strcmp(core->records[index].name, annotation) == 0) return index;
    return SIZE_MAX;
}

static int parameters(PyObject *node, WrtcLoweredFunction *function,
                      const WrtcCompilerCore *core) {
    PyObject *arguments = attribute(node, "args");
    PyObject *items = arguments == NULL ? NULL : attribute(arguments, "args");
    Py_ssize_t index, count;
    Py_XDECREF(arguments);
    if (items == NULL) return -1;
    count = PySequence_Size(items);
    function->parameters = calloc((size_t)count, sizeof(*function->parameters));
    if (count != 0 && function->parameters == NULL) {
        Py_DECREF(items); return PyErr_NoMemory(), -1;
    }
    function->parameter_count = (size_t)count;
    for (index = 0; index < count; index++) {
        PyObject *argument = PySequence_GetItem(items, index);
        PyObject *name = argument == NULL ? NULL : attribute(argument, "arg");
        PyObject *annotation = argument == NULL ? NULL : attribute(argument, "annotation");
        const char *text = name == NULL ? NULL : PyUnicode_AsUTF8(name);
        if (text == NULL) {
            Py_XDECREF(annotation); Py_XDECREF(name); Py_XDECREF(argument);
            Py_DECREF(items); return -1;
        }
        function->parameters[(size_t)index].name = copy_string(text);
        function->parameters[(size_t)index].annotation = annotation_text(annotation);
        if (type_shape_build(annotation, core,
                             &function->parameters[(size_t)index].shape) < 0) {
            Py_XDECREF(annotation); Py_DECREF(name); Py_DECREF(argument);
            Py_DECREF(items); return -1;
        }
        function->parameters[(size_t)index].boxed_type = annotation_type(annotation);
        function->parameters[(size_t)index].refined_type = WRTC_TYPE_UNKNOWN;
        function->parameters[(size_t)index].record_index = SIZE_MAX;
        function->parameters[(size_t)index].element_record_index = SIZE_MAX;
        function->parameters[(size_t)index].record_index =
            declared_record_index(core,
                function->parameters[(size_t)index].annotation);
        if ((function->parameters[(size_t)index].shape.kind == WRTC_TYPE_TUPLE ||
             function->parameters[(size_t)index].shape.kind == WRTC_TYPE_LIST) &&
            function->parameters[(size_t)index].shape.variadic &&
            function->parameters[(size_t)index].shape.item_count == 1u) {
            function->parameters[(size_t)index].element_type =
                function->parameters[(size_t)index].shape.items[0].kind;
            function->parameters[(size_t)index].element_record_index =
                function->parameters[(size_t)index].shape.items[0].record_index;
        }
        if (function->parameters[(size_t)index].record_index != SIZE_MAX) {
            function->parameters[(size_t)index].boxed_type = WRTC_TYPE_RECORD;
            function->parameters[(size_t)index].refined_type = WRTC_TYPE_RECORD;
        }
        function->parameters[(size_t)index].span = span_of(argument);
        Py_XDECREF(annotation); Py_DECREF(name); Py_DECREF(argument);
        if (function->parameters[(size_t)index].name == NULL ||
            function->parameters[(size_t)index].annotation == NULL) {
            Py_DECREF(items); return PyErr_NoMemory(), -1;
        }
    }
    Py_DECREF(items);
    return 0;
}

static char *dotted_name(PyObject *node) {
    if (is_kind(node, "Name")) return identifier(node);
    if (is_kind(node, "Attribute")) {
        PyObject *value = attribute(node, "value");
        PyObject *name = attribute(node, "attr");
        char *prefix = value == NULL ? NULL : dotted_name(value);
        const char *suffix = name == NULL ? NULL : PyUnicode_AsUTF8(name);
        char *result = NULL;
        if (prefix != NULL && suffix != NULL) {
            size_t length = strlen(prefix) + strlen(suffix) + 2u;
            result = malloc(length);
            if (result != NULL) (void)snprintf(result, length, "%s.%s", prefix, suffix);
        }
        free(prefix); Py_XDECREF(name); Py_XDECREF(value);
        return result;
    }
    return NULL;
}

static int constant_u64(PyObject *node, const WrtcCompilerCore *core,
                        unsigned long long *result) {
    PyObject *value = NULL;
    if (is_kind(node, "Constant")) value = attribute(node, "value");
    else if (is_kind(node, "Name")) {
        char *name = identifier(node);
        if (name != NULL) value = PyDict_GetItemString(core->constant_values, name);
        Py_XINCREF(value); free(name);
    }
    if (value == NULL || !PyLong_CheckExact(value)) { Py_XDECREF(value); return -1; }
    *result = PyLong_AsUnsignedLongLong(value);
    Py_DECREF(value);
    return PyErr_Occurred() ? -1 : 0;
}

static WrtcLoweredParameter *find_parameter(WrtcLoweredFunction *function,
                                            const char *name) {
    size_t index;
    for (index = 0u; index < function->parameter_count; index++)
        if (strcmp(function->parameters[index].name, name) == 0)
            return &function->parameters[index];
    return NULL;
}

static int apply_spec(PyObject *spec, const WrtcCompilerCore *core,
                      WrtcLoweredParameter *parameter) {
    PyObject *callable = spec;
    PyObject *arguments = NULL, *keywords = NULL;
    char *name;
    if (is_kind(spec, "Call")) {
        callable = attribute(spec, "func");
        arguments = attribute(spec, "args");
        keywords = attribute(spec, "keywords");
        if (callable == NULL || arguments == NULL || keywords == NULL) goto error;
    } else Py_INCREF(callable);
    name = dotted_name(callable);
    if (name == NULL) goto error;
    if (strcmp(name, "pymeta.u8") == 0 || strcmp(name, "pymeta.u16") == 0 ||
        strcmp(name, "pymeta.u32") == 0 || strcmp(name, "pymeta.u64") == 0) {
        parameter->boxed_type = WRTC_TYPE_INT;
        parameter->refined_type = WRTC_TYPE_INT;
        parameter->bit_width = (unsigned)strtoul(name + strlen("pymeta.u"), NULL, 10);
        parameter->has_range = 1u; parameter->low = 0u;
        parameter->high = parameter->bit_width == 64u ? ULLONG_MAX :
                          (1ull << parameter->bit_width) - 1ull;
    } else if (strcmp(name, "pymeta.Integer") == 0) {
        unsigned long long width;
        PyObject *first = arguments == NULL || PySequence_Size(arguments) == 0 ?
                          NULL : PySequence_GetItem(arguments, 0);
        if (first == NULL || constant_u64(first, core, &width) < 0 || width == 0u || width > 64u) {
            Py_XDECREF(first); free(name); goto error;
        }
        Py_DECREF(first); parameter->boxed_type = WRTC_TYPE_INT;
        parameter->refined_type = WRTC_TYPE_INT;
        parameter->bit_width = (unsigned)width; parameter->has_range = 1u;
        parameter->low = 0u; parameter->high = width == 64u ? ULLONG_MAX :
                                               (1ull << width) - 1ull;
        if (keywords != NULL) {
            Py_ssize_t index, count = PySequence_Size(keywords);
            for (index = 0; index < count; index++) {
                PyObject *keyword = PySequence_GetItem(keywords, index);
                PyObject *arg = keyword == NULL ? NULL : attribute(keyword, "arg");
                PyObject *value = keyword == NULL ? NULL : attribute(keyword, "value");
                const char *key = arg == NULL ? NULL : PyUnicode_AsUTF8(arg);
                char *setting = value == NULL ? NULL : dotted_name(value);
                if (key != NULL && strcmp(key, "overflow") == 0 && setting != NULL &&
                    strstr(setting, "WRAP") != NULL) parameter->wraps = 1u;
                free(setting); Py_XDECREF(value); Py_XDECREF(arg); Py_XDECREF(keyword);
            }
        }
    } else if (strcmp(name, "pymeta.buffer") == 0) {
        parameter->boxed_type = WRTC_TYPE_BYTES;
        parameter->refined_type = WRTC_TYPE_BUFFER;
        if (keywords != NULL) {
            Py_ssize_t index, count = PySequence_Size(keywords);
            for (index = 0; index < count; index++) {
                PyObject *keyword = PySequence_GetItem(keywords, index);
                PyObject *arg = keyword == NULL ? NULL : attribute(keyword, "arg");
                PyObject *value = keyword == NULL ? NULL : attribute(keyword, "value");
                const char *key = arg == NULL ? NULL : PyUnicode_AsUTF8(arg);
                unsigned long long maximum;
                if (key != NULL && strcmp(key, "maximum") == 0 && value != NULL &&
                    constant_u64(value, core, &maximum) == 0 && maximum <= SIZE_MAX)
                    parameter->maximum_length = (size_t)maximum;
                Py_XDECREF(value); Py_XDECREF(arg); Py_XDECREF(keyword);
            }
        }
    } else { free(name); goto error; }
    free(name); Py_XDECREF(keywords); Py_XDECREF(arguments); Py_DECREF(callable);
    return 0;
error:
    Py_XDECREF(keywords); Py_XDECREF(arguments); Py_XDECREF(callable);
    return -1;
}

static int apply_region(PyObject *node, const WrtcCompilerCore *core,
                        WrtcLoweredFunction *function) {
    PyObject *decorators = attribute(node, "decorator_list");
    Py_ssize_t index, count;
    int found = 0;
    if (decorators == NULL) return -1;
    count = PySequence_Size(decorators);
    for (index = 0; index < count; index++) {
        PyObject *decorator = PySequence_GetItem(decorators, index);
        PyObject *callable = decorator != NULL && is_kind(decorator, "Call") ?
                             attribute(decorator, "func") : NULL;
        char *name = callable == NULL ? NULL : dotted_name(callable);
        if (name != NULL && strcmp(name, "pymeta.region") == 0) {
            PyObject *keywords = attribute(decorator, "keywords");
            Py_ssize_t keyword_index, keyword_count = keywords == NULL ? 0 :
                                                   PySequence_Size(keywords);
            found = 1;
            for (keyword_index = 0; keyword_index < keyword_count; keyword_index++) {
                PyObject *keyword = PySequence_GetItem(keywords, keyword_index);
                PyObject *arg = keyword == NULL ? NULL : attribute(keyword, "arg");
                PyObject *value = keyword == NULL ? NULL : attribute(keyword, "value");
                const char *key = arg == NULL ? NULL : PyUnicode_AsUTF8(arg);
                WrtcLoweredParameter *parameter = key == NULL ? NULL :
                                                    find_parameter(function, key);
                if (parameter == NULL || value == NULL ||
                    apply_spec(value, core, parameter) < 0) {
                    Py_XDECREF(value); Py_XDECREF(arg); Py_XDECREF(keyword);
                    Py_XDECREF(keywords); free(name); Py_XDECREF(callable);
                    Py_XDECREF(decorator); Py_DECREF(decorators); return -1;
                }
                Py_DECREF(value); Py_DECREF(arg); Py_DECREF(keyword);
            }
            Py_XDECREF(keywords);
        }
        free(name); Py_XDECREF(callable); Py_XDECREF(decorator);
    }
    Py_DECREF(decorators);
    if (function->is_public && !found) {
        PyErr_Format(PyExc_ValueError, "%s:%d:%d: error: public function requires pymeta.region metadata",
                     core->filename, span_of(node).line, span_of(node).column);
        return -1;
    }
    if (function->is_public) {
        size_t parameter_index;
        for (parameter_index = 0u; parameter_index < function->parameter_count;
             parameter_index++) {
            WrtcLoweredParameter *parameter = &function->parameters[parameter_index];
            int complete_integer = parameter->boxed_type == WRTC_TYPE_INT &&
                                   parameter->has_range && parameter->bit_width != 0u;
            int complete_buffer = parameter->boxed_type == WRTC_TYPE_BYTES &&
                                  parameter->maximum_length != 0u;
            if (!complete_integer && !complete_buffer) {
                PyErr_Format(PyExc_ValueError,
                             "%s:%d:%d: error: parameter %s lacks complete region typing",
                             core->filename, parameter->span.line,
                             parameter->span.column, parameter->name);
                return -1;
            }
        }
    }
    return 0;
}

static WrtcTypeKind python_value_type(PyObject *value) {
    if (value == Py_None) return WRTC_TYPE_NONE;
    if (PyBool_Check(value)) return WRTC_TYPE_BOOL;
    if (PyLong_CheckExact(value)) return WRTC_TYPE_INT;
    if (PyUnicode_CheckExact(value)) return WRTC_TYPE_STR;
    if (PyBytes_CheckExact(value)) return WRTC_TYPE_BYTES;
    if (PyTuple_Check(value)) return WRTC_TYPE_TUPLE;
    if (PyList_Check(value)) return WRTC_TYPE_LIST;
    return WRTC_TYPE_UNKNOWN;
}

static int build_constants(const WrtcCompilerCore *core,
                           WrtcLoweringProgram *program) {
    Py_ssize_t index, count = PyList_GET_SIZE(core->constant_names);
    program->constant_count = (size_t)count;
    program->constants = calloc(program->constant_count, sizeof(*program->constants));
    if (program->constant_count != 0u && program->constants == NULL)
        return PyErr_NoMemory(), -1;
    for (index = 0; index < count; index++) {
        PyObject *name = PyList_GET_ITEM(core->constant_names, index);
        const char *text = PyUnicode_AsUTF8(name);
        PyObject *value = text == NULL ? NULL : PyDict_GetItemString(core->constant_values, text);
        PyObject *representation = value == NULL ? NULL : PyObject_Repr(value);
        const char *literal = representation == NULL ? NULL : PyUnicode_AsUTF8(representation);
        if (text == NULL || literal == NULL) { Py_XDECREF(representation); return -1; }
        program->constants[(size_t)index].name = copy_string(text);
        program->constants[(size_t)index].type = python_value_type(value);
        program->constants[(size_t)index].literal = copy_string(literal);
        Py_DECREF(representation);
        if (program->constants[(size_t)index].name == NULL ||
            program->constants[(size_t)index].literal == NULL)
            return PyErr_NoMemory(), -1;
    }
    return 0;
}

static const WrtcLoweringOp *child_with_role(const WrtcLoweredFunction *function,
                                             const WrtcLoweringOp *operation,
                                             const char *role) {
    size_t index;
    for (index = 0u; index < operation->operand_count; index++) {
        const WrtcLoweringOp *child = &function->operations[operation->operands[index]];
        if (child->role != NULL && strcmp(child->role, role) == 0) return child;
    }
    return NULL;
}

static WrtcLoweredLocal *find_local(WrtcLoweredFunction *function,
                                    const char *name) {
    size_t index;
    for (index = 0u; index < function->local_count; index++)
        if (strcmp(function->locals[index].name, name) == 0)
            return &function->locals[index];
    return NULL;
}

static int merge_local(WrtcLoweredFunction *function, const char *name,
                       const WrtcLoweringOp *value, WrtcSourceSpan span) {
    WrtcLoweredLocal *local = find_local(function, name);
    if (local == NULL) {
        size_t count = function->local_count + 1u;
        WrtcLoweredLocal *items;
        if (count < function->local_count) return PyErr_NoMemory(), -1;
        items = realloc(function->locals, count * sizeof(*items));
        if (items == NULL) return PyErr_NoMemory(), -1;
        function->locals = items;
        local = &items[function->local_count];
        memset(local, 0, sizeof(*local));
        local->name = copy_string(name);
        if (local->name == NULL) return PyErr_NoMemory(), -1;
        local->record_index = SIZE_MAX;
        local->element_record_index = SIZE_MAX;
        local->span = span;
        function->local_count = count;
    }
    if (value->type == WRTC_TYPE_UNKNOWN) return 0;
    if (local->type != WRTC_TYPE_UNKNOWN && local->type != value->type) {
        PyErr_Format(PyExc_ValueError,
                     "ambiguous native type for local %s at %d:%d", name,
                     span.line, span.column);
        return -1;
    }
    local->type = value->type;
    if (value->bit_width != 0u) {
        if (value->bit_width > local->bit_width)
            local->bit_width = value->bit_width;
        local->is_signed = local->is_signed || value->is_signed;
        local->wraps = local->wraps || value->wraps;
    }
    local->owns_value = value->owns_value;
    if (value->record_index != SIZE_MAX) {
        if (local->record_index != SIZE_MAX &&
            local->record_index != value->record_index) {
            PyErr_Format(PyExc_ValueError,
                         "ambiguous native record type for local %s at %d:%d",
                         name, span.line, span.column);
            return -1;
        }
        local->record_index = value->record_index;
    }
    if (value->element_type != WRTC_TYPE_UNKNOWN) {
        if (local->element_type != WRTC_TYPE_UNKNOWN &&
            local->element_type != value->element_type) {
            PyErr_Format(PyExc_ValueError,
                         "ambiguous native element type for local %s at %d:%d",
                         name, span.line, span.column);
            return -1;
        }
        local->element_type = value->element_type;
        local->element_record_index = value->element_record_index;
    }
    return 0;
}

static int collect_locals(WrtcLoweredFunction *function) {
    size_t index;
    for (index = 0u; index < function->operation_count; index++) {
        WrtcLoweringOp *assignment = &function->operations[index];
        const WrtcLoweringOp *value;
        size_t target_index;
        if (assignment->kind != WRTC_LOWER_OP_ASSIGN) continue;
        value = child_with_role(function, assignment, "value");
        if (value == NULL) continue;
        for (target_index = index + 1u;
             target_index < assignment->subtree_end; target_index++) {
            const WrtcLoweringOp *target = &function->operations[target_index];
            int tuple_target_item = 0;
            if (target->role != NULL && strcmp(target->role, "elts") == 0 &&
                target->parent < function->operation_count) {
                const WrtcLoweringOp *parent =
                    &function->operations[target->parent];
                tuple_target_item = parent->role != NULL &&
                    (strcmp(parent->role, "targets") == 0 ||
                     strcmp(parent->role, "target") == 0);
            }
            if (target->symbol == NULL || target->role == NULL ||
                (!tuple_target_item && strcmp(target->role, "targets") != 0 &&
                 strcmp(target->role, "target") != 0)) continue;
            if (tuple_target_item) {
                WrtcLoweringOp unknown_value = *value;
                unknown_value.type = WRTC_TYPE_UNKNOWN;
                unknown_value.record_index = SIZE_MAX;
                if (merge_local(function, target->symbol, &unknown_value,
                                target->span) < 0) return -1;
            } else if (merge_local(function, target->symbol, value,
                                   target->span) < 0)
                return -1;
        }
    }
    return 0;
}

static int propagate_resolved_types(WrtcLoweredFunction *function) {
    size_t pass;
    for (pass = 0u; pass <= function->operation_count; pass++) {
        size_t index;
        int changed = 0;
        for (index = 0u; index < function->operation_count; index++) {
            WrtcLoweringOp *operation = &function->operations[index];
            if (operation->kind == WRTC_LOWER_OP_BINARY) {
                const WrtcLoweringOp *left = child_with_role(function, operation, "left");
                const WrtcLoweringOp *right = child_with_role(function, operation, "right");
                if (left == NULL) left = child_with_role(function, operation, "values");
                if (left != NULL && right != NULL &&
                    (left->type == WRTC_TYPE_BYTES ||
                     left->type == WRTC_TYPE_BYTE_VECTOR) &&
                    (right->type == WRTC_TYPE_BYTES ||
                     right->type == WRTC_TYPE_BYTE_VECTOR)) {
                    operation->type = left->type == WRTC_TYPE_BYTE_VECTOR ||
                                      right->type == WRTC_TYPE_BYTE_VECTOR ?
                                      WRTC_TYPE_BYTE_VECTOR : WRTC_TYPE_BYTES;
                    operation->owns_value = 1u;
                } else if (left != NULL && right != NULL &&
                           left->type == WRTC_TYPE_INT &&
                           right->type == WRTC_TYPE_INT) {
                    unsigned width = left->bit_width > right->bit_width ?
                                     left->bit_width : right->bit_width;
                    if (operation->bit_width != width) changed = 1;
                    operation->type = WRTC_TYPE_INT;
                    operation->bit_width = width;
                    operation->is_signed = left->is_signed || right->is_signed;
                    operation->wraps = left->wraps || right->wraps;
                }
            }
            if (strcmp(operation->syntax_kind, "Name") == 0 &&
                operation->symbol != NULL) {
                WrtcLoweredLocal *local = find_local(function, operation->symbol);
                WrtcLoweredParameter *parameter =
                    find_parameter(function, operation->symbol);
                if (local != NULL) {
                    if (operation->type == WRTC_TYPE_UNKNOWN &&
                        local->type != WRTC_TYPE_UNKNOWN) {
                        operation->type = local->type;
                        changed = 1;
                    }
                    operation->record_index = local->record_index;
                    operation->element_type = local->element_type;
                    operation->element_record_index = local->element_record_index;
                    operation->bit_width = local->bit_width;
                    operation->is_signed = local->is_signed;
                    operation->wraps = local->wraps;
                } else if (parameter != NULL) {
                    operation->record_index = parameter->record_index;
                    operation->element_type = parameter->element_type;
                    operation->element_record_index = parameter->element_record_index;
                    operation->bit_width = parameter->bit_width;
                    operation->wraps = parameter->wraps;
                    operation->is_signed = parameter->bit_width == 0u;
                }
            } else if (operation->kind == WRTC_LOWER_OP_SUBSCRIPT) {
                const WrtcLoweringOp *container =
                    child_with_role(function, operation, "value");
                const WrtcLoweringOp *slice =
                    child_with_role(function, operation, "slice");
                if (container != NULL && slice != NULL &&
                    strcmp(slice->syntax_kind, "Slice") != 0 &&
                    container->element_type != WRTC_TYPE_UNKNOWN) {
                    operation->type = container->element_type;
                    operation->record_index =
                        container->element_record_index;
                    changed = 1;
                }
            } else if (strcmp(operation->syntax_kind, "List") == 0 &&
                       operation->operand_count != 0u) {
                size_t operand_index;
                WrtcTypeKind element_type = WRTC_TYPE_UNKNOWN;
                size_t element_record = SIZE_MAX;
                for (operand_index = 0u; operand_index < operation->operand_count;
                     operand_index++) {
                    const WrtcLoweringOp *element =
                        &function->operations[operation->operands[operand_index]];
                    if (element->role == NULL || strcmp(element->role, "elts") != 0)
                        continue;
                    if (element_type == WRTC_TYPE_UNKNOWN) {
                        element_type = element->type;
                        element_record = element->record_index;
                    } else if (element->type != WRTC_TYPE_UNKNOWN &&
                               element_type != element->type) {
                        PyErr_Format(PyExc_ValueError,
                                     "ambiguous native element type at %d:%d",
                                     operation->span.line, operation->span.column);
                        return -1;
                    }
                }
                if (operation->element_type == WRTC_TYPE_UNKNOWN &&
                    element_type != WRTC_TYPE_UNKNOWN) {
                    operation->element_type = element_type;
                    operation->element_record_index = element_record;
                    changed = 1;
                }
            }
        }
        if (collect_locals(function) < 0) return -1;
        for (index = 0u; index < function->operation_count; index++) {
            WrtcLoweringOp *operation = &function->operations[index];
            const WrtcLoweringOp *callable;
            const WrtcLoweringOp *receiver;
            WrtcLoweredLocal *local;
            if (operation->kind != WRTC_LOWER_OP_COLLECTION_APPEND &&
                operation->kind != WRTC_LOWER_OP_COLLECTION_EXTEND &&
                operation->kind != WRTC_LOWER_OP_COLLECTION_POP) continue;
            callable = child_with_role(function, operation, "func");
            receiver = callable == NULL ? NULL :
                       child_with_role(function, callable, "value");
            local = receiver == NULL || receiver->symbol == NULL ? NULL :
                    find_local(function, receiver->symbol);
            if (local == NULL) continue;
            if (operation->kind == WRTC_LOWER_OP_COLLECTION_APPEND) {
                const WrtcLoweringOp *item = child_with_role(function, operation, "args");
                if (item != NULL && item->type != WRTC_TYPE_UNKNOWN) {
                    if (local->element_type != WRTC_TYPE_UNKNOWN &&
                        local->element_type != item->type) {
                        PyErr_Format(PyExc_ValueError,
                                     "ambiguous native element type for %s at %d:%d",
                                     local->name, operation->span.line,
                                     operation->span.column);
                        return -1;
                    }
                    if (local->element_type == WRTC_TYPE_UNKNOWN) changed = 1;
                    local->element_type = item->type;
                    local->element_record_index = item->record_index;
                }
                operation->type = WRTC_TYPE_NONE;
            } else if (operation->kind == WRTC_LOWER_OP_COLLECTION_POP &&
                       local->element_type != WRTC_TYPE_UNKNOWN) {
                if (operation->type == WRTC_TYPE_UNKNOWN) changed = 1;
                operation->type = local->element_type;
                operation->record_index = local->element_record_index;
            }
        }
        if (!changed) break;
    }
    return 0;
}

static int resolve_loop_targets(WrtcLoweredFunction *function) {
    size_t index;
    for (index = 0u; index < function->operation_count; index++) {
        WrtcLoweringOp *loop = &function->operations[index];
        const WrtcLoweringOp *iterator;
        const WrtcLoweringOp *target;
        WrtcLoweringOp value;
        if (loop->kind != WRTC_LOWER_OP_FOR) continue;
        iterator = child_with_role(function, loop, "iter");
        target = child_with_role(function, loop, "target");
        if (iterator == NULL || target == NULL) continue;
        memset(&value, 0, sizeof(value));
        value.record_index = SIZE_MAX;
        value.element_record_index = SIZE_MAX;
        if (iterator->kind == WRTC_LOWER_OP_BUILTIN_CALL &&
            iterator->symbol != NULL && strcmp(iterator->symbol, "range") == 0) {
            value.type = WRTC_TYPE_INT;
            if (target->symbol != NULL &&
                merge_local(function, target->symbol, &value, target->span) < 0)
                return -1;
        } else if (iterator->kind == WRTC_LOWER_OP_BUILTIN_CALL &&
                   iterator->symbol != NULL &&
                   strcmp(iterator->symbol, "enumerate") == 0) {
            const WrtcLoweringOp *source = child_with_role(function, iterator, "args");
            size_t target_item;
            for (target_item = 0u; target_item < target->operand_count; target_item++) {
                const WrtcLoweringOp *name =
                    &function->operations[target->operands[target_item]];
                if (name->symbol == NULL || name->role == NULL ||
                    strcmp(name->role, "elts") != 0) continue;
                value.type = name->role_index == 0u ? WRTC_TYPE_INT :
                             (source == NULL ? WRTC_TYPE_UNKNOWN : source->element_type);
                value.record_index = name->role_index == 0u || source == NULL ?
                                     SIZE_MAX : source->element_record_index;
                if (merge_local(function, name->symbol, &value, name->span) < 0)
                    return -1;
            }
        } else if (target->symbol != NULL &&
                   iterator->element_type != WRTC_TYPE_UNKNOWN) {
            value.type = iterator->element_type;
            value.record_index = iterator->element_record_index;
            if (merge_local(function, target->symbol, &value, target->span) < 0)
                return -1;
        } else if (strcmp(target->syntax_kind, "Tuple") == 0) {
            size_t target_item;
            for (target_item = 0u; target_item < target->operand_count;
                 target_item++) {
                const WrtcLoweringOp *name =
                    &function->operations[target->operands[target_item]];
                if (name->symbol != NULL && name->role != NULL &&
                    strcmp(name->role, "elts") == 0 &&
                    merge_local(function, name->symbol, &value,
                                name->span) < 0) return -1;
            }
        }
    }
    return 0;
}

static int resolve_attributes(WrtcLoweredFunction *function,
                              const WrtcLoweringProgram *program) {
    size_t index;
    for (index = 0u; index < function->operation_count; index++) {
        WrtcLoweringOp *attribute_op = &function->operations[index];
        const WrtcLoweringOp *receiver;
        const WrtcLoweredRecord *record;
        size_t field;
        if (attribute_op->kind != WRTC_LOWER_OP_ATTRIBUTE ||
            attribute_op->symbol == NULL) continue;
        receiver = child_with_role(function, attribute_op, "value");
        if (receiver == NULL || receiver->record_index == SIZE_MAX ||
            receiver->record_index >= program->record_count) continue;
        record = &program->records[receiver->record_index];
        attribute_op->record_index = receiver->record_index;
        for (field = 0u; field < record->field_count; field++)
            if (strcmp(record->fields[field].name, attribute_op->symbol) == 0) {
                attribute_op->type = record->fields[field].type;
                break;
            }
        if (field == record->field_count) {
            for (field = 0u; field < record->property_count; field++)
                if (strcmp(record->properties[field].name,
                           attribute_op->symbol) == 0) {
                    attribute_op->type = record->properties[field].return_type;
                    break;
                }
            if (field == record->property_count) {
                PyErr_Format(PyExc_ValueError,
                             "unknown field %s on native record %s at %d:%d",
                             attribute_op->symbol, record->name,
                             attribute_op->span.line,
                             attribute_op->span.column);
                return -1;
            }
        }
    }
    return 0;
}

static void infer_function_types(WrtcLoweredFunction *function,
                                 const WrtcCompilerCore *core) {
    size_t pass;
    for (pass = 0u; pass < function->operation_count + 1u; pass++) {
        size_t index;
        int changed = 0;
        for (index = 0u; index < function->operation_count; index++) {
            WrtcLoweringOp *operation = &function->operations[index];
            WrtcTypeKind inferred = operation->type;
            if (inferred != WRTC_TYPE_UNKNOWN) continue;
            if (strcmp(operation->syntax_kind, "Name") == 0 && operation->symbol != NULL) {
                WrtcLoweredParameter *parameter = find_parameter(function, operation->symbol);
                PyObject *constant = PyDict_GetItemString(core->constant_values,
                                                          operation->symbol);
                size_t previous;
                if (parameter != NULL) inferred = parameter->boxed_type;
                else if (constant != NULL) inferred = python_value_type(constant);
                for (previous = 0u; inferred == WRTC_TYPE_UNKNOWN && previous < index;
                     previous++) {
                    const WrtcLoweringOp *assignment = &function->operations[previous];
                    const WrtcLoweringOp *value;
                    size_t target_index;
                    if (assignment->kind != WRTC_LOWER_OP_ASSIGN) continue;
                    value = child_with_role(function, assignment, "value");
                    if (value == NULL || value->type == WRTC_TYPE_UNKNOWN) continue;
                    for (target_index = previous + 1u;
                         target_index < assignment->subtree_end; target_index++) {
                        const WrtcLoweringOp *target = &function->operations[target_index];
                        if (target->symbol != NULL && target->role != NULL &&
                            (strcmp(target->role, "targets") == 0 ||
                             strcmp(target->role, "target") == 0) &&
                            strcmp(target->symbol, operation->symbol) == 0)
                            inferred = value->type;
                    }
                }
            } else if (operation->kind == WRTC_LOWER_OP_BINARY ||
                       operation->kind == WRTC_LOWER_OP_UNARY)
                inferred = WRTC_TYPE_INT;
            else if (operation->kind == WRTC_LOWER_OP_COMPARE ||
                     operation->kind == WRTC_LOWER_OP_ANY_GENERATOR)
                inferred = WRTC_TYPE_BOOL;
            else if (operation->kind == WRTC_LOWER_OP_BUILTIN_CALL &&
                     operation->symbol != NULL) {
                if (strcmp(operation->symbol, "len") == 0 ||
                    strcmp(operation->symbol, "min") == 0 ||
                    strcmp(operation->symbol, "max") == 0)
                    inferred = WRTC_TYPE_INT;
                else if (strcmp(operation->symbol, "bool") == 0)
                    inferred = WRTC_TYPE_BOOL;
            } else if (operation->kind == WRTC_LOWER_OP_SUBSCRIPT) {
                const WrtcLoweringOp *value = child_with_role(function, operation, "value");
                const WrtcLoweringOp *slice = child_with_role(function, operation, "slice");
                if (value != NULL && slice != NULL &&
                    strcmp(slice->syntax_kind, "Slice") == 0) inferred = value->type;
                else if (value != NULL && (value->type == WRTC_TYPE_BYTES ||
                                           value->type == WRTC_TYPE_BUFFER))
                    inferred = WRTC_TYPE_INT;
            } else if (strcmp(operation->syntax_kind, "IfExp") == 0) {
                const WrtcLoweringOp *body = child_with_role(function, operation, "body");
                const WrtcLoweringOp *alternative = child_with_role(function, operation, "orelse");
                if (body != NULL && alternative != NULL && body->type == alternative->type)
                    inferred = body->type;
            }
            if (inferred != WRTC_TYPE_UNKNOWN) {
                operation->type = inferred; changed = 1;
            }
        }
        if (!changed) break;
    }
}

static PyObject *find_definition(const WrtcCompilerCore *core, const char *name) {
    PyObject *body = attribute(core->tree, "body");
    Py_ssize_t index, count;
    if (body == NULL) return NULL;
    count = PySequence_Size(body);
    for (index = 0; index < count; index++) {
        PyObject *node = PySequence_GetItem(body, index);
        if (node != NULL && is_kind(node, "FunctionDef")) {
            char *candidate = definition_name(node);
            int equal = candidate != NULL && strcmp(candidate, name) == 0;
            free(candidate);
            if (equal) { Py_DECREF(body); return node; }
        }
        Py_XDECREF(node);
    }
    Py_DECREF(body);
    return NULL;
}

static int build_records(const WrtcCompilerCore *core,
                         WrtcLoweringProgram *program) {
    size_t record_index;
    PyObject *body = attribute(core->tree, "body");
    if (body == NULL) return -1;
    program->record_count = core->record_count;
    program->records = calloc(program->record_count, sizeof(*program->records));
    if (program->record_count != 0u && program->records == NULL) {
        Py_DECREF(body); return PyErr_NoMemory(), -1;
    }
    for (record_index = 0u; record_index < program->record_count; record_index++) {
        WrtcLoweredRecord *record = &program->records[record_index];
        const WrtcRecordIR *source = &core->records[record_index];
        size_t field_index;
        Py_ssize_t node_index, node_count = PySequence_Size(body);
        PyObject *definition = NULL;
        record->name = copy_string(source->name);
        record->field_count = source->field_count;
        record->property_count = source->property_count;
        record->fields = calloc(record->field_count, sizeof(*record->fields));
        record->properties = calloc(record->property_count, sizeof(*record->properties));
        if (record->name == NULL || (record->field_count != 0u && record->fields == NULL) ||
            (record->property_count != 0u && record->properties == NULL)) {
            Py_DECREF(body); return PyErr_NoMemory(), -1;
        }
        for (field_index = 0u; field_index < record->field_count; field_index++) {
            record->fields[field_index].name = copy_string(source->fields[field_index].name);
            record->fields[field_index].type = source->fields[field_index].type;
            record->fields[field_index].has_default = source->fields[field_index].has_default;
            if (record->fields[field_index].name == NULL) {
                Py_DECREF(body); return PyErr_NoMemory(), -1;
            }
        }
        for (node_index = 0; node_index < node_count; node_index++) {
            PyObject *node = PySequence_GetItem(body, node_index);
            if (node != NULL && is_kind(node, "ClassDef")) {
                char *name = definition_name(node);
                if (name != NULL && strcmp(name, record->name) == 0)
                    definition = Py_NewRef(node);
                free(name);
            }
            Py_XDECREF(node);
            if (definition != NULL) break;
        }
        if (definition != NULL) {
            PyObject *members = attribute(definition, "body");
            Py_ssize_t member_index, member_count = members == NULL ? 0 : PySequence_Size(members);
            size_t property_index = 0u;
            for (member_index = 0; member_index < member_count; member_index++) {
                PyObject *member = PySequence_GetItem(members, member_index);
                if (member != NULL && is_kind(member, "AnnAssign")) {
                    PyObject *target = attribute(member, "target");
                    PyObject *value = attribute(member, "value");
                    char *name = target != NULL && is_kind(target, "Name") ? identifier(target) : NULL;
                    for (field_index = 0u; name != NULL && field_index < record->field_count; field_index++) {
                        if (strcmp(record->fields[field_index].name, name) == 0 &&
                            value != NULL && value != Py_None) {
                            PyObject *literal_value = is_kind(value, "Constant") ?
                                                      attribute(value, "value") : Py_NewRef(value);
                            PyObject *representation = literal_value == NULL ? NULL :
                                                       PyObject_Repr(literal_value);
                            const char *text = representation == NULL ? NULL : PyUnicode_AsUTF8(representation);
                            if (text != NULL) record->fields[field_index].default_literal = copy_string(text);
                            Py_XDECREF(representation); Py_XDECREF(literal_value);
                        }
                    }
                    free(name); Py_XDECREF(value); Py_XDECREF(target);
                } else if (member != NULL && is_kind(member, "FunctionDef") &&
                           property_index < record->property_count) {
                    WrtcLoweredFunction *property = &record->properties[property_index++];
                    PyObject *returns = attribute(member, "returns");
                    property->name = definition_name(member);
                    property->docstring = function_docstring(member);
                    property->return_annotation = annotation_text(returns);
                    if (type_shape_build(returns, core,
                                         &property->return_shape) < 0) {
                        Py_XDECREF(returns); Py_XDECREF(member);
                        Py_XDECREF(members); Py_DECREF(definition);
                        Py_DECREF(body); return -1;
                    }
                    property->return_type = annotation_type(returns);
                    Py_XDECREF(returns);
                    if (property->name == NULL || parameters(member, property, core) < 0 ||
                        property->docstring == NULL ||
                        property->return_annotation == NULL ||
                        walk(member, core, property, SIZE_MAX, NULL, 0u) < 0) {
                        Py_XDECREF(member); Py_XDECREF(members); Py_DECREF(definition);
                        Py_DECREF(body); return -1;
                    }
                    if (property->parameter_count != 1u) {
                        PyErr_Format(PyExc_ValueError,
                                     "%s:%d:%d: error: record property requires self only",
                                     core->filename, span_of(member).line,
                                     span_of(member).column);
                        Py_DECREF(member); Py_DECREF(members); Py_DECREF(definition);
                        Py_DECREF(body); return -1;
                    }
                    property->parameters[0].boxed_type = WRTC_TYPE_RECORD;
                    property->parameters[0].refined_type = WRTC_TYPE_RECORD;
                    property->parameters[0].record_index = record_index;
                    infer_function_types(property, core);
                    if (collect_locals(property) < 0 ||
                        propagate_resolved_types(property) < 0 ||
                        resolve_loop_targets(property) < 0) {
                        Py_XDECREF(member); Py_XDECREF(members);
                        Py_DECREF(definition); Py_DECREF(body); return -1;
                    }
                }
                Py_XDECREF(member);
            }
            Py_XDECREF(members); Py_DECREF(definition);
        }
    }
    Py_DECREF(body);
    return 0;
}

int wrtc_lowering_build(const WrtcCompilerCore *core, WrtcLoweringProgram **out) {
    WrtcLoweringProgram *program = calloc(1, sizeof(*program));
    size_t source_index, output_index = 0u;
    if (program == NULL) return PyErr_NoMemory(), -1;
    if (build_constants(core, program) < 0) {
        wrtc_lowering_free(program); return -1;
    }
    if (build_records(core, program) < 0) {
        wrtc_lowering_free(program); return -1;
    }
    {
        size_t record, property;
        for (record = 0u; record < program->record_count; record++)
            for (property = 0u;
                 property < program->records[record].property_count; property++)
                if (resolve_attributes(
                        &program->records[record].properties[property],
                        program) < 0) {
                    wrtc_lowering_free(program); return -1;
                }
    }
    for (source_index = 0u; source_index < core->function_count; source_index++)
        if (core->functions[source_index].is_reachable) program->function_count++;
    program->functions = calloc(program->function_count, sizeof(*program->functions));
    if (program->function_count != 0u && program->functions == NULL) {
        wrtc_lowering_free(program); return PyErr_NoMemory(), -1;
    }
    for (source_index = 0u; source_index < core->function_count; source_index++) {
        PyObject *definition;
        WrtcLoweredFunction *function;
        if (!core->functions[source_index].is_reachable) continue;
        function = &program->functions[output_index++];
        function->name = copy_string(core->functions[source_index].name);
        function->return_type = core->functions[source_index].type;
        function->return_record_index = SIZE_MAX;
        function->is_public = core->functions[source_index].is_public;
        definition = find_definition(core, function->name);
        if (definition != NULL) {
            PyObject *returns = attribute(definition, "returns");
            function->docstring = function_docstring(definition);
            function->return_annotation = annotation_text(returns);
            if (type_shape_build(returns, core, &function->return_shape) < 0) {
                Py_XDECREF(returns); Py_DECREF(definition);
                wrtc_lowering_free(program); return -1;
            }
            Py_XDECREF(returns);
            {
                size_t declared = declared_record_index(core,
                                                        function->return_annotation);
                if (declared != SIZE_MAX) {
                    function->return_type = WRTC_TYPE_RECORD;
                    function->return_record_index = declared;
                }
            }
        }
        if (function->name == NULL || definition == NULL ||
            function->docstring == NULL || function->return_annotation == NULL ||
            parameters(definition, function, core) < 0 ||
            apply_region(definition, core, function) < 0 ||
            walk(definition, core, function, SIZE_MAX, NULL, 0u) < 0) {
            Py_XDECREF(definition); wrtc_lowering_free(program); return -1;
        }
        infer_function_types(function, core);
        if (collect_locals(function) < 0 ||
            propagate_resolved_types(function) < 0 ||
            resolve_loop_targets(function) < 0 ||
            propagate_resolved_types(function) < 0 ||
            resolve_attributes(function, program) < 0) {
            Py_DECREF(definition); wrtc_lowering_free(program); return -1;
        }
        Py_DECREF(definition);
    }
    {
        size_t function_index_value;
        for (function_index_value = 0u; function_index_value < program->function_count;
             function_index_value++) {
            WrtcLoweredFunction *function = &program->functions[function_index_value];
            size_t operation_index;
            for (operation_index = 0u; operation_index < function->operation_count;
                 operation_index++) {
                WrtcLoweringOp *operation = &function->operations[operation_index];
                size_t target;
                if (operation->kind != WRTC_LOWER_OP_DIRECT_CALL ||
                    operation->symbol == NULL) continue;
                operation->target_function = SIZE_MAX;
                for (target = 0u; target < program->function_count; target++)
                    if (strcmp(program->functions[target].name, operation->symbol) == 0)
                        operation->target_function = target;
                if (operation->target_function == SIZE_MAX) {
                    PyErr_Format(PyExc_ValueError,
                                 "%s:%d:%d: error: unresolved IR call target %s",
                                 core->filename, operation->span.line,
                                 operation->span.column, operation->symbol);
                    wrtc_lowering_free(program); return -1;
                }
                operation->type = program->functions[operation->target_function].return_type;
                operation->record_index =
                    program->functions[operation->target_function].return_record_index;
                {
                    const WrtcTypeShape *shape =
                        &program->functions[operation->target_function].return_shape;
                    if ((shape->kind == WRTC_TYPE_TUPLE ||
                         shape->kind == WRTC_TYPE_LIST) &&
                        shape->item_count == 1u && shape->variadic) {
                        operation->element_type = shape->items[0].kind;
                        operation->element_record_index =
                            shape->items[0].record_index;
                    }
                }
            }
        }
    }
    {
        size_t function_index_value;
        for (function_index_value = 0u;
             function_index_value < program->function_count;
             function_index_value++) {
            WrtcLoweredFunction *function =
                &program->functions[function_index_value];
            if (collect_locals(function) < 0 ||
                propagate_resolved_types(function) < 0 ||
                resolve_loop_targets(function) < 0 ||
                propagate_resolved_types(function) < 0 ||
                resolve_attributes(function, program) < 0) {
                wrtc_lowering_free(program); return -1;
            }
        }
    }
    *out = program;
    return 0;
}

void wrtc_lowering_free(WrtcLoweringProgram *program) {
    size_t function_index_value;
    if (program == NULL) return;
    for (function_index_value = 0u; function_index_value < program->function_count;
         function_index_value++) {
        WrtcLoweredFunction *function = &program->functions[function_index_value];
        size_t parameter_index;
        for (parameter_index = 0u; parameter_index < function->parameter_count;
             parameter_index++) {
            free(function->parameters[parameter_index].name);
            free(function->parameters[parameter_index].annotation);
            type_shape_clear(&function->parameters[parameter_index].shape);
        }
        free(function->parameters);
        for (parameter_index = 0u; parameter_index < function->local_count;
             parameter_index++) free(function->locals[parameter_index].name);
        free(function->locals);
        for (parameter_index = 0u; parameter_index < function->operation_count;
             parameter_index++) {
            free(function->operations[parameter_index].syntax_kind);
            free(function->operations[parameter_index].symbol);
            free(function->operations[parameter_index].role);
            free(function->operations[parameter_index].operands);
            free(function->operations[parameter_index].literal);
        }
        free(function->operations);
        free(function->docstring);
        free(function->return_annotation);
        type_shape_clear(&function->return_shape);
        free(function->name);
    }
    free(program->functions);
    for (function_index_value = 0u; function_index_value < program->record_count;
         function_index_value++) {
        WrtcLoweredRecord *record = &program->records[function_index_value];
        size_t field_index;
        for (field_index = 0u; field_index < record->field_count; field_index++) {
            free(record->fields[field_index].name);
            free(record->fields[field_index].default_literal);
        }
        for (field_index = 0u; field_index < record->property_count; field_index++) {
            WrtcLoweredFunction *property = &record->properties[field_index];
            size_t item;
            for (item = 0u; item < property->parameter_count; item++)
                { free(property->parameters[item].name);
                  free(property->parameters[item].annotation);
                  type_shape_clear(&property->parameters[item].shape); }
            for (item = 0u; item < property->operation_count; item++) {
                free(property->operations[item].syntax_kind);
                free(property->operations[item].symbol);
                free(property->operations[item].role);
                free(property->operations[item].operands);
                free(property->operations[item].literal);
            }
            free(property->parameters); free(property->operations);
            free(property->docstring); free(property->return_annotation);
            type_shape_clear(&property->return_shape);
            free(property->name);
        }
        free(record->properties); free(record->fields); free(record->name);
    }
    free(program->records);
    for (function_index_value = 0u; function_index_value < program->constant_count;
         function_index_value++) {
        free(program->constants[function_index_value].name);
        free(program->constants[function_index_value].literal);
    }
    free(program->constants);
    free(program);
}

const WrtcLoweredFunction *wrtc_lowering_find_function(
    const WrtcLoweringProgram *program, const char *name) {
    size_t index;
    for (index = 0u; index < program->function_count; index++)
        if (strcmp(program->functions[index].name, name) == 0)
            return &program->functions[index];
    return NULL;
}
