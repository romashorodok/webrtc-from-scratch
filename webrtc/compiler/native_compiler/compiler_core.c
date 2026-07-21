#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include "compiler_core.h"

typedef struct { size_t begin; size_t end; } Cut;
typedef struct { Cut *items; size_t count; size_t capacity; } Cuts;

static char *copy_text(const char *value) {
    const size_t n = strlen(value);
    char *copy = malloc(n + 1u);
    if (copy != NULL) memcpy(copy, value, n + 1u);
    return copy;
}

static const char *kind(PyObject *node) {
    const char *name = Py_TYPE(node)->tp_name;
    const char *dot = strrchr(name, '.');
    return dot == NULL ? name : dot + 1;
}

static int is_kind(PyObject *node, const char *name) {
    return node != NULL && strcmp(kind(node), name) == 0;
}

static PyObject *attr(PyObject *node, const char *name) {
    return PyObject_GetAttrString(node, name);
}

static int integer_attr(PyObject *node, const char *name, int fallback) {
    PyObject *value = attr(node, name);
    long result;
    if (value == NULL) { PyErr_Clear(); return fallback; }
    result = PyLong_AsLong(value); Py_DECREF(value);
    if (result == -1 && PyErr_Occurred()) { PyErr_Clear(); return fallback; }
    return (int)result;
}

static WrtcSourceSpan span_of(PyObject *node) {
    WrtcSourceSpan span;
    span.line = integer_attr(node, "lineno", 1);
    span.column = integer_attr(node, "col_offset", 0) + 1;
    span.end_line = integer_attr(node, "end_lineno", span.line);
    span.end_column = integer_attr(node, "end_col_offset", span.column - 1) + 1;
    return span;
}

static int diagnostic(const char *filename, PyObject *node, const char *message) {
    const WrtcSourceSpan span = span_of(node);
    PyErr_Format(PyExc_ValueError, "%s:%d:%d: error: %s", filename,
                 span.line, span.column, message);
    return -1;
}

static char *name_value(PyObject *node) {
    PyObject *value = attr(node, "id");
    const char *raw; char *result = NULL;
    if (value == NULL) return NULL;
    raw = PyUnicode_AsUTF8(value);
    if (raw != NULL) result = copy_text(raw);
    Py_DECREF(value); return result;
}

static char *definition_name(PyObject *node) {
    PyObject *value = attr(node, "name");
    const char *raw; char *result = NULL;
    if (value == NULL) return NULL;
    raw = PyUnicode_AsUTF8(value);
    if (raw != NULL) result = copy_text(raw);
    Py_DECREF(value); return result;
}

static char *decorator_name(PyObject *node) {
    if (is_kind(node, "Call")) {
        PyObject *function = attr(node, "func"); char *result;
        if (function == NULL) return NULL;
        result = decorator_name(function); Py_DECREF(function); return result;
    }
    if (is_kind(node, "Name")) return name_value(node);
    if (is_kind(node, "Attribute")) {
        PyObject *base = attr(node, "value"), *field = attr(node, "attr");
        char *left = NULL, *result = NULL; const char *right;
        if (base == NULL || field == NULL) goto done;
        left = decorator_name(base); right = PyUnicode_AsUTF8(field);
        if (left != NULL && right != NULL) {
            result = malloc(strlen(left) + strlen(right) + 2u);
            if (result != NULL) (void)sprintf(result, "%s.%s", left, right);
        }
done: free(left); Py_XDECREF(field); Py_XDECREF(base); return result;
    }
    return copy_text("");
}

static int safe_value(PyObject *node, PyObject *constants, PyObject **out);

static int metadata_expr(PyObject *node, PyObject *constants) {
    PyObject *value = NULL;
    if (safe_value(node, constants, &value) == 0) { Py_DECREF(value); return 0; }
    PyErr_Clear();
    if (is_kind(node, "Attribute")) {
        char *name = decorator_name(node); int allowed = name != NULL && strncmp(name, "pymeta.", 7) == 0;
        free(name); if (allowed) return 0;
    }
    if (is_kind(node, "Name")) {
        char *name = name_value(node); int allowed = name != NULL &&
            (strcmp(name, "u8") == 0 || strcmp(name, "u16") == 0 || strcmp(name, "u32") == 0 ||
             strcmp(name, "u64") == 0 || strcmp(name, "Integer") == 0 || strcmp(name, "buffer") == 0);
        free(name); if (allowed) return 0;
    }
    if (is_kind(node, "Call")) {
        PyObject *function = attr(node, "func"), *args = attr(node, "args"), *keywords = attr(node, "keywords");
        char *name = function == NULL ? NULL : decorator_name(function); Py_ssize_t i, count;
        int allowed = name != NULL && (strncmp(name, "pymeta.", 7) == 0 || strcmp(name, "Integer") == 0 || strcmp(name, "buffer") == 0);
        free(name); Py_XDECREF(function);
        if (!allowed || args == NULL || keywords == NULL) { Py_XDECREF(keywords); Py_XDECREF(args); return -1; }
        count = PySequence_Size(args);
        for (i = 0; i < count; i++) { PyObject *item = PySequence_GetItem(args, i); if (item == NULL || metadata_expr(item, constants) < 0) { Py_XDECREF(item); Py_DECREF(keywords); Py_DECREF(args); return -1; } Py_DECREF(item); }
        count = PySequence_Size(keywords);
        for (i = 0; i < count; i++) { PyObject *keyword = PySequence_GetItem(keywords, i), *arg_name = keyword == NULL ? NULL : attr(keyword, "arg"), *item = keyword == NULL ? NULL : attr(keyword, "value");
            if (keyword == NULL || arg_name == NULL || arg_name == Py_None || item == NULL || metadata_expr(item, constants) < 0) { Py_XDECREF(item); Py_XDECREF(arg_name); Py_XDECREF(keyword); Py_DECREF(keywords); Py_DECREF(args); return -1; }
            Py_DECREF(item); Py_DECREF(arg_name); Py_DECREF(keyword);
        }
        Py_DECREF(keywords); Py_DECREF(args); return 0;
    }
    if (is_kind(node, "Tuple") || is_kind(node, "List")) {
        PyObject *elts = attr(node, "elts"); Py_ssize_t i, count;
        if (elts == NULL) return -1; count = PySequence_Size(elts);
        for (i = 0; i < count; i++) { PyObject *item = PySequence_GetItem(elts, i); if (item == NULL || metadata_expr(item, constants) < 0) { Py_XDECREF(item); Py_DECREF(elts); return -1; } Py_DECREF(item); }
        Py_DECREF(elts); return 0;
    }
    return -1;
}

static int validate_metadata_decorator(PyObject *decorator, PyObject *constants) {
    PyObject *args, *keywords; Py_ssize_t i, count;
    if (!is_kind(decorator, "Call")) return 0;
    args = attr(decorator, "args"); keywords = attr(decorator, "keywords");
    if (args == NULL || keywords == NULL) { Py_XDECREF(keywords); Py_XDECREF(args); return -1; }
    count = PySequence_Size(args);
    for (i = 0; i < count; i++) { PyObject *item = PySequence_GetItem(args, i); if (item == NULL || metadata_expr(item, constants) < 0) { Py_XDECREF(item); Py_DECREF(keywords); Py_DECREF(args); return -1; } Py_DECREF(item); }
    count = PySequence_Size(keywords);
    for (i = 0; i < count; i++) { PyObject *keyword = PySequence_GetItem(keywords, i), *arg_name = keyword == NULL ? NULL : attr(keyword, "arg"), *item = keyword == NULL ? NULL : attr(keyword, "value");
        if (keyword == NULL || arg_name == NULL || arg_name == Py_None || item == NULL || metadata_expr(item, constants) < 0) { Py_XDECREF(item); Py_XDECREF(arg_name); Py_XDECREF(keyword); Py_DECREF(keywords); Py_DECREF(args); return -1; }
        Py_DECREF(item); Py_DECREF(arg_name); Py_DECREF(keyword);
    }
    Py_DECREF(keywords); Py_DECREF(args); return 0;
}

static int safe_sequence(PyObject *node, PyObject *constants, PyObject **out) {
    PyObject *elts = attr(node, "elts"), *result = NULL; Py_ssize_t i, n;
    const int tuple = is_kind(node, "Tuple");
    if (elts == NULL) return -1;
    n = PySequence_Size(elts); result = tuple ? PyTuple_New(n) : PyList_New(n);
    if (result == NULL) goto fail;
    for (i = 0; i < n; i++) {
        PyObject *item = PySequence_GetItem(elts, i), *value = NULL;
        if (item == NULL || safe_value(item, constants, &value) < 0) {
            Py_XDECREF(item); Py_XDECREF(value); goto fail;
        }
        Py_DECREF(item);
        if (tuple) PyTuple_SET_ITEM(result, i, value);
        else PyList_SET_ITEM(result, i, value);
    }
    Py_DECREF(elts); *out = result; return 0;
fail: Py_XDECREF(result); Py_DECREF(elts); return -1;
}

static int safe_value(PyObject *node, PyObject *constants, PyObject **out) {
    if (is_kind(node, "Constant")) {
        PyObject *value = attr(node, "value");
        if (value == NULL) return -1;
        if (!(value == Py_None || PyBool_Check(value) || PyLong_CheckExact(value) ||
              PyUnicode_CheckExact(value) || PyBytes_CheckExact(value))) {
            Py_DECREF(value); PyErr_SetString(PyExc_ValueError, "unsupported literal"); return -1;
        }
        *out = value; return 0;
    }
    if (is_kind(node, "Tuple") || is_kind(node, "List"))
        return safe_sequence(node, constants, out);
    if (is_kind(node, "Name")) {
        char *name = name_value(node); PyObject *value;
        if (name == NULL) return -1;
        value = PyDict_GetItemString(constants, name); free(name);
        if (value == NULL) { PyErr_SetString(PyExc_ValueError, "unknown constant name"); return -1; }
        *out = Py_NewRef(value); return 0;
    }
    if (is_kind(node, "UnaryOp")) {
        PyObject *operand_node = attr(node, "operand"), *op = attr(node, "op"), *operand = NULL, *result = NULL;
        if (operand_node == NULL || op == NULL || safe_value(operand_node, constants, &operand) < 0) goto unary_done;
        if (!PyLong_CheckExact(operand)) { PyErr_SetString(PyExc_ValueError, "constant unary operand must be int"); goto unary_done; }
        if (is_kind(op, "USub")) result = PyNumber_Negative(operand);
        else if (is_kind(op, "UAdd")) result = PyNumber_Positive(operand);
        else if (is_kind(op, "Invert")) result = PyNumber_Invert(operand);
        else PyErr_SetString(PyExc_ValueError, "unsupported constant unary operator");
unary_done: Py_XDECREF(operand); Py_XDECREF(op); Py_XDECREF(operand_node);
        if (result == NULL) return -1; *out = result; return 0;
    }
    if (is_kind(node, "BinOp")) {
        PyObject *ln = attr(node, "left"), *rn = attr(node, "right"), *op = attr(node, "op");
        PyObject *left = NULL, *right = NULL, *result = NULL;
        if (ln == NULL || rn == NULL || op == NULL || safe_value(ln, constants, &left) < 0 || safe_value(rn, constants, &right) < 0) goto binary_done;
        if (!PyLong_CheckExact(left) || !PyLong_CheckExact(right)) { PyErr_SetString(PyExc_ValueError, "constant binary operands must be int"); goto binary_done; }
        if (is_kind(op, "Add")) result = PyNumber_Add(left, right);
        else if (is_kind(op, "Sub")) result = PyNumber_Subtract(left, right);
        else if (is_kind(op, "Mult")) result = PyNumber_Multiply(left, right);
        else if (is_kind(op, "FloorDiv")) result = PyNumber_FloorDivide(left, right);
        else if (is_kind(op, "Mod")) result = PyNumber_Remainder(left, right);
        else if (is_kind(op, "LShift")) result = PyNumber_Lshift(left, right);
        else if (is_kind(op, "RShift")) result = PyNumber_Rshift(left, right);
        else if (is_kind(op, "BitOr")) result = PyNumber_Or(left, right);
        else if (is_kind(op, "BitAnd")) result = PyNumber_And(left, right);
        else if (is_kind(op, "BitXor")) result = PyNumber_Xor(left, right);
        else PyErr_SetString(PyExc_ValueError, "unsupported constant binary operator");
binary_done: Py_XDECREF(right); Py_XDECREF(left); Py_XDECREF(op); Py_XDECREF(rn); Py_XDECREF(ln);
        if (result == NULL) return -1; *out = result; return 0;
    }
    PyErr_SetString(PyExc_ValueError, "constant expression is not deterministic"); return -1;
}

static int add_cut(Cuts *cuts, size_t begin, size_t end) {
    Cut *next;
    if (end <= begin) return 0;
    if (cuts->count == cuts->capacity) {
        const size_t capacity = cuts->capacity == 0 ? 8u : cuts->capacity * 2u;
        next = realloc(cuts->items, capacity * sizeof(*next));
        if (next == NULL) return -1;
        cuts->items = next; cuts->capacity = capacity;
    }
    cuts->items[cuts->count].begin = begin;
    cuts->items[cuts->count].end = end; cuts->count++; return 0;
}

static size_t line_offset(const char *source, size_t length, int line) {
    size_t offset = 0; int current = 1;
    while (offset < length && current < line) if (source[offset++] == '\n') current++;
    return offset;
}

static int cut_node_lines(Cuts *cuts, const char *source, size_t length, PyObject *node) {
    WrtcSourceSpan span = span_of(node);
    const size_t begin = line_offset(source, length, span.line);
    size_t end = line_offset(source, length, span.end_line + 1);
    if (end == begin) end = length;
    return add_cut(cuts, begin, end);
}

static int compare_cut(const void *a, const void *b) {
    const Cut *left = a, *right = b;
    return left->begin < right->begin ? -1 : left->begin > right->begin;
}

static char *apply_cuts(const char *source, size_t length, Cuts *cuts) {
    char *result = malloc(length + 1u); size_t input = 0, output = 0, i;
    if (result == NULL) return NULL;
    qsort(cuts->items, cuts->count, sizeof(*cuts->items), compare_cut);
    for (i = 0; i < cuts->count; i++) {
        size_t begin = cuts->items[i].begin, end = cuts->items[i].end;
        if (begin < input) begin = input;
        if (begin > input) { memcpy(result + output, source + input, begin - input); output += begin - input; }
        if (end > input) input = end;
    }
    if (input < length) { memcpy(result + output, source + input, length - input); output += length - input; }
    result[output] = '\0'; return result;
}

static int allowed_import(PyObject *node) {
    static const char *const allowed[] = {"__future__", "dataclasses", "typing", "pymeta", NULL};
    PyObject *names = NULL, *module = NULL; Py_ssize_t i, n; int result = 1;
    if (is_kind(node, "ImportFrom")) {
        const char *raw; module = attr(node, "module");
        if (module == NULL || module == Py_None) { Py_XDECREF(module); return 0; }
        raw = PyUnicode_AsUTF8(module);
        result = 0; for (i = 0; allowed[i] != NULL; i++) if (strcmp(raw, allowed[i]) == 0) result = 1;
        Py_DECREF(module); return result;
    }
    names = attr(node, "names"); if (names == NULL) return 0; n = PySequence_Size(names);
    for (i = 0; i < n && result; i++) {
        PyObject *alias = PySequence_GetItem(names, i), *name = alias == NULL ? NULL : attr(alias, "name"); const char *raw; size_t j; int found = 0;
        if (name == NULL) { Py_XDECREF(alias); result = 0; break; }
        raw = PyUnicode_AsUTF8(name);
        for (j = 0; allowed[j] != NULL; j++) if (strncmp(raw, allowed[j], strlen(allowed[j])) == 0 && (raw[strlen(allowed[j])] == '\0' || raw[strlen(allowed[j])] == '.')) found = 1;
        result = found; Py_DECREF(name); Py_DECREF(alias);
    }
    Py_DECREF(names); return result;
}

static int is_pymeta_import(PyObject *node) {
    PyObject *module = NULL, *names = NULL; Py_ssize_t i, n; int found = 0;
    if (is_kind(node, "ImportFrom")) {
        module = attr(node, "module");
        if (module != NULL && module != Py_None) found = strcmp(PyUnicode_AsUTF8(module), "pymeta") == 0;
        Py_XDECREF(module); return found;
    }
    names = attr(node, "names"); if (names == NULL) return 0; n = PySequence_Size(names);
    for (i = 0; i < n; i++) {
        PyObject *alias = PySequence_GetItem(names, i), *name = alias == NULL ? NULL : attr(alias, "name");
        if (name != NULL && strcmp(PyUnicode_AsUTF8(name), "pymeta") == 0) found = 1;
        Py_XDECREF(name); Py_XDECREF(alias);
    }
    Py_DECREF(names); return found;
}

static WrtcTypeKind annotation_type(PyObject *annotation) {
    char *name;
    if (annotation == NULL || annotation == Py_None) return WRTC_TYPE_UNKNOWN;
    if (is_kind(annotation, "Subscript")) {
        PyObject *value = attr(annotation, "value"); WrtcTypeKind result = annotation_type(value);
        Py_XDECREF(value); return result;
    }
    if (!is_kind(annotation, "Name")) return WRTC_TYPE_UNKNOWN;
    name = name_value(annotation); if (name == NULL) return WRTC_TYPE_UNKNOWN;
#define T(n, v) if (strcmp(name, n) == 0) { free(name); return v; }
    T("None", WRTC_TYPE_NONE) T("bool", WRTC_TYPE_BOOL) T("int", WRTC_TYPE_INT)
    T("str", WRTC_TYPE_STR) T("bytes", WRTC_TYPE_BYTES) T("memoryview", WRTC_TYPE_BUFFER)
    T("tuple", WRTC_TYPE_TUPLE) T("list", WRTC_TYPE_LIST) T("object", WRTC_TYPE_OBJECT)
#undef T
    free(name); return WRTC_TYPE_RECORD;
}

static int walk_ir(PyObject *node, WrtcCompilerCore *core, WrtcFunctionIR *function,
                   int collect_calls, int *forbidden) {
    PyObject *fields = NULL; Py_ssize_t i, n;
    static const char *const denied[] = {"AsyncFunctionDef", "Await", "Yield", "YieldFrom", "Lambda", "Try", "With", "AsyncWith", "Match", "NamedExpr", "Global", "Nonlocal", "Delete", NULL};
    for (i = 0; denied[i] != NULL; i++) if (is_kind(node, denied[i])) {
        char message[256];
        (void)snprintf(message, sizeof message, "unsupported reachable operation %s", denied[i]);
        *forbidden = 1; return diagnostic(core->filename, node, message);
    }
    if (function != NULL) {
        if (is_kind(node, "If") || is_kind(node, "For") || is_kind(node, "While") || is_kind(node, "Return")) function->block_count++;
        if (is_kind(node, "Raise")) function->exception_edge_count++;
        if (is_kind(node, "List") || is_kind(node, "ListComp") || is_kind(node, "Bytes")) function->owns_result = 1;
        if (collect_calls && is_kind(node, "Call")) {
            PyObject *callable = attr(node, "func");
            if (callable != NULL && is_kind(callable, "Name")) {
                char *called = name_value(callable); size_t j;
                if (called != NULL) for (j = 0; j < core->function_count; j++) if (strcmp(called, core->functions[j].name) == 0) function->call_count++;
                free(called);
            }
            Py_XDECREF(callable);
        }
    }
    fields = attr(node, "_fields"); if (fields == NULL) { PyErr_Clear(); return 0; }
    n = PySequence_Size(fields);
    for (i = 0; i < n; i++) {
        PyObject *field = PySequence_GetItem(fields, i), *value;
        const char *field_name;
        if (field == NULL) { Py_DECREF(fields); return -1; }
        field_name = PyUnicode_AsUTF8(field); value = field_name == NULL ? NULL : attr(node, field_name); Py_DECREF(field);
        if (value == NULL) { Py_DECREF(fields); return -1; }
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t j, count = PySequence_Size(value);
            for (j = 0; j < count; j++) { PyObject *child = PySequence_GetItem(value, j); if (child != NULL && walk_ir(child, core, function, collect_calls, forbidden) < 0) { Py_DECREF(child); Py_DECREF(value); Py_DECREF(fields); return -1; } Py_XDECREF(child); }
        } else if (PyObject_HasAttrString(value, "_fields")) {
            if (walk_ir(value, core, function, collect_calls, forbidden) < 0) { Py_DECREF(value); Py_DECREF(fields); return -1; }
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields); return 0;
}

static int mark_reachable(WrtcCompilerCore *core, PyObject **function_nodes, size_t index, unsigned char *state) {
    PyObject *fields = NULL; Py_ssize_t i, n;
    if (state[index] == 1) return diagnostic(core->filename, function_nodes[index], "recursive function graph is not supported");
    if (state[index] == 2) return 0;
    state[index] = 1; core->functions[index].is_reachable = 1;
    /* Calls are found with the same generic AST walk, and resolved here. */
    fields = attr(function_nodes[index], "_fields");
    if (fields == NULL) return -1;
    /* Iterative object stack keeps traversal independent of Python ast.walk. */
    {
        PyObject *stack = PyList_New(1); Py_ssize_t position = 0;
        if (stack == NULL) { Py_DECREF(fields); return -1; }
        PyList_SET_ITEM(stack, 0, Py_NewRef(function_nodes[index]));
        while (position < PyList_GET_SIZE(stack)) {
            PyObject *node = PyList_GET_ITEM(stack, position++), *node_fields = attr(node, "_fields");
            if (is_kind(node, "Call")) {
                PyObject *callable = attr(node, "func");
                if (callable != NULL && is_kind(callable, "Name")) {
                    char *called = name_value(callable); size_t j;
                    if (called != NULL) for (j = 0; j < core->function_count; j++) if (strcmp(called, core->functions[j].name) == 0 && mark_reachable(core, function_nodes, j, state) < 0) { free(called); Py_DECREF(callable); Py_XDECREF(node_fields); Py_DECREF(stack); Py_DECREF(fields); return -1; }
                    free(called);
                }
                Py_XDECREF(callable);
            }
            if (node_fields == NULL) { PyErr_Clear(); continue; }
            n = PySequence_Size(node_fields);
            for (i = 0; i < n; i++) {
                PyObject *field = PySequence_GetItem(node_fields, i), *value;
                const char *raw = field == NULL ? NULL : PyUnicode_AsUTF8(field);
                value = raw == NULL ? NULL : attr(node, raw); Py_XDECREF(field);
                if (value == NULL) { Py_DECREF(node_fields); Py_DECREF(stack); Py_DECREF(fields); return -1; }
                if (PyList_Check(value) || PyTuple_Check(value)) {
                    Py_ssize_t j, count = PySequence_Size(value);
                    for (j = 0; j < count; j++) { PyObject *child = PySequence_GetItem(value, j); if (child != NULL && PyObject_HasAttrString(child, "_fields")) PyList_Append(stack, child); Py_XDECREF(child); }
                } else if (PyObject_HasAttrString(value, "_fields")) PyList_Append(stack, value);
                Py_DECREF(value);
            }
            Py_DECREF(node_fields);
        }
        Py_DECREF(stack);
    }
    Py_DECREF(fields); state[index] = 2; return 0;
}

int wrtc_compiler_core_analyze(const char *source, size_t source_length,
                               const char *filename, WrtcCompilerCore **out) {
    WrtcCompilerCore *core = calloc(1, sizeof(*core)); PyObject *ast = NULL, *parse = NULL, *text = NULL, *path = NULL;
    PyObject *body = NULL, *explicit_exports = NULL, **function_nodes = NULL; Cuts cuts = {0}; Py_ssize_t i, n; size_t function_node_count = 0; int status = -1;
    if (core == NULL) return PyErr_NoMemory(), -1;
    core->filename = copy_text(filename); core->constant_values = PyDict_New(); core->constant_names = PyList_New(0);
    if (core->filename == NULL || core->constant_values == NULL || core->constant_names == NULL) goto done;
    ast = PyImport_ImportModule("ast"); parse = ast == NULL ? NULL : PyObject_GetAttrString(ast, "parse");
    text = PyUnicode_DecodeUTF8(source, (Py_ssize_t)source_length, "strict"); path = PyUnicode_DecodeFSDefault(filename);
    if (parse == NULL || text == NULL || path == NULL) goto done;
    core->tree = PyObject_CallFunctionObjArgs(parse, text, path, NULL);
    if (core->tree == NULL) {
        if (PyErr_ExceptionMatches(PyExc_SyntaxError)) {
            PyObject *type = NULL, *value = NULL, *tb = NULL, *msg = NULL, *lineno = NULL, *offset = NULL;
            long line = 1, col = 1; const char *raw = "invalid syntax";
            PyErr_Fetch(&type, &value, &tb); PyErr_NormalizeException(&type, &value, &tb);
            if (value != NULL) { msg = attr(value, "msg"); lineno = attr(value, "lineno"); offset = attr(value, "offset"); }
            if (msg != NULL) raw = PyUnicode_AsUTF8(msg); if (lineno != NULL && lineno != Py_None) line = PyLong_AsLong(lineno); if (offset != NULL && offset != Py_None) col = PyLong_AsLong(offset);
            PyErr_Format(PyExc_ValueError, "%s:%ld:%ld: error: %s", filename, line, col, raw);
            Py_XDECREF(offset); Py_XDECREF(lineno); Py_XDECREF(msg); Py_XDECREF(tb); Py_XDECREF(value); Py_XDECREF(type);
        }
        goto done;
    }
    body = attr(core->tree, "body"); if (body == NULL) goto done; n = PySequence_Size(body);
    for (i = 0; i < n; i++) {
        PyObject *node = PySequence_GetItem(body, i);
        if (node == NULL) goto done;
        if (is_kind(node, "FunctionDef")) core->function_count++;
        else if (is_kind(node, "ClassDef")) core->record_count++;
        Py_DECREF(node);
    }
    core->functions = calloc(core->function_count, sizeof(*core->functions)); function_nodes = calloc(core->function_count, sizeof(*function_nodes));
    function_node_count = core->function_count;
    core->records = calloc(core->record_count, sizeof(*core->records));
    if ((core->function_count && (core->functions == NULL || function_nodes == NULL)) || (core->record_count && core->records == NULL)) goto done;
    {
        size_t fi = 0, ri = 0;
        for (i = 0; i < n; i++) {
            PyObject *node = PySequence_GetItem(body, i), *value = NULL;
            if (node == NULL) goto done;
            if (is_kind(node, "Import") || is_kind(node, "ImportFrom")) {
                if (!allowed_import(node)) { diagnostic(filename, node, "unsafe import is not supported"); Py_DECREF(node); goto done; }
                if (is_pymeta_import(node) && cut_node_lines(&cuts, source, source_length, node) < 0) { Py_DECREF(node); goto done; }
            } else if (is_kind(node, "FunctionDef") || is_kind(node, "ClassDef")) {
                PyObject *decorators = attr(node, "decorator_list"); Py_ssize_t j, count = decorators == NULL ? 0 : PySequence_Size(decorators);
                if (is_kind(node, "FunctionDef")) { core->functions[fi].name = definition_name(node); core->functions[fi].span = span_of(node); function_nodes[fi++] = Py_NewRef(node); }
                else {
                    PyObject *class_body = attr(node, "body"); Py_ssize_t k, class_count = class_body == NULL ? 0 : PySequence_Size(class_body);
                    core->records[ri].name = definition_name(node); core->records[ri].span = span_of(node);
                    for (k = 0; k < class_count; k++) { PyObject *member = PySequence_GetItem(class_body, k); if (member != NULL && is_kind(member, "AnnAssign")) core->records[ri].field_count++; Py_XDECREF(member); }
                    core->records[ri].fields = calloc(core->records[ri].field_count, sizeof(*core->records[ri].fields));
                    if (core->records[ri].field_count != 0u && core->records[ri].fields == NULL) { Py_XDECREF(class_body); Py_XDECREF(decorators); Py_DECREF(node); goto done; }
                    {
                        size_t field_index = 0;
                        for (k = 0; k < class_count; k++) {
                            PyObject *member = PySequence_GetItem(class_body, k);
                            if (member != NULL && is_kind(member, "AnnAssign")) {
                                PyObject *target = attr(member, "target"), *annotation = attr(member, "annotation"), *default_value = attr(member, "value");
                                core->records[ri].fields[field_index].name = target != NULL && is_kind(target, "Name") ? name_value(target) : NULL;
                                core->records[ri].fields[field_index].span = span_of(member);
                                core->records[ri].fields[field_index].type = annotation_type(annotation);
                                core->records[ri].fields[field_index].has_default = default_value != NULL && default_value != Py_None;
                                Py_XDECREF(default_value); Py_XDECREF(annotation); Py_XDECREF(target); field_index++;
                            } else if (member != NULL && is_kind(member, "FunctionDef")) {
                                PyObject *member_decorators = attr(member, "decorator_list"); Py_ssize_t m, member_count = member_decorators == NULL ? 0 : PySequence_Size(member_decorators);
                                for (m = 0; m < member_count; m++) { PyObject *member_deco = PySequence_GetItem(member_decorators, m); char *member_name = member_deco == NULL ? NULL : decorator_name(member_deco); if (member_name != NULL && strcmp(member_name, "property") == 0) core->records[ri].property_count++; free(member_name); Py_XDECREF(member_deco); }
                                Py_XDECREF(member_decorators);
                            }
                            Py_XDECREF(member);
                        }
                    }
                    Py_XDECREF(class_body); ri++;
                }
                for (j = 0; j < count; j++) {
                    PyObject *deco = PySequence_GetItem(decorators, j); char *name = decorator_name(deco); int allowed;
                    if (name == NULL) { Py_XDECREF(deco); Py_XDECREF(decorators); Py_DECREF(node); goto done; }
                    allowed = strcmp(name, "dataclass") == 0 || strcmp(name, "property") == 0 || strcmp(name, "record") == 0 || strcmp(name, "required") == 0 || strcmp(name, "effects") == 0 || strcmp(name, "region") == 0 || strncmp(name, "pymeta.", 7) == 0;
                    if (!allowed) { char message[512]; (void)snprintf(message, sizeof message, "unsupported decorator %s", name[0] ? name : kind(deco)); diagnostic(filename, deco, message); free(name); Py_DECREF(deco); Py_XDECREF(decorators); Py_DECREF(node); goto done; }
                    if ((strncmp(name, "pymeta.", 7) == 0 || strcmp(name, "record") == 0 || strcmp(name, "effects") == 0 || strcmp(name, "region") == 0) && validate_metadata_decorator(deco, core->constant_values) < 0) { PyErr_Clear(); diagnostic(filename, deco, "PyMeta declaration must contain only deterministic metadata expressions"); free(name); Py_DECREF(deco); Py_XDECREF(decorators); Py_DECREF(node); goto done; }
                    if ((strncmp(name, "pymeta.", 7) == 0 || strcmp(name, "record") == 0 || strcmp(name, "required") == 0 || strcmp(name, "effects") == 0 || strcmp(name, "region") == 0) && cut_node_lines(&cuts, source, source_length, deco) < 0) { free(name); Py_DECREF(deco); Py_XDECREF(decorators); Py_DECREF(node); goto done; }
                    free(name); Py_DECREF(deco);
                }
                Py_XDECREF(decorators);
            } else if (is_kind(node, "Expr")) {
                value = attr(node, "value");
                if (value == NULL || !is_kind(value, "Constant")) { Py_XDECREF(value); diagnostic(filename, node, "unsupported module statement Expr"); Py_DECREF(node); goto done; }
                Py_DECREF(value);
            } else if (is_kind(node, "Assign") || is_kind(node, "AnnAssign")) {
                PyObject *targets = NULL; int all_assignment = 0;
                value = attr(node, "value"); if (value == NULL || value == Py_None) { Py_XDECREF(value); diagnostic(filename, node, "module assignment requires a value"); Py_DECREF(node); goto done; }
                if (is_kind(node, "Assign")) targets = attr(node, "targets");
                else { PyObject *target = attr(node, "target"); targets = target == NULL ? NULL : PyTuple_Pack(1, target); Py_XDECREF(target); }
                if (targets == NULL) { Py_DECREF(value); Py_DECREF(node); goto done; }
                { Py_ssize_t j, count = PySequence_Size(targets);
                    for (j = 0; j < count; j++) { PyObject *target = PySequence_GetItem(targets, j); char *name = target != NULL && is_kind(target, "Name") ? name_value(target) : NULL; PyObject *evaluated = NULL;
                        if (name != NULL && strcmp(name, "__all__") == 0) {
                            if (safe_value(value, core->constant_values, &evaluated) < 0 || !(PyTuple_Check(evaluated) || PyList_Check(evaluated))) { PyErr_Clear(); diagnostic(filename, node, "__all__ must be a literal string sequence"); free(name); Py_XDECREF(evaluated); Py_XDECREF(target); Py_DECREF(targets); Py_DECREF(value); Py_DECREF(node); goto done; }
                            { Py_ssize_t k, ec = PySequence_Size(evaluated); for (k = 0; k < ec; k++) { PyObject *entry = PySequence_GetItem(evaluated, k); if (entry == NULL || !PyUnicode_CheckExact(entry)) { Py_XDECREF(entry); diagnostic(filename, node, "__all__ must be a literal string sequence"); free(name); Py_DECREF(evaluated); Py_XDECREF(target); Py_DECREF(targets); Py_DECREF(value); Py_DECREF(node); goto done; } Py_DECREF(entry); } }
                            Py_XSETREF(explicit_exports, evaluated); all_assignment = 1;
                        } else if (name != NULL) {
                            if (safe_value(value, core->constant_values, &evaluated) < 0) { PyErr_Clear(); diagnostic(filename, node, is_kind(value, "Call") ? "executable module assignment is not supported" : "module constant is not a deterministic expression"); free(name); Py_XDECREF(target); Py_DECREF(targets); Py_DECREF(value); Py_DECREF(node); goto done; }
                            if (PyDict_SetItemString(core->constant_values, name, evaluated) < 0) { free(name); Py_DECREF(evaluated); Py_XDECREF(target); Py_DECREF(targets); Py_DECREF(value); Py_DECREF(node); goto done; }
                            if (name[0] == '_' && strcmp(name, "__all__") != 0) { PyObject *pyname = PyUnicode_FromString(name); if (pyname == NULL || PyList_Append(core->constant_names, pyname) < 0) { Py_XDECREF(pyname); free(name); Py_DECREF(evaluated); Py_XDECREF(target); Py_DECREF(targets); Py_DECREF(value); Py_DECREF(node); goto done; } Py_DECREF(pyname); }
                            Py_DECREF(evaluated);
                        }
                        free(name); Py_XDECREF(target);
                    }
                }
                (void)all_assignment; Py_DECREF(targets); Py_DECREF(value);
            } else { char message[256]; (void)snprintf(message, sizeof message, "unsupported module statement %s", kind(node)); diagnostic(filename, node, message); Py_DECREF(node); goto done; }
            Py_DECREF(node);
        }
    }
    core->exports = explicit_exports != NULL ? PySequence_List(explicit_exports) : PyList_New(0);
    if (core->exports == NULL) goto done;
    if (explicit_exports == NULL) {
        size_t j; for (j = 0; j < core->function_count; j++) if (core->functions[j].name[0] != '_') { PyObject *name = PyUnicode_FromString(core->functions[j].name); if (name == NULL || PyList_Append(core->exports, name) < 0) { Py_XDECREF(name); goto done; } Py_DECREF(name); }
    }
    { Py_ssize_t j, ec = PyList_GET_SIZE(core->exports); for (j = 0; j < ec; j++) { PyObject *name = PyList_GET_ITEM(core->exports, j); const char *raw = PyUnicode_AsUTF8(name); size_t k; int found = 0;
            for (k = 0; k < (size_t)j; k++) if (PyObject_RichCompareBool(name, PyList_GET_ITEM(core->exports, (Py_ssize_t)k), Py_EQ) == 1) { PyErr_Format(PyExc_ValueError, "%s:1:1: error: __all__ contains duplicate names", filename); goto done; }
            for (k = 0; k < core->function_count; k++) if (strcmp(raw, core->functions[k].name) == 0) { core->functions[k].is_public = 1; found = 1; }
            if (!found) { size_t r; for (r = 0; r < core->record_count; r++) if (strcmp(raw, core->records[r].name) == 0) { PyErr_Format(PyExc_ValueError, "%s:%d:%d: error: exported name '%s' is not a function", filename, core->records[r].span.line, core->records[r].span.column, raw); goto done; } PyErr_Format(PyExc_ValueError, "%s:1:1: error: exported name '%s' is missing", filename, raw); goto done; }
        }
    }
    { unsigned char *state = calloc(core->function_count, 1u); size_t j; if (state == NULL && core->function_count) goto done;
        for (j = 0; j < core->function_count; j++) if (core->functions[j].is_public && mark_reachable(core, function_nodes, j, state) < 0) { free(state); goto done; }
        free(state);
    }
    { size_t j; for (j = 0; j < core->function_count; j++) if (core->functions[j].is_reachable) { int forbidden = 0; PyObject *returns = attr(function_nodes[j], "returns"); core->functions[j].type = annotation_type(returns); Py_XDECREF(returns); if (walk_ir(function_nodes[j], core, &core->functions[j], 1, &forbidden) < 0) goto done; } }
    core->lowered_source = apply_cuts(source, source_length, &cuts); if (core->lowered_source == NULL) goto done;
    *out = core; core = NULL; status = 0;
done:
    if (function_nodes != NULL) { size_t j; for (j = 0; j < function_node_count; j++) Py_XDECREF(function_nodes[j]); }
    free(function_nodes); free(cuts.items); Py_XDECREF(explicit_exports); Py_XDECREF(body); Py_XDECREF(path); Py_XDECREF(text); Py_XDECREF(parse); Py_XDECREF(ast); wrtc_compiler_core_free(core); return status;
}

void wrtc_compiler_core_free(WrtcCompilerCore *core) {
    size_t i; if (core == NULL) return;
    for (i = 0; i < core->function_count; i++) free(core->functions[i].name);
    for (i = 0; i < core->record_count; i++) { size_t j; free(core->records[i].name); for (j = 0; j < core->records[i].field_count; j++) free(core->records[i].fields[j].name); free(core->records[i].fields); }
    free(core->functions); free(core->records); free(core->filename); free(core->lowered_source);
    Py_XDECREF(core->tree); Py_XDECREF(core->exports); Py_XDECREF(core->constant_names); Py_XDECREF(core->constant_values); free(core);
}

const WrtcFunctionIR *wrtc_compiler_core_find_function(const WrtcCompilerCore *core, const char *name) {
    size_t i; for (i = 0; i < core->function_count; i++) if (strcmp(core->functions[i].name, name) == 0) return &core->functions[i]; return NULL;
}
