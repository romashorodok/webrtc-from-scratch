#include "native_class.h"
#include "native_class_generator.h"
#include "native_operation.h"
#include "native_storage.h"

#include <stdlib.h>
#include <string.h>

static char *copy_text(const char *value) {
    size_t length;
    char *copy;
    if (value == NULL) return NULL;
    length = strlen(value);
    copy = malloc(length + 1u);
    if (copy != NULL) memcpy(copy, value, length + 1u);
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
    if (value == NULL) {
        PyErr_Clear();
        return fallback;
    }
    result = PyLong_AsLong(value);
    Py_DECREF(value);
    if (result == -1 && PyErr_Occurred()) {
        PyErr_Clear();
        return fallback;
    }
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

static int diagnostic(const WrtcCompilerCore *core, PyObject *node,
                      const char *message) {
    WrtcSourceSpan span = span_of(node);
    PyErr_Format(PyExc_ValueError, "%s:%d:%d: error: %s", core->filename,
                 span.line, span.column, message);
    return -1;
}

static char *node_name(PyObject *node) {
    PyObject *value = attr(node, "id");
    const char *text;
    char *result = NULL;
    if (value == NULL) return NULL;
    text = PyUnicode_AsUTF8(value);
    if (text != NULL) result = copy_text(text);
    Py_DECREF(value);
    return result;
}

static char *definition_name(PyObject *node) {
    PyObject *value = attr(node, "name");
    const char *text;
    char *result = NULL;
    if (value == NULL) return NULL;
    text = PyUnicode_AsUTF8(value);
    if (text != NULL) result = copy_text(text);
    Py_DECREF(value);
    return result;
}

static char *dotted_name(PyObject *node) {
    if (is_kind(node, "Name")) return node_name(node);
    if (is_kind(node, "Call")) {
        PyObject *function = attr(node, "func");
        char *result = function == NULL ? NULL : dotted_name(function);
        Py_XDECREF(function);
        return result;
    }
    if (is_kind(node, "Attribute")) {
        PyObject *base = attr(node, "value");
        PyObject *field = attr(node, "attr");
        char *left = base == NULL ? NULL : dotted_name(base);
        const char *right = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        char *result = NULL;
        if (left != NULL && right != NULL) {
            size_t size = strlen(left) + strlen(right) + 2u;
            result = malloc(size);
            if (result != NULL)
                (void)snprintf(result, size, "%s.%s", left, right);
        }
        free(left);
        Py_XDECREF(field);
        Py_XDECREF(base);
        return result;
    }
    return copy_text("");
}

static int final_name_is(PyObject *node, const char *wanted) {
    char *name = dotted_name(node);
    const char *final;
    int result = 0;
    if (name != NULL) {
        final = strrchr(name, '.');
        final = final == NULL ? name : final + 1;
        result = strcmp(final, wanted) == 0;
    }
    free(name);
    return result;
}

static int has_called_decorator(PyObject *node, const char *wanted) {
    PyObject *decorators = attr(node, "decorator_list");
    Py_ssize_t index, count;
    int found = 0;
    if (decorators == NULL) return 0;
    count = PySequence_Size(decorators);
    for (index = 0; index < count; index++) {
        PyObject *decorator = PySequence_GetItem(decorators, index);
        if (decorator != NULL &&
            ((is_kind(decorator, "Call") &&
              final_name_is(decorator, wanted)) ||
             (!is_kind(decorator, "Call") &&
              final_name_is(decorator, wanted))))
            found = 1;
        Py_XDECREF(decorator);
        if (found) break;
    }
    Py_DECREF(decorators);
    return found;
}

static PyObject *call_keyword(PyObject *call, const char *wanted) {
    PyObject *keywords = attr(call, "keywords");
    Py_ssize_t index, count;
    if (keywords == NULL) return NULL;
    count = PySequence_Size(keywords);
    for (index = 0; index < count; index++) {
        PyObject *keyword = PySequence_GetItem(keywords, index);
        PyObject *name = keyword == NULL ? NULL : attr(keyword, "arg");
        const char *text =
            name == NULL || name == Py_None ? NULL : PyUnicode_AsUTF8(name);
        if (text != NULL && strcmp(text, wanted) == 0) {
            PyObject *value = attr(keyword, "value");
            Py_XDECREF(name);
            Py_DECREF(keyword);
            Py_DECREF(keywords);
            return value;
        }
        Py_XDECREF(name);
        Py_XDECREF(keyword);
    }
    Py_DECREF(keywords);
    return NULL;
}

static char *constant_string(PyObject *node) {
    PyObject *value =
        node != NULL && is_kind(node, "Constant") ? attr(node, "value") : NULL;
    const char *text =
        value != NULL && PyUnicode_Check(value) ? PyUnicode_AsUTF8(value) : NULL;
    char *result = text == NULL ? NULL : copy_text(text);
    Py_XDECREF(value);
    return result;
}

static char *called_decorator_keyword_string(PyObject *node,
                                             const char *wanted,
                                             const char *keyword) {
    PyObject *decorators = attr(node, "decorator_list");
    Py_ssize_t index, count;
    char *result = NULL;
    if (decorators == NULL) return NULL;
    count = PySequence_Size(decorators);
    for (index = 0; index < count && result == NULL; index++) {
        PyObject *decorator = PySequence_GetItem(decorators, index);
        if (decorator != NULL && is_kind(decorator, "Call") &&
            final_name_is(decorator, wanted)) {
            PyObject *value = call_keyword(decorator, keyword);
            result = constant_string(value);
            Py_XDECREF(value);
        }
        Py_XDECREF(decorator);
    }
    Py_DECREF(decorators);
    return result;
}

static char *scalar_text(PyObject *node) {
    PyObject *value;
    char *result = constant_string(node);
    if (result != NULL || node == NULL) return result;
    if (is_kind(node, "Call")) {
        PyObject *arguments = attr(node, "args");
        if (arguments != NULL && PySequence_Size(arguments) == 1) {
            PyObject *argument = PySequence_GetItem(arguments, 0);
            result = scalar_text(argument);
            Py_XDECREF(argument);
        }
        Py_XDECREF(arguments);
        if (result != NULL) return result;
    }
    if (is_kind(node, "Constant")) {
        value = attr(node, "value");
        if (value != NULL && PyLong_CheckExact(value)) {
            PyObject *text = PyObject_Str(value);
            const char *raw = text == NULL ? NULL : PyUnicode_AsUTF8(text);
            if (raw != NULL) result = copy_text(raw);
            Py_XDECREF(text);
        }
        Py_XDECREF(value);
    } else {
        result = dotted_name(node);
    }
    return result;
}

static int expression_contains(PyObject *node, const char *wanted) {
    PyObject *fields;
    Py_ssize_t index, count;
    if (node == NULL) return 0;
    if ((is_kind(node, "Name") || is_kind(node, "Attribute") ||
         is_kind(node, "Call")) && final_name_is(node, wanted))
        return 1;
    fields = attr(node, "_fields");
    if (fields == NULL) {
        PyErr_Clear();
        return 0;
    }
    count = PySequence_Size(fields);
    for (index = 0; index < count; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (value == NULL) {
            Py_DECREF(fields);
            return 0;
        }
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child, children = PySequence_Size(value);
            for (child = 0; child < children; child++) {
                PyObject *item = PySequence_GetItem(value, child);
                int found = expression_contains(item, wanted);
                Py_XDECREF(item);
                if (found) {
                    Py_DECREF(value);
                    Py_DECREF(fields);
                    return 1;
                }
            }
        } else if (expression_contains(value, wanted)) {
            Py_DECREF(value);
            Py_DECREF(fields);
            return 1;
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    return 0;
}

static char *string_call_argument(PyObject *node, const char *call_name) {
    PyObject *args, *first, *value;
    const char *text;
    char *result = NULL;
    if (!is_kind(node, "Call") || !final_name_is(node, call_name)) return NULL;
    args = attr(node, "args");
    first = args != NULL && PySequence_Size(args) > 0
                ? PySequence_GetItem(args, 0) : NULL;
    value = first != NULL && is_kind(first, "Constant")
                ? attr(first, "value") : NULL;
    text = value != NULL && PyUnicode_Check(value)
               ? PyUnicode_AsUTF8(value) : NULL;
    if (text != NULL) result = copy_text(text);
    Py_XDECREF(value);
    Py_XDECREF(first);
    Py_XDECREF(args);
    return result;
}

static char *find_string_call(PyObject *node, const char *call_name) {
    PyObject *fields;
    Py_ssize_t index, count;
    char *found = string_call_argument(node, call_name);
    if (found != NULL || node == NULL) return found;
    fields = attr(node, "_fields");
    if (fields == NULL) {
        PyErr_Clear();
        return NULL;
    }
    count = PySequence_Size(fields);
    for (index = 0; index < count && found == NULL; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (value == NULL) continue;
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child, children = PySequence_Size(value);
            for (child = 0; child < children && found == NULL; child++) {
                PyObject *item = PySequence_GetItem(value, child);
                found = find_string_call(item, call_name);
                Py_XDECREF(item);
            }
        } else {
            found = find_string_call(value, call_name);
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    return found;
}

static char *find_call_keyword_text(PyObject *node, const char *call_name,
                                    const char *keyword_name) {
    PyObject *fields;
    Py_ssize_t index, count;
    char *found = NULL;
    if (node == NULL) return NULL;
    if (is_kind(node, "Call") && final_name_is(node, call_name)) {
        PyObject *value = call_keyword(node, keyword_name);
        found = scalar_text(value);
        Py_XDECREF(value);
        if (found != NULL) return found;
    }
    fields = attr(node, "_fields");
    if (fields == NULL) {
        PyErr_Clear();
        return NULL;
    }
    count = PySequence_Size(fields);
    for (index = 0; index < count && found == NULL; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (value == NULL) continue;
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child, children = PySequence_Size(value);
            for (child = 0; child < children && found == NULL; child++) {
                PyObject *item = PySequence_GetItem(value, child);
                found = find_call_keyword_text(
                    item, call_name, keyword_name);
                Py_XDECREF(item);
            }
        } else {
            found = find_call_keyword_text(value, call_name, keyword_name);
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    return found;
}

static char *find_queue_item_type(PyObject *node) {
    PyObject *fields;
    Py_ssize_t index, count;
    char *found = NULL;
    if (node == NULL) return NULL;
    if (is_kind(node, "Subscript")) {
        PyObject *value = attr(node, "value");
        PyObject *slice = attr(node, "slice");
        if (value != NULL &&
            (final_name_is(value, "Queue") ||
             final_name_is(value, "SimpleQueue") ||
             final_name_is(value, "BoundedQueue")) &&
            slice != NULL)
            found = dotted_name(slice);
        Py_XDECREF(slice);
        Py_XDECREF(value);
        if (found != NULL) return found;
    }
    fields = attr(node, "_fields");
    if (fields == NULL) {
        PyErr_Clear();
        return NULL;
    }
    count = PySequence_Size(fields);
    for (index = 0; index < count && found == NULL; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (value == NULL) continue;
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child, children = PySequence_Size(value);
            for (child = 0; child < children && found == NULL; child++) {
                PyObject *item = PySequence_GetItem(value, child);
                found = find_queue_item_type(item);
                Py_XDECREF(item);
            }
        } else {
            found = find_queue_item_type(value);
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    return found;
}

static int called_decorator_keyword_true(PyObject *node,
                                         const char *decorator_name,
                                         const char *keyword_name) {
    PyObject *decorators = attr(node, "decorator_list");
    Py_ssize_t decorator_index;
    const Py_ssize_t decorator_count =
        decorators == NULL ? 0 : PySequence_Size(decorators);
    int result = 0;
    for (decorator_index = 0;
         decorator_index < decorator_count && !result;
         decorator_index++) {
        PyObject *decorator =
            PySequence_GetItem(decorators, decorator_index);
        PyObject *keywords = NULL;
        Py_ssize_t keyword_index, keyword_count;
        if (decorator == NULL || !is_kind(decorator, "Call") ||
            !final_name_is(decorator, decorator_name)) {
            Py_XDECREF(decorator);
            continue;
        }
        keywords = attr(decorator, "keywords");
        keyword_count = keywords == NULL ? 0 : PySequence_Size(keywords);
        for (keyword_index = 0;
             keyword_index < keyword_count && !result;
             keyword_index++) {
            PyObject *keyword =
                PySequence_GetItem(keywords, keyword_index);
            PyObject *argument =
                keyword == NULL ? NULL : attr(keyword, "arg");
            PyObject *value =
                keyword == NULL ? NULL : attr(keyword, "value");
            PyObject *constant =
                value != NULL && is_kind(value, "Constant")
                    ? attr(value, "value") : NULL;
            const char *argument_text =
                argument == NULL ? NULL : PyUnicode_AsUTF8(argument);
            result =
                argument_text != NULL &&
                strcmp(argument_text, keyword_name) == 0 &&
                constant == Py_True;
            Py_XDECREF(constant);
            Py_XDECREF(value);
            Py_XDECREF(argument);
            Py_XDECREF(keyword);
        }
        Py_XDECREF(keywords);
        Py_DECREF(decorator);
    }
    Py_XDECREF(decorators);
    return result;
}

static unsigned atomic_uint_width(PyObject *node) {
    PyObject *value = NULL, *slice = NULL, *raw = NULL;
    unsigned result = 0u;
    long width;
    PyObject *fields;
    Py_ssize_t index, count;
    if (node == NULL) return 0u;
    if (is_kind(node, "Subscript")) {
        value = attr(node, "value");
        slice = attr(node, "slice");
        if (value != NULL && final_name_is(value, "atomic") &&
            slice != NULL && is_kind(slice, "Subscript")) {
            PyObject *representation = attr(slice, "value");
            PyObject *bits = attr(slice, "slice");
            if (representation != NULL &&
                final_name_is(representation, "uint") &&
                bits != NULL && is_kind(bits, "Constant"))
                raw = attr(bits, "value");
            width = raw != NULL && PyLong_CheckExact(raw)
                        ? PyLong_AsLong(raw) : 0;
            if (!PyErr_Occurred() && width > 0)
                result = (unsigned)width;
            else
                PyErr_Clear();
            Py_XDECREF(raw);
            Py_XDECREF(bits);
            Py_XDECREF(representation);
        }
        Py_XDECREF(slice);
        Py_XDECREF(value);
        if (result != 0u) return result;
    }
    fields = attr(node, "_fields");
    if (fields == NULL) {
        PyErr_Clear();
        return 0u;
    }
    count = PySequence_Size(fields);
    for (index = 0; index < count && result == 0u; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *child = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (child == NULL) continue;
        if (PyList_Check(child) || PyTuple_Check(child)) {
            Py_ssize_t item_index, item_count = PySequence_Size(child);
            for (item_index = 0; item_index < item_count && result == 0u;
                 item_index++) {
                PyObject *item = PySequence_GetItem(child, item_index);
                result = atomic_uint_width(item);
                Py_XDECREF(item);
            }
        } else {
            result = atomic_uint_width(child);
        }
        Py_DECREF(child);
    }
    Py_DECREF(fields);
    return result;
}

static WrtcTypeKind annotation_type(PyObject *annotation) {
    char *name;
    WrtcTypeKind result = WRTC_TYPE_UNKNOWN;
    if (annotation == NULL || annotation == Py_None) return result;
    if (is_kind(annotation, "Subscript")) {
        PyObject *value = attr(annotation, "value");
        PyObject *slice = attr(annotation, "slice");
        if (value != NULL && final_name_is(value, "Annotated") &&
            slice != NULL && is_kind(slice, "Tuple")) {
            PyObject *elts = attr(slice, "elts");
            PyObject *first =
                elts != NULL && PySequence_Size(elts) > 0
                    ? PySequence_GetItem(elts, 0) : NULL;
            result = annotation_type(first);
            Py_XDECREF(first);
            Py_XDECREF(elts);
        } else {
            result = annotation_type(value);
        }
        Py_XDECREF(slice);
        Py_XDECREF(value);
        return result;
    }
    if (!is_kind(annotation, "Name")) return result;
    name = node_name(annotation);
    if (name == NULL) return result;
    if (strcmp(name, "bool") == 0) result = WRTC_TYPE_BOOL;
    else if (strcmp(name, "int") == 0) result = WRTC_TYPE_INT;
    else if (strcmp(name, "float") == 0) result = WRTC_TYPE_OBJECT;
    else if (strcmp(name, "str") == 0) result = WRTC_TYPE_STR;
    else if (strcmp(name, "bytes") == 0) result = WRTC_TYPE_BYTES;
    else if (strcmp(name, "list") == 0) result = WRTC_TYPE_LIST;
    else result = WRTC_TYPE_RECORD;
    free(name);
    return result;
}

static char *annotation_declared_type(PyObject *annotation) {
    if (annotation == NULL || annotation == Py_None) return NULL;
    if (is_kind(annotation, "Subscript")) {
        PyObject *value = attr(annotation, "value");
        PyObject *slice = attr(annotation, "slice");
        char *result = NULL;
        if (value != NULL && final_name_is(value, "Annotated") &&
            slice != NULL && is_kind(slice, "Tuple")) {
            PyObject *elements = attr(slice, "elts");
            PyObject *first =
                elements != NULL && PySequence_Size(elements) > 0
                    ? PySequence_GetItem(elements, 0) : NULL;
            result = annotation_declared_type(first);
            Py_XDECREF(first);
            Py_XDECREF(elements);
        }
        Py_XDECREF(slice);
        Py_XDECREF(value);
        return result;
    }
    return dotted_name(annotation);
}

static int parse_native_decorator(const WrtcCompilerCore *core,
                                  PyObject *decorator,
                                  WrtcNativeClassIR *class_ir) {
    PyObject *args = attr(decorator, "args");
    PyObject *gc = call_keyword(decorator, "gc");
    PyObject *weakrefs = call_keyword(decorator, "weakrefs");
    PyObject *layout =
        args != NULL && PySequence_Size(args) > 0
            ? PySequence_GetItem(args, 0) : NULL;
    PyObject *weak_value =
        weakrefs != NULL && is_kind(weakrefs, "Constant")
            ? attr(weakrefs, "value") : NULL;
    int valid = args != NULL && PySequence_Size(args) == 1 &&
                layout != NULL && final_name_is(layout, "compact_object") &&
                gc != NULL && final_name_is(gc, "tracked") &&
                weak_value == Py_False;
    Py_XDECREF(weak_value);
    Py_XDECREF(layout);
    Py_XDECREF(weakrefs);
    Py_XDECREF(gc);
    Py_XDECREF(args);
    if (!valid)
        return diagnostic(core, decorator,
                          "unsupported native_class representation");
    class_ir->compact_object = 1u;
    class_ir->gc_tracked = 1u;
    return 0;
}

static int parse_region_decorator(const WrtcCompilerCore *core,
                                  PyObject *decorator,
                                  WrtcNativeRegionIR *region) {
    PyObject *args = attr(decorator, "args");
    PyObject *policy =
        args != NULL && PySequence_Size(args) > 0
            ? PySequence_GetItem(args, 0) : NULL;
    PyObject *effects = call_keyword(decorator, "effects");
    PyObject *fusion = call_keyword(decorator, "fusion");
    PyObject *execute = call_keyword(decorator, "execute");
    if (policy != NULL && final_name_is(policy, "required"))
        region->policy = WRTC_REGION_REQUIRED;
    else if (policy != NULL && final_name_is(policy, "preferred"))
        region->policy = WRTC_REGION_PREFERRED;
    else if (policy != NULL && is_kind(policy, "Constant")) {
        PyObject *value = attr(policy, "value");
        const char *text =
            value != NULL && PyUnicode_Check(value)
                ? PyUnicode_AsUTF8(value) : NULL;
        if (text != NULL && strcmp(text, "required") == 0)
            region->policy = WRTC_REGION_REQUIRED;
        else if (text != NULL && strcmp(text, "preferred") == 0)
            region->policy = WRTC_REGION_PREFERRED;
        Py_XDECREF(value);
    }
    if (effects != NULL) {
        PyObject *owner = call_keyword(effects, "owner");
        PyObject *noescape = call_keyword(effects, "noescape");
        PyObject *allocation = call_keyword(effects, "allocate");
        PyObject *suspension = call_keyword(effects, "suspend");
        region->owner = constant_string(owner);
        Py_XDECREF(owner);
        if (region->owner == NULL)
            region->owner = find_string_call(effects, "owned_by");
        if (expression_contains(effects, "READ") ||
            expression_contains(effects, "read"))
            region->capabilities |= WRTC_REGION_READ;
        if (expression_contains(effects, "WRITE") ||
            expression_contains(effects, "write"))
            region->capabilities |= WRTC_REGION_WRITE;
        if (expression_contains(effects, "ALLOCATE") ||
            expression_contains(effects, "allocate"))
            region->capabilities |= WRTC_REGION_ALLOCATE;
        if (expression_contains(effects, "RAISE") ||
            expression_contains(effects, "raise_"))
            region->capabilities |= WRTC_REGION_RAISE;
        if (noescape != NULL)
            region->capabilities |= WRTC_REGION_NOESCAPE;
        if (allocation != NULL && final_name_is(allocation, "never"))
            region->capabilities |= WRTC_REGION_NO_ALLOCATE;
        if (suspension != NULL && final_name_is(suspension, "never"))
            region->capabilities |= WRTC_REGION_NO_SUSPEND;
        if (expression_contains(effects, "packet_pool"))
            region->capabilities |= WRTC_REGION_PACKET_POOL;
        Py_XDECREF(suspension);
        Py_XDECREF(allocation);
        Py_XDECREF(noescape);
    }
    if (fusion != NULL || expression_contains(decorator, "fuse") ||
        expression_contains(decorator, "fusion"))
        region->fusion_requested = 1u;
    if (execute != NULL && is_kind(execute, "Call") &&
        final_name_is(execute, "owned_shard")) {
        PyObject *key = call_keyword(execute, "key");
        PyObject *workers = call_keyword(execute, "workers");
        PyObject *input = call_keyword(execute, "input");
        PyObject *output = call_keyword(execute, "output");
        PyObject *ordered = call_keyword(execute, "ordered");
        PyObject *ordered_value =
            ordered != NULL && is_kind(ordered, "Constant")
                ? attr(ordered, "value") : NULL;
        region->capabilities |= WRTC_REGION_OWNED_SHARD;
        region->shard_key = scalar_text(key);
        region->shard_workers = scalar_text(workers);
        region->shard_ordered =
            ordered == NULL || ordered_value == Py_True;
        if (input != NULL && final_name_is(input, "spsc"))
            region->capabilities |= WRTC_REGION_SPSC;
        if (output != NULL && final_name_is(output, "spsc"))
            region->capabilities |= WRTC_REGION_SPSC;
        if (input != NULL && final_name_is(input, "mpsc"))
            region->capabilities |= WRTC_REGION_MPSC;
        if (output != NULL && final_name_is(output, "mpsc"))
            region->capabilities |= WRTC_REGION_MPSC;
        Py_XDECREF(ordered_value);
        Py_XDECREF(ordered);
        Py_XDECREF(output);
        Py_XDECREF(input);
        Py_XDECREF(workers);
        Py_XDECREF(key);
    }
    Py_XDECREF(execute);
    Py_XDECREF(fusion);
    Py_XDECREF(effects);
    Py_XDECREF(policy);
    Py_XDECREF(args);
    if (region->policy == WRTC_REGION_UNSPECIFIED)
        return diagnostic(core, decorator,
                          "region policy must be required or preferred");
    return 0;
}

static int analyze_region_body(PyObject *node, WrtcNativeRegionIR *region) {
    PyObject *fields = attr(node, "_fields");
    Py_ssize_t index, count;
    if (fields == NULL) {
        PyErr_Clear();
        return 0;
    }
    if (is_kind(node, "Call")) {
        PyObject *function = attr(node, "func");
        char *name = function == NULL ? NULL : dotted_name(function);
        WrtcNativeCallEdgeIR *calls;
        const char *final = name == NULL ? NULL : strrchr(name, '.');
        final = final == NULL ? name : final + 1;
        calls = realloc(region->calls,
                        (region->call_count + 1u) * sizeof(*calls));
        if (calls == NULL) {
            free(name);
            Py_XDECREF(function);
            Py_DECREF(fields);
            PyErr_NoMemory();
            return -1;
        }
        region->calls = calls;
        memset(&region->calls[region->call_count], 0,
               sizeof(region->calls[region->call_count]));
        region->calls[region->call_count].target = copy_text(name);
        region->calls[region->call_count].span = span_of(node);
        region->calls[region->call_count].target_class = (size_t)-1;
        region->calls[region->call_count].target_region = (size_t)-1;
        if (region->call_count == 0u)
            region->direct_call_target = copy_text(name);
        region->call_count++;
        region->capabilities |= WRTC_REGION_CALL;
        if (final != NULL &&
            (strcmp(final, "append") == 0 ||
             strcmp(final, "appendleft") == 0 ||
             strcmp(final, "popleft") == 0))
            region->capabilities |= WRTC_REGION_FIFO;
        if (final != NULL &&
            (strcmp(final, "heapify") == 0 ||
             strcmp(final, "heappop") == 0 ||
             strcmp(final, "heappush") == 0))
            region->capabilities |= WRTC_REGION_MIN_HEAP;
        if (final != NULL && strcmp(final, "select") == 0)
            region->capabilities |= WRTC_REGION_SELECTOR_POLL;
        if (final != NULL &&
            (strcmp(final, "recv") == 0 ||
             strcmp(final, "recvfrom") == 0 ||
             strcmp(final, "recv_into") == 0 ||
             strcmp(final, "recvfrom_into") == 0))
            region->capabilities |= WRTC_REGION_SOCKET_RECEIVE;
        if (final != NULL &&
            (strcmp(final, "recv_into") == 0 ||
             strcmp(final, "recvfrom_into") == 0))
            region->capabilities |= WRTC_REGION_RECEIVE_INTO;
        if (final != NULL &&
            (strcmp(final, "acquire") == 0 ||
             strcmp(final, "release") == 0 ||
             strcmp(final, "receive_one") == 0))
            region->capabilities |= WRTC_REGION_PACKET_POOL;
        if (final != NULL && strcmp(final, "deliver") == 0)
            region->capabilities |= WRTC_REGION_DELIVERY;
        if (final != NULL && strcmp(final, "request_reschedule") == 0)
            region->capabilities |= WRTC_REGION_RESCHEDULE;
        if (final != NULL &&
            (strcmp(final, "load") == 0 ||
             strcmp(final, "store") == 0 ||
             strcmp(final, "exchange") == 0 ||
             strcmp(final, "compare_exchange") == 0 ||
             strcmp(final, "fetch_add") == 0))
            region->capabilities |= WRTC_REGION_ATOMIC;
        if (final != NULL && strcmp(final, "compare_exchange") == 0) {
            region->capabilities |= WRTC_REGION_COMPARE_EXCHANGE;
        }
        if (final != NULL &&
            (strcmp(final, "put_nowait") == 0 ||
             strcmp(final, "get_nowait") == 0 ||
             strcmp(final, "drain_snapshot") == 0)) {
            region->capabilities |= WRTC_REGION_BOUNDED_QUEUE;
            region->queue_linearization_proven = 1u;
        }
        if (final != NULL && strcmp(final, "_write_to_self") == 0)
            region->capabilities |= WRTC_REGION_COALESCED_NOTIFICATION;
        if (final != NULL &&
            (strcmp(final, "join") == 0 ||
             strcmp(final, "stop_admission") == 0))
            region->capabilities |= WRTC_REGION_SHUTDOWN;
        if (final != NULL && strcmp(final, "_run") == 0)
            region->capabilities |= WRTC_REGION_HANDLE_RUN;
        if (final != NULL &&
            (strcmp(final, "_processor") == 0 ||
             strcmp(final, "_on_result") == 0 ||
             strcmp(final, "call_soon_threadsafe") == 0))
            region->worker_python_free = 0u;
        free(name);
        Py_XDECREF(function);
    }
    if (is_kind(node, "For")) {
        PyObject *iterator = attr(node, "iter");
        region->loop_count++;
        if (iterator != NULL && is_kind(iterator, "Call") &&
            final_name_is(iterator, "range")) {
            PyObject *arguments = attr(iterator, "args");
            PyObject *bound =
                arguments != NULL && PySequence_Size(arguments) == 1
                    ? PySequence_GetItem(arguments, 0) : NULL;
            if (bound != NULL) {
                region->bounded_loop_count++;
                region->capabilities |= WRTC_REGION_BOUNDED_LOOP;
                if (expression_contains(bound, "budget") ||
                    expression_contains(bound, "receive_packet_budget"))
                    region->capabilities |= WRTC_REGION_PACKET_BUDGET;
            }
            Py_XDECREF(bound);
            Py_XDECREF(arguments);
        }
        Py_XDECREF(iterator);
    }
    if (is_kind(node, "Compare") &&
        (expression_contains(node, "time_budget") ||
         expression_contains(node, "receive_time_budget_us")) &&
        expression_contains(node, "time"))
        region->capabilities |= WRTC_REGION_TIME_BUDGET;
    if ((is_kind(node, "Attribute") || is_kind(node, "Name")) &&
        (final_name_is(node, "EVENT_READ") ||
         final_name_is(node, "EVENT_WRITE")))
        region->capabilities |= WRTC_REGION_SELECTOR_EVENT_MASK;
    if ((is_kind(node, "Attribute") || is_kind(node, "Name")) &&
        (final_name_is(node, "data") || final_name_is(node, "fileobj")))
        region->capabilities |= WRTC_REGION_SELECTOR_KEY_DATA;
    count = PySequence_Size(fields);
    for (index = 0; index < count; index++) {
        PyObject *field = PySequence_GetItem(fields, index);
        const char *name = field == NULL ? NULL : PyUnicode_AsUTF8(field);
        PyObject *value = name == NULL ? NULL : attr(node, name);
        Py_XDECREF(field);
        if (value == NULL) {
            Py_DECREF(fields);
            return -1;
        }
        if (PyList_Check(value) || PyTuple_Check(value)) {
            Py_ssize_t child, children = PySequence_Size(value);
            for (child = 0; child < children; child++) {
                PyObject *item = PySequence_GetItem(value, child);
                if (item == NULL || analyze_region_body(item, region) < 0) {
                    Py_XDECREF(item);
                    Py_DECREF(value);
                    Py_DECREF(fields);
                    return -1;
                }
                Py_DECREF(item);
            }
        } else if (analyze_region_body(value, region) < 0) {
            Py_DECREF(value);
            Py_DECREF(fields);
            return -1;
        }
        Py_DECREF(value);
    }
    Py_DECREF(fields);
    region->selector_shape_validated =
        (region->capabilities & WRTC_REGION_SELECTOR_EVENT_MASK) != 0u &&
        (region->capabilities & WRTC_REGION_SELECTOR_KEY_DATA) != 0u;
    if (region->selector_shape_validated)
        region->capabilities |= WRTC_REGION_SELECTOR_DISPATCH;
    region->packet_order_preserved =
        (region->capabilities & WRTC_REGION_BOUNDED_LOOP) != 0u &&
        (region->capabilities & WRTC_REGION_DELIVERY) != 0u;
    region->pool_lifetime_checked =
        (region->capabilities & WRTC_REGION_PACKET_POOL) != 0u &&
        (region->capabilities & WRTC_REGION_NOESCAPE) != 0u;
    region->bounded_interleaving =
        (region->capabilities & WRTC_REGION_PACKET_BUDGET) != 0u &&
        (region->capabilities & WRTC_REGION_TIME_BUDGET) != 0u &&
        (region->capabilities & WRTC_REGION_RESCHEDULE) != 0u;
    if ((region->capabilities & WRTC_REGION_BOUNDED_QUEUE) != 0u &&
        expression_contains(node, "Full"))
        region->full_queue_behavior_proven = 1u;
    if ((region->capabilities & WRTC_REGION_COALESCED_NOTIFICATION) != 0u &&
        (region->capabilities & WRTC_REGION_COMPARE_EXCHANGE) != 0u)
        region->wakeup_coalescing_proven = 1u;
    if ((region->capabilities & WRTC_REGION_OWNED_SHARD) != 0u &&
        region->shard_key != NULL && region->shard_workers != NULL &&
        region->shard_ordered)
        region->ownership_transfer_proven = 1u;
    region->reclamation_proven = 0u;
    if ((region->capabilities & WRTC_REGION_SHUTDOWN) != 0u)
        region->shutdown_interaction_proven = 1u;
    return 0;
}

static int analyze_class(const WrtcCompilerCore *core, PyObject *node,
                         WrtcNativeClassIR *class_ir) {
    PyObject *decorators = attr(node, "decorator_list");
    PyObject *body = attr(node, "body");
    PyObject *bases = attr(node, "bases");
    Py_ssize_t index, count;
    size_t field_index = 0u, region_index = 0u;
    int marked = 0;
    if (decorators == NULL || body == NULL || bases == NULL) goto error;
    count = PySequence_Size(decorators);
    for (index = 0; index < count; index++) {
        PyObject *decorator = PySequence_GetItem(decorators, index);
        if (decorator != NULL && is_kind(decorator, "Call") &&
            final_name_is(decorator, "native_class")) {
            if (marked || parse_native_decorator(core, decorator, class_ir) < 0) {
                Py_XDECREF(decorator);
                goto error;
            }
            marked = 1;
        }
        Py_XDECREF(decorator);
    }
    if (!marked) {
        Py_DECREF(bases);
        Py_DECREF(body);
        Py_DECREF(decorators);
        return 0;
    }
    class_ir->name = definition_name(node);
    class_ir->filename = copy_text(core->filename);
    class_ir->span = span_of(node);
    if (PySequence_Size(bases) == 1) {
        PyObject *base = PySequence_GetItem(bases, 0);
        class_ir->base = base == NULL ? NULL : dotted_name(base);
        Py_XDECREF(base);
    }
    count = PySequence_Size(body);
    for (index = 0; index < count; index++) {
        PyObject *member = PySequence_GetItem(body, index);
        PyObject *member_decorators =
            member != NULL && is_kind(member, "FunctionDef")
                ? attr(member, "decorator_list") : NULL;
        Py_ssize_t deco_index, deco_count =
            member_decorators == NULL ? 0 : PySequence_Size(member_decorators);
        if (member != NULL && is_kind(member, "AnnAssign"))
            class_ir->field_count++;
        if (member != NULL && is_kind(member, "FunctionDef")) {
            char *member_name = definition_name(member);
            if (member_name != NULL &&
                (strcmp(member_name, "__init__") == 0 ||
                 strcmp(member_name, "__new__") == 0))
                class_ir->custom_constructor = 1u;
            free(member_name);
        }
        for (deco_index = 0; deco_index < deco_count; deco_index++) {
            PyObject *decorator =
                PySequence_GetItem(member_decorators, deco_index);
            if (decorator != NULL && is_kind(decorator, "Call") &&
                final_name_is(decorator, "region"))
                class_ir->region_count++;
            Py_XDECREF(decorator);
        }
        Py_XDECREF(member_decorators);
        Py_XDECREF(member);
    }
    class_ir->fields = calloc(class_ir->field_count, sizeof(*class_ir->fields));
    class_ir->regions =
        calloc(class_ir->region_count, sizeof(*class_ir->regions));
    if ((class_ir->field_count != 0u && class_ir->fields == NULL) ||
        (class_ir->region_count != 0u && class_ir->regions == NULL))
        goto error;
    for (index = 0; index < count; index++) {
        PyObject *member = PySequence_GetItem(body, index);
        if (member != NULL && is_kind(member, "AnnAssign")) {
            PyObject *target = attr(member, "target");
            PyObject *annotation = attr(member, "annotation");
            WrtcNativeFieldIR *field = &class_ir->fields[field_index++];
            field->name =
                target != NULL && is_kind(target, "Name")
                    ? node_name(target) : NULL;
            field->span = span_of(member);
            field->type = annotation_type(annotation);
            field->declared_type = annotation_declared_type(annotation);
            field->native_storage =
                expression_contains(annotation, "native_field") ? 1u : 0u;
            field->exact_type =
                expression_contains(annotation, "exact_type") ? 1u : 0u;
            if (expression_contains(annotation, "spsc"))
                field->storage_kind = WRTC_NATIVE_FIELD_SPSC;
            else if (expression_contains(annotation, "mpsc"))
                field->storage_kind = WRTC_NATIVE_FIELD_MPSC;
            else if (expression_contains(annotation, "fifo"))
                field->storage_kind = WRTC_NATIVE_FIELD_FIFO;
            else if (expression_contains(annotation, "min_heap"))
                field->storage_kind = WRTC_NATIVE_FIELD_MIN_HEAP;
            else if (field->native_storage)
                field->storage_kind = WRTC_NATIVE_FIELD_SCALAR;
            else
                field->storage_kind = WRTC_NATIVE_FIELD_PYOBJECT;
            field->heap_key =
                find_call_keyword_text(annotation, "min_heap", "key");
            field->heap_ordering =
                find_call_keyword_text(annotation, "min_heap", "ordering");
            field->owner = find_string_call(annotation, "owned_by");
            field->atomic =
                expression_contains(annotation, "atomic") ? 1u : 0u;
            if (field->atomic) {
                field->atomic_width = atomic_uint_width(annotation);
                field->atomic_memory_order = copy_text("seq_cst");
                field->atomic_scope = copy_text("process");
                field->atomic_linearization =
                    copy_text("compare_exchange");
                field->native_storage = 1u;
                field->storage_kind = WRTC_NATIVE_FIELD_ATOMIC_UINT32;
            }
            field->coalesced_notification =
                expression_contains(annotation, "coalesced_notification")
                    ? 1u : 0u;
            if (expression_contains(annotation, "spsc"))
                field->queue_topology = WRTC_QUEUE_SPSC;
            else if (expression_contains(annotation, "mpsc"))
                field->queue_topology = WRTC_QUEUE_MPSC;
            field->queue_capacity = find_call_keyword_text(
                annotation, "bounded_queue", "capacity");
            field->queue_item_type = find_queue_item_type(annotation);
            Py_XDECREF(annotation);
            Py_XDECREF(target);
        } else if (member != NULL && is_kind(member, "FunctionDef")) {
            PyObject *member_decorators = attr(member, "decorator_list");
            Py_ssize_t deco_index, deco_count =
                member_decorators == NULL ? 0 : PySequence_Size(member_decorators);
            for (deco_index = 0; deco_index < deco_count; deco_index++) {
                PyObject *decorator =
                    PySequence_GetItem(member_decorators, deco_index);
                if (decorator != NULL && is_kind(decorator, "Call") &&
                    final_name_is(decorator, "region")) {
                    WrtcNativeRegionIR *region =
                        &class_ir->regions[region_index++];
                    region->name = definition_name(member);
                    region->span = span_of(member);
                    {
                        PyObject *returns = attr(member, "returns");
                        region->result_type =
                            returns == NULL || returns == Py_None
                                ? NULL : dotted_name(returns);
                        Py_XDECREF(returns);
                    }
                    if (parse_region_decorator(core, decorator, region) < 0) {
                        Py_XDECREF(decorator);
                        Py_XDECREF(member_decorators);
                        Py_DECREF(member);
                        goto error;
                    }
                    if (wrtc_py_ir_lower_signature(
                            member,
                            class_ir->filename == NULL
                                ? core->filename : class_ir->filename,
                            &region->signature) < 0) {
                        Py_XDECREF(decorator);
                        Py_XDECREF(member_decorators);
                        Py_DECREF(member);
                        goto error;
                    }
                    {
                        PyObject *statements = attr(member, "body");
                        Py_ssize_t statement_index, statement_count =
                            statements == NULL ? -1 : PySequence_Size(statements);
                        if (statements == NULL ||
                            wrtc_py_ir_lower_suite(
                                statements,
                                class_ir->filename == NULL
                                    ? core->filename : class_ir->filename,
                                &region->body) < 0) {
                            Py_XDECREF(statements);
                            Py_XDECREF(decorator);
                            Py_XDECREF(member_decorators);
                            Py_DECREF(member);
                            goto error;
                        }
                        for (statement_index = 0;
                             statement_index < statement_count;
                             statement_index++) {
                            PyObject *statement =
                                PySequence_GetItem(statements, statement_index);
                            if (statement == NULL ||
                                analyze_region_body(statement, region) < 0) {
                                Py_XDECREF(statement);
                                Py_XDECREF(statements);
                                Py_XDECREF(decorator);
                                Py_XDECREF(member_decorators);
                                Py_DECREF(member);
                                goto error;
                            }
                            Py_DECREF(statement);
                        }
                        Py_XDECREF(statements);
                    }
                }
                Py_XDECREF(decorator);
            }
            Py_XDECREF(member_decorators);
        }
        Py_XDECREF(member);
    }
    /*
     * Field descriptors are available to every method, but they do not make
     * every method concurrent.  Operation proof below attaches atomic/queue
     * capabilities only to regions that actually touch those fields.
     */
    Py_DECREF(bases);
    Py_DECREF(body);
    Py_DECREF(decorators);
    return 1;
error:
    Py_XDECREF(bases);
    Py_XDECREF(body);
    Py_XDECREF(decorators);
    return -1;
}

int wrtc_native_class_analyze(const char *source, size_t source_length,
                              const char *filename,
                              WrtcNativeClassProgram **out) {
    WrtcCompilerCore syntax = {0};
    WrtcNativeClassProgram *program;
    PyObject *ast = NULL, *parse = NULL, *text = NULL, *path = NULL;
    PyObject *body = NULL;
    Py_ssize_t index, count;
    size_t class_index = 0u;
    size_t record_index = 0u;
    if (source == NULL || filename == NULL || out == NULL) {
        PyErr_SetString(PyExc_ValueError, "native class analysis input is absent");
        return -1;
    }
    *out = NULL;
    syntax.filename = copy_text(filename);
    ast = PyImport_ImportModule("ast");
    parse = ast == NULL ? NULL : PyObject_GetAttrString(ast, "parse");
    text = PyUnicode_DecodeUTF8(source, (Py_ssize_t)source_length, "strict");
    path = PyUnicode_DecodeFSDefault(filename);
    syntax.tree =
        parse == NULL || text == NULL || path == NULL
            ? NULL : PyObject_CallFunctionObjArgs(parse, text, path, NULL);
    if (syntax.filename == NULL || syntax.tree == NULL) goto parse_error;
    program = calloc(1u, sizeof(*program));
    if (program == NULL) {
        PyErr_NoMemory();
        goto parse_error;
    }
    body = attr(syntax.tree, "body");
    if (body == NULL) {
        free(program);
        goto parse_error;
    }
    count = PySequence_Size(body);
    for (index = 0; index < count; index++) {
        PyObject *node = PySequence_GetItem(body, index);
        PyObject *decorators =
            node != NULL && is_kind(node, "ClassDef")
                ? attr(node, "decorator_list") : NULL;
        Py_ssize_t deco, deco_count =
            decorators == NULL ? 0 : PySequence_Size(decorators);
        for (deco = 0; deco < deco_count; deco++) {
            PyObject *decorator = PySequence_GetItem(decorators, deco);
            if (decorator != NULL && is_kind(decorator, "Call") &&
                final_name_is(decorator, "native_class")) {
                program->class_count++;
                Py_DECREF(decorator);
                break;
            }
            Py_XDECREF(decorator);
        }
        Py_XDECREF(decorators);
        if (node != NULL && is_kind(node, "ClassDef") &&
            has_called_decorator(node, "record"))
            program->record_count++;
        Py_XDECREF(node);
    }
    program->classes =
        calloc(program->class_count, sizeof(*program->classes));
    if (program->class_count != 0u && program->classes == NULL) {
        Py_CLEAR(body);
        free(program);
        PyErr_NoMemory();
        goto parse_error;
    }
    program->records =
        calloc(program->record_count, sizeof(*program->records));
    if (program->record_count != 0u && program->records == NULL) {
        Py_CLEAR(body);
        wrtc_native_class_free(program);
        PyErr_NoMemory();
        goto parse_error;
    }
    for (index = 0; index < count; index++) {
        PyObject *node = PySequence_GetItem(body, index);
        if (node != NULL && is_kind(node, "ClassDef") &&
            has_called_decorator(node, "record")) {
            PyObject *members = attr(node, "body");
            Py_ssize_t member_index, member_count =
                members == NULL ? 0 : PySequence_Size(members);
            WrtcTypedRecordIR *record = &program->records[record_index++];
            char *record_abi =
                called_decorator_keyword_string(node, "record", "abi");
            record->name = definition_name(node);
            record->filename = copy_text(filename);
            record->span = span_of(node);
            record->representation_proven = 1u;
            for (member_index = 0; member_index < member_count;
                 member_index++) {
                PyObject *member = PySequence_GetItem(members, member_index);
                if (member != NULL && is_kind(member, "AnnAssign")) {
                    PyObject *annotation = attr(member, "annotation");
                    record->field_count++;
                    if (annotation == NULL ||
                        !(expression_contains(annotation, "uint") ||
                          expression_contains(annotation, "sint") ||
                          expression_contains(annotation, "float_") ||
                          expression_contains(annotation, "buffer"))) {
                        /*
                         * CPython-native queues may retain an exact Python
                         * record as one owned object.  Its non-native fields
                         * remain boxed; they are not falsely described as a
                         * fixed unboxed C layout.
                         */
                        record->boxed_field_count++;
                    }
                    Py_XDECREF(annotation);
                }
                Py_XDECREF(member);
            }
            record->abi_declared =
                record_abi != NULL && record_abi[0] != '\0';
            record->boxed_ownership_proven =
                record->abi_declared &&
                has_called_decorator(node, "dataclass") &&
                called_decorator_keyword_true(
                    node, "dataclass", "frozen") &&
                called_decorator_keyword_true(
                    node, "dataclass", "slots");
            record->exact_runtime_type_guard =
                record->boxed_ownership_proven;
            record->representation_proven =
                record->abi_declared &&
                (record->boxed_field_count == 0u ||
                 record->boxed_ownership_proven);
            free(record_abi);
            Py_XDECREF(members);
        }
        int result =
            node != NULL && is_kind(node, "ClassDef")
                ? analyze_class(&syntax, node, &program->classes[class_index]) : 0;
        Py_XDECREF(node);
        if (result < 0) {
            Py_CLEAR(body);
            wrtc_native_class_free(program);
            program = NULL;
            goto parse_error;
        }
        if (result > 0) class_index++;
    }
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++) {
            WrtcNativeRegionIR *region =
                &program->classes[class_index].regions[region_index];
            size_t typed_index;
            const char *result = region->result_type;
            const char *final =
                result == NULL ? NULL : strrchr(result, '.');
            final = final == NULL ? result : final + 1;
            for (typed_index = 0u; typed_index < program->record_count;
                 typed_index++) {
                if (final != NULL &&
                    strcmp(final, program->records[typed_index].name) == 0) {
                    region->capabilities |= WRTC_REGION_TYPED_RECORD;
                    region->typed_worker_records =
                        program->records[typed_index].abi_declared &&
                        program->records[typed_index].representation_proven;
                }
            }
        }
    }
    for (index = 0; index < count; index++) {
        PyObject *node = PySequence_GetItem(body, index);
        if (node != NULL && is_kind(node, "FunctionDef")) {
            char *function_name = definition_name(node);
            if (function_name != NULL && function_name[0] != '_') {
                const WrtcNativeClassIR *target = NULL;
                for (class_index = 0u;
                     class_index < program->class_count; class_index++)
                    if (expression_contains(
                            node, program->classes[class_index].name)) {
                        if (target != NULL) {
                            target = NULL;
                            break;
                        }
                        target = &program->classes[class_index];
                    }
                if (target != NULL) {
                    WrtcNativeFactoryIR *factories = realloc(
                        program->factories,
                        (program->factory_count + 1u) * sizeof(*factories));
                    WrtcNativeFactoryIR *factory;
                    PyObject *statements;
                    if (factories == NULL) {
                        free(function_name);
                        Py_DECREF(node);
                        Py_CLEAR(body);
                        wrtc_native_class_free(program);
                        program = NULL;
                        PyErr_NoMemory();
                        goto parse_error;
                    }
                    program->factories = factories;
                    factory = &program->factories[program->factory_count++];
                    memset(factory, 0, sizeof(*factory));
                    factory->name = function_name;
                    function_name = NULL;
                    factory->filename = copy_text(filename);
                    factory->target_class = copy_text(target->name);
                    factory->span = span_of(node);
                    statements = attr(node, "body");
                    if (factory->filename == NULL ||
                        factory->target_class == NULL ||
                        statements == NULL ||
                        wrtc_py_ir_lower_signature(
                            node, filename, &factory->signature) < 0 ||
                        wrtc_py_ir_lower_suite(
                            statements, filename, &factory->body) < 0) {
                        Py_XDECREF(statements);
                        free(function_name);
                        Py_DECREF(node);
                        Py_CLEAR(body);
                        wrtc_native_class_free(program);
                        program = NULL;
                        goto parse_error;
                    }
                    Py_DECREF(statements);
                    if (program->factory_name == NULL)
                        program->factory_name = copy_text(factory->name);
                }
            }
            free(function_name);
        }
        Py_XDECREF(node);
    }
    Py_CLEAR(body);
    wrtc_native_class_resolve_calls(program);
    *out = program;
    Py_DECREF(syntax.tree);
    Py_DECREF(path);
    Py_DECREF(text);
    Py_DECREF(parse);
    Py_DECREF(ast);
    free(syntax.filename);
    return 0;
parse_error:
    Py_XDECREF(body);
    Py_XDECREF(syntax.tree);
    Py_XDECREF(path);
    Py_XDECREF(text);
    Py_XDECREF(parse);
    Py_XDECREF(ast);
    free(syntax.filename);
    return -1;
}

int wrtc_native_class_merge(WrtcNativeClassProgram *destination,
                            WrtcNativeClassProgram *source) {
    WrtcNativeClassIR *classes;
    WrtcTypedRecordIR *records;
    WrtcNativeFactoryIR *factories;
    size_t class_count, record_count, factory_count;
    if (destination == NULL || source == NULL) {
        PyErr_SetString(PyExc_ValueError, "native class merge input is absent");
        return -1;
    }
    class_count = destination->class_count + source->class_count;
    record_count = destination->record_count + source->record_count;
    factory_count = destination->factory_count + source->factory_count;
    if (class_count < destination->class_count ||
        record_count < destination->record_count) {
        PyErr_NoMemory();
        return -1;
    }
    if (destination->factory_name == NULL &&
        source->factory_name != NULL) {
        destination->factory_name = source->factory_name;
        source->factory_name = NULL;
    }
    factories = destination->factories;
    if (source->factory_count != 0u) {
        factories =
            realloc(factories, factory_count * sizeof(*factories));
        if (factories == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        memcpy(factories + destination->factory_count, source->factories,
               source->factory_count * sizeof(*factories));
        destination->factories = factories;
        destination->factory_count = factory_count;
        free(source->factories);
        source->factories = NULL;
        source->factory_count = 0u;
    }
    classes = destination->classes;
    if (source->class_count != 0u) {
        classes = realloc(classes, class_count * sizeof(*classes));
        if (classes == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        memcpy(classes + destination->class_count, source->classes,
               source->class_count * sizeof(*classes));
        destination->classes = classes;
        destination->class_count = class_count;
        free(source->classes);
        source->classes = NULL;
        source->class_count = 0u;
    }
    records = destination->records;
    if (source->record_count != 0u) {
        records = realloc(records, record_count * sizeof(*records));
        if (records == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        memcpy(records + destination->record_count, source->records,
               source->record_count * sizeof(*records));
        destination->records = records;
        destination->record_count = record_count;
        free(source->records);
        source->records = NULL;
        source->record_count = 0u;
    }
    return 0;
}

static const char *final_type_name(const char *type_name,
                                   char *buffer, size_t buffer_size) {
    const char *begin = type_name;
    const char *end;
    const char *dot;
    size_t length;
    if (type_name == NULL || buffer_size == 0u) return NULL;
    while (*begin == '\'' || *begin == '"' || *begin == ' ') begin++;
    end = begin + strlen(begin);
    while (end > begin &&
           (end[-1] == '\'' || end[-1] == '"' || end[-1] == ' '))
        end--;
    dot = end;
    while (dot > begin && dot[-1] != '.') dot--;
    length = (size_t)(end - dot);
    if (length == 0u || length >= buffer_size) return NULL;
    memcpy(buffer, dot, length);
    buffer[length] = '\0';
    return buffer;
}

static size_t class_index_for_type(const WrtcNativeClassProgram *program,
                                   const char *type_name) {
    char final_name[256];
    size_t index;
    if (final_type_name(type_name, final_name, sizeof final_name) == NULL)
        return (size_t)-1;
    for (index = 0u; index < program->class_count; index++)
        if (strcmp(program->classes[index].name, final_name) == 0)
            return index;
    return (size_t)-1;
}

static const WrtcPyParameterIR *region_parameter(
    const WrtcNativeRegionIR *region, const char *name) {
    size_t index;
    if (region->signature == NULL) return NULL;
    for (index = 0u; index < region->signature->parameter_count; index++)
        if (strcmp(region->signature->parameters[index].name, name) == 0)
            return &region->signature->parameters[index];
    return NULL;
}

static void resolve_call_edge(WrtcNativeClassProgram *program,
                              size_t source_class_index,
                              WrtcNativeRegionIR *region,
                              WrtcNativeCallEdgeIR *edge) {
    char *target_copy, *part, *save = NULL;
    char *parts[32];
    size_t part_count = 0u, current_class = (size_t)-1, part_index;
    int exact_receiver = 0;
    edge->resolved = 0u;
    edge->required_callee = 0u;
    edge->exact_receiver = 0u;
    edge->fused = 0u;
    edge->target_class = (size_t)-1;
    edge->target_region = (size_t)-1;
    if (edge->target == NULL) return;
    target_copy = copy_text(edge->target);
    if (target_copy == NULL) {
        PyErr_Clear();
        return;
    }
    for (part = strtok_r(target_copy, ".", &save);
         part != NULL && part_count < sizeof parts / sizeof parts[0];
         part = strtok_r(NULL, ".", &save))
        parts[part_count++] = part;
    if (part != NULL || part_count < 2u) goto done;
    if (strcmp(parts[0], "self") == 0) {
        current_class = source_class_index;
        exact_receiver = 1;
    } else {
        const WrtcPyParameterIR *parameter =
            region_parameter(region, parts[0]);
        if (parameter != NULL) {
            current_class =
                class_index_for_type(program, parameter->annotation);
            /*
             * A typed region parameter supplies a guardable receiver class,
             * not an unchecked exact-type assumption.  Generated dispatch
             * verifies the concrete heap type before bypassing lookup and
             * executes the ordinary Python call on mismatch.
             */
            exact_receiver = current_class != (size_t)-1;
        }
    }
    if (current_class == (size_t)-1) goto done;
    for (part_index = 1u; part_index + 1u < part_count; part_index++) {
        const WrtcNativeClassIR *class_ir = &program->classes[current_class];
        const WrtcNativeFieldIR *field = NULL;
        size_t field_index;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++)
            if (strcmp(class_ir->fields[field_index].name,
                       parts[part_index]) == 0) {
                field = &class_ir->fields[field_index];
                break;
            }
        if (field == NULL) goto done;
        current_class =
            class_index_for_type(program, field->declared_type);
        if (current_class == (size_t)-1) goto done;
        exact_receiver = exact_receiver && field->exact_type;
    }
    {
        WrtcNativeClassIR *target_class = &program->classes[current_class];
        size_t target_region;
        for (target_region = 0u; target_region < target_class->region_count;
             target_region++)
            if (strcmp(target_class->regions[target_region].name,
                       parts[part_count - 1u]) == 0) {
                edge->resolved = 1u;
                edge->target_class = current_class;
                edge->target_region = target_region;
                edge->required_callee =
                    target_class->regions[target_region].policy ==
                    WRTC_REGION_REQUIRED;
                edge->exact_receiver = exact_receiver ? 1u : 0u;
                edge->fused =
                    edge->required_callee && edge->exact_receiver;
                break;
            }
    }
done:
    free(target_copy);
}

static int region_owner_is(const WrtcNativeRegionIR *region,
                           const char *owner) {
    return region->owner != NULL && strcmp(region->owner, owner) == 0;
}

/*
 * Prove the MPSC contract from semantic operations and normalized metadata.
 * The runtime algorithm supplies the acquire/release publication protocol and
 * the atomic admission/quiescence barrier; source IR must still prove who may
 * publish, who dequeues, how notification is rearmed, and that shutdown closes
 * admission before the reactor drains and reclaims the queue.
 */
static void finalize_mpsc_proofs(WrtcNativeClassProgram *program) {
    WrtcNativeOperationTable *table = NULL;
    size_t class_index;
    if (program == NULL ||
        wrtc_native_operation_prove(program, &table) < 0 ||
        table == NULL) {
        PyErr_Clear();
        return;
    }
    for (class_index = 0u; class_index < program->class_count;
         class_index++) {
        WrtcNativeClassIR *class_ir = &program->classes[class_index];
        size_t field_index;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++) {
            WrtcNativeFieldIR *field = &class_ir->fields[field_index];
            size_t operation_index;
            int producer = 0, full = 0, consumer = 0;
            int close_seen = 0, close_drain = 0, notification = 0;
            int lifecycle = 0;
            if (field->queue_topology != WRTC_QUEUE_MPSC) continue;
            field->payload_representation_proven =
                field->typed_queue_payload;
            for (operation_index = 0u;
                 operation_index < table->operation_count;
                 operation_index++) {
                const WrtcNativeOperationIR *operation =
                    &table->operations[operation_index];
                const WrtcNativeFieldOperationProof *proof =
                    &table->fields[operation->field_proof_index];
                WrtcNativeRegionIR *region;
                size_t scan;
                size_t close_order = (size_t)-1;
                size_t empty_order = (size_t)-1;
                size_t get_order = (size_t)-1;
                size_t lifecycle_order = (size_t)-1;
                size_t reset_order = (size_t)-1;
                size_t rearm_order = (size_t)-1;
                if (proof->class_index != class_index ||
                    proof->field_index != field_index)
                    continue;
                region = &program->classes[operation->region_class_index]
                              .regions[operation->region_index];
                region->capabilities |=
                    WRTC_REGION_MPSC | WRTC_REGION_BOUNDED_QUEUE;
                if (operation->kind == WRTC_NATIVE_OP_MPSC_PUT_NOWAIT &&
                    region_owner_is(region, "shared")) {
                    producer = 1;
                    /*
                     * The generated bounded send has the explicit
                     * OK/FULL/CLOSED result set; source may translate FULL,
                     * but it does not need to catch it locally to prove that
                     * the queue itself is nonblocking and bounded.
                     */
                    full = 1;
                }
                if (operation->kind == WRTC_NATIVE_OP_MPSC_GET_NOWAIT &&
                    region_owner_is(region, "reactor"))
                    consumer = 1;
                if (operation->kind == WRTC_NATIVE_OP_MPSC_CLOSE)
                    close_seen = 1;
                if (!region_owner_is(region, "reactor")) continue;
                for (scan = 0u; scan < table->operation_count; scan++) {
                    const WrtcNativeOperationIR *candidate =
                        &table->operations[scan];
                    const WrtcNativeFieldOperationProof *candidate_proof =
                        &table->fields[candidate->field_proof_index];
                    const WrtcNativeFieldIR *candidate_field;
                    if (candidate->region_class_index !=
                            operation->region_class_index ||
                        candidate->region_index != operation->region_index)
                        continue;
                    candidate_field =
                        &program->classes[candidate_proof->class_index]
                             .fields[candidate_proof->field_index];
                    if (candidate_proof->class_index == class_index &&
                        candidate_proof->field_index == field_index) {
                        if (candidate->kind == WRTC_NATIVE_OP_MPSC_CLOSE)
                            close_order = candidate->evaluation_order;
                        else if (candidate->kind ==
                                 WRTC_NATIVE_OP_MPSC_EMPTY)
                            empty_order = candidate->evaluation_order;
                        else if (candidate->kind ==
                                 WRTC_NATIVE_OP_MPSC_GET_NOWAIT)
                            get_order = candidate->evaluation_order;
                    }
                    if (candidate_field->storage_kind ==
                            WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                        candidate_field->coalesced_notification) {
                        region->capabilities |=
                            WRTC_REGION_COALESCED_NOTIFICATION;
                        if (candidate->kind ==
                            WRTC_NATIVE_OP_ATOMIC_STORE)
                            reset_order = candidate->evaluation_order;
                        else if (candidate->kind ==
                                 WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE)
                            rearm_order = candidate->evaluation_order;
                    } else if (candidate_field->storage_kind ==
                                   WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                               candidate->kind ==
                                   WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE)
                        lifecycle_order = candidate->evaluation_order;
                }
                if (close_order != (size_t)-1 &&
                    empty_order != (size_t)-1 &&
                    get_order != (size_t)-1 &&
                    close_order < empty_order && empty_order < get_order)
                    close_drain = 1;
                if (reset_order != (size_t)-1 &&
                    empty_order != (size_t)-1 &&
                    rearm_order != (size_t)-1 &&
                    reset_order < empty_order && empty_order < rearm_order)
                    notification = 1;
                if (lifecycle_order != (size_t)-1 &&
                    close_order != (size_t)-1 &&
                    lifecycle_order < close_order && close_drain)
                    lifecycle = 1;
            }
            field->producer_admission_proven =
                producer && field->queue_capacity != NULL;
            field->producer_quiescence_proven =
                close_seen ? 1u : 0u;
            field->reactor_dequeue_proven =
                consumer ? 1u : 0u;
            field->close_drain_order_proven =
                close_drain ? 1u : 0u;
            field->notification_rearm_proven =
                notification ? 1u : 0u;
            field->lifecycle_shutdown_proven =
                lifecycle ? 1u : 0u;
            field->mpsc_memory_ordering_proven =
                producer && consumer && close_seen &&
                field->queue_capacity != NULL;
            field->reactor_reclamation_proven =
                consumer && close_drain &&
                field->producer_quiescence_proven;
            for (operation_index = 0u;
                 operation_index < class_ir->region_count;
                 operation_index++) {
                WrtcNativeRegionIR *region =
                    &class_ir->regions[operation_index];
                if ((region->capabilities & WRTC_REGION_MPSC) == 0u)
                    continue;
                region->producer_admission_proven =
                    field->producer_admission_proven;
                region->producer_quiescence_proven =
                    field->producer_quiescence_proven;
                region->reactor_dequeue_proven =
                    field->reactor_dequeue_proven;
                region->close_drain_order_proven =
                    field->close_drain_order_proven;
                region->memory_ordering_proven =
                    field->mpsc_memory_ordering_proven;
                region->queue_linearization_proven =
                    field->mpsc_memory_ordering_proven;
                region->ownership_transfer_proven =
                    field->payload_representation_proven &&
                    field->producer_admission_proven &&
                    field->reactor_dequeue_proven;
                region->reclamation_proven =
                    field->reactor_reclamation_proven;
                region->full_queue_behavior_proven =
                    full ? 1u : 0u;
                region->wakeup_coalescing_proven =
                    field->notification_rearm_proven;
                region->shutdown_interaction_proven =
                    field->lifecycle_shutdown_proven;
            }
        }
    }
    wrtc_native_operation_table_free(table);
}

/*
 * A bounded SPSC channel has exactly one publishing owner and one consuming
 * owner.  The reusable runtime supplies release publication, acquire
 * consumption, and close/admission quiescence.  Source operations prove the
 * two endpoints plus close-before-drain ownership reclamation.
 */
static void finalize_spsc_proofs(WrtcNativeClassProgram *program) {
    WrtcNativeOperationTable *table = NULL;
    size_t class_index;
    if (program == NULL ||
        wrtc_native_operation_prove(program, &table) < 0 ||
        table == NULL) {
        PyErr_Clear();
        return;
    }
    for (class_index = 0u; class_index < program->class_count;
         class_index++) {
        WrtcNativeClassIR *class_ir = &program->classes[class_index];
        size_t field_index;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++) {
            WrtcNativeFieldIR *field = &class_ir->fields[field_index];
            size_t operation_index;
            int producer = 0, consumer = 0, full = 0;
            int close_seen = 0, close_drain = 0;
            if (field->queue_topology != WRTC_QUEUE_SPSC) continue;
            field->payload_representation_proven =
                field->typed_queue_payload;
            for (operation_index = 0u;
                 operation_index < table->operation_count;
                 operation_index++) {
                const WrtcNativeOperationIR *operation =
                    &table->operations[operation_index];
                const WrtcNativeFieldOperationProof *proof =
                    &table->fields[operation->field_proof_index];
                WrtcNativeRegionIR *region;
                size_t scan, close_order = (size_t)-1;
                size_t empty_order = (size_t)-1;
                size_t get_order = (size_t)-1;
                if (proof->class_index != class_index ||
                    proof->field_index != field_index)
                    continue;
                region = &program->classes[operation->region_class_index]
                              .regions[operation->region_index];
                region->capabilities |=
                    WRTC_REGION_SPSC | WRTC_REGION_BOUNDED_QUEUE;
                if (operation->kind == WRTC_NATIVE_OP_SPSC_PUT_NOWAIT) {
                    producer = 1;
                    full = 1;
                } else if (operation->kind ==
                           WRTC_NATIVE_OP_SPSC_GET_NOWAIT) {
                    consumer = 1;
                } else if (operation->kind ==
                           WRTC_NATIVE_OP_SPSC_CLOSE) {
                    close_seen = 1;
                }
                for (scan = 0u; scan < table->operation_count; scan++) {
                    const WrtcNativeOperationIR *candidate =
                        &table->operations[scan];
                    const WrtcNativeFieldOperationProof *candidate_proof =
                        &table->fields[candidate->field_proof_index];
                    if (candidate->region_class_index !=
                            operation->region_class_index ||
                        candidate->region_index != operation->region_index ||
                        candidate_proof->class_index != class_index ||
                        candidate_proof->field_index != field_index)
                        continue;
                    if (candidate->kind == WRTC_NATIVE_OP_SPSC_CLOSE)
                        close_order = candidate->evaluation_order;
                    else if (candidate->kind ==
                             WRTC_NATIVE_OP_SPSC_EMPTY)
                        empty_order = candidate->evaluation_order;
                    else if (candidate->kind ==
                             WRTC_NATIVE_OP_SPSC_GET_NOWAIT)
                        get_order = candidate->evaluation_order;
                }
                if (close_order != (size_t)-1 &&
                    empty_order != (size_t)-1 &&
                    get_order != (size_t)-1 &&
                    close_order < empty_order && empty_order < get_order)
                    close_drain = 1;
            }
            field->spsc_producer_proven =
                producer && field->queue_capacity != NULL;
            field->spsc_consumer_proven = consumer ? 1u : 0u;
            field->spsc_close_drain_proven =
                close_seen && close_drain;
            field->spsc_memory_ordering_proven =
                producer && consumer && close_seen;
            field->spsc_reclamation_proven =
                field->spsc_close_drain_proven && consumer;
            for (operation_index = 0u;
                 operation_index < class_ir->region_count;
                 operation_index++) {
                WrtcNativeRegionIR *region =
                    &class_ir->regions[operation_index];
                if ((region->capabilities & WRTC_REGION_SPSC) == 0u)
                    continue;
                region->queue_linearization_proven =
                    field->spsc_memory_ordering_proven;
                region->memory_ordering_proven =
                    field->spsc_memory_ordering_proven;
                region->producer_admission_proven =
                    field->spsc_producer_proven;
                region->producer_quiescence_proven =
                    close_seen ? 1u : 0u;
                region->reactor_dequeue_proven =
                    field->spsc_consumer_proven;
                region->close_drain_order_proven =
                    field->spsc_close_drain_proven;
                region->ownership_transfer_proven =
                    field->payload_representation_proven &&
                    field->spsc_producer_proven &&
                    field->spsc_consumer_proven;
                region->reclamation_proven =
                    field->spsc_reclamation_proven;
                region->full_queue_behavior_proven = full ? 1u : 0u;
                region->shutdown_interaction_proven =
                    field->spsc_close_drain_proven;
                region->typed_worker_records =
                    field->payload_representation_proven;
            }
        }
    }
    wrtc_native_operation_table_free(table);
}

void wrtc_native_class_resolve_calls(WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    if (program == NULL) return;
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        WrtcNativeClassIR *source = &program->classes[class_index];
        size_t field_index;
        for (field_index = 0u; field_index < source->field_count;
             field_index++) {
            WrtcNativeFieldIR *field = &source->fields[field_index];
            size_t record_index;
            field->typed_queue_payload = 0u;
            if (field->queue_item_type == NULL) continue;
            for (record_index = 0u; record_index < program->record_count;
                 record_index++) {
                char final_name[256];
                if (final_type_name(field->queue_item_type, final_name,
                                    sizeof final_name) != NULL &&
                    strcmp(program->records[record_index].name,
                           final_name) == 0 &&
                    program->records[record_index].abi_declared &&
                    program->records[record_index]
                        .representation_proven) {
                    field->typed_queue_payload = 1u;
                    break;
                }
            }
        }
    }
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        WrtcNativeClassIR *source = &program->classes[class_index];
        for (region_index = 0u; region_index < source->region_count;
             region_index++) {
            WrtcNativeRegionIR *region = &source->regions[region_index];
            size_t call_index;
            region->direct_callee_resolved = 0u;
            region->direct_callee_fused = 0u;
            for (call_index = 0u; call_index < region->call_count;
                 call_index++) {
                WrtcNativeCallEdgeIR *edge = &region->calls[call_index];
                resolve_call_edge(program, class_index, region, edge);
                if (region->call_count == 1u) {
                    region->direct_callee_resolved = edge->resolved;
                    region->direct_callee_fused = edge->fused;
                }
            }
        }
    }
    finalize_mpsc_proofs(program);
    finalize_spsc_proofs(program);
}

static int dict_set_owned(PyObject *mapping, const char *name, PyObject *value) {
    int status;
    if (value == NULL) return -1;
    status = PyDict_SetItemString(mapping, name, value);
    Py_DECREF(value);
    return status;
}

static PyObject *capability_names(unsigned capabilities) {
    static const struct {
        unsigned flag;
        const char *name;
    } names[] = {
        {WRTC_REGION_READ, "read"},
        {WRTC_REGION_WRITE, "write"},
        {WRTC_REGION_ALLOCATE, "allocate"},
        {WRTC_REGION_RAISE, "raise"},
        {WRTC_REGION_FIFO, "fifo"},
        {WRTC_REGION_MIN_HEAP, "min_heap"},
        {WRTC_REGION_CALL, "call"},
        {WRTC_REGION_SELECTOR_POLL, "selector_poll"},
        {WRTC_REGION_SELECTOR_DISPATCH, "selector_dispatch"},
        {WRTC_REGION_SOCKET_RECEIVE, "socket_receive"},
        {WRTC_REGION_RECEIVE_INTO, "receive_into"},
        {WRTC_REGION_BOUNDED_LOOP, "bounded_loop"},
        {WRTC_REGION_PACKET_BUDGET, "packet_budget"},
        {WRTC_REGION_TIME_BUDGET, "time_budget"},
        {WRTC_REGION_PACKET_POOL, "packet_pool"},
        {WRTC_REGION_DELIVERY, "delivery"},
        {WRTC_REGION_RESCHEDULE, "reschedule"},
        {WRTC_REGION_NOESCAPE, "noescape"},
        {WRTC_REGION_NO_ALLOCATE, "no_allocate"},
        {WRTC_REGION_NO_SUSPEND, "no_suspend"},
        {WRTC_REGION_SELECTOR_EVENT_MASK, "selector_event_mask"},
        {WRTC_REGION_SELECTOR_KEY_DATA, "selector_key_data"},
        {WRTC_REGION_ATOMIC, "atomic"},
        {WRTC_REGION_COMPARE_EXCHANGE, "compare_exchange"},
        {WRTC_REGION_SPSC, "spsc"},
        {WRTC_REGION_MPSC, "mpsc"},
        {WRTC_REGION_BOUNDED_QUEUE, "bounded_queue"},
        {WRTC_REGION_COALESCED_NOTIFICATION, "coalesced_notification"},
        {WRTC_REGION_OWNED_SHARD, "owned_shard"},
        {WRTC_REGION_TYPED_RECORD, "typed_record"},
        {WRTC_REGION_SHUTDOWN, "shutdown"},
        {WRTC_REGION_HANDLE_RUN, "handle_run"},
    };
    PyObject *items = PyList_New(0);
    PyObject *result;
    size_t index;
    if (items == NULL) return NULL;
    for (index = 0u; index < sizeof(names) / sizeof(names[0]); index++) {
        PyObject *item;
        if ((capabilities & names[index].flag) == 0u) continue;
        item = PyUnicode_FromString(names[index].name);
        if (item == NULL || PyList_Append(items, item) < 0) {
            Py_XDECREF(item);
            Py_DECREF(items);
            return NULL;
        }
        Py_DECREF(item);
    }
    result = PyList_AsTuple(items);
    Py_DECREF(items);
    return result;
}

static PyObject *span_report(WrtcSourceSpan span, const char *filename) {
    PyObject *result = PyDict_New();
    if (result == NULL ||
        dict_set_owned(result, "filename",
                       PyUnicode_FromString(filename == NULL ? "" : filename)) < 0 ||
        dict_set_owned(result, "line", PyLong_FromLong(span.line)) < 0 ||
        dict_set_owned(result, "column", PyLong_FromLong(span.column)) < 0 ||
        dict_set_owned(result, "end_line", PyLong_FromLong(span.end_line)) < 0 ||
        dict_set_owned(result, "end_column",
                       PyLong_FromLong(span.end_column)) < 0) {
        Py_XDECREF(result);
        return NULL;
    }
    return result;
}

static const WrtcNativeFieldOperationProof *field_operation_proof(
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t field_index, size_t *proof_index) {
    size_t index;
    if (table == NULL) return NULL;
    for (index = 0u; index < table->field_count; index++)
        if (table->fields[index].class_index == class_index &&
            table->fields[index].field_index == field_index) {
            if (proof_index != NULL) *proof_index = index;
            return &table->fields[index];
        }
    return NULL;
}

/*
 * Keep this list synchronized with the generic hook emitter.  A complete
 * semantic proof is not itself evidence that generated code exists for the
 * operation.
 */
static int operation_kind_lowerable(WrtcNativeOperationKind kind) {
    return kind == WRTC_NATIVE_OP_ALIAS_BIND ||
           kind == WRTC_NATIVE_OP_SCALAR_READ ||
           kind == WRTC_NATIVE_OP_SCALAR_WRITE ||
           kind == WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE ||
           kind == WRTC_NATIVE_OP_LENGTH ||
           kind == WRTC_NATIVE_OP_TRUTH ||
           kind == WRTC_NATIVE_OP_ROOT_READ ||
           kind == WRTC_NATIVE_OP_ITERATE ||
           kind == WRTC_NATIVE_OP_SLICE_ASSIGN ||
           kind == WRTC_NATIVE_OP_BOXED_WRITE ||
           kind == WRTC_NATIVE_OP_FIFO_APPEND ||
           kind == WRTC_NATIVE_OP_FIFO_POPLEFT ||
           kind == WRTC_NATIVE_OP_HEAPIFY ||
           kind == WRTC_NATIVE_OP_HEAP_PUSH ||
           kind == WRTC_NATIVE_OP_HEAP_POP ||
           kind == WRTC_NATIVE_OP_ATOMIC_LOAD ||
           kind == WRTC_NATIVE_OP_ATOMIC_STORE ||
           kind == WRTC_NATIVE_OP_MPSC_PUT_NOWAIT ||
           kind == WRTC_NATIVE_OP_MPSC_GET_NOWAIT ||
           kind == WRTC_NATIVE_OP_MPSC_QSIZE ||
           kind == WRTC_NATIVE_OP_MPSC_EMPTY ||
           kind == WRTC_NATIVE_OP_MPSC_CLOSE ||
           kind == WRTC_NATIVE_OP_SPSC_PUT_NOWAIT ||
           kind == WRTC_NATIVE_OP_SPSC_GET_NOWAIT ||
           kind == WRTC_NATIVE_OP_SPSC_QSIZE ||
           kind == WRTC_NATIVE_OP_SPSC_EMPTY ||
           kind == WRTC_NATIVE_OP_SPSC_CLOSE ||
           kind == WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE;
}

static int field_operations_lowerable(
    const WrtcNativeOperationTable *table, size_t proof_index) {
    size_t index;
    if (table == NULL) return 0;
    for (index = 0u; index < table->operation_count; index++)
        if (table->operations[index].field_proof_index == proof_index &&
            !operation_kind_lowerable(table->operations[index].kind))
            return 0;
    return 1;
}

static PyObject *operation_sites_report(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t region_index, const char *fallback_filename) {
    PyObject *sites = PyList_New(0);
    size_t index;
    if (sites == NULL) return NULL;
    for (index = 0u; table != NULL && index < table->operation_count;
         index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        const WrtcNativeFieldOperationProof *proof;
        const WrtcNativeClassIR *field_class;
        const WrtcNativeFieldIR *field;
        PyObject *site;
        if (operation->region_class_index != class_index ||
            operation->region_index != region_index)
            continue;
        proof = &table->fields[operation->field_proof_index];
        field_class = &program->classes[proof->class_index];
        field = &field_class->fields[proof->field_index];
        site = PyDict_New();
        if (site == NULL ||
            dict_set_owned(
                site, "operation",
                PyUnicode_FromString(wrtc_native_operation_kind_name(
                    operation->kind))) < 0 ||
            dict_set_owned(site, "evaluation_order",
                           PyLong_FromSize_t(
                               operation->evaluation_order)) < 0 ||
            dict_set_owned(site, "field",
                           PyUnicode_FromString(field->name)) < 0 ||
            dict_set_owned(site, "field_class",
                           PyUnicode_FromString(field_class->name)) < 0 ||
            dict_set_owned(
                site, "alias",
                operation->alias_name == NULL
                    ? Py_NewRef(Py_None)
                    : PyUnicode_FromString(operation->alias_name)) < 0 ||
            dict_set_owned(
                site, "detail",
                operation->detail == NULL
                    ? Py_NewRef(Py_None)
                    : PyUnicode_FromString(operation->detail)) < 0 ||
            dict_set_owned(site, "atomic_width",
                           PyLong_FromUnsignedLong(
                               operation->kind ==
                                       WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE
                                   ? field->atomic_width : 0u)) < 0 ||
            dict_set_owned(
                site, "memory_order",
                operation->kind ==
                            WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE &&
                        field->atomic_memory_order != NULL
                    ? PyUnicode_FromString(field->atomic_memory_order)
                    : Py_NewRef(Py_None)) < 0 ||
            dict_set_owned(
                site, "linearization",
                operation->kind ==
                            WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE &&
                        field->atomic_linearization != NULL
                    ? PyUnicode_FromString(field->atomic_linearization)
                    : Py_NewRef(Py_None)) < 0 ||
            dict_set_owned(
                site, "lowered",
                PyBool_FromLong(operation_kind_lowerable(operation->kind))) <
                0 ||
            dict_set_owned(
                site, "execution",
                PyUnicode_FromString(
                    !operation_kind_lowerable(operation->kind)
                        ? "not_emitted"
                        : operation->kind == WRTC_NATIVE_OP_TRUTH ||
                                  operation->kind == WRTC_NATIVE_OP_ITERATE ||
                                  operation->kind ==
                                      WRTC_NATIVE_OP_SLICE_ASSIGN
                              ? "native_storage_hook_with_boxed_deopt"
                        : field->storage_kind == WRTC_NATIVE_FIELD_FIFO ||
                                  field->storage_kind ==
                                      WRTC_NATIVE_FIELD_MIN_HEAP
                              ? "guarded_native_storage_hook_with_boxed_fallback"
                              : "native_storage_hook")) < 0 ||
            dict_set_owned(
                site, "source",
                span_report(
                    operation->span,
                    program->classes[class_index].filename == NULL
                        ? fallback_filename
                        : program->classes[class_index].filename)) < 0 ||
            PyList_Append(sites, site) < 0) {
            Py_XDECREF(site);
            Py_DECREF(sites);
            return NULL;
        }
        Py_DECREF(site);
    }
    return sites;
}

static PyObject *remaining_calls_report(
    const WrtcNativeClassProgram *program,
    const WrtcNativeClassIR *class_ir,
    const WrtcNativeRegionIR *region,
    const WrtcNativeOperationTable *operation_table,
    size_t class_index, size_t region_index,
    const char *fallback_filename) {
    PyObject *calls = PyList_New(0);
    size_t index;
    if (calls == NULL) return NULL;
    for (index = 0u; index < region->call_count; index++) {
        const WrtcNativeCallEdgeIR *edge = &region->calls[index];
        size_t operation_index;
        int lowered = 0;
        PyObject *call;
        PyObject *callee;
        for (operation_index = 0u;
             operation_table != NULL &&
             operation_index < operation_table->operation_count;
             operation_index++) {
            const WrtcNativeOperationIR *operation =
                &operation_table->operations[operation_index];
            if (operation->region_class_index == class_index &&
                operation->region_index == region_index &&
                operation_kind_lowerable(operation->kind) &&
                operation->span.line == edge->span.line &&
                operation->span.column == edge->span.column &&
                operation->span.end_line == edge->span.end_line &&
                operation->span.end_column == edge->span.end_column) {
                lowered = 1;
                break;
            }
        }
        if (lowered || edge->fused) continue;
        call = PyDict_New();
        if (edge->resolved &&
            edge->target_class < program->class_count &&
            edge->target_region <
                program->classes[edge->target_class].region_count) {
            const WrtcNativeClassIR *target_class =
                &program->classes[edge->target_class];
            const WrtcNativeRegionIR *target_region =
                &target_class->regions[edge->target_region];
            callee = PyUnicode_FromFormat("%s.%s", target_class->name,
                                          target_region->name);
        } else
            callee = Py_NewRef(Py_None);
        if (call == NULL || callee == NULL ||
            dict_set_owned(call, "target",
                           edge->target == NULL
                               ? Py_NewRef(Py_None)
                               : PyUnicode_FromString(edge->target)) < 0 ||
            dict_set_owned(call, "source",
                           span_report(
                               edge->span,
                               class_ir->filename == NULL
                                   ? fallback_filename
                                   : class_ir->filename)) < 0 ||
            dict_set_owned(call, "direct_callee_resolved",
                           PyBool_FromLong(edge->resolved)) < 0 ||
            PyDict_SetItemString(call, "resolved_callee", callee) < 0 ||
            dict_set_owned(call, "execution",
                           PyUnicode_FromString("python_call")) < 0 ||
            PyList_Append(calls, call) < 0) {
            Py_XDECREF(callee);
            Py_XDECREF(call);
            Py_DECREF(calls);
            return NULL;
        }
        Py_DECREF(callee);
        Py_DECREF(call);
    }
    return calls;
}

static PyObject *fusion_decisions_report(
    const WrtcNativeClassProgram *program,
    const WrtcNativeClassIR *class_ir,
    const WrtcNativeRegionIR *region,
    const char *fallback_filename) {
    PyObject *decisions = PyList_New(0);
    size_t index;
    if (decisions == NULL) return NULL;
    for (index = 0u; index < region->call_count; index++) {
        const WrtcNativeCallEdgeIR *edge = &region->calls[index];
        PyObject *decision;
        PyObject *callee;
        if (!edge->resolved) continue;
        if (edge->target_class < program->class_count &&
            edge->target_region <
                program->classes[edge->target_class].region_count) {
            const WrtcNativeClassIR *target_class =
                &program->classes[edge->target_class];
            const WrtcNativeRegionIR *target_region =
                &target_class->regions[edge->target_region];
            callee = PyUnicode_FromFormat("%s.%s", target_class->name,
                                          target_region->name);
        } else
            callee = Py_NewRef(Py_None);
        decision = PyDict_New();
        if (decision == NULL || callee == NULL ||
            dict_set_owned(
                decision, "target",
                edge->target == NULL ? Py_NewRef(Py_None)
                                     : PyUnicode_FromString(edge->target)) < 0 ||
            PyDict_SetItemString(decision, "resolved_callee", callee) < 0 ||
            dict_set_owned(decision, "required_callee",
                           PyBool_FromLong(edge->required_callee)) < 0 ||
            dict_set_owned(decision, "exact_receiver",
                           PyBool_FromLong(edge->exact_receiver)) < 0 ||
            dict_set_owned(decision, "fused",
                           PyBool_FromLong(edge->fused)) < 0 ||
            dict_set_owned(
                decision, "execution",
                PyUnicode_FromString(
                    edge->fused ? "guarded_direct_required_region_call"
                                : "python_call")) < 0 ||
            dict_set_owned(
                decision, "source",
                span_report(edge->span,
                            class_ir->filename == NULL
                                ? fallback_filename
                                : class_ir->filename)) < 0 ||
            PyList_Append(decisions, decision) < 0) {
            Py_XDECREF(callee);
            Py_XDECREF(decision);
            Py_DECREF(decisions);
            return NULL;
        }
        Py_DECREF(callee);
        Py_DECREF(decision);
    }
    return decisions;
}

static int region_operations_complete(
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t region_index) {
    size_t index;
    for (index = 0u; table != NULL && index < table->operation_count;
         index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        if (operation->region_class_index == class_index &&
            operation->region_index == region_index &&
            operation->kind == WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE)
            return 0;
    }
    return 1;
}

static int region_operations_lowerable(
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t region_index) {
    size_t index;
    for (index = 0u; table != NULL && index < table->operation_count;
         index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        if (operation->region_class_index == class_index &&
            operation->region_index == region_index &&
            !operation_kind_lowerable(operation->kind))
            return 0;
    }
    return 1;
}

static int region_atomic_proven(const WrtcNativeOperationTable *table,
                                size_t class_index, size_t region_index) {
    size_t index;
    for (index = 0u; table != NULL && index < table->operation_count;
         index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        if (operation->region_class_index == class_index &&
            operation->region_index == region_index &&
            operation->kind == WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE)
            return 1;
    }
    return 0;
}

static WrtcSourceSpan region_rejection_span(
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t region_index, WrtcSourceSpan fallback) {
    size_t index;
    for (index = 0u; table != NULL && index < table->operation_count;
         index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        if (operation->region_class_index == class_index &&
            operation->region_index == region_index &&
            !operation_kind_lowerable(operation->kind))
            return operation->span;
    }
    return fallback;
}

static PyObject *rejection_report(const char *code, const char *message,
                                  WrtcSourceSpan span,
                                  const char *filename) {
    PyObject *item = PyDict_New();
    if (item == NULL ||
        dict_set_owned(item, "code", PyUnicode_FromString(code)) < 0 ||
        dict_set_owned(item, "message", PyUnicode_FromString(message)) < 0 ||
        dict_set_owned(item, "source", span_report(span, filename)) < 0) {
        Py_XDECREF(item);
        return NULL;
    }
    return item;
}

static int region_mpsc_complete(const WrtcNativeRegionIR *region) {
    if ((region->capabilities & WRTC_REGION_MPSC) == 0u) return 1;
    return region->queue_linearization_proven &&
           region->memory_ordering_proven &&
           region->producer_admission_proven &&
           region->producer_quiescence_proven &&
           region->reactor_dequeue_proven &&
           region->ownership_transfer_proven &&
           region->reclamation_proven &&
           region->full_queue_behavior_proven &&
           region->wakeup_coalescing_proven &&
           region->close_drain_order_proven &&
           region->shutdown_interaction_proven;
}

static int region_spsc_complete(const WrtcNativeRegionIR *region) {
    if ((region->capabilities & WRTC_REGION_SPSC) == 0u) return 1;
    return region->queue_linearization_proven &&
           region->memory_ordering_proven &&
           region->producer_admission_proven &&
           region->producer_quiescence_proven &&
           region->ownership_transfer_proven &&
           region->reclamation_proven &&
           region->full_queue_behavior_proven &&
           region->close_drain_order_proven &&
           region->shutdown_interaction_proven &&
           region->typed_worker_records;
}

static const char *spsc_rejection_reason(
    const WrtcNativeClassIR *class_ir) {
    size_t index;
    for (index = 0u; index < class_ir->field_count; index++) {
        const WrtcNativeFieldIR *field = &class_ir->fields[index];
        if (field->queue_topology != WRTC_QUEUE_SPSC) continue;
        if (!field->payload_representation_proven)
            return "SPSC payload is not an exact ABI-declared record";
        if (!field->spsc_producer_proven)
            return "SPSC has no proven single-producer nonblocking send";
        if (!field->spsc_consumer_proven)
            return "SPSC has no proven single-consumer nonblocking receive";
        if (!field->spsc_close_drain_proven)
            return "SPSC shutdown does not prove close-before-drain";
        if (!field->spsc_memory_ordering_proven)
            return "SPSC release/acquire memory ordering is incomplete";
        if (!field->spsc_reclamation_proven)
            return "SPSC accepted items are not reclaimed exactly once";
    }
    return "native concurrency emission requires complete SPSC "
           "linearization, ownership, reclamation, and shutdown proofs";
}

static const char *mpsc_rejection_reason(
    const WrtcNativeClassIR *class_ir) {
    size_t index;
    for (index = 0u; index < class_ir->field_count; index++) {
        const WrtcNativeFieldIR *field = &class_ir->fields[index];
        if (field->queue_topology != WRTC_QUEUE_MPSC) continue;
        if (!field->payload_representation_proven)
            return "MPSC payload is not an exact ABI-declared record with "
                   "proven native or boxed CPython ownership";
        if (!field->producer_admission_proven)
            return "MPSC has no proven shared-producer publication region";
        if (!field->reactor_dequeue_proven)
            return "MPSC dequeue is not proven reactor-only";
        if (!field->producer_quiescence_proven)
            return "MPSC shutdown does not close producer admission";
        if (!field->close_drain_order_proven)
            return "MPSC shutdown does not prove close-before-reactor-drain";
        if (!field->notification_rearm_proven)
            return "coalesced notification reset/rearm is not linearized "
                   "around the empty check";
        if (!field->lifecycle_shutdown_proven)
            return "LoopLifecycle close transition is not ordered before "
                   "MPSC close and drain";
        if (!field->mpsc_memory_ordering_proven)
            return "MPSC publication and close memory ordering is incomplete";
        if (!field->reactor_reclamation_proven)
            return "MPSC node reclamation is not reactor-only after producer "
                   "quiescence";
    }
    return "native concurrency emission requires complete linearization, "
           "ownership, reclamation, and shutdown proofs";
}

PyObject *wrtc_native_class_capability_report(
    const WrtcNativeClassProgram *program, const char *filename) {
    PyObject *report = PyDict_New();
    PyObject *classes = PyList_New(0);
    PyObject *records = PyList_New(0);
    WrtcNativeOperationTable *operation_table = NULL;
    int generator_accepted = 0;
    size_t class_index;
    if (report == NULL || classes == NULL || records == NULL) goto error;
    if (dict_set_owned(report, "schema",
                       PyUnicode_FromString("pymeta.capabilities.v2")) < 0 ||
        PyDict_SetItemString(report, "classes", classes) < 0 ||
        PyDict_SetItemString(report, "typed_records", records) < 0)
        goto error;
    if (program == NULL) {
        Py_DECREF(records);
        Py_DECREF(classes);
        return report;
    }
    generator_accepted = wrtc_native_class_can_emit(program);
    if (wrtc_native_operation_prove(program, &operation_table) < 0)
        goto error;
    if (dict_set_owned(report, "generator_accepted",
                       PyBool_FromLong(generator_accepted)) < 0 ||
        dict_set_owned(report, "operation_proof_complete",
                       PyBool_FromLong(operation_table->complete)) < 0)
        goto error;
    for (class_index = 0u; class_index < program->record_count; class_index++) {
        const WrtcTypedRecordIR *record = &program->records[class_index];
        PyObject *record_report = PyDict_New();
        if (record_report == NULL ||
            dict_set_owned(record_report, "name",
                           PyUnicode_FromString(record->name)) < 0 ||
            dict_set_owned(record_report, "source",
                           span_report(record->span,
                                       record->filename == NULL
                                           ? filename
                                           : record->filename)) < 0 ||
            dict_set_owned(record_report, "field_count",
                           PyLong_FromSize_t(record->field_count)) < 0 ||
            dict_set_owned(record_report, "boxed_field_count",
                           PyLong_FromSize_t(record->boxed_field_count)) < 0 ||
            dict_set_owned(record_report, "abi_declared",
                           PyBool_FromLong(record->abi_declared)) < 0 ||
            dict_set_owned(record_report, "representation_proven",
                           PyBool_FromLong(
                               record->representation_proven)) < 0 ||
            dict_set_owned(record_report, "boxed_ownership_proven",
                           PyBool_FromLong(
                               record->boxed_ownership_proven)) < 0 ||
            dict_set_owned(record_report, "exact_runtime_type_guard",
                           PyBool_FromLong(
                               record->exact_runtime_type_guard)) < 0 ||
            PyList_Append(records, record_report) < 0) {
            Py_XDECREF(record_report);
            goto error;
        }
        Py_DECREF(record_report);
    }
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        const WrtcNativeClassIR *class_ir = &program->classes[class_index];
        PyObject *class_report = PyDict_New();
        PyObject *regions = PyList_New(0);
        PyObject *fields = PyList_New(0);
        size_t region_index, field_index;
        if (class_report == NULL || regions == NULL || fields == NULL ||
            dict_set_owned(class_report, "name",
                           PyUnicode_FromString(class_ir->name)) < 0 ||
            dict_set_owned(class_report, "source",
                           span_report(class_ir->span,
                                       class_ir->filename == NULL
                                           ? filename
                                           : class_ir->filename)) < 0 ||
            PyDict_SetItemString(class_report, "fields", fields) < 0 ||
            PyDict_SetItemString(class_report, "regions", regions) < 0)
            goto class_error;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++) {
            const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
            PyObject *field_report = PyDict_New();
            const WrtcNativeFieldOperationProof *operation_proof;
            size_t operation_proof_index = 0u;
            const char *storage_reason = NULL;
            int storage_eligible =
                wrtc_native_storage_field_eligible(field, &storage_reason);
            int operation_lowerable;
            const char *representation;
            const char *algorithm =
                field->queue_topology == WRTC_QUEUE_SPSC ? "spsc" :
                field->queue_topology == WRTC_QUEUE_MPSC ? "mpsc" : "none";
            const char *storage =
                field->storage_kind == WRTC_NATIVE_FIELD_SCALAR
                    ? "native_scalar"
                    : field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                          ? "fifo"
                          : field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP
                                ? "min_heap"
                                : field->storage_kind ==
                                          WRTC_NATIVE_FIELD_ATOMIC_UINT32
                                      ? "atomic_uint32"
                                : field->storage_kind ==
                                          WRTC_NATIVE_FIELD_MPSC
                                      ? "bounded_mpsc"
                                : field->storage_kind ==
                                          WRTC_NATIVE_FIELD_SPSC
                                      ? "bounded_spsc"
                                : "pyobject";
            operation_proof = field_operation_proof(
                operation_table, class_index, field_index,
                &operation_proof_index);
            operation_lowerable =
                operation_proof != NULL && operation_proof->touched &&
                field_operations_lowerable(operation_table,
                                           operation_proof_index);
            if (generator_accepted)
                representation =
                    field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT
                        ? "boxed"
                        : field->storage_kind == WRTC_NATIVE_FIELD_SCALAR
                              ? "native"
                              : "guarded_native_with_boxed_fallback";
            else if (field->storage_kind ==
                     WRTC_NATIVE_FIELD_PYOBJECT)
                representation = "boxed_pending_emission";
            else if (operation_proof != NULL &&
                     operation_proof->complete && operation_lowerable &&
                     storage_eligible)
                representation = "native_pending_integration";
            else
                representation = "native_rejected";
            if (field_report == NULL ||
                dict_set_owned(field_report, "name",
                               PyUnicode_FromString(field->name)) < 0 ||
                dict_set_owned(field_report, "source",
                               span_report(field->span,
                                           class_ir->filename == NULL
                                               ? filename
                                               : class_ir->filename)) < 0 ||
                dict_set_owned(field_report, "owner",
                               field->owner == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(field->owner)) < 0 ||
                dict_set_owned(field_report, "atomic",
                               PyBool_FromLong(field->atomic)) < 0 ||
                dict_set_owned(field_report, "atomic_width",
                               PyLong_FromUnsignedLong(
                                   field->atomic_width)) < 0 ||
                dict_set_owned(
                    field_report, "atomic_memory_order",
                    field->atomic_memory_order == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(
                              field->atomic_memory_order)) < 0 ||
                dict_set_owned(
                    field_report, "atomic_scope",
                    field->atomic_scope == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(field->atomic_scope)) < 0 ||
                dict_set_owned(
                    field_report, "atomic_linearization",
                    field->atomic_linearization == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(
                              field->atomic_linearization)) < 0 ||
                dict_set_owned(field_report, "storage",
                               PyUnicode_FromString(storage)) < 0 ||
                dict_set_owned(field_report, "representation",
                               PyUnicode_FromString(representation)) < 0 ||
                dict_set_owned(field_report, "storage_eligible",
                               PyBool_FromLong(storage_eligible)) < 0 ||
                dict_set_owned(
                    field_report, "storage_reason",
                    storage_reason == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(storage_reason)) < 0 ||
                dict_set_owned(
                    field_report, "operation_proof_touched",
                    PyBool_FromLong(operation_proof != NULL &&
                                    operation_proof->touched)) < 0 ||
                dict_set_owned(
                    field_report, "operation_proof_complete",
                    PyBool_FromLong(operation_proof != NULL &&
                                    operation_proof->complete)) < 0 ||
                dict_set_owned(
                    field_report, "operation_lowering_complete",
                    PyBool_FromLong(operation_lowerable)) < 0 ||
                dict_set_owned(
                    field_report, "operation_count",
                    PyLong_FromSize_t(
                        operation_proof == NULL
                            ? 0u : operation_proof->operation_count)) < 0 ||
                dict_set_owned(field_report, "heap_key",
                               field->heap_key == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(field->heap_key)) < 0 ||
                dict_set_owned(
                    field_report, "heap_ordering",
                    field->heap_ordering == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(field->heap_ordering)) < 0 ||
                dict_set_owned(field_report, "queue_algorithm",
                               PyUnicode_FromString(algorithm)) < 0 ||
                dict_set_owned(field_report, "capacity",
                               field->queue_capacity == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(
                                         field->queue_capacity)) < 0 ||
                dict_set_owned(
                    field_report, "bounded",
                    PyBool_FromLong(field->queue_capacity != NULL)) < 0 ||
                dict_set_owned(
                    field_report, "queue_item_type",
                    field->queue_item_type == NULL
                        ? Py_NewRef(Py_None)
                        : PyUnicode_FromString(field->queue_item_type)) < 0 ||
                dict_set_owned(
                    field_report, "typed_queue_payload",
                    PyBool_FromLong(field->typed_queue_payload)) < 0 ||
                dict_set_owned(
                    field_report, "payload_representation_proven",
                    PyBool_FromLong(
                        field->payload_representation_proven)) < 0 ||
                dict_set_owned(
                    field_report, "producer_admission_proven",
                    PyBool_FromLong(
                        field->producer_admission_proven)) < 0 ||
                dict_set_owned(
                    field_report, "producer_quiescence_proven",
                    PyBool_FromLong(
                        field->producer_quiescence_proven)) < 0 ||
                dict_set_owned(
                    field_report, "reactor_dequeue_proven",
                    PyBool_FromLong(
                        field->reactor_dequeue_proven)) < 0 ||
                dict_set_owned(
                    field_report, "close_drain_order_proven",
                    PyBool_FromLong(
                        field->close_drain_order_proven)) < 0 ||
                dict_set_owned(
                    field_report, "notification_rearm_proven",
                    PyBool_FromLong(
                        field->notification_rearm_proven)) < 0 ||
                dict_set_owned(
                    field_report, "lifecycle_shutdown_proven",
                    PyBool_FromLong(
                        field->lifecycle_shutdown_proven)) < 0 ||
                dict_set_owned(
                    field_report, "mpsc_memory_ordering_proven",
                    PyBool_FromLong(
                        field->mpsc_memory_ordering_proven)) < 0 ||
                dict_set_owned(
                    field_report, "reactor_reclamation_proven",
                    PyBool_FromLong(
                        field->reactor_reclamation_proven)) < 0 ||
                dict_set_owned(
                    field_report, "fifo_publication_order",
                    PyBool_FromLong(
                        field->queue_topology != WRTC_QUEUE_NONE)) < 0 ||
                dict_set_owned(
                    field_report, "producer_ownership",
                    field->queue_topology == WRTC_QUEUE_MPSC
                        ? PyUnicode_FromString("external_multi_producer")
                        : field->queue_topology == WRTC_QUEUE_SPSC
                              ? PyUnicode_FromString("single_producer")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "consumer_ownership",
                    field->queue_topology == WRTC_QUEUE_MPSC
                        ? PyUnicode_FromString("reactor_only")
                        : field->queue_topology == WRTC_QUEUE_SPSC
                              ? PyUnicode_FromString("single_consumer")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "send_outcomes",
                    field->queue_topology != WRTC_QUEUE_NONE
                        ? PyUnicode_FromString("ok|full|closed_nonblocking")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "receive_outcomes",
                    field->queue_topology != WRTC_QUEUE_NONE
                        ? PyUnicode_FromString("ok|empty_nonblocking")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "close_behavior",
                    field->queue_topology != WRTC_QUEUE_NONE
                        ? PyUnicode_FromString(
                              "reject_new_sends_then_drain_buffer")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "queue_memory_ordering",
                    field->queue_topology == WRTC_QUEUE_MPSC
                        ? PyUnicode_FromString(
                              field->mpsc_memory_ordering_proven
                                  ? "release_publish_acquire_consume;"
                                    "acq_rel_admission_close"
                                  : "not_proven")
                        : field->queue_topology == WRTC_QUEUE_SPSC
                              ? PyUnicode_FromString(
                                    field->spsc_memory_ordering_proven
                                        ? "release_publish_acquire_consume;"
                                          "acq_rel_admission_close"
                                        : "not_proven")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    field_report, "reclamation_owner",
                    field->queue_topology == WRTC_QUEUE_MPSC
                        ? PyUnicode_FromString(
                              field->reactor_reclamation_proven
                                  ? "reactor_after_producer_quiescence"
                                  : "not_proven")
                        : field->queue_topology == WRTC_QUEUE_SPSC
                              ? PyUnicode_FromString(
                                    field->spsc_reclamation_proven
                                        ? "single_consumer_after_close"
                                        : "not_proven")
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(field_report, "coalesced_notification",
                               PyBool_FromLong(
                                   field->coalesced_notification)) < 0 ||
                PyList_Append(fields, field_report) < 0) {
                Py_XDECREF(field_report);
                goto class_error;
            }
            Py_DECREF(field_report);
        }
        for (region_index = 0u; region_index < class_ir->region_count;
             region_index++) {
            const WrtcNativeRegionIR *region = &class_ir->regions[region_index];
            PyObject *region_report = PyDict_New();
            PyObject *proofs = PyDict_New();
            PyObject *operation_sites = operation_sites_report(
                program, operation_table, class_index, region_index,
                filename);
            PyObject *remaining_calls = remaining_calls_report(
                program, class_ir, region, operation_table, class_index,
                region_index, filename);
            PyObject *fusion_decisions = fusion_decisions_report(
                program, class_ir, region, filename);
            PyObject *rejection_reasons = PyList_New(0);
            PyObject *execution = PyDict_New();
            int operation_complete = region_operations_complete(
                operation_table, class_index, region_index);
            int operation_lowerable = region_operations_lowerable(
                operation_table, class_index, region_index);
            int atomic_proven = region_atomic_proven(
                operation_table, class_index, region_index);
            const int mpsc_complete = region_mpsc_complete(region);
            const int spsc_complete = region_spsc_complete(region);
            const unsigned unproven_concurrency =
                (region->capabilities &
                 (WRTC_REGION_OWNED_SHARD | WRTC_REGION_TYPED_RECORD)) |
                (((region->capabilities & WRTC_REGION_SPSC) != 0u &&
                  !spsc_complete)
                     ? WRTC_REGION_SPSC : 0u) |
                (((region->capabilities & WRTC_REGION_MPSC) != 0u &&
                  !mpsc_complete)
                     ? WRTC_REGION_MPSC : 0u) |
                (((region->capabilities &
                  (WRTC_REGION_BOUNDED_QUEUE |
                    WRTC_REGION_COALESCED_NOTIFICATION)) != 0u &&
                  (region->capabilities &
                   (WRTC_REGION_MPSC | WRTC_REGION_SPSC)) == 0u)
                     ? WRTC_REGION_BOUNDED_QUEUE : 0u) |
                (((region->capabilities &
                   (WRTC_REGION_ATOMIC |
                    WRTC_REGION_COMPARE_EXCHANGE)) != 0u) &&
                 !atomic_proven
                     ? WRTC_REGION_ATOMIC : 0u);
            WrtcSourceSpan rejection_span = region_rejection_span(
                operation_table, class_index, region_index, region->span);
            const char *region_filename =
                class_ir->filename == NULL ? filename : class_ir->filename;
            const char *rejection_code =
                !operation_complete
                    ? "native_operation_proof"
                    : !operation_lowerable
                          ? "native_operation_emission"
                          : unproven_concurrency
                                ? ((region->capabilities &
                                    WRTC_REGION_MPSC) != 0u
                                       ? "mpsc_contract_unproven"
                                       : (region->capabilities &
                                          WRTC_REGION_SPSC) != 0u
                                             ? "spsc_contract_unproven"
                                       : "native_concurrency_unproven")
                                : "native_class_emission";
            const char *status =
                generator_accepted
                    ? "compiled"
                    : region->policy == WRTC_REGION_REQUIRED
                          ? "rejected" : "interpreted";
            const char *reason =
                generator_accepted
                    ? "accepted by native-class generator integration"
                    : !operation_complete
                          ? "native-field operation proof rejected one or "
                            "more source sites"
                    : !operation_lowerable
                          ? "native-field operation proof succeeded, but one "
                            "or more source sites have no generic emitted hook"
                    : unproven_concurrency
                    ? ((region->capabilities & WRTC_REGION_MPSC) != 0u
                           ? mpsc_rejection_reason(class_ir)
                           : (region->capabilities & WRTC_REGION_SPSC) != 0u
                                 ? spsc_rejection_reason(class_ir)
                           : "native concurrency emission requires complete "
                             "linearization, ownership, reclamation, and "
                             "worker reachability proofs")
                          : atomic_proven
                                ? "atomic compare-exchange lowering is "
                                  "proven; the containing artifact is "
                                  "rejected by another required class or "
                                  "region"
                          : region->call_count == 1u &&
                              region->loop_count == 0u &&
                              region->direct_call_target != NULL
                          ? region->direct_callee_resolved
                                ? region->direct_callee_fused
                                      ? "direct-call facade is fusion-ready; "
                                        "the containing artifact is rejected "
                                        "by another required region"
                                      : "direct-call facade and required "
                                        "callee are resolved, but exact "
                                        "receiver lowering is unavailable"
                                : "direct-call facade is lowerable, but its "
                                  "required callee is outside the analyzed "
                                  "source set"
                          : "generic CPython native-class emission is "
                            "unavailable";
            if (!mpsc_complete &&
                (region->capabilities & WRTC_REGION_MPSC) != 0u) {
                size_t mpsc_field;
                for (mpsc_field = 0u;
                     mpsc_field < class_ir->field_count; mpsc_field++)
                    if (class_ir->fields[mpsc_field].queue_topology ==
                        WRTC_QUEUE_MPSC) {
                        rejection_span =
                            class_ir->fields[mpsc_field].span;
                        break;
                    }
            }
            if (!spsc_complete &&
                (region->capabilities & WRTC_REGION_SPSC) != 0u) {
                size_t spsc_field;
                for (spsc_field = 0u;
                     spsc_field < class_ir->field_count; spsc_field++)
                    if (class_ir->fields[spsc_field].queue_topology ==
                        WRTC_QUEUE_SPSC) {
                        rejection_span =
                            class_ir->fields[spsc_field].span;
                        break;
                    }
            }
            if (rejection_reasons != NULL && !generator_accepted) {
                PyObject *item = rejection_report(
                    rejection_code, reason, rejection_span,
                    region_filename);
                if (item == NULL ||
                    PyList_Append(rejection_reasons, item) < 0) {
                    Py_XDECREF(item);
                    Py_CLEAR(rejection_reasons);
                } else
                    Py_DECREF(item);
            }
            if (region_report == NULL || proofs == NULL ||
                operation_sites == NULL || remaining_calls == NULL ||
                fusion_decisions == NULL ||
                rejection_reasons == NULL || execution == NULL ||
                dict_set_owned(region_report, "name",
                               PyUnicode_FromString(region->name)) < 0 ||
                dict_set_owned(region_report, "source",
                               span_report(region->span,
                                           class_ir->filename == NULL
                                               ? filename
                                               : class_ir->filename)) < 0 ||
                dict_set_owned(region_report, "policy",
                               PyUnicode_FromString(
                                   region->policy == WRTC_REGION_REQUIRED
                                       ? "required" : "preferred")) < 0 ||
                dict_set_owned(region_report, "status",
                               PyUnicode_FromString(status)) < 0 ||
                dict_set_owned(
                    region_report, "reason",
                    PyUnicode_FromString(reason)) < 0 ||
                dict_set_owned(
                    region_report, "direct_call_target",
                    region->call_count == 1u &&
                            region->direct_call_target != NULL
                        ? PyUnicode_FromString(region->direct_call_target)
                        : Py_NewRef(Py_None)) < 0 ||
                dict_set_owned(
                    region_report, "direct_callee_resolved",
                    PyBool_FromLong(region->direct_callee_resolved)) < 0 ||
                dict_set_owned(
                    region_report, "direct_callee_fused",
                    PyBool_FromLong(region->direct_callee_fused)) < 0 ||
                PyDict_SetItemString(region_report, "fusion_decisions",
                                     fusion_decisions) < 0 ||
                PyDict_SetItemString(region_report, "operation_sites",
                                     operation_sites) < 0 ||
                dict_set_owned(
                    region_report, "operation_proof_complete",
                    PyBool_FromLong(operation_complete)) < 0 ||
                dict_set_owned(
                    region_report, "operation_lowering_complete",
                    PyBool_FromLong(operation_lowerable)) < 0 ||
                PyDict_SetItemString(region_report,
                                     "remaining_python_calls",
                                     remaining_calls) < 0 ||
                PyDict_SetItemString(region_report, "rejection_reasons",
                                     rejection_reasons) < 0 ||
                dict_set_owned(
                    execution, "body",
                    PyUnicode_FromString(
                        generator_accepted
                            ? "boxed_semantic_codegen"
                            : "not_emitted")) < 0 ||
                dict_set_owned(
                    execution, "exceptions",
                    PyUnicode_FromString(
                        generator_accepted
                            ? "CPython exception propagation"
                            : "not_emitted")) < 0 ||
                dict_set_owned(
                    execution, "cleanup",
                    PyUnicode_FromString(
                        generator_accepted
                            ? "single cleanup epilogue with owned-reference "
                              "release"
                            : "not_emitted")) < 0 ||
                PyDict_SetItemString(region_report, "execution_strategy",
                                     execution) < 0 ||
                dict_set_owned(region_report, "capabilities",
                               capability_names(region->capabilities)) < 0 ||
                dict_set_owned(region_report, "owner",
                               region->owner == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(region->owner)) < 0 ||
                dict_set_owned(region_report, "shard_key",
                               region->shard_key == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(
                                         region->shard_key)) < 0 ||
                dict_set_owned(region_report, "shard_workers",
                               region->shard_workers == NULL
                                   ? Py_NewRef(Py_None)
                                   : PyUnicode_FromString(
                                         region->shard_workers)) < 0 ||
                dict_set_owned(region_report, "shard_ordered",
                               PyBool_FromLong(region->shard_ordered)) < 0 ||
                dict_set_owned(region_report, "call_count",
                               PyLong_FromSize_t(region->call_count)) < 0 ||
                dict_set_owned(region_report, "loop_count",
                               PyLong_FromSize_t(region->loop_count)) < 0 ||
                dict_set_owned(region_report, "bounded_loop_count",
                               PyLong_FromSize_t(region->bounded_loop_count)) < 0 ||
                dict_set_owned(proofs, "selector_shape_validated",
                               PyBool_FromLong(region->selector_shape_validated)) < 0 ||
                dict_set_owned(proofs, "packet_order_preserved",
                               PyBool_FromLong(region->packet_order_preserved)) < 0 ||
                dict_set_owned(proofs, "pool_lifetime_checked",
                               PyBool_FromLong(region->pool_lifetime_checked)) < 0 ||
                dict_set_owned(proofs, "bounded_interleaving",
                               PyBool_FromLong(region->bounded_interleaving)) < 0 ||
                dict_set_owned(proofs, "atomic_linearization",
                               PyBool_FromLong(atomic_proven)) < 0 ||
                dict_set_owned(proofs, "queue_linearization",
                               PyBool_FromLong(
                                   region->queue_linearization_proven)) < 0 ||
                dict_set_owned(proofs, "producer_admission",
                               PyBool_FromLong(
                                   region->producer_admission_proven)) < 0 ||
                dict_set_owned(proofs, "producer_quiescence",
                               PyBool_FromLong(
                                   region->producer_quiescence_proven)) < 0 ||
                dict_set_owned(proofs, "reactor_only_dequeue",
                               PyBool_FromLong(
                                   region->reactor_dequeue_proven)) < 0 ||
                dict_set_owned(proofs, "close_drain_order",
                               PyBool_FromLong(
                                   region->close_drain_order_proven)) < 0 ||
                dict_set_owned(proofs, "memory_ordering",
                               PyUnicode_FromString(
                                   (region->capabilities &
                                   WRTC_REGION_MPSC) != 0u
                                       ? (region->memory_ordering_proven
                                              ? "release_publish_"
                                                "acquire_consume;"
                                                "acq_rel_admission_close"
                                              : "not_proven")
                                       : (region->capabilities &
                                          WRTC_REGION_SPSC) != 0u
                                             ? (region->memory_ordering_proven
                                                    ? "release_publish_"
                                                      "acquire_consume;"
                                                      "acq_rel_admission_close"
                                                    : "not_proven")
                                       : atomic_proven ? "seq_cst"
                                                       : "not_proven")) < 0 ||
                dict_set_owned(proofs, "ownership_transfer",
                               PyBool_FromLong(
                                   region->ownership_transfer_proven)) < 0 ||
                dict_set_owned(proofs, "node_reclamation",
                               PyBool_FromLong(
                                   region->reclamation_proven)) < 0 ||
                dict_set_owned(proofs, "full_queue_behavior",
                               PyBool_FromLong(
                                   region->full_queue_behavior_proven)) < 0 ||
                dict_set_owned(proofs, "wakeup_coalescing",
                               PyBool_FromLong(
                                   region->wakeup_coalescing_proven)) < 0 ||
                dict_set_owned(proofs, "shutdown_interaction",
                               PyBool_FromLong(
                                   region->shutdown_interaction_proven)) < 0 ||
                dict_set_owned(proofs, "worker_python_free",
                               PyBool_FromLong(
                                   region->worker_python_free)) < 0 ||
                dict_set_owned(proofs, "typed_worker_records",
                               PyBool_FromLong(
                                   region->typed_worker_records)) < 0 ||
                PyDict_SetItemString(region_report, "proofs", proofs) < 0 ||
                PyList_Append(regions, region_report) < 0) {
                Py_XDECREF(execution);
                Py_XDECREF(rejection_reasons);
                Py_XDECREF(remaining_calls);
                Py_XDECREF(fusion_decisions);
                Py_XDECREF(operation_sites);
                Py_XDECREF(proofs);
                Py_XDECREF(region_report);
                goto class_error;
            }
            Py_DECREF(execution);
            Py_DECREF(rejection_reasons);
            Py_DECREF(remaining_calls);
            Py_DECREF(fusion_decisions);
            Py_DECREF(operation_sites);
            Py_DECREF(proofs);
            Py_DECREF(region_report);
        }
        if (PyList_Append(classes, class_report) < 0) goto class_error;
        Py_DECREF(fields);
        Py_DECREF(regions);
        Py_DECREF(class_report);
        continue;
class_error:
        Py_XDECREF(fields);
        Py_XDECREF(regions);
        Py_XDECREF(class_report);
        goto error;
    }
    Py_DECREF(records);
    Py_DECREF(classes);
    wrtc_native_operation_table_free(operation_table);
    return report;
error:
    wrtc_native_operation_table_free(operation_table);
    Py_XDECREF(records);
    Py_XDECREF(classes);
    Py_XDECREF(report);
    return NULL;
}

void wrtc_native_class_free(WrtcNativeClassProgram *program) {
    size_t class_index;
    if (program == NULL) return;
    free(program->factory_name);
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        WrtcNativeClassIR *class_ir = &program->classes[class_index];
        size_t index;
        free(class_ir->name);
        free(class_ir->base);
        free(class_ir->filename);
        for (index = 0u; index < class_ir->field_count; index++) {
            free(class_ir->fields[index].name);
            free(class_ir->fields[index].declared_type);
            free(class_ir->fields[index].owner);
            free(class_ir->fields[index].heap_key);
            free(class_ir->fields[index].heap_ordering);
            free(class_ir->fields[index].queue_capacity);
            free(class_ir->fields[index].queue_item_type);
            free(class_ir->fields[index].atomic_memory_order);
            free(class_ir->fields[index].atomic_scope);
            free(class_ir->fields[index].atomic_linearization);
        }
        for (index = 0u; index < class_ir->region_count; index++) {
            size_t call_index;
            free(class_ir->regions[index].name);
            free(class_ir->regions[index].owner);
            free(class_ir->regions[index].shard_key);
            free(class_ir->regions[index].shard_workers);
            free(class_ir->regions[index].result_type);
            free(class_ir->regions[index].direct_call_target);
            for (call_index = 0u;
                 call_index < class_ir->regions[index].call_count;
                 call_index++)
                free(class_ir->regions[index].calls[call_index].target);
            free(class_ir->regions[index].calls);
            wrtc_py_suite_ir_free(class_ir->regions[index].body);
            wrtc_py_signature_ir_free(class_ir->regions[index].signature);
        }
        free(class_ir->fields);
        free(class_ir->regions);
    }
    for (class_index = 0u; class_index < program->record_count; class_index++) {
        free(program->records[class_index].name);
        free(program->records[class_index].filename);
    }
    free(program->classes);
    free(program->records);
    for (class_index = 0u; class_index < program->factory_count;
         class_index++) {
        free(program->factories[class_index].name);
        free(program->factories[class_index].filename);
        free(program->factories[class_index].target_class);
        wrtc_py_suite_ir_free(program->factories[class_index].body);
        wrtc_py_signature_ir_free(program->factories[class_index].signature);
    }
    free(program->factories);
    free(program);
}

int wrtc_native_class_requires_lowering(const WrtcNativeClassProgram *program) {
    return program != NULL && program->class_count != 0u;
}
