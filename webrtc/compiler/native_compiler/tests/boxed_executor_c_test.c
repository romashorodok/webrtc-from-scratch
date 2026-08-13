#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>

#include "boxed_executor.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static PyObject *function_body(PyObject *globals, const char *source,
                               const char *name) {
    PyObject *result = PyRun_String(source, Py_file_input, globals, globals);
    PyObject *ast = NULL, *tree = NULL, *body = NULL, *function = NULL;
    PyObject *statements = NULL;
    if (result == NULL) return NULL;
    Py_DECREF(result);
    ast = PyImport_ImportModule("ast");
    tree = ast == NULL ? NULL : PyObject_CallMethod(ast, "parse", "s", source);
    body = tree == NULL ? NULL : PyObject_GetAttrString(tree, "body");
    if (body != NULL) {
        Py_ssize_t index, count = PySequence_Size(body);
        for (index = 0; index < count; index++) {
            PyObject *candidate = PySequence_GetItem(body, index);
            PyObject *candidate_name =
                candidate == NULL
                    ? NULL : PyObject_GetAttrString(candidate, "name");
            const char *text = candidate_name == NULL
                                   ? NULL : PyUnicode_AsUTF8(candidate_name);
            if (text != NULL && strcmp(text, name) == 0) {
                function = candidate;
                Py_XDECREF(candidate_name);
                break;
            }
            Py_XDECREF(candidate_name);
            Py_XDECREF(candidate);
        }
    }
    statements =
        function == NULL ? NULL : PyObject_GetAttrString(function, "body");
    Py_XDECREF(function);
    Py_XDECREF(body);
    Py_XDECREF(tree);
    Py_XDECREF(ast);
    return statements;
}

static int run_region(PyObject *globals, const char *source,
                      const char *name, PyObject *locals,
                      PyObject **result) {
    PyObject *body = function_body(globals, source, name);
    WrtcPySuiteIR *suite = NULL;
    int status;
    if (body == NULL) return -1;
    status = wrtc_py_ir_lower_suite(
        body, "boxed_component.py", &suite);
    Py_DECREF(body);
    if (status < 0) return -1;
    status = wrtc_boxed_execute(suite, globals, locals, result);
    wrtc_py_suite_ir_free(suite);
    return status;
}

int main(void) {
    static const char source[] =
        "class Box:\n"
        "    def __init__(self, values):\n"
        "        self.values = values\n"
        "        self.cleaned = 0\n"
        "def region(loop, events):\n"
        "    scheduled = loop.values\n"
        "    retained = []\n"
        "    for handle in scheduled:\n"
        "        if handle < 0:\n"
        "            continue\n"
        "        retained.append(handle)\n"
        "    scheduled[:] = retained\n"
        "    total = 0\n"
        "    for key, mask in events:\n"
        "        if mask & 1 and key is not None:\n"
        "            total += key\n"
        "    try:\n"
        "        if total > 10:\n"
        "            raise ValueError('large')\n"
        "    except ValueError as error:\n"
        "        total += len(str(error))\n"
        "    finally:\n"
        "        loop.cleaned += 1\n"
        "    return min(max(0, total), 100)\n"
        "def final_return(value):\n"
        "    try:\n"
        "        return value\n"
        "    finally:\n"
        "        if value < 0:\n"
        "            return 9\n"
        "def chained(value):\n"
        "    return 0 < value < 5\n"
        "def caused():\n"
        "    try:\n"
        "        raise ValueError('inner')\n"
        "    except ValueError as error:\n"
        "        raise RuntimeError('outer') from error\n"
        "def unbound():\n"
        "    return local\n"
        "    local = 1\n";
    PyObject *globals, *locals, *box_type, *box, *values, *events;
    PyObject *result = NULL, *expected = NULL, *function;
    static const WrtcBoxedParameterSpec parameters[] = {
        {"x", WRTC_PY_PARAM_POSITIONAL_ONLY, NULL, 0},
        {"y", WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD, "make_default()", 1},
        {"rest", WRTC_PY_PARAM_VAR_POSITIONAL, NULL, 0},
        {"flag", WRTC_PY_PARAM_KEYWORD_ONLY, "7", 1},
        {"extras", WRTC_PY_PARAM_VAR_KEYWORD, NULL, 0},
    };
    WrtcBoxedSignature signature = {
        "bound", parameters, 5u, NULL
    };
    static const char *const binary_names[] = {
        "add", "subtract", "multiply", "matrix_multiply", "true_divide",
        "floor_divide", "remainder", "power", "left_shift", "right_shift",
        "and_", "xor", "or_"
    };
    static const char binary_source[] =
        "class Operand:\n"
        " def __matmul__(self, other): return ('matmul', other)\n"
        "def add(x,y): return x+y\n"
        "def subtract(x,y): return x-y\n"
        "def multiply(x,y): return x*y\n"
        "def matrix_multiply(x,y): return x@y\n"
        "def true_divide(x,y): return x/y\n"
        "def floor_divide(x,y): return x//y\n"
        "def remainder(x,y): return x%y\n"
        "def power(x,y): return x**y\n"
        "def left_shift(x,y): return x<<y\n"
        "def right_shift(x,y): return x>>y\n"
        "def and_(x,y): return x&y\n"
        "def xor(x,y): return x^y\n"
        "def or_(x,y): return x|y\n";

    Py_Initialize();
    globals = PyDict_New();
    locals = PyDict_New();
    CHECK(globals != NULL && locals != NULL);
    CHECK(PyDict_SetItemString(
              globals, "__builtins__", PyEval_GetBuiltins()) == 0);
    CHECK(function_body(globals, source, "region") != NULL);
    {
        PyObject *loaded = PyRun_String(
            binary_source, Py_file_input, globals, globals);
        size_t binary_index;
        CHECK(loaded != NULL);
        Py_DECREF(loaded);
        CHECK(wrtc_py_binary_from_name("Div") == WRTC_PY_BINARY_TRUE_DIVIDE);
        CHECK(strcmp(wrtc_py_binary_name(WRTC_PY_BINARY_TRUE_DIVIDE),
                     "TrueDiv") == 0);
        for (binary_index = 0u;
             binary_index < sizeof binary_names / sizeof binary_names[0];
             binary_index++) {
            const char *binary_name = binary_names[binary_index];
            PyObject *left = NULL, *right = PyLong_FromLong(3);
            PyObject *python_function = Py_XNewRef(
                PyDict_GetItemString(globals, binary_name));
            if (strcmp(binary_name, "matrix_multiply") == 0) {
                PyObject *operand = PyDict_GetItemString(globals, "Operand");
                left = operand == NULL ? NULL : PyObject_CallNoArgs(operand);
            } else {
                left = PyLong_FromLong(12);
            }
            CHECK(left != NULL && right != NULL && python_function != NULL);
            PyDict_Clear(locals);
            CHECK(PyDict_SetItemString(locals, "x", left) == 0);
            CHECK(PyDict_SetItemString(locals, "y", right) == 0);
            CHECK(run_region(globals, binary_source, binary_name,
                             locals, &result) == 0);
            expected = PyObject_CallFunctionObjArgs(
                python_function, left, right, NULL);
            CHECK(expected != NULL);
            {
                int parity = PyObject_RichCompareBool(result, expected, Py_EQ);
                if (parity != 1) {
                    (void)fprintf(stderr, "binary parity failed: %s\n", binary_name);
                    PyObject_Print(result, stderr, 0);
                    (void)fputc('\n', stderr);
                    PyObject_Print(expected, stderr, 0);
                    (void)fputc('\n', stderr);
                }
                CHECK(parity == 1);
            }
            Py_CLEAR(expected);
            Py_CLEAR(result);
            Py_DECREF(right);
            Py_DECREF(left);
            Py_DECREF(python_function);
        }
    }
    box_type = PyDict_GetItemString(globals, "Box");
    values = Py_BuildValue("[iiii]", -1, 2, 3, -4);
    events = Py_BuildValue("[(ii)(ii)(Oi)]", 7, 1, 5, 0, Py_None, 1);
    box = box_type == NULL || values == NULL
              ? NULL : PyObject_CallOneArg(box_type, values);
    CHECK(box != NULL && events != NULL);
    PyDict_Clear(locals);
    CHECK(PyDict_SetItemString(locals, "loop", box) == 0);
    CHECK(PyDict_SetItemString(locals, "events", events) == 0);
    CHECK(run_region(
              globals, source, "region", locals, &result) == 0);
    function = PyDict_GetItemString(globals, "region");
    expected = function == NULL
                   ? NULL : PyObject_CallFunctionObjArgs(
                                 function, box, events, NULL);
    CHECK(expected != NULL);
    CHECK(PyObject_RichCompareBool(result, expected, Py_EQ) == 1);
    CHECK(PyLong_AsLong(PyObject_GetAttrString(box, "cleaned")) == 2);
    Py_CLEAR(expected);
    Py_CLEAR(result);

    PyDict_Clear(locals);
    CHECK(PyDict_SetItemString(
              locals, "value", PyLong_FromLong(-2)) == 0);
    CHECK(run_region(
              globals, source, "final_return", locals, &result) == 0);
    CHECK(PyLong_AsLong(result) == 9);
    Py_CLEAR(result);

    PyDict_Clear(locals);
    CHECK(PyDict_SetItemString(
              locals, "value", PyLong_FromLong(3)) == 0);
    CHECK(run_region(
              globals, source, "chained", locals, &result) == 0);
    CHECK(result == Py_True);
    Py_CLEAR(result);

    PyDict_Clear(locals);
    CHECK(run_region(
              globals, source, "caused", locals, &result) < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_RuntimeError));
    {
        PyObject *type = NULL, *value = NULL, *traceback = NULL;
        PyObject *cause;
        PyErr_Fetch(&type, &value, &traceback);
        PyErr_NormalizeException(&type, &value, &traceback);
        cause = value == NULL ? NULL : PyException_GetCause(value);
    CHECK(cause != NULL && PyErr_GivenExceptionMatches(
                                   cause, PyExc_ValueError));
        Py_XDECREF(traceback);
        Py_XDECREF(value);
        Py_XDECREF(type);
    }

    {
        PyObject *setup = PyRun_String(
            "default_calls=0\n"
            "def make_default():\n"
            " global default_calls\n"
            " default_calls += 1\n"
            " return []\n",
            Py_file_input, globals, globals);
        PyObject *args = Py_BuildValue("(iii)", 1, 2, 3);
        PyObject *kwargs = Py_BuildValue("{s:i,s:i}", "flag", 4, "extra", 5);
        PyObject *bound = NULL;
        CHECK(setup != NULL);
        Py_DECREF(setup);
        CHECK(wrtc_boxed_signature_initialize(&signature, globals) == 0);
        CHECK(PyLong_AsLong(
                  PyDict_GetItemString(globals, "default_calls")) == 1);
        CHECK(wrtc_boxed_bind(
                  &signature, args, kwargs, &bound) == 0);
        CHECK(PyLong_AsLong(PyDict_GetItemString(bound, "x")) == 1);
        CHECK(PyLong_AsLong(PyDict_GetItemString(bound, "y")) == 2);
        CHECK(PyTuple_GET_SIZE(
                  PyDict_GetItemString(bound, "rest")) == 1);
        CHECK(PyLong_AsLong(PyDict_GetItemString(bound, "flag")) == 4);
        CHECK(PyLong_AsLong(PyDict_GetItemString(
                  PyDict_GetItemString(bound, "extras"), "extra")) == 5);
        wrtc_native_allocation_release_locals(bound);
        Py_DECREF(kwargs);
        Py_DECREF(args);
        args = Py_BuildValue("(i)", 1);
        CHECK(wrtc_boxed_bind(&signature, args, NULL, &bound) == 0);
        CHECK(PyDict_GetItemString(bound, "y") ==
              signature.defaults[1]);
        CHECK(PyLong_AsLong(
                  PyDict_GetItemString(globals, "default_calls")) == 1);
        wrtc_native_allocation_release_locals(bound);
        Py_DECREF(args);
        wrtc_boxed_signature_clear(&signature);
    }
    CHECK(PyDict_SetItemString(
              globals, "local", PyLong_FromLong(3)) == 0);
    PyDict_Clear(locals);
    CHECK(run_region(
              globals, source, "unbound", locals, &result) < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_UnboundLocalError));
    PyErr_Clear();

    {
        PyObject *counters = wrtc_native_allocation_counters(NULL, NULL);
        PyObject *fallback = counters == NULL ? NULL : PyDict_GetItemString(
            counters, "fallback_deoptimization.allocations");
        PyObject *live = counters == NULL ? NULL : PyDict_GetItemString(
            counters, "locals_dictionary.live");
        CHECK(fallback != NULL && PyLong_AsUnsignedLongLong(fallback) >= 6u);
        CHECK(live != NULL && PyLong_AsUnsignedLongLong(live) == 0u);
        Py_DECREF(counters);
        PyObject *reset = wrtc_native_reset_allocation_counters(NULL, NULL);
        CHECK(reset == Py_None);
        Py_DECREF(reset);
        counters = wrtc_native_allocation_counters(NULL, NULL);
        fallback = counters == NULL ? NULL : PyDict_GetItemString(
            counters, "fallback_deoptimization.allocations");
        CHECK(fallback != NULL && PyLong_AsUnsignedLongLong(fallback) == 0u);
        Py_DECREF(counters);
    }

    Py_DECREF(events);
    Py_DECREF(values);
    Py_DECREF(box);
    Py_DECREF(locals);
    Py_DECREF(globals);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
