#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "compiler_core.h"

#define CHECK(value) do { if (!(value)) { (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #value); return 1; } } while (0)

static int error_contains(const char *needle) {
    PyObject *type = NULL, *value = NULL, *traceback = NULL, *text = NULL;
    const char *message; int contains = 0;
    PyErr_Fetch(&type, &value, &traceback); PyErr_NormalizeException(&type, &value, &traceback);
    if (value != NULL) text = PyObject_Str(value);
    message = text == NULL ? NULL : PyUnicode_AsUTF8(text);
    if (message != NULL) contains = strstr(message, needle) != NULL;
    Py_XDECREF(text); Py_XDECREF(traceback); Py_XDECREF(value); Py_XDECREF(type);
    return contains;
}

int main(void) {
    static const char source[] =
        "from pymeta import required\n"
        "__all__ = ['run']\n"
        "_LIMIT = 2 * 8\n"
        "class Item:\n"
        "    value: int\n"
        "def _helper(value: int) -> int:\n"
        "    if value > _LIMIT:\n"
        "        raise ValueError('large')\n"
        "    return value + 1\n"
        "@required\n"
        "def run(value: int) -> int:\n"
        "    return _helper(value)\n";
    static const char bad[] = "import os\ndef run():\n    return 1\n";
    static const char executable_metadata[] =
        "import pymeta\n"
        "@pymeta.region('run', value=pymeta.u16, hidden=make_metadata())\n"
        "def run(value: int) -> int:\n    return value\n";
    WrtcCompilerCore *core = NULL; const WrtcFunctionIR *run, *helper; PyObject *limit;
    Py_Initialize();
    CHECK(wrtc_compiler_core_analyze(source, sizeof(source) - 1u, "fixture.py", &core) == 0);
    CHECK(core != NULL); CHECK(core->function_count == 2u); CHECK(core->record_count == 1u);
    CHECK(core->records[0].field_count == 1u); CHECK(PyList_GET_SIZE(core->exports) == 1);
    CHECK(strcmp(core->records[0].fields[0].name, "value") == 0);
    CHECK(core->records[0].fields[0].type == WRTC_TYPE_INT);
    CHECK(strcmp(PyUnicode_AsUTF8(PyList_GET_ITEM(core->exports, 0)), "run") == 0);
    limit = PyDict_GetItemString(core->constant_values, "_LIMIT");
    CHECK(limit != NULL && PyLong_AsLong(limit) == 16);
    CHECK(strstr(core->lowered_source, "pymeta") == NULL);
    CHECK(strstr(core->lowered_source, "@required") == NULL);
    run = wrtc_compiler_core_find_function(core, "run"); helper = wrtc_compiler_core_find_function(core, "_helper");
    CHECK(run != NULL && run->is_public && run->is_reachable);
    CHECK(helper != NULL && !helper->is_public && helper->is_reachable);
    CHECK(run->span.line == 11 && run->span.column == 1);
    wrtc_compiler_core_free(core); core = NULL;
    CHECK(wrtc_compiler_core_analyze(bad, sizeof(bad) - 1u, "bad.py", &core) < 0);
    CHECK(error_contains("bad.py:1:1: error: unsafe import is not supported"));
    CHECK(core == NULL);
    CHECK(wrtc_compiler_core_analyze(executable_metadata, sizeof(executable_metadata) - 1u, "metadata.py", &core) < 0);
    CHECK(error_contains("PyMeta declaration must contain only deterministic metadata expressions"));
    CHECK(core == NULL);
    CHECK(Py_FinalizeEx() == 0); return 0;
}
