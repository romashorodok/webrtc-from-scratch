#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boxed_codegen.h"
#include "boxed_module.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static PyObject *function_body(const char *source) {
    PyObject *ast = PyImport_ImportModule("ast");
    PyObject *tree =
        ast == NULL ? NULL : PyObject_CallMethod(ast, "parse", "s", source);
    PyObject *module_body =
        tree == NULL ? NULL : PyObject_GetAttrString(tree, "body");
    PyObject *function =
        module_body == NULL ? NULL : PySequence_GetItem(module_body, 0);
    PyObject *body =
        function == NULL ? NULL : PyObject_GetAttrString(function, "body");
    Py_XDECREF(function);
    Py_XDECREF(module_body);
    Py_XDECREF(tree);
    Py_XDECREF(ast);
    return body;
}

int main(void) {
    static const char source[] =
        "def execute(loop, values):\n"
        "    total = 0\n"
        "    for value in values:\n"
        "        if value < 0:\n"
        "            continue\n"
        "        total += value\n"
        "    try:\n"
        "        loop.value = values[:]\n"
        "    finally:\n"
        "        loop.done = True\n"
        "    return total\n";
    PyObject *body;
    WrtcPySuiteIR *suite = NULL;
    WrtcPyParameterIR parameter = {
        "self", NULL, NULL, {1, 1, 1, 5},
        WRTC_PY_PARAM_POSITIONAL_ONLY, 0
    };
    WrtcPySignatureIR signature = {"execute", &parameter, 1u};
    char *module_name;
    FILE *output;
    const char *output_path;
    char *text;
    long length;

    Py_Initialize();
    body = function_body(source);
    CHECK(body != NULL);
    CHECK(wrtc_py_ir_lower_suite(
              body, "generic_component.py", &suite) == 0);
    Py_DECREF(body);
    output_path = getenv("WRTC_BOXED_OUTPUT");
    output = output_path == NULL ? tmpfile() : fopen(output_path, "w+b");
    CHECK(output != NULL);
    CHECK(wrtc_boxed_emit_runtime(output) == 0);
    CHECK(wrtc_boxed_emit_suite(
              output, "region_body_0", suite) == 0);
    CHECK(wrtc_boxed_emit_signature(
              output, "region_signature_0", &signature) == 0);
    module_name = wrtc_boxed_module_name(WRTC_BOXED_PACKAGE_SOURCE);
    CHECK(module_name != NULL);
    if (strcmp(module_name, "webrtc.event_loop.scheduler") != 0)
        (void)fprintf(stderr, "derived module: %s\n", module_name);
    CHECK(strcmp(module_name, "webrtc.event_loop.scheduler") == 0);
    CHECK(wrtc_boxed_emit_module_globals(
              output, "region_module_0", module_name) == 0);
    free(module_name);
    CHECK(fputs(
              "WrtcPySuiteIR*wrtc_boxed_test_suite=&region_body_0;\n",
              output) >= 0);
    CHECK(fputs(
              "WrtcBoxedSignature*wrtc_boxed_test_signature="
              "&region_signature_0;\n"
              "int(*wrtc_boxed_test_globals_init)(void)="
              "region_module_0_initialize_globals;\n"
              "void(*wrtc_boxed_test_globals_clear)(void)="
              "region_module_0_clear_globals;\n",
              output) >= 0);
    CHECK(fflush(output) == 0 && fseek(output, 0, SEEK_END) == 0);
    length = ftell(output);
    CHECK(length > 0 && fseek(output, 0, SEEK_SET) == 0);
    text = malloc((size_t)length + 1u);
    CHECK(text != NULL);
    CHECK(fread(text, 1u, (size_t)length, output) == (size_t)length);
    text[length] = '\0';
    CHECK(strstr(text, "int wrtc_boxed_execute(") != NULL);
    CHECK(strstr(text, "static WrtcPySuiteIR region_body_0=") != NULL);
    CHECK(strstr(text, "region_body_0_statements") != NULL);
    CHECK(strstr(text, "static WrtcBoxedSignature region_signature_0=") != NULL);
    CHECK(strstr(text, "PyImport_ImportModule(\"webrtc.event_loop.scheduler\")") != NULL);
    CHECK(strstr(text, "generic_component.py") == NULL);
    CHECK(strstr(text, "WebRTC") == NULL);
    free(text);
    CHECK(fclose(output) == 0);
    wrtc_py_suite_ir_free(suite);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
