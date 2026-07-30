#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "native_class.h"
#include "native_class_generator.h"

#ifndef WRTC_CAPABILITY_SOURCE
#error "WRTC_CAPABILITY_SOURCE is required"
#endif

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static PyObject *first_region(PyObject *report) {
    PyObject *classes = PyDict_GetItemString(report, "classes");
    PyObject *class_report =
        classes == NULL ? NULL : PyList_GetItem(classes, 0);
    PyObject *regions =
        class_report == NULL
            ? NULL : PyDict_GetItemString(class_report, "regions");
    return regions == NULL ? NULL : PyList_GetItem(regions, 0);
}

static PyObject *first_field(PyObject *report) {
    PyObject *classes = PyDict_GetItemString(report, "classes");
    PyObject *class_report =
        classes == NULL ? NULL : PyList_GetItem(classes, 0);
    PyObject *fields =
        class_report == NULL
            ? NULL : PyDict_GetItemString(class_report, "fields");
    return fields == NULL ? NULL : PyList_GetItem(fields, 0);
}

static int accepted_test(void) {
    static const char source[] =
        "import asyncio\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Accepted(asyncio.SelectorEventLoop):\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def ping(self, value):\n"
        "        return value\n";
    WrtcNativeClassProgram *program = NULL;
    PyObject *report, *region, *strategy;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_CAPABILITY_SOURCE,
              &program) == 0);
    CHECK(wrtc_native_class_can_emit(program));
    report = wrtc_native_class_capability_report(
        program, WRTC_CAPABILITY_SOURCE);
    CHECK(report != NULL);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(report, "generator_accepted")) == 1);
    region = first_region(report);
    CHECK(region != NULL);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "status")),
                 "compiled") == 0);
    CHECK(PyList_GET_SIZE(PyDict_GetItemString(
              region, "rejection_reasons")) == 0);
    strategy = PyDict_GetItemString(region, "execution_strategy");
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(strategy, "body")),
                 "boxed_semantic_codegen") == 0);
    CHECK(strstr(PyUnicode_AsUTF8(
                     PyDict_GetItemString(strategy, "cleanup")),
                 "cleanup epilogue") != NULL);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

static int pending_storage_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import asyncio\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class WorkSet(asyncio.SelectorEventLoop):\n"
        "    work: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('single')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def turn(self, value):\n"
        "        self.work.append(value)\n"
        "        return self.work.popleft()\n";
    WrtcNativeClassProgram *program = NULL;
    PyObject *report, *region, *field, *sites, *calls;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_CAPABILITY_SOURCE,
              &program) == 0);
    CHECK(wrtc_native_class_can_emit(program));
    report = wrtc_native_class_capability_report(
        program, WRTC_CAPABILITY_SOURCE);
    CHECK(report != NULL);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(report, "generator_accepted")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              report, "operation_proof_complete")) == 1);
    field = first_field(report);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(field, "representation")),
                 "guarded_native_with_boxed_fallback") == 0);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              field, "operation_proof_complete")) == 1);
    CHECK(PyLong_AsLong(PyDict_GetItemString(
              field, "operation_count")) == 2);
    region = first_region(report);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "status")),
                 "compiled") == 0);
    sites = PyDict_GetItemString(region, "operation_sites");
    calls = PyDict_GetItemString(region, "remaining_python_calls");
    CHECK(PyList_GET_SIZE(sites) == 2);
    CHECK(PyList_GET_SIZE(calls) == 0);
    CHECK(strcmp(PyUnicode_AsUTF8(PyDict_GetItemString(
                     PyList_GetItem(sites, 0), "operation")),
                 "fifo_append") == 0);
    CHECK(PyList_GET_SIZE(PyDict_GetItemString(
              region, "rejection_reasons")) == 0);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

static int rejected_proof_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import asyncio\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class WorkSet(asyncio.SelectorEventLoop):\n"
        "    work: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('single')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def expose(self):\n"
        "        return self.work\n";
    WrtcNativeClassProgram *program = NULL;
    PyObject *report, *region, *field, *sites, *rejection, *source_report;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_CAPABILITY_SOURCE,
              &program) == 0);
    report = wrtc_native_class_capability_report(
        program, WRTC_CAPABILITY_SOURCE);
    CHECK(report != NULL);
    field = first_field(report);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(field, "representation")),
                 "native_rejected") == 0);
    region = first_region(report);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              region, "operation_proof_complete")) == 0);
    sites = PyDict_GetItemString(region, "operation_sites");
    CHECK(PyList_GET_SIZE(sites) == 1);
    CHECK(strcmp(PyUnicode_AsUTF8(PyDict_GetItemString(
                     PyList_GetItem(sites, 0), "operation")),
                 "unsupported_escape") == 0);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              PyList_GetItem(sites, 0), "lowered")) == 0);
    CHECK(strstr(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "reason")),
                 "operation proof") != NULL);
    rejection = PyList_GetItem(
        PyDict_GetItemString(region, "rejection_reasons"), 0);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(rejection, "code")),
                 "native_operation_proof") == 0);
    source_report = PyDict_GetItemString(rejection, "source");
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(source_report, "filename")),
                 WRTC_CAPABILITY_SOURCE) == 0);
    CHECK(PyLong_AsLong(
              PyDict_GetItemString(source_report, "line")) == 9);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

static int length_lowering_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import asyncio\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class WorkSet(asyncio.SelectorEventLoop):\n"
        "    work: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('single')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def count(self):\n"
        "        return len(self.work)\n";
    WrtcNativeClassProgram *program = NULL;
    PyObject *report, *region, *field, *sites;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_CAPABILITY_SOURCE,
              &program) == 0);
    CHECK(wrtc_native_class_can_emit(program));
    report = wrtc_native_class_capability_report(
        program, WRTC_CAPABILITY_SOURCE);
    CHECK(report != NULL);
    field = first_field(report);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              field, "operation_proof_complete")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              field, "operation_lowering_complete")) == 1);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(field, "representation")),
                 "guarded_native_with_boxed_fallback") == 0);
    region = first_region(report);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              region, "operation_proof_complete")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              region, "operation_lowering_complete")) == 1);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "status")),
                 "compiled") == 0);
    sites = PyDict_GetItemString(region, "operation_sites");
    CHECK(PyList_GET_SIZE(sites) == 1);
    CHECK(strcmp(PyUnicode_AsUTF8(PyDict_GetItemString(
                     PyList_GetItem(sites, 0), "operation")),
                 "length") == 0);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              PyList_GetItem(sites, 0), "lowered")) == 1);
    CHECK(PyList_GET_SIZE(PyDict_GetItemString(
              region, "rejection_reasons")) == 0);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

int main(void) {
    Py_Initialize();
    CHECK(accepted_test() == 0);
    CHECK(pending_storage_test() == 0);
    CHECK(rejected_proof_test() == 0);
    CHECK(length_lowering_test() == 0);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
