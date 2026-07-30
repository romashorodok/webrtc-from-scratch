#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "statement_ir.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static PyObject *method_body(const char *source) {
    PyObject *ast = PyImport_ImportModule("ast");
    PyObject *tree =
        ast == NULL ? NULL : PyObject_CallMethod(ast, "parse", "s", source);
    PyObject *module_body =
        tree == NULL ? NULL : PyObject_GetAttrString(tree, "body");
    PyObject *class_node =
        module_body == NULL ? NULL : PySequence_GetItem(module_body, 0);
    PyObject *class_body =
        class_node == NULL ? NULL : PyObject_GetAttrString(class_node, "body");
    PyObject *method =
        class_body == NULL ? NULL : PySequence_GetItem(class_body, 0);
    PyObject *body =
        method == NULL ? NULL : PyObject_GetAttrString(method, "body");
    Py_XDECREF(method);
    Py_XDECREF(class_body);
    Py_XDECREF(class_node);
    Py_XDECREF(module_body);
    Py_XDECREF(tree);
    Py_XDECREF(ast);
    return body;
}

int main(void) {
    static const char source[] =
        "class Scheduler:\n"
        "    def turn(self, loop, events):\n"
        "        scheduled = loop._scheduled\n"
        "        retained = []\n"
        "        for handle in scheduled:\n"
        "            if handle._cancelled:\n"
        "                continue\n"
        "            retained.append(handle)\n"
        "        scheduled[:] = retained\n"
        "        while scheduled and scheduled[0]._cancelled:\n"
        "            scheduled.pop(0)\n"
        "        for key, mask in events:\n"
        "            reader, writer = key.data\n"
        "            if mask & 1 and reader is not None:\n"
        "                loop._ready.append(reader)\n"
        "        for index in range(len(loop._ready)):\n"
        "            try:\n"
        "                loop._ready[index]._run()\n"
        "            finally:\n"
        "                loop._current_handle = None\n"
        "        return min(max(0.0, scheduled[0]._when - loop.time()), 1)\n";
    static const char exception_source[] =
        "class Inbox:\n"
        "    def publish(self, queue):\n"
        "        try:\n"
        "            queue.put_nowait(1)\n"
        "        except ValueError as error:\n"
        "            raise RuntimeError('full') from error\n";
    PyObject *body;
    WrtcPySuiteIR *suite = NULL;
    const WrtcPyStmtIR *loop;

    Py_Initialize();
    body = method_body(source);
    CHECK(body != NULL);
    CHECK(wrtc_py_ir_lower_suite(body, "scheduler_component.py", &suite) == 0);
    Py_DECREF(body);
    CHECK(suite != NULL && suite->statement_count == 8u);
    CHECK(suite->statements[0].kind == WRTC_PY_STMT_ASSIGN);
    CHECK(suite->statements[0].expressions[0].kind ==
          WRTC_PY_EXPR_ATTRIBUTE);
    CHECK(suite->statements[1].expressions[0].kind == WRTC_PY_EXPR_LIST);
    CHECK(suite->statements[2].kind == WRTC_PY_STMT_FOR);
    CHECK(suite->statements[2].expressions[0].kind == WRTC_PY_EXPR_NAME);
    CHECK(suite->statements[2].body[0].kind == WRTC_PY_STMT_IF);
    CHECK(suite->statements[3].expressions[1].kind ==
          WRTC_PY_EXPR_SUBSCRIPT);
    CHECK(suite->statements[4].kind == WRTC_PY_STMT_WHILE);
    CHECK(suite->statements[4].expressions[0].kind ==
          WRTC_PY_EXPR_BOOLEAN);
    CHECK(suite->statements[5].expressions[0].kind == WRTC_PY_EXPR_TUPLE);
    loop = &suite->statements[6];
    CHECK(loop->kind == WRTC_PY_STMT_FOR && loop->iterator_is_range);
    CHECK(loop->body[0].kind == WRTC_PY_STMT_TRY_FINALLY);
    CHECK(loop->body[0].finalbody_count == 1u);
    CHECK(suite->statements[7].kind == WRTC_PY_STMT_RETURN);
    CHECK(suite->statements[7].expressions[0].kind == WRTC_PY_EXPR_CALL);
    CHECK(suite->statements[7].span.line == 21);
    CHECK(suite->statements[7].span.column == 9);
    wrtc_py_suite_ir_free(suite);
    suite = NULL;

    body = method_body(exception_source);
    CHECK(body != NULL);
    CHECK(wrtc_py_ir_lower_suite(
              body, "command_component.py", &suite) == 0);
    Py_DECREF(body);
    CHECK(suite->statement_count == 1u);
    CHECK(suite->statements[0].kind == WRTC_PY_STMT_TRY);
    CHECK(suite->statements[0].handler_count == 1u);
    CHECK(suite->statements[0].handlers[0].kind ==
          WRTC_PY_STMT_EXCEPT_HANDLER);
    CHECK(strcmp(suite->statements[0].handlers[0].operation, "error") == 0);
    CHECK(suite->statements[0].handlers[0].body[0].kind ==
          WRTC_PY_STMT_RAISE);
    CHECK(suite->statements[0].handlers[0].body[0].expression_count == 2u);
    wrtc_py_suite_ir_free(suite);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
