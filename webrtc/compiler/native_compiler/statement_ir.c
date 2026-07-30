#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "statement_ir.h"

static PyObject *attribute(PyObject *value, const char *name) {
    return value == NULL ? NULL : PyObject_GetAttrString(value, name);
}

static const char *node_kind(PyObject *node) {
    const char *name =
        node == NULL || Py_TYPE(node) == NULL ? "" : Py_TYPE(node)->tp_name;
    const char *dot = strrchr(name, '.');
    return dot == NULL ? name : dot + 1;
}

static int is_kind(PyObject *node, const char *name) {
    return node != NULL && strcmp(node_kind(node), name) == 0;
}

static long integer_attribute(PyObject *node, const char *name,
                              long fallback) {
    PyObject *value = attribute(node, name);
    long result = fallback;
    if (value != NULL && value != Py_None) result = PyLong_AsLong(value);
    Py_XDECREF(value);
    return result;
}

static WrtcSourceSpan source_span(PyObject *node) {
    WrtcSourceSpan result;
    result.line = (int)integer_attribute(node, "lineno", 1);
    result.column = (int)integer_attribute(node, "col_offset", 0) + 1;
    result.end_line =
        (int)integer_attribute(node, "end_lineno", result.line);
    result.end_column =
        (int)integer_attribute(node, "end_col_offset", result.column - 1) + 1;
    return result;
}

static char *copy_text(const char *value) {
    char *result;
    if (value == NULL) return NULL;
    result = malloc(strlen(value) + 1u);
    if (result != NULL) strcpy(result, value);
    return result;
}

static char *object_text(PyObject *value) {
    PyObject *text = value == NULL ? NULL : PyObject_Str(value);
    const char *utf8 = text == NULL ? NULL : PyUnicode_AsUTF8(text);
    char *result = utf8 == NULL ? NULL : copy_text(utf8);
    Py_XDECREF(text);
    return result;
}

static char *unparse(PyObject *node) {
    PyObject *ast = PyImport_ImportModule("ast");
    PyObject *function =
        ast == NULL ? NULL : PyObject_GetAttrString(ast, "unparse");
    PyObject *text =
        function == NULL ? NULL : PyObject_CallOneArg(function, node);
    const char *utf8 = text == NULL ? NULL : PyUnicode_AsUTF8(text);
    char *result = utf8 == NULL ? NULL : copy_text(utf8);
    Py_XDECREF(text);
    Py_XDECREF(function);
    Py_XDECREF(ast);
    return result;
}

static int diagnostic(const char *filename, PyObject *node,
                      const char *detail) {
    WrtcSourceSpan span = source_span(node);
    PyErr_Format(PyExc_ValueError, "%s:%d:%d: error: %s",
                 filename == NULL ? "<module>" : filename,
                 span.line, span.column, detail);
    return -1;
}

void wrtc_py_expr_ir_clear(WrtcPyExprIR *expression) {
    size_t index;
    if (expression == NULL) return;
    for (index = 0u; index < expression->child_count; index++)
        wrtc_py_expr_ir_clear(&expression->children[index]);
    for (index = 0u; index < expression->keyword_count; index++)
        free(expression->keyword_names[index]);
    for (index = 0u; index < expression->operation_count; index++)
        free(expression->operations[index]);
    free(expression->operations);
    free(expression->keyword_names);
    free(expression->children);
    free(expression->operation);
    free(expression->text);
    memset(expression, 0, sizeof(*expression));
}

void wrtc_py_stmt_ir_clear(WrtcPyStmtIR *statement) {
    size_t index;
    if (statement == NULL) return;
    for (index = 0u; index < statement->expression_count; index++)
        wrtc_py_expr_ir_clear(&statement->expressions[index]);
    for (index = 0u; index < statement->body_count; index++)
        wrtc_py_stmt_ir_clear(&statement->body[index]);
    for (index = 0u; index < statement->orelse_count; index++)
        wrtc_py_stmt_ir_clear(&statement->orelse[index]);
    for (index = 0u; index < statement->finalbody_count; index++)
        wrtc_py_stmt_ir_clear(&statement->finalbody[index]);
    for (index = 0u; index < statement->handler_count; index++)
        wrtc_py_stmt_ir_clear(&statement->handlers[index]);
    free(statement->expressions);
    free(statement->body);
    free(statement->orelse);
    free(statement->finalbody);
    free(statement->handlers);
    free(statement->operation);
    memset(statement, 0, sizeof(*statement));
}

void wrtc_py_suite_ir_free(WrtcPySuiteIR *suite) {
    size_t index;
    if (suite == NULL) return;
    for (index = 0u; index < suite->statement_count; index++)
        wrtc_py_stmt_ir_clear(&suite->statements[index]);
    for (index = 0u; index < suite->local_count; index++)
        free(suite->local_names[index]);
    free(suite->local_names);
    free(suite->statements);
    free(suite);
}

static int add_local(WrtcPySuiteIR *suite, const char *name) {
    char **names;
    size_t index;
    for (index = 0u; index < suite->local_count; index++)
        if (strcmp(suite->local_names[index], name) == 0) return 0;
    names = realloc(suite->local_names,
                    (suite->local_count + 1u) * sizeof(*names));
    if (names == NULL) return PyErr_NoMemory(), -1;
    suite->local_names = names;
    suite->local_names[suite->local_count] = copy_text(name);
    if (suite->local_names[suite->local_count] == NULL)
        return PyErr_NoMemory(), -1;
    suite->local_count++;
    return 0;
}

static int collect_target_locals(WrtcPySuiteIR *suite,
                                 const WrtcPyExprIR *target) {
    size_t index;
    if (target->kind == WRTC_PY_EXPR_NAME)
        return add_local(suite, target->operation);
    if (target->kind != WRTC_PY_EXPR_TUPLE &&
        target->kind != WRTC_PY_EXPR_LIST)
        return 0;
    for (index = 0u; index < target->child_count; index++)
        if (collect_target_locals(suite, &target->children[index]) < 0)
            return -1;
    return 0;
}

static int collect_statement_locals(WrtcPySuiteIR *suite,
                                    const WrtcPyStmtIR *statements,
                                    size_t count) {
    size_t index, child;
    for (index = 0u; index < count; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        if (statement->kind == WRTC_PY_STMT_ASSIGN)
            for (child = 1u; child < statement->expression_count; child++)
                if (collect_target_locals(
                        suite, &statement->expressions[child]) < 0)
                    return -1;
        if ((statement->kind == WRTC_PY_STMT_AUGMENTED_ASSIGN ||
             statement->kind == WRTC_PY_STMT_FOR) &&
            collect_target_locals(suite, &statement->expressions[0]) < 0)
            return -1;
        if (statement->kind == WRTC_PY_STMT_EXCEPT_HANDLER &&
            statement->operation != NULL &&
            add_local(suite, statement->operation) < 0)
            return -1;
        if (collect_statement_locals(
                suite, statement->body, statement->body_count) < 0 ||
            collect_statement_locals(
                suite, statement->orelse, statement->orelse_count) < 0 ||
            collect_statement_locals(
                suite, statement->finalbody,
                statement->finalbody_count) < 0 ||
            collect_statement_locals(
                suite, statement->handlers,
                statement->handler_count) < 0)
            return -1;
    }
    return 0;
}

static int lower_expression(PyObject *node, const char *filename,
                            WrtcPyExprIR *out);
static int lower_statements(PyObject *sequence, const char *filename,
                            WrtcPyStmtIR **out, size_t *count);

static int allocate_expression_children(WrtcPyExprIR *out, size_t count) {
    out->child_count = count;
    out->children = calloc(count, sizeof(*out->children));
    if (count != 0u && out->children == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

static int lower_expression_sequence(PyObject *sequence, const char *filename,
                                     WrtcPyExprIR *out, size_t offset) {
    Py_ssize_t index, count = PySequence_Size(sequence);
    for (index = 0; index < count; index++) {
        PyObject *item = PySequence_GetItem(sequence, index);
        if (item == NULL ||
            lower_expression(item, filename,
                             &out->children[offset + (size_t)index]) < 0) {
            Py_XDECREF(item);
            return -1;
        }
        Py_DECREF(item);
    }
    return 0;
}

static int lower_expression(PyObject *node, const char *filename,
                            WrtcPyExprIR *out) {
    PyObject *first = NULL, *second = NULL, *third = NULL;
    PyObject *items = NULL, *keywords = NULL;
    Py_ssize_t index, item_count, keyword_count;
    memset(out, 0, sizeof(*out));
    out->span = source_span(node);
    out->text = unparse(node);
    if (out->text == NULL) goto error;
    if (is_kind(node, "Name")) {
        first = attribute(node, "id");
        out->kind = WRTC_PY_EXPR_NAME;
        out->operation = object_text(first);
    } else if (is_kind(node, "Attribute")) {
        first = attribute(node, "value");
        second = attribute(node, "attr");
        out->kind = WRTC_PY_EXPR_ATTRIBUTE;
        out->operation = object_text(second);
        if (allocate_expression_children(out, 1u) < 0 ||
            lower_expression(first, filename, &out->children[0]) < 0)
            goto error;
    } else if (is_kind(node, "Constant")) {
        first = attribute(node, "value");
        out->kind = WRTC_PY_EXPR_CONSTANT;
        out->operation = copy_text(
            first == Py_None ? "NoneType" : Py_TYPE(first)->tp_name);
    } else if (is_kind(node, "Call")) {
        first = attribute(node, "func");
        items = attribute(node, "args");
        keywords = attribute(node, "keywords");
        item_count = items == NULL ? -1 : PySequence_Size(items);
        keyword_count = keywords == NULL ? -1 : PySequence_Size(keywords);
        if (item_count < 0 || keyword_count < 0 ||
            allocate_expression_children(
                out, 1u + (size_t)item_count + (size_t)keyword_count) < 0)
            goto error;
        out->kind = WRTC_PY_EXPR_CALL;
        out->positional_count = (size_t)item_count;
        out->keyword_count = (size_t)keyword_count;
        out->keyword_names =
            calloc((size_t)keyword_count, sizeof(*out->keyword_names));
        if (keyword_count != 0 && out->keyword_names == NULL) {
            PyErr_NoMemory();
            goto error;
        }
        if (lower_expression(first, filename, &out->children[0]) < 0 ||
            lower_expression_sequence(items, filename, out, 1u) < 0)
            goto error;
        for (index = 0; index < keyword_count; index++) {
            PyObject *keyword = PySequence_GetItem(keywords, index);
            PyObject *name =
                keyword == NULL ? NULL : attribute(keyword, "arg");
            PyObject *value =
                keyword == NULL ? NULL : attribute(keyword, "value");
            if (keyword == NULL || name == NULL || name == Py_None ||
                value == NULL) {
                Py_XDECREF(value);
                Py_XDECREF(name);
                Py_XDECREF(keyword);
                diagnostic(filename, node,
                           "starred native-region calls are unsupported");
                goto error;
            }
            out->keyword_names[(size_t)index] = object_text(name);
            if (out->keyword_names[(size_t)index] == NULL ||
                lower_expression(
                    value, filename,
                    &out->children[1u + (size_t)item_count +
                                   (size_t)index]) < 0) {
                Py_DECREF(value);
                Py_DECREF(name);
                Py_DECREF(keyword);
                goto error;
            }
            Py_DECREF(value);
            Py_DECREF(name);
            Py_DECREF(keyword);
        }
    } else if (is_kind(node, "BinOp") || is_kind(node, "BoolOp") ||
               is_kind(node, "Compare")) {
        if (is_kind(node, "BoolOp")) {
            items = attribute(node, "values");
            second = attribute(node, "op");
            item_count = items == NULL ? -1 : PySequence_Size(items);
            if (item_count < 0 ||
                allocate_expression_children(out, (size_t)item_count) < 0 ||
                lower_expression_sequence(items, filename, out, 0u) < 0)
                goto error;
            out->kind = WRTC_PY_EXPR_BOOLEAN;
            out->operation = copy_text(node_kind(second));
        } else if (is_kind(node, "Compare")) {
            Py_ssize_t operation_count;
            first = attribute(node, "left");
            items = attribute(node, "comparators");
            second = attribute(node, "ops");
            item_count = items == NULL ? -1 : PySequence_Size(items);
            if (item_count < 0 ||
                allocate_expression_children(
                    out, 1u + (size_t)item_count) < 0 ||
                lower_expression(first, filename, &out->children[0]) < 0 ||
                lower_expression_sequence(items, filename, out, 1u) < 0)
                goto error;
            out->kind = WRTC_PY_EXPR_COMPARE;
            operation_count =
                second == NULL ? -1 : PySequence_Size(second);
            if (operation_count < 0 || operation_count != item_count)
                goto error;
            out->operation_count = (size_t)operation_count;
            out->operations =
                calloc(out->operation_count, sizeof(*out->operations));
            if (out->operation_count != (size_t)item_count ||
                (out->operation_count != 0u &&
                 out->operations == NULL)) {
                if (out->operations == NULL) PyErr_NoMemory();
                goto error;
            }
            for (index = 0;
                 index < (Py_ssize_t)out->operation_count; index++) {
                PyObject *operation = PySequence_GetItem(second, index);
                out->operations[(size_t)index] =
                    copy_text(node_kind(operation));
                Py_XDECREF(operation);
                if (out->operations[(size_t)index] == NULL) {
                    PyErr_NoMemory();
                    goto error;
                }
            }
            out->operation = copy_text(
                out->operation_count == 1u
                    ? out->operations[0] : "comparison_chain");
        } else {
            first = attribute(node, "left");
            second = attribute(node, "right");
            third = attribute(node, "op");
            if (allocate_expression_children(out, 2u) < 0 ||
                lower_expression(first, filename, &out->children[0]) < 0 ||
                lower_expression(second, filename, &out->children[1]) < 0)
                goto error;
            out->kind = WRTC_PY_EXPR_BINARY;
            out->operation = copy_text(node_kind(third));
        }
    } else if (is_kind(node, "UnaryOp")) {
        first = attribute(node, "operand");
        second = attribute(node, "op");
        if (allocate_expression_children(out, 1u) < 0 ||
            lower_expression(first, filename, &out->children[0]) < 0)
            goto error;
        out->kind = WRTC_PY_EXPR_UNARY;
        out->operation = copy_text(node_kind(second));
    } else if (is_kind(node, "Tuple") || is_kind(node, "List")) {
        items = attribute(node, "elts");
        item_count = items == NULL ? -1 : PySequence_Size(items);
        if (item_count < 0 ||
            allocate_expression_children(out, (size_t)item_count) < 0 ||
            lower_expression_sequence(items, filename, out, 0u) < 0)
            goto error;
        out->kind = is_kind(node, "Tuple")
                        ? WRTC_PY_EXPR_TUPLE : WRTC_PY_EXPR_LIST;
    } else if (is_kind(node, "Subscript")) {
        first = attribute(node, "value");
        second = attribute(node, "slice");
        if (allocate_expression_children(out, 2u) < 0 ||
            lower_expression(first, filename, &out->children[0]) < 0 ||
            lower_expression(second, filename, &out->children[1]) < 0)
            goto error;
        out->kind = WRTC_PY_EXPR_SUBSCRIPT;
    } else if (is_kind(node, "Slice")) {
        static const char *const fields[] = {"lower", "upper", "step"};
        if (allocate_expression_children(out, 3u) < 0) goto error;
        for (index = 0; index < 3; index++) {
            first = attribute(node, fields[index]);
            if (first == NULL) goto error;
            if (first == Py_None) {
                out->children[(size_t)index].kind = WRTC_PY_EXPR_CONSTANT;
                out->children[(size_t)index].span = out->span;
                out->children[(size_t)index].text = copy_text("None");
                out->children[(size_t)index].operation =
                    copy_text("NoneType");
            } else if (lower_expression(
                           first, filename,
                           &out->children[(size_t)index]) < 0) {
                Py_DECREF(first);
                goto error;
            }
            Py_CLEAR(first);
        }
        out->kind = WRTC_PY_EXPR_SLICE;
    } else {
        char detail[192];
        (void)snprintf(detail, sizeof detail,
                       "unsupported native-region expression %s",
                       node_kind(node));
        diagnostic(filename, node, detail);
        goto error;
    }
    if (out->operation == NULL &&
        (out->kind == WRTC_PY_EXPR_NAME ||
         out->kind == WRTC_PY_EXPR_ATTRIBUTE ||
         out->kind == WRTC_PY_EXPR_CONSTANT ||
         out->kind == WRTC_PY_EXPR_BINARY ||
         out->kind == WRTC_PY_EXPR_UNARY ||
         out->kind == WRTC_PY_EXPR_BOOLEAN ||
         out->kind == WRTC_PY_EXPR_COMPARE))
        goto error;
    Py_XDECREF(keywords);
    Py_XDECREF(items);
    Py_XDECREF(third);
    Py_XDECREF(second);
    Py_XDECREF(first);
    return 0;
error:
    Py_XDECREF(keywords);
    Py_XDECREF(items);
    Py_XDECREF(third);
    Py_XDECREF(second);
    Py_XDECREF(first);
    wrtc_py_expr_ir_clear(out);
    return -1;
}

static int lower_statement_expressions(PyObject *sequence,
                                       const char *filename,
                                       WrtcPyStmtIR *out,
                                       size_t extra) {
    Py_ssize_t index, count = PySequence_Size(sequence);
    out->expression_count = extra + (size_t)count;
    out->expressions =
        calloc(out->expression_count, sizeof(*out->expressions));
    if (out->expression_count != 0u && out->expressions == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (index = 0; index < count; index++) {
        PyObject *item = PySequence_GetItem(sequence, index);
        if (item == NULL ||
            lower_expression(item, filename,
                             &out->expressions[extra + (size_t)index]) < 0) {
            Py_XDECREF(item);
            return -1;
        }
        Py_DECREF(item);
    }
    return 0;
}

static int lower_statement(PyObject *node, const char *filename,
                           WrtcPyStmtIR *out) {
    PyObject *first = NULL, *second = NULL, *third = NULL;
    PyObject *body = NULL, *orelse = NULL, *finalbody = NULL;
    PyObject *handlers = NULL;
    memset(out, 0, sizeof(*out));
    out->span = source_span(node);
    if (is_kind(node, "Expr")) {
        first = attribute(node, "value");
        out->kind = WRTC_PY_STMT_EXPR;
        out->expression_count = 1u;
    } else if (is_kind(node, "Assign") || is_kind(node, "AnnAssign")) {
        PyObject *targets = NULL;
        first = attribute(node, "value");
        out->kind = WRTC_PY_STMT_ASSIGN;
        if (is_kind(node, "Assign")) {
            targets = attribute(node, "targets");
        } else {
            PyObject *target = attribute(node, "target");
            targets = target == NULL ? NULL : PyTuple_Pack(1, target);
            Py_XDECREF(target);
        }
        if (targets == NULL)
            goto error;
        if (lower_statement_expressions(targets, filename, out, 1u) < 0) {
            Py_DECREF(targets);
            goto error;
        }
        Py_DECREF(targets);
        if (lower_expression(first, filename, &out->expressions[0]) < 0)
            goto error;
    } else if (is_kind(node, "AugAssign")) {
        first = attribute(node, "target");
        second = attribute(node, "value");
        third = attribute(node, "op");
        out->kind = WRTC_PY_STMT_AUGMENTED_ASSIGN;
        out->operation = copy_text(node_kind(third));
        out->expression_count = 2u;
    } else if (is_kind(node, "If") || is_kind(node, "While")) {
        first = attribute(node, "test");
        body = attribute(node, "body");
        orelse = attribute(node, "orelse");
        out->kind =
            is_kind(node, "If") ? WRTC_PY_STMT_IF : WRTC_PY_STMT_WHILE;
        out->expression_count = 1u;
    } else if (is_kind(node, "For")) {
        first = attribute(node, "target");
        second = attribute(node, "iter");
        body = attribute(node, "body");
        orelse = attribute(node, "orelse");
        out->kind = WRTC_PY_STMT_FOR;
        out->expression_count = 2u;
        if (is_kind(second, "Call")) {
            PyObject *function = attribute(second, "func");
            char *function_text = function == NULL ? NULL : unparse(function);
            out->iterator_is_range =
                function != NULL && is_kind(function, "Name") &&
                function_text != NULL && strcmp(function_text, "range") == 0;
            free(function_text);
            Py_XDECREF(function);
        }
    } else if (is_kind(node, "Try")) {
        handlers = attribute(node, "handlers");
        body = attribute(node, "body");
        orelse = attribute(node, "orelse");
        finalbody = attribute(node, "finalbody");
        if (handlers == NULL || body == NULL || orelse == NULL ||
            finalbody == NULL) {
            goto error;
        }
        out->kind = PySequence_Size(handlers) == 0 &&
                            PySequence_Size(finalbody) != 0
                        ? WRTC_PY_STMT_TRY_FINALLY : WRTC_PY_STMT_TRY;
    } else if (is_kind(node, "ExceptHandler")) {
        first = attribute(node, "type");
        second = attribute(node, "name");
        body = attribute(node, "body");
        out->kind = WRTC_PY_STMT_EXCEPT_HANDLER;
        out->operation =
            second == NULL || second == Py_None ? NULL : object_text(second);
        out->expression_count = first == Py_None ? 0u : 1u;
    } else if (is_kind(node, "Return")) {
        first = attribute(node, "value");
        out->kind = WRTC_PY_STMT_RETURN;
        out->expression_count = first == Py_None ? 0u : 1u;
    } else if (is_kind(node, "Raise")) {
        first = attribute(node, "exc");
        second = attribute(node, "cause");
        out->kind = WRTC_PY_STMT_RAISE;
        out->expression_count =
            (first == Py_None ? 0u : 1u) + (second == Py_None ? 0u : 1u);
    } else if (is_kind(node, "Break")) {
        out->kind = WRTC_PY_STMT_BREAK;
    } else if (is_kind(node, "Continue")) {
        out->kind = WRTC_PY_STMT_CONTINUE;
    } else if (is_kind(node, "Pass")) {
        out->kind = WRTC_PY_STMT_PASS;
    } else {
        char detail[192];
        (void)snprintf(detail, sizeof detail,
                       "unsupported native-region statement %s",
                       node_kind(node));
        diagnostic(filename, node, detail);
        goto error;
    }
    if (out->expression_count != 0u && out->expressions == NULL) {
        out->expressions =
            calloc(out->expression_count, sizeof(*out->expressions));
        if (out->expressions == NULL) {
            PyErr_NoMemory();
            goto error;
        }
        if (lower_expression(first, filename, &out->expressions[0]) < 0)
            goto error;
        if (out->expression_count > 1u &&
            lower_expression(second, filename, &out->expressions[1]) < 0)
            goto error;
    }
    if (body != NULL &&
        lower_statements(body, filename, &out->body, &out->body_count) < 0)
        goto error;
    if (orelse != NULL &&
        lower_statements(
            orelse, filename, &out->orelse, &out->orelse_count) < 0)
        goto error;
    if (finalbody != NULL &&
        lower_statements(finalbody, filename, &out->finalbody,
                         &out->finalbody_count) < 0)
        goto error;
    if (handlers != NULL &&
        lower_statements(handlers, filename, &out->handlers,
                         &out->handler_count) < 0)
        goto error;
    Py_XDECREF(handlers);
    Py_XDECREF(finalbody);
    Py_XDECREF(orelse);
    Py_XDECREF(body);
    Py_XDECREF(third);
    Py_XDECREF(second);
    Py_XDECREF(first);
    return 0;
error:
    Py_XDECREF(handlers);
    Py_XDECREF(finalbody);
    Py_XDECREF(orelse);
    Py_XDECREF(body);
    Py_XDECREF(third);
    Py_XDECREF(second);
    Py_XDECREF(first);
    wrtc_py_stmt_ir_clear(out);
    return -1;
}

static int lower_statements(PyObject *sequence, const char *filename,
                            WrtcPyStmtIR **out, size_t *count) {
    Py_ssize_t index, length = PySequence_Size(sequence);
    WrtcPyStmtIR *statements;
    if (length < 0) return -1;
    statements = calloc((size_t)length, sizeof(*statements));
    if (length != 0 && statements == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (index = 0; index < length; index++) {
        PyObject *node = PySequence_GetItem(sequence, index);
        if (node == NULL ||
            lower_statement(node, filename, &statements[(size_t)index]) < 0) {
            Py_ssize_t previous;
            Py_XDECREF(node);
            for (previous = 0; previous < index; previous++)
                wrtc_py_stmt_ir_clear(&statements[(size_t)previous]);
            free(statements);
            return -1;
        }
        Py_DECREF(node);
    }
    *out = statements;
    *count = (size_t)length;
    return 0;
}

int wrtc_py_ir_lower_suite(PyObject *statements, const char *filename,
                           WrtcPySuiteIR **out) {
    WrtcPySuiteIR *result;
    if (statements == NULL || out == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "native-region statement IR input is absent");
        return -1;
    }
    *out = NULL;
    result = calloc(1u, sizeof(*result));
    if (result == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    if (lower_statements(statements, filename, &result->statements,
                         &result->statement_count) < 0) {
        wrtc_py_suite_ir_free(result);
        return -1;
    }
    if (collect_statement_locals(
            result, result->statements, result->statement_count) < 0) {
        wrtc_py_suite_ir_free(result);
        return -1;
    }
    *out = result;
    return 0;
}

void wrtc_py_signature_ir_free(WrtcPySignatureIR *signature) {
    size_t index;
    if (signature == NULL) return;
    for (index = 0u; index < signature->parameter_count; index++) {
        free(signature->parameters[index].name);
        free(signature->parameters[index].annotation);
        free(signature->parameters[index].default_expression);
    }
    free(signature->parameters);
    free(signature->name);
    free(signature);
}

static int append_parameters(WrtcPySignatureIR *signature, PyObject *items,
                             WrtcPyParameterKind kind, PyObject *defaults,
                             Py_ssize_t default_offset) {
    Py_ssize_t index, count = PySequence_Size(items);
    for (index = 0; index < count; index++) {
        WrtcPyParameterIR *parameter =
            &signature->parameters[signature->parameter_count++];
        PyObject *argument = PySequence_GetItem(items, index);
        PyObject *name =
            argument == NULL ? NULL : attribute(argument, "arg");
        PyObject *annotation =
            argument == NULL ? NULL : attribute(argument, "annotation");
        PyObject *default_value =
            defaults != NULL && index >= default_offset
                ? PySequence_GetItem(defaults, index - default_offset) : NULL;
        parameter->span = source_span(argument);
        parameter->kind = kind;
        parameter->name = object_text(name);
        if (annotation != NULL && annotation != Py_None)
            parameter->annotation = unparse(annotation);
        if (default_value != NULL && default_value != Py_None) {
            parameter->has_default = 1u;
            parameter->default_expression = unparse(default_value);
        }
        Py_XDECREF(default_value);
        Py_XDECREF(annotation);
        Py_XDECREF(name);
        Py_XDECREF(argument);
        if (parameter->name == NULL ||
            (parameter->has_default &&
             parameter->default_expression == NULL))
            return -1;
    }
    return 0;
}

int wrtc_py_ir_lower_signature(PyObject *function, const char *filename,
                               WrtcPySignatureIR **out) {
    WrtcPySignatureIR *signature;
    PyObject *name = NULL, *arguments = NULL;
    PyObject *posonly = NULL, *positional = NULL, *vararg = NULL;
    PyObject *keyword_only = NULL, *kwarg = NULL;
    PyObject *defaults = NULL, *keyword_defaults = NULL;
    Py_ssize_t positional_count, default_count;
    size_t count;
    (void)filename;
    if (function == NULL || out == NULL) {
        PyErr_SetString(PyExc_ValueError, "function signature input is absent");
        return -1;
    }
    *out = NULL;
    arguments = attribute(function, "args");
    name = attribute(function, "name");
    posonly = attribute(arguments, "posonlyargs");
    positional = attribute(arguments, "args");
    vararg = attribute(arguments, "vararg");
    keyword_only = attribute(arguments, "kwonlyargs");
    kwarg = attribute(arguments, "kwarg");
    defaults = attribute(arguments, "defaults");
    keyword_defaults = attribute(arguments, "kw_defaults");
    if (arguments == NULL || name == NULL || posonly == NULL ||
        positional == NULL || vararg == NULL || keyword_only == NULL ||
        kwarg == NULL || defaults == NULL || keyword_defaults == NULL)
        goto error;
    count = (size_t)(PySequence_Size(posonly) +
                     PySequence_Size(positional) +
                     PySequence_Size(keyword_only)) +
            (vararg == Py_None ? 0u : 1u) +
            (kwarg == Py_None ? 0u : 1u);
    signature = calloc(1u, sizeof(*signature));
    if (signature == NULL) {
        PyErr_NoMemory();
        goto error;
    }
    signature->name = object_text(name);
    signature->parameters = calloc(count, sizeof(*signature->parameters));
    if (signature->name == NULL ||
        (count != 0u && signature->parameters == NULL)) {
        if (signature->parameters == NULL) PyErr_NoMemory();
        wrtc_py_signature_ir_free(signature);
        goto error;
    }
    positional_count =
        PySequence_Size(posonly) + PySequence_Size(positional);
    default_count = PySequence_Size(defaults);
    if (append_parameters(
            signature, posonly, WRTC_PY_PARAM_POSITIONAL_ONLY,
            defaults, positional_count - default_count) < 0 ||
        append_parameters(
            signature, positional, WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD,
            defaults,
            PySequence_Size(positional) - default_count) < 0)
        goto signature_error;
    if (vararg != Py_None) {
        PyObject *one = PyTuple_Pack(1, vararg);
        if (one == NULL ||
            append_parameters(
                signature, one, WRTC_PY_PARAM_VAR_POSITIONAL,
                NULL, 0) < 0) {
            Py_XDECREF(one);
            goto signature_error;
        }
        Py_DECREF(one);
    }
    if (append_parameters(
            signature, keyword_only, WRTC_PY_PARAM_KEYWORD_ONLY,
            keyword_defaults, 0) < 0)
        goto signature_error;
    if (kwarg != Py_None) {
        PyObject *one = PyTuple_Pack(1, kwarg);
        if (one == NULL ||
            append_parameters(
                signature, one, WRTC_PY_PARAM_VAR_KEYWORD,
                NULL, 0) < 0) {
            Py_XDECREF(one);
            goto signature_error;
        }
        Py_DECREF(one);
    }
    *out = signature;
    Py_DECREF(keyword_defaults);
    Py_DECREF(defaults);
    Py_DECREF(kwarg);
    Py_DECREF(keyword_only);
    Py_DECREF(vararg);
    Py_DECREF(positional);
    Py_DECREF(posonly);
    Py_DECREF(name);
    Py_DECREF(arguments);
    return 0;
signature_error:
    wrtc_py_signature_ir_free(signature);
error:
    Py_XDECREF(keyword_defaults);
    Py_XDECREF(defaults);
    Py_XDECREF(kwarg);
    Py_XDECREF(keyword_only);
    Py_XDECREF(vararg);
    Py_XDECREF(positional);
    Py_XDECREF(posonly);
    Py_XDECREF(name);
    Py_XDECREF(arguments);
    return -1;
}
