#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boxed_codegen.h"
#include "boxed_executor_source.h"

typedef struct {
    FILE *output;
    const char *prefix;
    size_t next_expression;
    size_t next_statement;
} EmitContext;

static int valid_identifier(const char *value) {
    size_t index;
    if (value == NULL || value[0] == '\0' ||
        !(isalpha((unsigned char)value[0]) || value[0] == '_'))
        return 0;
    for (index = 1u; value[index] != '\0'; index++)
        if (!(isalnum((unsigned char)value[index]) || value[index] == '_'))
            return 0;
    return 1;
}

static int quoted(FILE *output, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (value == NULL) return fputs("NULL", output) < 0 ? -1 : 0;
    if (fputc('"', output) == EOF) return -1;
    while (*cursor != 0u) {
        const unsigned char byte = *cursor++;
        if (byte == '"' || byte == '\\') {
            if (fputc('\\', output) == EOF ||
                fputc((int)byte, output) == EOF)
                return -1;
        } else if (byte == '\n') {
            if (fputs("\\n", output) < 0) return -1;
        } else if (byte == '\r') {
            if (fputs("\\r", output) < 0) return -1;
        } else if (byte == '\t') {
            if (fputs("\\t", output) < 0) return -1;
        } else if (byte < 0x20u || byte >= 0x7fu) {
            if (fprintf(output, "\\%03o", (unsigned)byte) < 0) return -1;
        } else if (fputc((int)byte, output) == EOF) {
            return -1;
        }
    }
    return fputc('"', output) == EOF ? -1 : 0;
}

static int emit_span(FILE *output, WrtcSourceSpan span) {
    return fprintf(output, "{%d,%d,%d,%d}", span.line, span.column,
                   span.end_line, span.end_column) < 0
               ? -1 : 0;
}

static int emit_pointer(FILE *output, const char *prefix, const char *label,
                        size_t identifier, size_t count) {
    if (count == 0u) return fputs("NULL", output) < 0 ? -1 : 0;
    return fprintf(output, "%s_%s_%zu", prefix, label, identifier) < 0
               ? -1 : 0;
}

static int emit_expression_dependencies(EmitContext *context,
                                        const WrtcPyExprIR *expression,
                                        size_t *identifier);
static int emit_statement_dependencies(EmitContext *context,
                                       const WrtcPyStmtIR *statement,
                                       size_t *identifier);

static int emit_string_array(FILE *output, const char *prefix,
                             const char *label, size_t identifier,
                             char *const *values, size_t count) {
    size_t index;
    if (count == 0u) return 0;
    if (fprintf(output, "static char*%s_%s_%zu[]={",
                prefix, label, identifier) < 0)
        return -1;
    for (index = 0u; index < count; index++)
        if (quoted(output, values[index]) < 0 ||
            fputc(',', output) == EOF)
            return -1;
    return fputs("};\n", output) < 0 ? -1 : 0;
}

static int emit_expression_initializer(
    EmitContext *context, const WrtcPyExprIR *expression, size_t identifier) {
    FILE *output = context->output;
    if (fprintf(output, "{%d,", (int)expression->kind) < 0 ||
        emit_span(output, expression->span) < 0 ||
        fputc(',', output) == EOF ||
        quoted(output, expression->text) < 0 ||
        fputc(',', output) == EOF ||
        quoted(output, expression->operation) < 0 ||
        fputc(',', output) == EOF ||
        emit_pointer(output, context->prefix, "expr_ops", identifier,
                     expression->operation_count) < 0 ||
        fprintf(output, ",%zu,", expression->operation_count) < 0 ||
        emit_pointer(output, context->prefix, "expr_keywords", identifier,
                     expression->keyword_count) < 0 ||
        fputc(',', output) == EOF ||
        emit_pointer(output, context->prefix, "expr_children", identifier,
                     expression->child_count) < 0 ||
        fprintf(output, ",%zu,%zu,%zu}", expression->child_count,
                expression->positional_count,
                expression->keyword_count) < 0)
        return -1;
    return 0;
}

static int emit_expression_dependencies(EmitContext *context,
                                        const WrtcPyExprIR *expression,
                                        size_t *identifier) {
    size_t id = context->next_expression++;
    size_t *children = NULL;
    size_t index;
    *identifier = id;
    if (expression->child_count != 0u) {
        children = calloc(expression->child_count, sizeof(*children));
        if (children == NULL) return -1;
        for (index = 0u; index < expression->child_count; index++)
            if (emit_expression_dependencies(
                    context, &expression->children[index],
                    &children[index]) < 0) {
                free(children);
                return -1;
            }
    }
    if (emit_string_array(context->output, context->prefix, "expr_ops", id,
                          expression->operations,
                          expression->operation_count) < 0 ||
        emit_string_array(context->output, context->prefix, "expr_keywords",
                          id, expression->keyword_names,
                          expression->keyword_count) < 0) {
        free(children);
        return -1;
    }
    if (expression->child_count != 0u) {
        if (fprintf(context->output,
                    "static WrtcPyExprIR %s_expr_children_%zu[]={",
                    context->prefix, id) < 0) {
            free(children);
            return -1;
        }
        for (index = 0u; index < expression->child_count; index++)
            if (emit_expression_initializer(
                    context, &expression->children[index],
                    children[index]) < 0 ||
                fputc(',', context->output) == EOF) {
                free(children);
                return -1;
            }
        if (fputs("};\n", context->output) < 0) {
            free(children);
            return -1;
        }
    }
    free(children);
    return 0;
}

static int emit_statement_initializer(
    EmitContext *context, const WrtcPyStmtIR *statement, size_t identifier) {
    FILE *output = context->output;
    if (fprintf(output, "{%d,", (int)statement->kind) < 0 ||
        emit_span(output, statement->span) < 0 ||
        fputc(',', output) == EOF ||
        quoted(output, statement->operation) < 0 ||
        fputc(',', output) == EOF ||
        emit_pointer(output, context->prefix, "stmt_expr", identifier,
                     statement->expression_count) < 0 ||
        fprintf(output, ",%zu,", statement->expression_count) < 0 ||
        emit_pointer(output, context->prefix, "stmt_body", identifier,
                     statement->body_count) < 0 ||
        fprintf(output, ",%zu,", statement->body_count) < 0 ||
        emit_pointer(output, context->prefix, "stmt_else", identifier,
                     statement->orelse_count) < 0 ||
        fprintf(output, ",%zu,", statement->orelse_count) < 0 ||
        emit_pointer(output, context->prefix, "stmt_final", identifier,
                     statement->finalbody_count) < 0 ||
        fprintf(output, ",%zu,", statement->finalbody_count) < 0 ||
        emit_pointer(output, context->prefix, "stmt_handlers", identifier,
                     statement->handler_count) < 0 ||
        fprintf(output, ",%zu,%u}", statement->handler_count,
                statement->iterator_is_range ? 1u : 0u) < 0)
        return -1;
    return 0;
}

static int emit_expression_array(EmitContext *context,
                                 const WrtcPyStmtIR *statement,
                                 size_t statement_id) {
    size_t *identifiers;
    size_t index;
    if (statement->expression_count == 0u) return 0;
    identifiers =
        calloc(statement->expression_count, sizeof(*identifiers));
    if (identifiers == NULL) return -1;
    for (index = 0u; index < statement->expression_count; index++)
        if (emit_expression_dependencies(
                context, &statement->expressions[index],
                &identifiers[index]) < 0) {
            free(identifiers);
            return -1;
        }
    if (fprintf(context->output,
                "static WrtcPyExprIR %s_stmt_expr_%zu[]={",
                context->prefix, statement_id) < 0) {
        free(identifiers);
        return -1;
    }
    for (index = 0u; index < statement->expression_count; index++)
        if (emit_expression_initializer(
                context, &statement->expressions[index],
                identifiers[index]) < 0 ||
            fputc(',', context->output) == EOF) {
            free(identifiers);
            return -1;
        }
    free(identifiers);
    return fputs("};\n", context->output) < 0 ? -1 : 0;
}

static int emit_statement_array(EmitContext *context, const char *label,
                                size_t parent_id,
                                const WrtcPyStmtIR *statements, size_t count) {
    size_t *identifiers;
    size_t index;
    if (count == 0u) return 0;
    identifiers = calloc(count, sizeof(*identifiers));
    if (identifiers == NULL) return -1;
    for (index = 0u; index < count; index++)
        if (emit_statement_dependencies(
                context, &statements[index], &identifiers[index]) < 0) {
            free(identifiers);
            return -1;
        }
    if (fprintf(context->output,
                "static WrtcPyStmtIR %s_stmt_%s_%zu[]={",
                context->prefix, label, parent_id) < 0) {
        free(identifiers);
        return -1;
    }
    for (index = 0u; index < count; index++)
        if (emit_statement_initializer(
                context, &statements[index], identifiers[index]) < 0 ||
            fputc(',', context->output) == EOF) {
            free(identifiers);
            return -1;
        }
    free(identifiers);
    return fputs("};\n", context->output) < 0 ? -1 : 0;
}

static int emit_statement_dependencies(EmitContext *context,
                                       const WrtcPyStmtIR *statement,
                                       size_t *identifier) {
    const size_t id = context->next_statement++;
    *identifier = id;
    return emit_expression_array(context, statement, id) < 0 ||
                   emit_statement_array(context, "body", id,
                                        statement->body,
                                        statement->body_count) < 0 ||
                   emit_statement_array(context, "else", id,
                                        statement->orelse,
                                        statement->orelse_count) < 0 ||
                   emit_statement_array(context, "final", id,
                                        statement->finalbody,
                                        statement->finalbody_count) < 0 ||
                   emit_statement_array(context, "handlers", id,
                                        statement->handlers,
                                        statement->handler_count) < 0
               ? -1 : 0;
}

int wrtc_boxed_emit_suite(FILE *output, const char *symbol,
                          const WrtcPySuiteIR *suite) {
    EmitContext context;
    size_t *identifiers;
    size_t index;
    if (output == NULL || suite == NULL || !valid_identifier(symbol))
        return -1;
    context.output = output;
    context.prefix = symbol;
    context.next_expression = 0u;
    context.next_statement = 0u;
    identifiers = calloc(suite->statement_count, sizeof(*identifiers));
    if (suite->statement_count != 0u && identifiers == NULL) return -1;
    for (index = 0u; index < suite->statement_count; index++)
        if (emit_statement_dependencies(
                &context, &suite->statements[index],
                &identifiers[index]) < 0) {
            free(identifiers);
            return -1;
        }
    if (suite->statement_count != 0u &&
        fprintf(output, "static WrtcPyStmtIR %s_statements[]={", symbol) < 0) {
        free(identifiers);
        return -1;
    }
    for (index = 0u; index < suite->statement_count; index++)
        if (emit_statement_initializer(
                &context, &suite->statements[index],
                identifiers[index]) < 0 ||
            fputc(',', output) == EOF) {
            free(identifiers);
            return -1;
        }
    free(identifiers);
    if (suite->statement_count != 0u && fputs("};\n", output) < 0)
        return -1;
    if (emit_string_array(output, symbol, "locals", 0u,
                          suite->local_names, suite->local_count) < 0)
        return -1;
    if (fprintf(output, "static WrtcPySuiteIR %s={", symbol) < 0)
        return -1;
    if (suite->statement_count == 0u) {
        if (fputs("NULL", output) < 0) return -1;
    } else if (fprintf(output, "%s_statements", symbol) < 0) {
        return -1;
    }
    if (fprintf(output, ",%zu,", suite->statement_count) < 0 ||
        emit_pointer(output, symbol, "locals", 0u,
                     suite->local_count) < 0)
        return -1;
    return fprintf(output, ",%zu};\n", suite->local_count) < 0 ? -1 : 0;
}

int wrtc_boxed_emit_signature(FILE *output, const char *symbol,
                              const WrtcPySignatureIR *signature) {
    size_t index;
    if (output == NULL || signature == NULL || !valid_identifier(symbol))
        return -1;
    if (fprintf(output,
                "static const WrtcBoxedParameterSpec %s_parameters[]={",
                symbol) < 0)
        return -1;
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcPyParameterIR *parameter =
            &signature->parameters[index];
        if (fputc('{', output) == EOF ||
            quoted(output, parameter->name) < 0 ||
            fprintf(output, ",%d,", (int)parameter->kind) < 0 ||
            quoted(output, parameter->default_expression) < 0 ||
            fprintf(output, ",%u},", parameter->has_default ? 1u : 0u) < 0)
            return -1;
    }
    if (fputs("};\n", output) < 0 ||
        fprintf(output, "static WrtcBoxedSignature %s={", symbol) < 0 ||
        quoted(output, signature->name) < 0 ||
        fprintf(output, ",%s_parameters,%zu,NULL};\n", symbol,
                signature->parameter_count) < 0)
        return -1;
    return 0;
}

int wrtc_boxed_emit_module_globals(FILE *output, const char *symbol,
                                   const char *module_name) {
    if (output == NULL || !valid_identifier(symbol) ||
        module_name == NULL || module_name[0] == '\0')
        return -1;
    if (fprintf(output,
                "static PyObject*%s_module=NULL,*%s_globals=NULL;\n"
                "static int %s_initialize_globals(void){"
                "%s_module=PyImport_ImportModule(",
                symbol, symbol, symbol, symbol) < 0 ||
        quoted(output, module_name) < 0 ||
        fprintf(output,
                ");if(!%s_module)return -1;"
                "%s_globals=PyObject_GetAttrString(%s_module,\"__dict__\");"
                "if(!%s_globals){Py_CLEAR(%s_module);return -1;}return 0;}\n"
                "static void %s_clear_globals(void){Py_CLEAR(%s_globals);"
                "Py_CLEAR(%s_module);}\n",
                symbol, symbol, symbol, symbol, symbol,
                symbol, symbol, symbol) < 0)
        return -1;
    return 0;
}

int wrtc_boxed_emit_runtime(FILE *output) {
    static const char marker[] =
        "typedef enum {\n    WRTC_FLOW_NORMAL";
    const char *source = (const char *)wrtc_boxed_executor_source;
    const char *implementation = strstr(source, marker);
    static const char declarations[] =
        "#define PY_SSIZE_T_CLEAN\n#include <Python.h>\n"
        "#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "typedef struct{int line,column,end_line,end_column;}WrtcSourceSpan;\n"
        "typedef enum{WRTC_PY_EXPR_NAME=0,WRTC_PY_EXPR_ATTRIBUTE,"
        "WRTC_PY_EXPR_CONSTANT,WRTC_PY_EXPR_CALL,WRTC_PY_EXPR_BINARY,"
        "WRTC_PY_EXPR_UNARY,WRTC_PY_EXPR_BOOLEAN,WRTC_PY_EXPR_COMPARE,"
        "WRTC_PY_EXPR_TUPLE,WRTC_PY_EXPR_LIST,WRTC_PY_EXPR_DICT,"
        "WRTC_PY_EXPR_JOINED_STRING,WRTC_PY_EXPR_FORMATTED_VALUE,"
        "WRTC_PY_EXPR_LAMBDA,WRTC_PY_EXPR_SUBSCRIPT,"
        "WRTC_PY_EXPR_SLICE}WrtcPyExprKind;\n"
        "typedef struct WrtcPyExprIR{WrtcPyExprKind kind;WrtcSourceSpan span;"
        "char*text,*operation,**operations;size_t operation_count;"
        "char**keyword_names;struct WrtcPyExprIR*children;"
        "size_t child_count,positional_count,keyword_count;}WrtcPyExprIR;\n"
        "typedef enum{WRTC_PY_STMT_EXPR=0,WRTC_PY_STMT_ASSIGN,"
        "WRTC_PY_STMT_AUGMENTED_ASSIGN,WRTC_PY_STMT_IF,WRTC_PY_STMT_WHILE,"
        "WRTC_PY_STMT_FOR,WRTC_PY_STMT_TRY,WRTC_PY_STMT_TRY_FINALLY,"
        "WRTC_PY_STMT_EXCEPT_HANDLER,WRTC_PY_STMT_RETURN,WRTC_PY_STMT_RAISE,"
        "WRTC_PY_STMT_BREAK,WRTC_PY_STMT_CONTINUE,WRTC_PY_STMT_PASS}"
        "WrtcPyStmtKind;\n"
        "typedef struct WrtcPyStmtIR{WrtcPyStmtKind kind;WrtcSourceSpan span;"
        "char*operation;WrtcPyExprIR*expressions;size_t expression_count;"
        "struct WrtcPyStmtIR*body;size_t body_count;"
        "struct WrtcPyStmtIR*orelse;size_t orelse_count;"
        "struct WrtcPyStmtIR*finalbody;size_t finalbody_count;"
        "struct WrtcPyStmtIR*handlers;size_t handler_count;"
        "unsigned iterator_is_range:1;}WrtcPyStmtIR;\n"
        "typedef struct{WrtcPyStmtIR*statements;size_t statement_count;"
        "char**local_names;size_t local_count;}WrtcPySuiteIR;\n";
    static const char signatures[] =
        "typedef enum{WRTC_PY_PARAM_POSITIONAL_ONLY=0,"
        "WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD,WRTC_PY_PARAM_VAR_POSITIONAL,"
        "WRTC_PY_PARAM_KEYWORD_ONLY,WRTC_PY_PARAM_VAR_KEYWORD}"
        "WrtcPyParameterKind;\n"
        "typedef struct{const char*name;WrtcPyParameterKind kind;"
        "const char*default_expression;unsigned has_default:1;}"
        "WrtcBoxedParameterSpec;\n"
        "typedef struct{const char*name;const WrtcBoxedParameterSpec*parameters;"
        "size_t parameter_count;PyObject**defaults;}WrtcBoxedSignature;\n"
        "typedef PyObject*(*WrtcBoxedNativeEvaluate)(void*,"
        "const WrtcPyExprIR*,void*,int*);"
        "typedef int(*WrtcBoxedNativeAssign)(void*,const WrtcPyExprIR*,"
        "PyObject*,void*,int*);"
        "typedef struct{void*context;WrtcBoxedNativeEvaluate evaluate;"
        "WrtcBoxedNativeAssign assign;}WrtcBoxedNativeHooks;\n"
        "int wrtc_boxed_execute_with_hooks(const WrtcPySuiteIR*,PyObject*,"
        "PyObject*,const WrtcBoxedNativeHooks*,PyObject**);"
        "PyObject*wrtc_boxed_hook_evaluate(const WrtcPyExprIR*,void*);"
        "PyObject*wrtc_boxed_hook_local(const char*,void*);"
        "void wrtc_boxed_signature_clear(WrtcBoxedSignature*signature);\n";
    if (output == NULL || implementation == NULL ||
        fputs(declarations, output) < 0 ||
        fputs(signatures, output) < 0)
        return -1;
    return fwrite(implementation, 1u, strlen(implementation), output) ==
                   strlen(implementation)
               ? 0 : -1;
}
