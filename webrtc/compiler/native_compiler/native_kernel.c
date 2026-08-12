#include "native_kernel.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **names;
    char **types;
    size_t count;
    const WrtcNativeClassProgram *program;
    const WrtcNativeClassIR *class_ir;
    const WrtcNativeRegionIR *region;
    size_t statements;
    size_t calls;
    const char *reason;
    WrtcSourceSpan span;
} Proof;

static char *duplicate_text(const char *text) {
    const size_t length = text == NULL ? 0u : strlen(text);
    char *copy = malloc(length + 1u);
    if (copy != NULL) memcpy(copy, text == NULL ? "" : text, length + 1u);
    return copy;
}

static const char *final_name(const char *text) {
    const char *end, *start;
    static char name[256];
    size_t length;
    if (text == NULL) return NULL;
    end = text + strlen(text);
    while (end > text && !isalnum((unsigned char)end[-1]) && end[-1] != '_')
        end--;
    start = end;
    while (start > text &&
           (isalnum((unsigned char)start[-1]) || start[-1] == '_'))
        start--;
    length = (size_t)(end - start);
    if (length == 0u || length >= sizeof name) return NULL;
    memcpy(name, start, length);
    name[length] = '\0';
    return name;
}

static const WrtcTypedRecordIR *record_type(
    const WrtcNativeClassProgram *program, const char *annotation) {
    const char *name = final_name(annotation);
    size_t index;
    if (name == NULL) return NULL;
    for (index = 0u; index < program->record_count; index++)
        if (strcmp(program->records[index].name, name) == 0)
            return &program->records[index];
    return NULL;
}

static int scalar_type(const char *annotation, unsigned *width,
                       int *wrapping) {
    const char *marker, *digits;
    unsigned value = 0u;
    if (annotation == NULL) return 0;
    if (strcmp(annotation, "bool") == 0) {
        *width = 1u;
        *wrapping = 0;
        return 1;
    }
    marker = strstr(annotation, "uint[");
    if (marker == NULL) return 0;
    digits = marker + 5;
    while (isdigit((unsigned char)*digits)) {
        value = value * 10u + (unsigned)(*digits - '0');
        digits++;
    }
    if (*digits != ']' ||
        (value != 8u && value != 16u && value != 32u && value != 64u))
        return 0;
    *width = value;
    *wrapping = strstr(annotation, "wrap") != NULL;
    return 1;
}

static const char *uint_annotation(unsigned width) {
    switch (width) {
        case 8u: return "Annotated[int, uint[8]]";
        case 16u: return "Annotated[int, uint[16]]";
        case 32u: return "Annotated[int, uint[32]]";
        case 64u: return "Annotated[int, uint[64]]";
        default: return NULL;
    }
}

static const char *lookup_type(const Proof *proof, const char *name) {
    size_t index;
    for (index = 0u; index < proof->count; index++)
        if (strcmp(proof->names[index], name) == 0)
            return proof->types[index];
    return NULL;
}

static int add_name(Proof *proof, const char *name, const char *type) {
    char **names, **types;
    if (lookup_type(proof, name) != NULL) return 0;
    if (proof->count == SIZE_MAX / sizeof(*names)) return -1;
    names = realloc(proof->names, (proof->count + 1u) * sizeof(*names));
    if (names == NULL) return -1;
    proof->names = names;
    types = realloc(proof->types, (proof->count + 1u) * sizeof(*types));
    if (types == NULL) return -1;
    proof->types = types;
    proof->names[proof->count] = duplicate_text(name);
    proof->types[proof->count] = duplicate_text(type);
    if (proof->names[proof->count] == NULL ||
        proof->types[proof->count] == NULL)
        return -1;
    proof->count++;
    return 0;
}

static int reject(Proof *proof, const WrtcSourceSpan span,
                  const char *reason) {
    if (proof->reason == NULL) {
        proof->reason = reason;
        proof->span = span;
    }
    return 0;
}

static const WrtcNativeRegionIR *callee_region(
    const Proof *proof, const WrtcPyExprIR *call) {
    size_t index;
    if (call->child_count == 0u ||
        call->children[0].kind != WRTC_PY_EXPR_ATTRIBUTE ||
        call->children[0].child_count != 1u ||
        call->children[0].children[0].kind != WRTC_PY_EXPR_NAME ||
        strcmp(call->children[0].children[0].operation, "self") != 0)
        return NULL;
    for (index = 0u; index < proof->class_ir->region_count; index++)
        if (strcmp(proof->class_ir->regions[index].name,
                   call->children[0].operation) == 0 &&
            proof->class_ir->regions[index].policy == WRTC_REGION_REQUIRED)
            return &proof->class_ir->regions[index];
    return NULL;
}

static const WrtcTypedRecordIR *constructor_record(
    const Proof *proof, const WrtcPyExprIR *call) {
    if (call->child_count == 0u ||
        call->children[0].kind != WRTC_PY_EXPR_NAME)
        return NULL;
    return record_type(proof->program, call->children[0].operation);
}

static const char *prove_expression(Proof *proof,
                                    const WrtcPyExprIR *expression);

static const char *prove_call(Proof *proof,
                              const WrtcPyExprIR *expression) {
    const WrtcNativeRegionIR *callee = callee_region(proof, expression);
    const WrtcTypedRecordIR *constructor =
        constructor_record(proof, expression);
    const char *type;
    size_t index;
    if (constructor != NULL) {
        if (!constructor->worker_abi_eligible ||
            expression->keyword_count != 0u ||
            expression->child_count != constructor->field_count + 1u) {
            reject(proof, expression->span,
                   "kernel record constructor does not match its native ABI");
            return NULL;
        }
        for (index = 0u; index < constructor->field_count; index++) {
            const WrtcWorkerRecordFieldIR *field =
                &constructor->fields[index];
            unsigned expression_width;
            int expression_wrapping;
            type = prove_expression(
                proof, &expression->children[index + 1u]);
            if (field->kind != WRTC_WORKER_FIELD_UINT || type == NULL ||
                !scalar_type(type, &expression_width,
                             &expression_wrapping)) {
                reject(proof, expression->children[index + 1u].span,
                       "kernel result record requires native scalar fields");
                return NULL;
            }
        }
        proof->calls++;
        return constructor->name;
    }
    if (callee == NULL) {
        reject(proof, expression->span,
               "kernel call is not an exact required native-region call");
        return NULL;
    }
    if (expression->keyword_count != 0u) {
        reject(proof, expression->span,
               "kernel calls do not accept keyword arguments");
        return NULL;
    }
    for (index = 1u; index < expression->child_count; index++)
        if ((type = prove_expression(proof, &expression->children[index])) == NULL)
            return NULL;
    proof->calls++;
    return callee->result_type;
}

static const char *prove_expression(Proof *proof,
                                    const WrtcPyExprIR *expression) {
    unsigned width;
    int wrapping;
    size_t index;
    const char *type;
    switch (expression->kind) {
        case WRTC_PY_EXPR_NAME:
            type = lookup_type(proof, expression->operation);
            if (type == NULL)
                reject(proof, expression->span,
                       "kernel name has no proven native representation");
            return type;
        case WRTC_PY_EXPR_CONSTANT:
            if (strcmp(expression->operation, "int") == 0)
                return "Annotated[int, uint[64]]";
            if (strcmp(expression->operation, "bool") == 0)
                return "bool";
            reject(proof, expression->span,
                   "kernel constant is not a supported native scalar");
            return NULL;
        case WRTC_PY_EXPR_ATTRIBUTE: {
            const WrtcTypedRecordIR *record;
            if (expression->child_count != 1u ||
                expression->children[0].kind != WRTC_PY_EXPR_NAME) {
                reject(proof, expression->span,
                       "dynamic or chained kernel attribute lookup is unsupported");
                return NULL;
            }
            type = lookup_type(proof, expression->children[0].operation);
            record = record_type(proof->program, type);
            if (record == NULL || !record->worker_abi_eligible) {
                reject(proof, expression->span,
                       "kernel attribute receiver is not a proven native record");
                return NULL;
            }
            for (index = 0u; index < record->field_count; index++)
                if (strcmp(record->fields[index].name,
                           expression->operation) == 0 &&
                    record->fields[index].kind == WRTC_WORKER_FIELD_UINT)
                    return uint_annotation(record->fields[index].width);
            reject(proof, expression->span,
                   "kernel record field is boxed or absent");
            return NULL;
        }
        case WRTC_PY_EXPR_BINARY:
            if (expression->child_count != 2u ||
                prove_expression(proof, &expression->children[0]) == NULL ||
                prove_expression(proof, &expression->children[1]) == NULL)
                return NULL;
            if (strcmp(expression->operation, "Add") != 0 &&
                strcmp(expression->operation, "Sub") != 0 &&
                strcmp(expression->operation, "Mult") != 0 &&
                strcmp(expression->operation, "FloorDiv") != 0 &&
                strcmp(expression->operation, "Mod") != 0) {
                reject(proof, expression->span,
                       "kernel binary operation has no portable lowering");
                return NULL;
            }
            return prove_expression(proof, &expression->children[0]);
        case WRTC_PY_EXPR_COMPARE:
            if (expression->operation_count == 0u) return NULL;
            for (index = 0u; index < expression->operation_count; index++)
                if (strcmp(expression->operations[index], "Eq") != 0 &&
                    strcmp(expression->operations[index], "NotEq") != 0 &&
                    strcmp(expression->operations[index], "Lt") != 0 &&
                    strcmp(expression->operations[index], "LtE") != 0 &&
                    strcmp(expression->operations[index], "Gt") != 0 &&
                    strcmp(expression->operations[index], "GtE") != 0) {
                    reject(proof, expression->span,
                           "kernel comparison has no scalar lowering");
                    return NULL;
                }
            for (index = 0u; index < expression->child_count; index++)
                if (prove_expression(proof, &expression->children[index]) == NULL)
                    return NULL;
            return "bool";
        case WRTC_PY_EXPR_BOOLEAN:
            if (strcmp(expression->operation, "And") != 0 &&
                strcmp(expression->operation, "Or") != 0) return NULL;
            for (index = 0u; index < expression->child_count; index++)
                if (prove_expression(proof, &expression->children[index]) == NULL)
                    return NULL;
            return "bool";
        case WRTC_PY_EXPR_UNARY:
            type = expression->child_count == 1u
                       ? prove_expression(proof, &expression->children[0])
                       : NULL;
            if (type == NULL) return NULL;
            if (strcmp(expression->operation, "Not") == 0) return "bool";
            if (strcmp(expression->operation, "UAdd") == 0 &&
                scalar_type(type, &width, &wrapping)) return type;
            reject(proof, expression->span,
                   "kernel unary operation has no unsigned lowering");
            return NULL;
        case WRTC_PY_EXPR_CALL:
            return prove_call(proof, expression);
        default:
            reject(proof, expression->span,
                   "kernel expression requires Python objects or allocation");
            return NULL;
    }
}

static int prove_statements(Proof *proof, const WrtcPyStmtIR *statements,
                            size_t count) {
    size_t index;
    for (index = 0u; index < count && proof->reason == NULL; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        const char *type;
        proof->statements++;
        switch (statement->kind) {
            case WRTC_PY_STMT_ASSIGN:
                if (statement->expression_count != 2u ||
                    statement->expressions[1].kind != WRTC_PY_EXPR_NAME ||
                    (type = prove_expression(
                         proof, &statement->expressions[0])) == NULL ||
                    add_name(proof, statement->expressions[1].operation,
                             type) < 0)
                    reject(proof, statement->span,
                           "kernel assignment target or representation is unsupported");
                break;
            case WRTC_PY_STMT_AUGMENTED_ASSIGN:
                if (statement->expression_count != 2u ||
                    statement->expressions[0].kind != WRTC_PY_EXPR_NAME ||
                    lookup_type(proof, statement->expressions[0].operation) == NULL ||
                    prove_expression(proof, &statement->expressions[1]) == NULL)
                    reject(proof, statement->span,
                           "kernel augmented assignment is unsupported");
                break;
            case WRTC_PY_STMT_IF:
                if (prove_expression(proof, &statement->expressions[0]) == NULL ||
                    !prove_statements(proof, statement->body,
                                      statement->body_count) ||
                    !prove_statements(proof, statement->orelse,
                                      statement->orelse_count)) return 0;
                break;
            case WRTC_PY_STMT_FOR:
            {
                size_t argument;
                if (!statement->iterator_is_range ||
                    statement->expression_count != 2u ||
                    statement->expressions[0].kind != WRTC_PY_EXPR_NAME ||
                    statement->expressions[1].kind != WRTC_PY_EXPR_CALL ||
                    statement->expressions[1].child_count < 2u ||
                    statement->expressions[1].children[0].kind != WRTC_PY_EXPR_NAME ||
                    strcmp(statement->expressions[1].children[0].operation,
                           "range") != 0) {
                    reject(proof, statement->span,
                           "kernel loops require an explicit range iterator");
                    break;
                }
                if (add_name(proof, statement->expressions[0].operation,
                             "Annotated[int, uint[64]]") < 0)
                    return 0;
                for (argument = 1u;
                     argument < statement->expressions[1].child_count;
                     argument++)
                    if (prove_expression(
                            proof, &statement->expressions[1]
                                        .children[argument]) == NULL)
                        return 0;
                proof->calls++;
                if (!prove_statements(proof, statement->body,
                                      statement->body_count) ||
                    !prove_statements(proof, statement->orelse,
                                      statement->orelse_count)) return 0;
                break;
            }
            case WRTC_PY_STMT_RETURN:
                if (statement->expression_count > 1u)
                    return 0;
                if (statement->expression_count == 1u) {
                    const char *returned = prove_expression(
                        proof, &statement->expressions[0]);
                    const WrtcTypedRecordIR *wanted =
                        record_type(proof->program,
                                    proof->region->result_type);
                    if (returned == NULL) return 0;
                    if (wanted != NULL &&
                        (statement->expressions[0].kind != WRTC_PY_EXPR_CALL ||
                         (constructor_record(
                              proof, &statement->expressions[0]) != wanted &&
                          (callee_region(
                               proof, &statement->expressions[0]) == NULL ||
                           record_type(
                               proof->program,
                               callee_region(
                                   proof, &statement->expressions[0])
                                   ->result_type) != wanted)))) {
                        reject(proof, statement->span,
                               "kernel record result must be constructed directly");
                        return 0;
                    }
                }
                break;
            case WRTC_PY_STMT_BREAK:
            case WRTC_PY_STMT_CONTINUE:
            case WRTC_PY_STMT_PASS:
                break;
            default:
                reject(proof, statement->span,
                       "kernel statement requires Python allocation, exception, or dynamic execution");
                break;
        }
    }
    return proof->reason == NULL;
}

static void clear_proof(Proof *proof) {
    size_t index;
    for (index = 0u; index < proof->count; index++) {
        free(proof->names[index]);
        free(proof->types[index]);
    }
    free(proof->names);
    free(proof->types);
}

void wrtc_native_kernel_prove(WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    if (program == NULL) return;
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        WrtcNativeClassIR *class_ir = &program->classes[class_index];
        for (region_index = 0u; region_index < class_ir->region_count;
             region_index++) {
            WrtcNativeRegionIR *region = &class_ir->regions[region_index];
            Proof proof = {0};
            size_t parameter;
            proof.program = program;
            proof.class_ir = class_ir;
            proof.region = region;
            free(region->kernel_rejection_reason);
            region->kernel_rejection_reason = NULL;
            region->kernel_statement_count = 0u;
            region->kernel_emitted_statement_count = 0u;
            region->kernel_call_count = region->call_count;
            region->kernel_emitted_call_count = 0u;
            region->kernel_emission_complete = 0u;
            region->kernel_python_free = 0u;
            if (region->policy != WRTC_REGION_REQUIRED ||
                region->body == NULL || region->signature == NULL) continue;
            {
                unsigned result_width;
                int result_wrapping;
                if (!scalar_type(region->result_type, &result_width,
                                 &result_wrapping) &&
                    record_type(program, region->result_type) == NULL) {
                    region->kernel_rejection_reason = duplicate_text(
                        "kernel result has no supported native scalar representation");
                    region->kernel_rejection_span = region->span;
                    continue;
                }
            }
            if (add_name(&proof, "self", class_ir->name) < 0) {
                proof.reason = "kernel proof workspace allocation failed";
                proof.span = region->span;
            }
            for (parameter = 0u; proof.reason == NULL &&
                 parameter < region->signature->parameter_count; parameter++) {
                const WrtcPyParameterIR *item =
                    &region->signature->parameters[parameter];
                unsigned width;
                int wrapping;
                if (strcmp(item->name, "self") == 0) continue;
                if (!scalar_type(item->annotation, &width, &wrapping) &&
                    record_type(program, item->annotation) == NULL) {
                    reject(&proof, item->span,
                           "kernel parameter has no supported native representation");
                    break;
                }
                if (add_name(&proof, item->name, item->annotation) < 0) {
                    reject(&proof, item->span,
                           "kernel proof workspace allocation failed");
                    break;
                }
            }
            if (proof.reason == NULL)
                (void)prove_statements(&proof, region->body->statements,
                                       region->body->statement_count);
            region->kernel_statement_count = proof.statements;
            region->kernel_emitted_statement_count =
                proof.reason == NULL ? proof.statements : 0u;
            region->kernel_emitted_call_count =
                proof.reason == NULL ? proof.calls : 0u;
            region->kernel_emission_complete = proof.reason == NULL;
            region->kernel_python_free = region->kernel_emission_complete;
            region->kernel_rejection_span =
                proof.reason == NULL ? region->span : proof.span;
            if (proof.reason != NULL)
                region->kernel_rejection_reason = duplicate_text(proof.reason);
            clear_proof(&proof);
        }
    }
    /* A body containing an exact native call is emitted only when its callee
     * also has a body.  Iterate to a fixed point; mutually recursive regions
     * that were locally proven remain accepted together. */
    for (;;) {
        int changed = 0;
        for (class_index = 0u; class_index < program->class_count; class_index++) {
            WrtcNativeClassIR *class_ir = &program->classes[class_index];
            for (region_index = 0u; region_index < class_ir->region_count;
                 region_index++) {
                WrtcNativeRegionIR *region = &class_ir->regions[region_index];
                size_t call;
                if (!region->kernel_emission_complete) continue;
                for (call = 0u; call < region->call_count; call++) {
                    WrtcNativeCallEdgeIR *edge = &region->calls[call];
                    if (edge->target != NULL &&
                        strcmp(edge->target, "range") == 0) continue;
                    if (edge->resolved &&
                        !program->classes[edge->target_class]
                             .regions[edge->target_region]
                             .kernel_emission_complete) {
                        region->kernel_emission_complete = 0u;
                        region->kernel_python_free = 0u;
                        region->kernel_emitted_statement_count = 0u;
                        region->kernel_emitted_call_count = 0u;
                        free(region->kernel_rejection_reason);
                        region->kernel_rejection_reason = duplicate_text(
                            "exact native callee has no complete kernel emission");
                        region->kernel_rejection_span = edge->span;
                        changed = 1;
                        break;
                    }
                }
            }
        }
        if (!changed) break;
    }
}

static int emit_expression(FILE *file, Proof *proof,
                           const WrtcPyExprIR *expression,
                           const char *prefix);

static size_t region_number(const WrtcNativeClassIR *class_ir,
                            const WrtcNativeRegionIR *region) {
    return (size_t)(region - class_ir->regions);
}

static int emit_expression(FILE *file, Proof *proof,
                           const WrtcPyExprIR *expression,
                           const char *prefix) {
    size_t index;
    const char *type;
    unsigned width = 64u;
    int wrapping = 0;
    if (expression->kind == WRTC_PY_EXPR_NAME)
        return fprintf(file, "v_%s", expression->operation) < 0 ? -1 : 0;
    if (expression->kind == WRTC_PY_EXPR_CONSTANT)
        return fputs(expression->text, file) < 0 ? -1 : 0;
    if (expression->kind == WRTC_PY_EXPR_ATTRIBUTE) {
        if (expression->child_count != 1u) return -1;
        return fprintf(file, "v_%s_%s",
                       expression->children[0].operation,
                       expression->operation) < 0 ? -1 : 0;
    }
    if (expression->kind == WRTC_PY_EXPR_BINARY) {
        static const struct { const char *python; const char *c; } names[] = {
            {"Add", "nk_add"}, {"Sub", "nk_sub"},
            {"Mult", "nk_mul"}, {"FloorDiv", "nk_div"},
            {"Mod", "nk_mod"}
        };
        const char *helper = NULL;
        type = prove_expression(proof, &expression->children[0]);
        (void)scalar_type(type, &width, &wrapping);
        for (index = 0u; index < sizeof names / sizeof names[0]; index++)
            if (strcmp(names[index].python, expression->operation) == 0)
                helper = names[index].c;
        if (helper == NULL || fprintf(file, "%s(", helper) < 0 ||
            emit_expression(file, proof, &expression->children[0], prefix) < 0 ||
            fputc(',', file) == EOF ||
            emit_expression(file, proof, &expression->children[1], prefix) < 0 ||
            fprintf(file, ",%u,%d,status)", width, wrapping) < 0) return -1;
        return 0;
    }
    if (expression->kind == WRTC_PY_EXPR_COMPARE) {
        static const struct { const char *python; const char *c; } names[] = {
            {"Eq", "=="}, {"NotEq", "!="}, {"Lt", "<"},
            {"LtE", "<="}, {"Gt", ">"}, {"GtE", ">="}
        };
        if (fputc('(', file) == EOF) return -1;
        for (index = 0u; index < expression->operation_count; index++) {
            size_t name;
            const char *token = NULL;
            if (index != 0u && fputs("&&", file) < 0) return -1;
            if (fputc('(', file) == EOF ||
                emit_expression(file, proof, &expression->children[index], prefix) < 0)
                return -1;
            for (name = 0u; name < sizeof names / sizeof names[0]; name++)
                if (strcmp(names[name].python,
                           expression->operations[index]) == 0)
                    token = names[name].c;
            if (token == NULL || fputs(token, file) < 0 ||
                emit_expression(file, proof, &expression->children[index + 1u],
                                prefix) < 0 || fputc(')', file) == EOF)
                return -1;
        }
        return fputc(')', file) == EOF ? -1 : 0;
    }
    if (expression->kind == WRTC_PY_EXPR_BOOLEAN) {
        const char *token = strcmp(expression->operation, "And") == 0
                                ? "&&" : "||";
        if (fputc('(', file) == EOF) return -1;
        for (index = 0u; index < expression->child_count; index++) {
            if (index != 0u && fputs(token, file) < 0) return -1;
            if (emit_expression(file, proof, &expression->children[index], prefix) < 0)
                return -1;
        }
        return fputc(')', file) == EOF ? -1 : 0;
    }
    if (expression->kind == WRTC_PY_EXPR_UNARY) {
        if (fputs(strcmp(expression->operation, "Not") == 0 ? "(!" : "(+",
                  file) < 0 ||
            emit_expression(file, proof, &expression->children[0], prefix) < 0)
            return -1;
        return fputc(')', file) == EOF ? -1 : 0;
    }
    if (expression->kind == WRTC_PY_EXPR_CALL) {
        const WrtcNativeRegionIR *callee = callee_region(proof, expression);
        const WrtcTypedRecordIR *callee_result;
        if (callee == NULL ||
            fprintf(file, "%s_%zu_%zu(", prefix,
                    (size_t)(proof->class_ir - proof->program->classes),
                    region_number(proof->class_ir, callee)) < 0)
            return -1;
        for (index = 1u; index < expression->child_count; index++) {
            const char *argument_type = prove_expression(
                proof, &expression->children[index]);
            const WrtcTypedRecordIR *argument_record =
                record_type(proof->program, argument_type);
            if (index != 1u && fputc(',', file) == EOF) return -1;
            if (argument_record != NULL &&
                expression->children[index].kind == WRTC_PY_EXPR_NAME) {
                size_t field;
                for (field = 0u; field < argument_record->field_count; field++) {
                    const WrtcWorkerRecordFieldIR *item =
                        &argument_record->fields[field];
                    if (field != 0u && fputc(',', file) == EOF) return -1;
                    if (item->kind == WRTC_WORKER_FIELD_READONLY_BUFFER) {
                        if (fprintf(file, "v_%s_%s_data,v_%s_%s_size",
                                    expression->children[index].operation,
                                    item->name,
                                    expression->children[index].operation,
                                    item->name) < 0) return -1;
                    } else if (fprintf(file, "v_%s_%s",
                                       expression->children[index].operation,
                                       item->name) < 0) return -1;
                }
            } else if (emit_expression(file, proof,
                                       &expression->children[index],
                                       prefix) < 0)
                return -1;
        }
        if (expression->child_count > 1u && fputc(',', file) == EOF)
            return -1;
        callee_result = record_type(proof->program, callee->result_type);
        if (callee_result != NULL) {
            for (index = 0u; index < callee_result->field_count; index++)
                if (fprintf(file, "out_%zu,", index) < 0) return -1;
        }
        return fputs("status)", file) < 0 ? -1 : 0;
    }
    return -1;
}

static int emit_statements(FILE *file, Proof *proof,
                           const WrtcPyStmtIR *statements, size_t count,
                           const char *prefix) {
    size_t index;
    for (index = 0u; index < count; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        switch (statement->kind) {
            case WRTC_PY_STMT_ASSIGN:
                if (fprintf(file, "v_%s=",
                            statement->expressions[1].operation) < 0 ||
                    emit_expression(file, proof, &statement->expressions[0],
                                    prefix) < 0 ||
                    fputs(";if(*status)return 0;\n", file) < 0) return -1;
                break;
            case WRTC_PY_STMT_AUGMENTED_ASSIGN: {
                WrtcPyExprIR binary = {0};
                binary.kind = WRTC_PY_EXPR_BINARY;
                binary.operation = statement->operation;
                binary.children = statement->expressions;
                binary.child_count = 2u;
                if (fprintf(file, "v_%s=",
                            statement->expressions[0].operation) < 0 ||
                    emit_expression(file, proof, &binary, prefix) < 0 ||
                    fputs(";if(*status)return 0;\n", file) < 0) return -1;
                break;
            }
            case WRTC_PY_STMT_IF:
                if (fputs("if(", file) < 0 ||
                    emit_expression(file, proof, &statement->expressions[0],
                                    prefix) < 0 || fputs("){\n", file) < 0 ||
                    emit_statements(file, proof, statement->body,
                                    statement->body_count, prefix) < 0 ||
                    fputs("}else{\n", file) < 0 ||
                    emit_statements(file, proof, statement->orelse,
                                    statement->orelse_count, prefix) < 0 ||
                    fputs("}\n", file) < 0) return -1;
                break;
            case WRTC_PY_STMT_FOR: {
                const WrtcPyExprIR *call = &statement->expressions[1];
                const WrtcPyExprIR *start = call->child_count == 2u
                                                ? NULL : &call->children[1];
                const WrtcPyExprIR *stop = call->child_count == 2u
                                               ? &call->children[1]
                                               : &call->children[2];
                if (call->child_count < 2u || call->child_count > 3u ||
                    fprintf(file, "for(v_%s=",
                            statement->expressions[0].operation) < 0)
                    return -1;
                if (start == NULL) {
                    if (fputc('0', file) == EOF) return -1;
                } else if (emit_expression(file, proof, start, prefix) < 0)
                    return -1;
                if (fprintf(file, ";v_%s<",
                            statement->expressions[0].operation) < 0 ||
                    emit_expression(file, proof, stop, prefix) < 0 ||
                    fprintf(file, ";v_%s++){\n",
                            statement->expressions[0].operation) < 0 ||
                    emit_statements(file, proof, statement->body,
                                    statement->body_count, prefix) < 0 ||
                    fputs("}\n", file) < 0) return -1;
                break;
            }
            case WRTC_PY_STMT_RETURN:
                if (statement->expression_count == 0u)
                    return fputs("return 0;\n", file) < 0 ? -1 : 0;
                {
                    const WrtcTypedRecordIR *record = record_type(
                        proof->program, proof->region->result_type);
                    if (record != NULL) {
                        const WrtcPyExprIR *call = &statement->expressions[0];
                        size_t field;
                        const WrtcTypedRecordIR *constructor =
                            constructor_record(proof, call);
                        if (call->kind != WRTC_PY_EXPR_CALL)
                            return -1;
                        if (constructor == NULL) {
                            if (fputs("return ", file) < 0 ||
                                emit_expression(file, proof, call, prefix) < 0 ||
                                fputs(";\n", file) < 0) return -1;
                            break;
                        }
                        if (call->child_count != record->field_count + 1u)
                            return -1;
                        for (field = 0u; field < record->field_count; field++) {
                            if (fprintf(file, "*out_%zu=nk_cast(", field) < 0 ||
                                emit_expression(file, proof,
                                                &call->children[field + 1u],
                                                prefix) < 0 ||
                                fprintf(file, ",%u,status);"
                                              "if(*status)return *status;\n",
                                        record->fields[field].width) < 0)
                                return -1;
                        }
                        return fputs("return *status;\n", file) < 0 ? -1 : 0;
                    }
                }
                if (fputs("return ", file) < 0 ||
                    emit_expression(file, proof, &statement->expressions[0],
                                    prefix) < 0 ||
                    fputs(";\n", file) < 0) return -1;
                break;
            case WRTC_PY_STMT_BREAK:
                if (fputs("break;\n", file) < 0) return -1;
                break;
            case WRTC_PY_STMT_CONTINUE:
                if (fputs("continue;\n", file) < 0) return -1;
                break;
            case WRTC_PY_STMT_PASS:
                if (fputs(";\n", file) < 0) return -1;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

static int emit_parameters(FILE *file, Proof *proof,
                           const WrtcPySignatureIR *signature) {
    size_t parameter;
    int first = 1;
    for (parameter = 0u; parameter < signature->parameter_count; parameter++) {
        const WrtcPyParameterIR *item = &signature->parameters[parameter];
        const WrtcTypedRecordIR *record;
        size_t field;
        if (strcmp(item->name, "self") == 0) continue;
        record = record_type(proof->program, item->annotation);
        if (record == NULL) {
            if (!first && fputc(',', file) == EOF) return -1;
            if (fprintf(file, "uint64_t v_%s", item->name) < 0) return -1;
            first = 0;
            continue;
        }
        for (field = 0u; field < record->field_count; field++) {
            if (!first && fputc(',', file) == EOF) return -1;
            if (record->fields[field].kind == WRTC_WORKER_FIELD_UINT) {
                if (fprintf(file, "uint64_t v_%s_%s", item->name,
                            record->fields[field].name) < 0) return -1;
            } else if (record->fields[field].kind == WRTC_WORKER_FIELD_SINT) {
                if (fprintf(file, "int64_t v_%s_%s", item->name,
                            record->fields[field].name) < 0) return -1;
            } else if (record->fields[field].kind == WRTC_WORKER_FIELD_FLOAT) {
                if (fprintf(file, "double v_%s_%s", item->name,
                            record->fields[field].name) < 0) return -1;
            } else if (record->fields[field].kind ==
                       WRTC_WORKER_FIELD_READONLY_BUFFER) {
                if (fprintf(file,
                            "const unsigned char*v_%s_%s_data,size_t v_%s_%s_size",
                            item->name, record->fields[field].name,
                            item->name, record->fields[field].name) < 0)
                    return -1;
            } else return -1;
            first = 0;
        }
    }
    {
        const WrtcTypedRecordIR *result = record_type(
            proof->program, proof->region->result_type);
        size_t field;
        if (result != NULL)
            for (field = 0u; field < result->field_count; field++) {
                const char *ctype =
                    result->fields[field].kind == WRTC_WORKER_FIELD_SINT
                        ? "int64_t"
                        : result->fields[field].kind == WRTC_WORKER_FIELD_FLOAT
                              ? "double" : "uint64_t";
                if (!first && fputc(',', file) == EOF) return -1;
                if (fprintf(file, "%s*out_%zu", ctype, field) < 0)
                    return -1;
                first = 0;
            }
    }
    if (!first && fputc(',', file) == EOF) return -1;
    return fputs("int*status", file) < 0 ? -1 : 0;
}

static const WrtcTypedRecordIR *worker_input_record(
    const WrtcNativeClassProgram *program,
    const WrtcNativeRegionIR *region) {
    size_t parameter;
    if (region->signature == NULL) return NULL;
    for (parameter = 0u; parameter < region->signature->parameter_count;
         parameter++) {
        const WrtcPyParameterIR *item =
            &region->signature->parameters[parameter];
        if (strcmp(item->name, "self") != 0)
            return record_type(program, item->annotation);
    }
    return NULL;
}

static int emit_worker_adapter(
    FILE *file, const WrtcNativeClassProgram *program,
    const WrtcNativeClassIR *class_ir, const WrtcNativeRegionIR *region,
    size_t class_index, size_t region_index, const char *prefix) {
    const WrtcTypedRecordIR *input = worker_input_record(program, region);
    const WrtcTypedRecordIR *output = record_type(program, region->result_type);
    size_t field;
    if ((region->capabilities & WRTC_REGION_OWNED_SHARD) == 0u ||
        !region->worker_emission_complete || input == NULL || output == NULL)
        return 0;
    (void)class_ir;
    if (fprintf(file,
                "int %s_worker_%zu_%zu(const WrtcNativeWorkerRecord*input,"
                "WrtcNativeWorkerRecord*output,WrtcNativeWorkerError*error,"
                "void*context){int status=0;(void)context;"
                "if(!input||!output||!error||input->value_count!=%zu||"
                "output->value_count!=%zu)return NK_INVALID_ARGUMENT;"
                "status=%s_%zu_%zu(",
                prefix, class_index, region_index, input->field_count,
                output->field_count, prefix, class_index, region_index) < 0)
        return -1;
    for (field = 0u; field < input->field_count; field++) {
        const WrtcWorkerRecordFieldIR *item = &input->fields[field];
        if (field != 0u && fputc(',', file) == EOF) return -1;
        if (item->kind == WRTC_WORKER_FIELD_UINT) {
            if (fprintf(file, "input->values[%zu].as.uint_value", field) < 0)
                return -1;
        } else if (item->kind == WRTC_WORKER_FIELD_SINT) {
            if (fprintf(file, "input->values[%zu].as.sint_value", field) < 0)
                return -1;
        } else if (item->kind == WRTC_WORKER_FIELD_FLOAT) {
            if (fprintf(file, "input->values[%zu].as.float_value", field) < 0)
                return -1;
        } else if (item->kind == WRTC_WORKER_FIELD_READONLY_BUFFER) {
            if (fprintf(file,
                        "input->values[%zu].as.bytes_value.data,"
                        "input->values[%zu].as.bytes_value.size",
                        field, field) < 0)
                return -1;
        } else return -1;
    }
    if (input->field_count != 0u && fputc(',', file) == EOF) return -1;
    for (field = 0u; field < output->field_count; field++) {
        const char *member =
            output->fields[field].kind == WRTC_WORKER_FIELD_SINT
                ? "sint_value"
                : output->fields[field].kind == WRTC_WORKER_FIELD_FLOAT
                      ? "float_value" : "uint_value";
        if (fprintf(file, "&output->values[%zu].as.%s,", field, member) < 0)
            return -1;
    }
    return fprintf(file,
                   "&status);if(status){error->code=WRTC_WORKER_ERROR_PROCESSOR;"
                   "error->processor_status=status;}return status;}\n") < 0
               ? -1 : 0;
}

int wrtc_native_kernel_emit(FILE *file,
                            const WrtcNativeClassProgram *program,
                            const char *symbol_prefix) {
    size_t class_index, region_index;
    if (file == NULL || program == NULL || symbol_prefix == NULL) return -1;
    if (fputs("#include <stddef.h>\n#include <stdint.h>\n#include <limits.h>\n"
              "#ifndef WRTC_NATIVE_WORKER_EMBEDDED\n"
              "#include \"native_worker_executor.h\"\n#endif\n"
              "enum{NK_OK=0,NK_OVERFLOW=1,NK_DIVZERO=2,"
              "NK_INVALID_ARGUMENT=3};\n"
              "uint64_t nk_max(unsigned w){return w==64?UINT64_MAX:"
              "((UINT64_C(1)<<w)-1);}\n"
              "uint64_t nk_add(uint64_t a,uint64_t b,unsigned w,int z,int*s){"
              "uint64_t m=nk_max(w);if(z)return(a+b)&m;if(a>m-b){*s=1;return 0;}return a+b;}\n"
              "uint64_t nk_sub(uint64_t a,uint64_t b,unsigned w,int z,int*s){"
              "uint64_t m=nk_max(w);if(z)return(a-b)&m;if(a<b){*s=1;return 0;}return a-b;}\n"
              "uint64_t nk_mul(uint64_t a,uint64_t b,unsigned w,int z,int*s){"
              "uint64_t m=nk_max(w);if(z)return(a*b)&m;if(b&&a>m/b){*s=1;return 0;}return a*b;}\n"
              "uint64_t nk_div(uint64_t a,uint64_t b,unsigned w,int z,int*s){"
              "(void)w;(void)z;if(!b){*s=2;return 0;}return a/b;}\n"
              "uint64_t nk_mod(uint64_t a,uint64_t b,unsigned w,int z,int*s){"
              "(void)w;(void)z;if(!b){*s=2;return 0;}return a%b;}\n"
              "uint64_t nk_cast(uint64_t a,unsigned w,int*s){uint64_t m=nk_max(w);"
              "if(a>m){*s=1;return 0;}return a;}\n",
              file) < 0) return -1;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++) {
            const WrtcNativeClassIR *class_ir = &program->classes[class_index];
            const WrtcNativeRegionIR *region = &class_ir->regions[region_index];
            Proof proof = {0};
            const WrtcTypedRecordIR *result;
            if (!region->kernel_emission_complete) continue;
            proof.program = program;
            proof.class_ir = class_ir;
            proof.region = region;
            result = record_type(program, region->result_type);
            if (fprintf(file, "%s %s_%zu_%zu(",
                        result == NULL ? "uint64_t" : "int", symbol_prefix,
                        class_index, region_index) < 0 ||
                emit_parameters(file, &proof, region->signature) < 0 ||
                fputs(");\n", file) < 0) return -1;
        }
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++) {
            const WrtcNativeClassIR *class_ir = &program->classes[class_index];
            const WrtcNativeRegionIR *region = &class_ir->regions[region_index];
            Proof proof = {0};
            size_t parameter;
            const WrtcTypedRecordIR *result;
            if (!region->kernel_emission_complete) continue;
            proof.program = program;
            proof.class_ir = class_ir;
            proof.region = region;
            result = record_type(program, region->result_type);
            (void)add_name(&proof, "self", class_ir->name);
            for (parameter = 0u; parameter < region->signature->parameter_count;
                 parameter++) {
                const WrtcPyParameterIR *item =
                    &region->signature->parameters[parameter];
                if (strcmp(item->name, "self") != 0)
                    (void)add_name(&proof, item->name, item->annotation);
            }
            if (fprintf(file, "%s %s_%zu_%zu(",
                        result == NULL ? "uint64_t" : "int", symbol_prefix,
                        class_index, region_index) < 0 ||
                emit_parameters(file, &proof, region->signature) < 0 ||
                fputs("){if(*status)return 0;\n", file) < 0) {
                clear_proof(&proof);
                return -1;
            }
            for (parameter = 0u;
                 parameter < region->signature->parameter_count; parameter++) {
                const WrtcPyParameterIR *item =
                    &region->signature->parameters[parameter];
                const WrtcTypedRecordIR *record;
                size_t field;
                if (strcmp(item->name, "self") == 0) continue;
                record = record_type(program, item->annotation);
                if (record == NULL) {
                    if (fprintf(file, "(void)v_%s;\n", item->name) < 0) {
                        clear_proof(&proof);
                        return -1;
                    }
                    continue;
                }
                for (field = 0u; field < record->field_count; field++) {
                    const WrtcWorkerRecordFieldIR *record_field =
                        &record->fields[field];
                    if (record_field->kind == WRTC_WORKER_FIELD_READONLY_BUFFER) {
                        if (fprintf(file, "(void)v_%s_%s_data;"
                                          "(void)v_%s_%s_size;\n",
                                    item->name, record_field->name,
                                    item->name, record_field->name) < 0) {
                            clear_proof(&proof);
                            return -1;
                        }
                    } else if (fprintf(file, "(void)v_%s_%s;\n",
                                       item->name,
                                       record_field->name) < 0) {
                        clear_proof(&proof);
                        return -1;
                    }
                }
            }
            for (parameter = 0u; parameter < region->body->local_count;
                 parameter++)
                if (fprintf(file, "uint64_t v_%s=0;\n",
                            region->body->local_names[parameter]) < 0) {
                    clear_proof(&proof);
                    return -1;
                }
            if (
                emit_statements(file, &proof, region->body->statements,
                                region->body->statement_count,
                                symbol_prefix) < 0 ||
                fputs("return 0;}\n", file) < 0) {
                clear_proof(&proof);
                return -1;
            }
            clear_proof(&proof);
        }
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (emit_worker_adapter(
                    file, program, &program->classes[class_index],
                    &program->classes[class_index].regions[region_index],
                    class_index, region_index, symbol_prefix) < 0)
                return -1;
    return ferror(file) ? -1 : 0;
}
