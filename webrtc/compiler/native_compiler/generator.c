#include "generator.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int quoted(FILE *file, const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    if (fputc('"', file) == EOF) return -1;
    for (; *p != 0u; p++) {
        if (*p == '\\' || *p == '"') { if (fputc('\\', file) == EOF) return -1; }
        if (*p == '\n') { if (fputs("\\n", file) < 0) return -1; }
        else if (*p == '\r') { if (fputs("\\r", file) < 0) return -1; }
        else if (*p < 32u || *p > 126u) {
            if (fprintf(file, "\\%03o", (unsigned)*p) < 0) return -1;
        } else if (fputc((int)*p, file) == EOF) return -1;
    }
    return fputc('"', file) == EOF ? -1 : 0;
}

static int string_or_null(FILE *file, const char *value) {
    return value == NULL ? (fputs("NULL", file) < 0 ? -1 : 0) : quoted(file, value);
}

static const char *binary_token(const char *name) {
    if (name == NULL) return NULL;
    if (strcmp(name, "Add") == 0) return "NV_OP_ADD";
    if (strcmp(name, "Sub") == 0) return "NV_OP_SUB";
    if (strcmp(name, "Mult") == 0) return "NV_OP_MULT";
    if (strcmp(name, "FloorDiv") == 0) return "NV_OP_FLOOR_DIV";
    if (strcmp(name, "Mod") == 0) return "NV_OP_MOD";
    if (strcmp(name, "LShift") == 0) return "NV_OP_LSHIFT";
    if (strcmp(name, "RShift") == 0) return "NV_OP_RSHIFT";
    if (strcmp(name, "BitAnd") == 0) return "NV_OP_BIT_AND";
    if (strcmp(name, "BitOr") == 0) return "NV_OP_BIT_OR";
    if (strcmp(name, "And") == 0) return "NV_OP_AND";
    if (strcmp(name, "Or") == 0) return "NV_OP_OR";
    return NULL;
}

static const char *unary_token(const char *name) {
    if (name == NULL) return NULL;
    if (strcmp(name, "Not") == 0) return "NV_OP_NOT";
    if (strcmp(name, "Invert") == 0) return "NV_OP_INVERT";
    if (strcmp(name, "USub") == 0) return "NV_OP_USUB";
    return NULL;
}

static const char *compare_token(const char *name) {
    if (name == NULL) return NULL;
    if (strcmp(name, "In") == 0) return "NV_OP_IN";
    if (strcmp(name, "NotIn") == 0) return "NV_OP_NOT_IN";
    if (strcmp(name, "Is") == 0) return "NV_OP_IS";
    if (strcmp(name, "IsNot") == 0) return "NV_OP_IS_NOT";
    if (strcmp(name, "Eq") == 0) return "NV_OP_EQ";
    if (strcmp(name, "NotEq") == 0) return "NV_OP_NOT_EQ";
    if (strcmp(name, "Lt") == 0) return "NV_OP_LT";
    if (strcmp(name, "LtE") == 0) return "NV_OP_LTE";
    if (strcmp(name, "Gt") == 0) return "NV_OP_GT";
    if (strcmp(name, "GtE") == 0) return "NV_OP_GTE";
    return NULL;
}

static const WrtcLoweringOp *child(const WrtcLoweredFunction *function,
                                   const WrtcLoweringOp *operation,
                                   const char *role, size_t ordinal) {
    size_t i, seen = 0u;
    for (i = 0u; i < operation->operand_count; i++) {
        const WrtcLoweringOp *candidate =
            &function->operations[operation->operands[i]];
        if (candidate->role != NULL && strcmp(candidate->role, role) == 0) {
            if (seen++ == ordinal) return candidate;
        }
    }
    return NULL;
}

static size_t op_index(const WrtcLoweredFunction *function,
                       const WrtcLoweringOp *operation) {
    return (size_t)(operation - function->operations);
}

static int emit_expression(FILE *file, const WrtcLoweringProgram *program,
                           const WrtcLoweredFunction *function,
                           const WrtcLoweringOp *operation);

static int emit_arguments(FILE *file, const WrtcLoweringProgram *program,
                          const WrtcLoweredFunction *function,
                          const WrtcLoweringOp *operation) {
    size_t i, count = 0u;
    if (fputs("(Nv[]){", file) < 0) return -1;
    for (i = 0u; i < operation->operand_count; i++) {
        const WrtcLoweringOp *argument =
            &function->operations[operation->operands[i]];
        if (argument->role == NULL || strcmp(argument->role, "args") != 0)
            continue;
        if (count++ != 0u && fputc(',', file) == EOF) return -1;
        if (emit_expression(file, program, function, argument) < 0) return -1;
    }
    return fputs("}", file) < 0 ? -1 : 0;
}

static int emit_constant(FILE *file, const WrtcLoweringOp *operation) {
    const char *literal = operation->literal;
    if (literal == NULL || strcmp(literal, "None") == 0)
        return fputs("nv_none()", file) < 0 ? -1 : 0;
    if (strcmp(literal, "True") == 0)
        return fputs("nv_int(1u)", file) < 0 ? -1 : 0;
    if (strcmp(literal, "False") == 0)
        return fputs("nv_int(0u)", file) < 0 ? -1 : 0;
    if (operation->type == WRTC_TYPE_INT)
        return fprintf(file, "nv_int((uint64_t)(%s))", literal) < 0 ? -1 : 0;
    if (operation->type == WRTC_TYPE_STR) {
        size_t n = strlen(literal);
        if (n >= 2u && (literal[0] == '\'' || literal[0] == '"') &&
            literal[n - 1u] == literal[0]) {
            size_t i;
            if (fputs("nv_str(\"", file) < 0) return -1;
            for (i = 1u; i + 1u < n; i++) {
                unsigned char c = (unsigned char)literal[i];
                if (c == '"' || c == '\\') {
                    if (fputc('\\', file) == EOF) return -1;
                }
                if (fputc((int)c, file) == EOF) return -1;
            }
            return fputs("\")", file) < 0 ? -1 : 0;
        }
    }
    if (operation->type == WRTC_TYPE_BYTES && literal[0] == 'b') {
        size_t n = strlen(literal);
        if (n >= 3u && (literal[1] == '\'' || literal[1] == '"')) {
            size_t i;
            if (fputs("nv_literal(\"", file) < 0) return -1;
            for (i = 2u; i + 1u < n; i++)
                if (fputc((unsigned char)literal[i], file) == EOF) return -1;
            if (fputs("\",sizeof(\"", file) < 0) return -1;
            for (i = 2u; i + 1u < n; i++)
                if (fputc((unsigned char)literal[i], file) == EOF) return -1;
            if (fputs("\")-1u)", file) < 0) return -1;
            return 0;
        }
    }
    return fputs("nv_fail(\"unsupported native literal\")", file) < 0 ? -1 : 0;
}

static const char *binary_operator(const WrtcLoweredFunction *function,
                                   const WrtcLoweringOp *operation) {
    size_t i;
    for (i = 0u; i < operation->operand_count; i++) {
        const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
        if (item->role != NULL && strcmp(item->role, "op") == 0)
            return item->syntax_kind;
    }
    return NULL;
}

static int emit_expression(FILE *file, const WrtcLoweringProgram *program,
                           const WrtcLoweredFunction *function,
                           const WrtcLoweringOp *operation) {
    const WrtcLoweringOp *left, *right, *argument, *value;
    const char *operator_name;
    size_t i;
    if (strcmp(operation->syntax_kind, "Name") == 0 && operation->symbol != NULL)
    {
        for (i = 0u; i < program->constant_count; i++) {
            const WrtcLoweredConstant *constant = &program->constants[i];
            if (strcmp(constant->name, operation->symbol) != 0) continue;
            if (constant->type == WRTC_TYPE_INT)
                return fprintf(file, "nv_int((uint64_t)(%s))", constant->literal) < 0 ? -1 : 0;
            if (constant->type == WRTC_TYPE_TUPLE) {
                if (fputs("nv_ints(", file) < 0 ||
                    quoted(file, constant->literal) < 0 ||
                    fputc(')', file) == EOF) return -1;
                return 0;
            }
        }
        if (strcmp(operation->symbol, "bytes") == 0)
            return fputs("nv_type(NV_BYTES)", file) < 0 ? -1 : 0;
        if (strcmp(operation->symbol, "int") == 0)
            return fputs("nv_type(NV_INT)", file) < 0 ? -1 : 0;
        return fprintf(file, "v_%s", operation->symbol) < 0 ? -1 : 0;
    }
    if (strcmp(operation->syntax_kind, "Constant") == 0)
        return emit_constant(file, operation);
    if (operation->kind == WRTC_LOWER_OP_DIRECT_CALL) {
        if (operation->target_function >= program->function_count)
            return fputs("nv_fail(\"unresolved native call\")", file) < 0 ? -1 : 0;
        if (fprintf(file, "nh_%zu(", operation->target_function) < 0 ||
            emit_arguments(file, program, function, operation) < 0 ||
            fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_RECORD_CONSTRUCT) {
        const WrtcLoweredRecord *record;
        size_t positional_count = 0u, field;
        if (operation->record_index >= program->record_count)
            return fputs("nv_fail(\"invalid native record type\")", file) < 0 ? -1 : 0;
        record = &program->records[operation->record_index];
        for (i = 0u; i < operation->operand_count; i++) {
            const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
            if (item->role != NULL && strcmp(item->role, "args") == 0)
                positional_count++;
        }
        if (fputs("nv_tuple((Nv[]){", file) < 0) return -1;
        for (field = 0u; field < record->field_count; field++) {
            const WrtcLoweringOp *field_value = field < positional_count ?
                child(function, operation, "args", field) : NULL;
            size_t operand;
            if (field != 0u && fputc(',', file) == EOF) return -1;
            for (operand = 0u; field_value == NULL &&
                 operand < operation->operand_count; operand++) {
                const WrtcLoweringOp *keyword =
                    &function->operations[operation->operands[operand]];
                if (keyword->role != NULL && strcmp(keyword->role, "keywords") == 0 &&
                    keyword->symbol != NULL &&
                    strcmp(keyword->symbol, record->fields[field].name) == 0)
                    field_value = child(function, keyword, "value", 0u);
            }
            if (field_value != NULL) {
                if (emit_expression(file, program, function, field_value) < 0) return -1;
            } else if (record->fields[field].has_default &&
                       record->fields[field].default_literal != NULL) {
                if (fprintf(file, "nv_int((uint64_t)(%s))",
                            record->fields[field].default_literal) < 0) return -1;
            } else if (fputs("nv_int(0u)", file) < 0) return -1;
        }
        return fprintf(file, "},%zuu)", record->field_count) < 0 ? -1 : 0;
    }
    if (operation->kind == WRTC_LOWER_OP_COLLECTION_POP) {
        const WrtcLoweringOp *callable = child(function, operation, "func", 0u);
        const WrtcLoweringOp *receiver = callable == NULL ? NULL :
                                          child(function, callable, "value", 0u);
        if (receiver == NULL || receiver->symbol == NULL)
            return fputs("nv_fail(\"pop receiver is not native local\")", file) < 0 ? -1 : 0;
        return fprintf(file, "nv_pop(&v_%s)", receiver->symbol) < 0 ? -1 : 0;
    }
    if (operation->kind == WRTC_LOWER_OP_ENDIAN_WRITE) {
        const WrtcLoweringOp *callable = child(function, operation, "func", 0u);
        const WrtcLoweringOp *receiver = callable == NULL ? NULL :
                                          child(function, callable, "value", 0u);
        const WrtcLoweringOp *length = child(function, operation, "args", 0u);
        if (receiver == NULL || length == NULL) return fputs("nv_fail(\"incomplete endian write\")", file) < 0 ? -1 : 0;
        if (fputs("nv_to_bytes(", file) < 0 ||
            emit_expression(file, program, function, receiver) < 0 ||
            fputc(',', file) == EOF ||
            emit_expression(file, program, function, length) < 0 ||
            fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_ANY_GENERATOR &&
        operation->symbol != NULL && strcmp(operation->symbol, "any") == 0) {
        const WrtcLoweringOp *generator = child(function, operation, "args", 0u);
        const WrtcLoweringOp *element = generator == NULL ? NULL :
                                          child(function, generator, "elt", 0u);
        const WrtcLoweringOp *comprehension = generator == NULL ? NULL :
                                                child(function, generator, "generators", 0u);
        const WrtcLoweringOp *iterator = comprehension == NULL ? NULL :
                                          child(function, comprehension, "iter", 0u);
        const WrtcLoweringOp *attribute = element == NULL ? NULL :
                                           child(function, element, "left", 0u);
        const WrtcLoweringOp *expected = element == NULL ? NULL :
                                          child(function, element, "comparators", 0u);
        size_t field, record_index = attribute == NULL ? SIZE_MAX :
                                     attribute->record_index;
        if (record_index >= program->record_count && iterator != NULL)
            record_index = iterator->element_record_index;
        if (attribute != NULL && record_index < program->record_count) {
            const WrtcLoweredRecord *record = &program->records[record_index];
            for (field = 0u; field < record->field_count; field++)
                if (attribute->symbol != NULL &&
                    strcmp(record->fields[field].name, attribute->symbol) == 0) break;
            if (field < record->field_count && iterator != NULL && expected != NULL) {
                if (fputs("nv_any_field_eq(", file) < 0 ||
                    emit_expression(file, program, function, iterator) < 0 ||
                    fprintf(file, ",%zuu,", field) < 0 ||
                    emit_expression(file, program, function, expected) < 0 ||
                    fputc(')', file) == EOF) return -1;
                return 0;
            }
        }
        return fputs("nv_fail(\"unsupported native any generator\")", file) < 0 ? -1 : 0;
    }
    if (operation->kind == WRTC_LOWER_OP_BINARY) {
        left = child(function, operation, "left", 0u);
        right = child(function, operation, "right", 0u);
        if (left == NULL) left = child(function, operation, "values", 0u);
        if (right == NULL) right = child(function, operation, "values", 1u);
        operator_name = binary_operator(function, operation);
        if (left == NULL || right == NULL || binary_token(operator_name) == NULL)
            return fputs("nv_fail(\"incomplete native binary\")", file) < 0 ? -1 : 0;
        if (fputs("nv_binary_checked(", file) < 0 ||
            emit_expression(file, program, function, left) < 0 || fputc(',', file) == EOF ||
            emit_expression(file, program, function, right) < 0 || fputc(',', file) == EOF ||
            fputs(binary_token(operator_name), file) < 0 || fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_COMPARE) {
        const WrtcLoweringOp *comparator = child(function, operation, "comparators", 0u);
        const WrtcLoweringOp *operator_node = child(function, operation, "ops", 0u);
        left = child(function, operation, "left", 0u);
        if (left == NULL || comparator == NULL || operator_node == NULL ||
            compare_token(operator_node->syntax_kind) == NULL)
            return fputs("nv_fail(\"incomplete native compare\")", file) < 0 ? -1 : 0;
        if (fputs("nv_compare(", file) < 0 ||
            emit_expression(file, program, function, left) < 0 || fputc(',', file) == EOF ||
            emit_expression(file, program, function, comparator) < 0 || fputc(',', file) == EOF ||
            fputs(compare_token(operator_node->syntax_kind), file) < 0 ||
            fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_BRANCH &&
        strcmp(operation->syntax_kind, "IfExp") == 0) {
        const WrtcLoweringOp *test = child(function, operation, "test", 0u);
        const WrtcLoweringOp *body = child(function, operation, "body", 0u);
        const WrtcLoweringOp *alternative = child(function, operation, "orelse", 0u);
        if (test == NULL || body == NULL || alternative == NULL ||
            fputs("(nv_truth(", file) < 0 ||
            emit_expression(file, program, function, test) < 0 ||
            fputs(")?", file) < 0 ||
            emit_expression(file, program, function, body) < 0 ||
            fputc(':', file) == EOF ||
            emit_expression(file, program, function, alternative) < 0 ||
            fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_UNARY) {
        argument = child(function, operation, "operand", 0u);
        operator_name = NULL;
        for (i = 0u; i < operation->operand_count; i++) {
            const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
            if (item->role != NULL && strcmp(item->role, "op") == 0)
                operator_name = item->syntax_kind;
        }
        if (argument == NULL || unary_token(operator_name) == NULL) return fputs("nv_fail(\"incomplete native unary\")", file) < 0 ? -1 : 0;
        if (fputs("nv_unary(", file) < 0 || emit_expression(file, program, function, argument) < 0 || fputc(',', file) == EOF || fputs(unary_token(operator_name), file) < 0 || fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_SUBSCRIPT) {
        const WrtcLoweringOp *container = child(function, operation, "value", 0u);
        const WrtcLoweringOp *slice = child(function, operation, "slice", 0u);
        if (container == NULL || slice == NULL) return fputs("nv_fail(\"incomplete native subscript\")", file) < 0 ? -1 : 0;
        if (strcmp(slice->syntax_kind, "Slice") == 0) {
            const WrtcLoweringOp *lower = child(function, slice, "lower", 0u);
            const WrtcLoweringOp *upper = child(function, slice, "upper", 0u);
            if (fputs("nv_slice(", file) < 0 || emit_expression(file, program, function, container) < 0 || fputc(',', file) == EOF) return -1;
            if (lower == NULL) { if (fputs("nv_none()", file) < 0) return -1; }
            else if (emit_expression(file, program, function, lower) < 0) return -1;
            if (fputc(',', file) == EOF) return -1;
            if (upper == NULL) { if (fputs("nv_none()", file) < 0) return -1; }
            else if (emit_expression(file, program, function, upper) < 0) return -1;
            return fputc(')', file) == EOF ? -1 : 0;
        }
        if (fputs("nv_get(", file) < 0 || emit_expression(file, program, function, container) < 0 || fputc(',', file) == EOF || emit_expression(file, program, function, slice) < 0 || fputc(')', file) == EOF) return -1;
        return 0;
    }
    if (operation->kind == WRTC_LOWER_OP_ATTRIBUTE &&
        operation->record_index < program->record_count &&
        operation->symbol != NULL) {
        const WrtcLoweredRecord *record = &program->records[operation->record_index];
        const WrtcLoweringOp *receiver = child(function, operation, "value", 0u);
        size_t field;
        for (field = 0u; field < record->field_count; field++)
            if (strcmp(record->fields[field].name, operation->symbol) == 0) break;
        if (receiver != NULL && field < record->field_count) {
            if (fputs("nv_get(", file) < 0 ||
                emit_expression(file, program, function, receiver) < 0 ||
                fprintf(file, ",nv_int(%zuu))", field) < 0) return -1;
            return 0;
        }
        if (receiver != NULL) {
            size_t property;
            for (property = 0u; property < record->property_count; property++)
                if (strcmp(record->properties[property].name,
                           operation->symbol) == 0) break;
            if (property < record->property_count) {
                if (fprintf(file, "np_%zu_%zu((Nv[]){",
                            operation->record_index, property) < 0 ||
                    emit_expression(file, program, function, receiver) < 0 ||
                    fputs("})", file) < 0) return -1;
                return 0;
            }
        }
    }
    if (operation->kind == WRTC_LOWER_OP_BUILTIN_CALL && operation->symbol != NULL) {
        argument = child(function, operation, "args", 0u);
        if (strcmp(operation->symbol, "len") == 0 && argument != NULL) {
            if (fputs("nv_len(", file) < 0 || emit_expression(file, program, function, argument) < 0 || fputc(')', file) == EOF) return -1;
            return 0;
        }
        if (strcmp(operation->symbol, "bool") == 0 && argument != NULL) {
            if (fputs("nv_bool(", file) < 0 || emit_expression(file, program, function, argument) < 0 || fputc(')', file) == EOF) return -1;
            return 0;
        }
        if (strcmp(operation->symbol, "type") == 0 && argument != NULL) {
            if (fputs("nv_typeof(", file) < 0 || emit_expression(file, program, function, argument) < 0 || fputc(')', file) == EOF) return -1;
            return 0;
        }
        if (strcmp(operation->symbol, "enumerate") == 0 && argument != NULL) {
            if (fputs("nv_enumerate(", file) < 0 || emit_expression(file, program, function, argument) < 0 || fputc(')', file) == EOF) return -1;
            return 0;
        }
        if (strcmp(operation->symbol, "range") == 0) {
            size_t count = 0u;
            for (i = 0u; i < operation->operand_count; i++) {
                const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
                if (item->role != NULL && strcmp(item->role, "args") == 0) count++;
            }
            if (fputs("nv_range(", file) < 0 ||
                emit_arguments(file, program, function, operation) < 0 ||
                fprintf(file, ",%zuu)", count) < 0) return -1;
            return 0;
        }
        if ((strcmp(operation->symbol, "min") == 0 ||
             strcmp(operation->symbol, "max") == 0) &&
            child(function, operation, "args", 1u) != NULL) {
            const WrtcLoweringOp *second = child(function, operation, "args", 1u);
            if (fputs(strcmp(operation->symbol, "min") == 0 ?
                      "nv_min(" : "nv_max(", file) < 0 ||
                emit_expression(file, program, function, argument) < 0 ||
                fputc(',', file) == EOF ||
                emit_expression(file, program, function, second) < 0 ||
                fputc(')', file) == EOF) return -1;
            return 0;
        }
        if ((strcmp(operation->symbol, "ValueError") == 0 ||
             strcmp(operation->symbol, "TypeError") == 0) && argument != NULL) {
            if (fputs("nv_raise(", file) < 0 ||
                fputs(strcmp(operation->symbol, "ValueError") == 0 ?
                      "PyExc_ValueError," : "PyExc_TypeError,", file) < 0 ||
                emit_expression(file, program, function, argument) < 0 ||
                fputc(')', file) == EOF) return -1;
            return 0;
        }
    }
    if (strcmp(operation->syntax_kind, "FormattedValue") == 0) {
        value = child(function, operation, "value", 0u);
        return value == NULL ? (fputs("nv_str(\"\")", file) < 0 ? -1 : 0) :
               emit_expression(file, program, function, value);
    }
    if (strcmp(operation->syntax_kind, "JoinedStr") == 0) {
        size_t count = 0u;
        if (fputs("nv_format((Nv[]){", file) < 0) return -1;
        for (i = 0u; i < operation->operand_count; i++) {
            const WrtcLoweringOp *part =
                &function->operations[operation->operands[i]];
            if (part->role == NULL || strcmp(part->role, "values") != 0) continue;
            if (count++ != 0u && fputc(',', file) == EOF) return -1;
            if (emit_expression(file, program, function, part) < 0) return -1;
        }
        return fprintf(file, "},%zuu)", count) < 0 ? -1 : 0;
    }
    if (operation->kind == WRTC_LOWER_OP_ALLOCATE && operation->symbol != NULL &&
        strcmp(operation->symbol, "bytes") == 0) {
        argument = child(function, operation, "args", 0u);
        if (argument != NULL && strcmp(argument->syntax_kind, "List") == 0) {
            const WrtcLoweringOp *element = child(function, argument, "elts", 0u);
            if (element != NULL && child(function, argument, "elts", 1u) == NULL) {
                if (fputs("nv_byte(", file) < 0 ||
                    emit_expression(file, program, function, element) < 0 ||
                    fputc(')', file) == EOF) return -1;
                return 0;
            }
        }
        if (argument != NULL) {
            if (fputs("nv_bytes(", file) < 0 ||
                emit_expression(file, program, function, argument) < 0 ||
                fputc(')', file) == EOF) return -1;
            return 0;
        }
    }
    if (operation->kind == WRTC_LOWER_OP_ALLOCATE && operation->symbol != NULL &&
        strcmp(operation->symbol, "bytearray") == 0) {
        argument = child(function, operation, "args", 0u);
        if (fputs("nv_bytearray(", file) < 0) return -1;
        if (argument == NULL) {
            if (fputs("nv_none()", file) < 0) return -1;
        } else if (emit_expression(file, program, function, argument) < 0) return -1;
        return fputc(')', file) == EOF ? -1 : 0;
    }
    if (operation->kind == WRTC_LOWER_OP_ALLOCATE && operation->symbol != NULL &&
        (strcmp(operation->symbol, "memoryview") == 0 ||
         strcmp(operation->symbol, "tuple") == 0 ||
         strcmp(operation->symbol, "list") == 0)) {
        argument = child(function, operation, "args", 0u);
        if (argument == NULL) return fputs("nv_tuple(NULL,0u)", file) < 0 ? -1 : 0;
        return emit_expression(file, program, function, argument);
    }
    if (strcmp(operation->syntax_kind, "Tuple") == 0 ||
        strcmp(operation->syntax_kind, "List") == 0) {
        size_t count = 0u;
        for (i = 0u; i < operation->operand_count; i++) {
            const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
            if (item->role != NULL && strcmp(item->role, "elts") == 0) count++;
        }
        if (fprintf(file, "nv_tuple((Nv[]){") < 0) return -1;
        count = 0u;
        for (i = 0u; i < operation->operand_count; i++) {
            const WrtcLoweringOp *item = &function->operations[operation->operands[i]];
            if (item->role == NULL || strcmp(item->role, "elts") != 0) continue;
            if (count++ != 0u && fputc(',', file) == EOF) return -1;
            if (emit_expression(file, program, function, item) < 0) return -1;
        }
        return fprintf(file, "},%zuu)", count) < 0 ? -1 : 0;
    }
    (void)file;
    (void)op_index(function, operation);
    return -1;
}

static int emit_statement(FILE *file, const WrtcLoweringProgram *program,
                          const WrtcLoweredFunction *function,
                          const WrtcLoweringOp *statement) {
    const WrtcLoweringOp *value, *target;
    size_t i;
    if (statement->kind == WRTC_LOWER_OP_RETURN) {
        value = child(function, statement, "value", 0u);
        if (fputs("return ", file) < 0 ||
            (value == NULL && function->parameter_count != 0u &&
             function->parameters[0].boxed_type == WRTC_TYPE_BYTE_VECTOR ?
             (fprintf(file, "v_%s", function->parameters[0].name) < 0 ? -1 : 0) :
             value == NULL ? (fputs("nv_none()", file) < 0 ? -1 : 0) :
             emit_expression(file, program, function, value)) < 0 ||
            fputs(";\n", file) < 0) return -1;
        return 0;
    }
    if (statement->kind == WRTC_LOWER_OP_ASSIGN) {
        value = child(function, statement, "value", 0u);
        target = child(function, statement, "targets", 0u);
        if (target == NULL) target = child(function, statement, "target", 0u);
        if (value != NULL && target != NULL && target->symbol != NULL &&
            strcmp(target->syntax_kind, "Name") == 0) {
            const char *augmented = strcmp(statement->syntax_kind, "AugAssign") == 0 ?
                                    binary_operator(function, statement) : NULL;
            if (fprintf(file, "v_%s=", target->symbol) < 0) return -1;
            if (augmented != NULL) {
                if (binary_token(augmented) == NULL ||
                    fprintf(file, "nv_binary(v_%s,", target->symbol) < 0 ||
                    emit_expression(file, program, function, value) < 0 ||
                    fputc(',', file) == EOF || fputs(binary_token(augmented), file) < 0 ||
                    fputc(')', file) == EOF) return -1;
            } else if (emit_expression(file, program, function, value) < 0) return -1;
            if (fputs(";if(v_", file) < 0 || fputs(target->symbol, file) < 0 ||
                fputs(".kind==NV_ERROR)return v_", file) < 0 ||
                fputs(target->symbol, file) < 0 || fputs(";\n", file) < 0) return -1;
        } else if (value != NULL && target != NULL &&
                   target->kind == WRTC_LOWER_OP_SUBSCRIPT) {
            const WrtcLoweringOp *receiver = child(function, target, "value", 0u);
            const WrtcLoweringOp *slice = child(function, target, "slice", 0u);
            if (receiver == NULL || receiver->symbol == NULL || slice == NULL)
                return fputs("return nv_fail(\"unsupported native subscript assignment\");\n", file) < 0 ? -1 : 0;
            if (strcmp(slice->syntax_kind, "Slice") == 0) {
                const WrtcLoweringOp *lower = child(function, slice, "lower", 0u);
                const WrtcLoweringOp *upper = child(function, slice, "upper", 0u);
                if (fprintf(file, "if(nv_store_slice(&v_%s,", receiver->symbol) < 0) return -1;
                if (lower == NULL) { if (fputs("nv_none()", file) < 0) return -1; }
                else if (emit_expression(file, program, function, lower) < 0) return -1;
                if (fputc(',', file) == EOF) return -1;
                if (upper == NULL) { if (fputs("nv_none()", file) < 0) return -1; }
                else if (emit_expression(file, program, function, upper) < 0) return -1;
                if (fputc(',', file) == EOF ||
                    emit_expression(file, program, function, value) < 0 ||
                    fputs(")<0)return nv_error();\n", file) < 0) return -1;
            } else if (fprintf(file, "if(nv_store(&v_%s,", receiver->symbol) < 0 ||
                       emit_expression(file, program, function, slice) < 0 ||
                       fputc(',', file) == EOF ||
                       emit_expression(file, program, function, value) < 0 ||
                       fputs(")<0)return nv_error();\n", file) < 0) return -1;
        } else if (value != NULL && target != NULL &&
                   target->kind == WRTC_LOWER_OP_ATTRIBUTE &&
                   target->record_index < program->record_count &&
                   target->symbol != NULL) {
            const WrtcLoweredRecord *record =
                &program->records[target->record_index];
            const WrtcLoweringOp *receiver = child(function, target, "value", 0u);
            size_t field;
            for (field = 0u; field < record->field_count; field++)
                if (strcmp(record->fields[field].name, target->symbol) == 0) break;
            {
                const char *augmented =
                    strcmp(statement->syntax_kind, "AugAssign") == 0 ?
                    binary_operator(function, statement) : NULL;
            if (receiver == NULL || receiver->symbol == NULL ||
                field == record->field_count ||
                fprintf(file, "if(nv_set(&v_%s,%zuu,",
                        receiver == NULL || receiver->symbol == NULL ?
                        "invalid" : receiver->symbol, field) < 0 ||
                (augmented != NULL &&
                 (fputs("nv_binary(nv_get(v_", file) < 0 ||
                  fputs(receiver->symbol, file) < 0 ||
                  fprintf(file, ",nv_int(%zuu)),", field) < 0)) ||
                emit_expression(file, program, function, value) < 0) return -1;
            if (augmented != NULL &&
                (binary_token(augmented) == NULL || fputc(',', file) == EOF ||
                 fputs(binary_token(augmented), file) < 0 ||
                 fputc(')', file) == EOF)) return -1;
            if (fputs(")<0)return nv_error();\n", file) < 0) return -1;
            }
        } else if (value != NULL && target != NULL &&
                   strcmp(target->syntax_kind, "Tuple") == 0) {
            size_t id = op_index(function, statement), target_number = 0u;
            if (fprintf(file, "{Nv unpack_%zu=", id) < 0 ||
                emit_expression(file, program, function, value) < 0 ||
                fprintf(file, ";if(unpack_%zu.kind==NV_ERROR)return unpack_%zu;if(unpack_%zu.kind!=NV_TUPLE)return nv_fail(\"unpack requires native tuple\");",
                        id, id, id) < 0) return -1;
            for (i = 0u; i < target->operand_count; i++) {
                const WrtcLoweringOp *part =
                    &function->operations[target->operands[i]];
                if (part->role == NULL || strcmp(part->role, "elts") != 0 ||
                    part->symbol == NULL) continue;
                if (fprintf(file, "if(unpack_%zu.tuple.n<=%zuu)return nv_fail(\"not enough values to unpack\");v_%s=unpack_%zu.tuple.v[%zuu];",
                            id, target_number, part->symbol, id,
                            target_number) < 0) return -1;
                target_number++;
            }
            if (fputs("}\n", file) < 0) return -1;
        } else if (fputs("return nv_fail(\"unsupported native assignment\");\n", file) < 0) return -1;
        return 0;
    }
    if (statement->kind == WRTC_LOWER_OP_BRANCH &&
        strcmp(statement->syntax_kind, "If") == 0) {
        const WrtcLoweringOp *test = child(function, statement, "test", 0u);
        if (test == NULL || fputs("if(nv_truth(", file) < 0 ||
            emit_expression(file, program, function, test) < 0 ||
            fputs(")){\n", file) < 0) return -1;
        for (i = 0u; i < statement->operand_count; i++) {
            const WrtcLoweringOp *nested = &function->operations[statement->operands[i]];
            if (nested->role != NULL && strcmp(nested->role, "body") == 0 &&
                emit_statement(file, program, function, nested) < 0) return -1;
        }
        if (fputs("}else{\n", file) < 0) return -1;
        for (i = 0u; i < statement->operand_count; i++) {
            const WrtcLoweringOp *nested = &function->operations[statement->operands[i]];
            if (nested->role != NULL && strcmp(nested->role, "orelse") == 0 &&
                emit_statement(file, program, function, nested) < 0) return -1;
        }
        return fputs("}\n", file) < 0 ? -1 : 0;
    }
    if (statement->kind == WRTC_LOWER_OP_FOR) {
        const WrtcLoweringOp *iterator = child(function, statement, "iter", 0u);
        const WrtcLoweringOp *loop_target = child(function, statement, "target", 0u);
        size_t id = op_index(function, statement);
        if (iterator != NULL && loop_target != NULL &&
            iterator->kind == WRTC_LOWER_OP_BUILTIN_CALL &&
            iterator->symbol != NULL && strcmp(iterator->symbol, "range") == 0 &&
            loop_target->symbol != NULL) {
            const WrtcLoweringOp *first = child(function, iterator, "args", 0u);
            const WrtcLoweringOp *second = child(function, iterator, "args", 1u);
            const WrtcLoweringOp *third = child(function, iterator, "args", 2u);
            if (first == NULL || fprintf(file, "{uint64_t rs_%zu=", id) < 0)
                return -1;
            if (second == NULL) {
                if (fputs("0u, re_", file) < 0 || fprintf(file, "%zu=", id) < 0 ||
                    emit_expression(file, program, function, first) < 0)
                    return -1;
            } else {
                if (emit_expression(file, program, function, first) < 0 ||
                    fprintf(file, ".i,re_%zu=", id) < 0 ||
                    emit_expression(file, program, function, second) < 0)
                    return -1;
            }
            if (fprintf(file, ".i,rp_%zu=", id) < 0) return -1;
            if (third == NULL) {
                if (fputs("1u", file) < 0) return -1;
            } else if (emit_expression(file, program, function, third) < 0 ||
                       fputs(".i", file) < 0) return -1;
            if (fprintf(file, ",ri_%zu;for(ri_%zu=rs_%zu;ri_%zu<re_%zu;ri_%zu+=rp_%zu){v_%s=nv_int(ri_%zu);",
                        id, id, id, id, id, id, id, loop_target->symbol, id) < 0)
                return -1;
            for (i = 0u; i < statement->operand_count; i++) {
                const WrtcLoweringOp *nested =
                    &function->operations[statement->operands[i]];
                if (nested->role != NULL && strcmp(nested->role, "body") == 0 &&
                    emit_statement(file, program, function, nested) < 0) return -1;
            }
            return fputs("}}\n", file) < 0 ? -1 : 0;
        }
        if (iterator != NULL && loop_target != NULL &&
            iterator->kind == WRTC_LOWER_OP_BUILTIN_CALL &&
            iterator->symbol != NULL && strcmp(iterator->symbol, "enumerate") == 0 &&
            strcmp(loop_target->syntax_kind, "Tuple") == 0) {
            const WrtcLoweringOp *source = child(function, iterator, "args", 0u);
            size_t target_number = 0u;
            if (source == NULL || fprintf(file, "{Nv it_%zu=", id) < 0 ||
                emit_expression(file, program, function, source) < 0 ||
                fprintf(file, ";size_t li_%zu;if(it_%zu.kind!=NV_TUPLE)return nv_fail(\"enumerate requires native container\");for(li_%zu=0;li_%zu<it_%zu.tuple.n;li_%zu++){",
                        id, id, id, id, id, id) < 0) return -1;
            for (i = 0u; i < loop_target->operand_count; i++) {
                const WrtcLoweringOp *part =
                    &function->operations[loop_target->operands[i]];
                if (part->role == NULL || strcmp(part->role, "elts") != 0 ||
                    part->symbol == NULL) continue;
                if (fprintf(file, target_number == 0u ?
                            "v_%s=nv_int(li_%zu);" :
                            "v_%s=it_%zu.tuple.v[li_%zu];",
                            part->symbol, id, id) < 0) return -1;
                target_number++;
            }
            for (i = 0u; i < statement->operand_count; i++) {
                const WrtcLoweringOp *nested =
                    &function->operations[statement->operands[i]];
                if (nested->role != NULL && strcmp(nested->role, "body") == 0 &&
                    emit_statement(file, program, function, nested) < 0) return -1;
            }
            return fputs("}}\n", file) < 0 ? -1 : 0;
        }
        if (iterator == NULL || loop_target == NULL ||
            fprintf(file, "{Nv it_%zu=", id) < 0 ||
            emit_expression(file, program, function, iterator) < 0 ||
            fprintf(file, ";size_t li_%zu;if(it_%zu.kind!=NV_TUPLE)return nv_fail(\"for requires native container\");for(li_%zu=0;li_%zu<it_%zu.tuple.n;li_%zu++){Nv item_%zu=it_%zu.tuple.v[li_%zu];",
                    id, id, id, id, id, id, id, id, id) < 0) return -1;
        if (strcmp(loop_target->syntax_kind, "Name") == 0 &&
            loop_target->symbol != NULL) {
            if (fprintf(file, "v_%s=item_%zu;", loop_target->symbol, id) < 0) return -1;
        } else if (strcmp(loop_target->syntax_kind, "Tuple") == 0) {
            size_t target_number = 0u;
            if (fprintf(file, "if(item_%zu.kind!=NV_TUPLE)return nv_fail(\"unpack requires native tuple\");", id) < 0) return -1;
            for (i = 0u; i < loop_target->operand_count; i++) {
                const WrtcLoweringOp *part =
                    &function->operations[loop_target->operands[i]];
                if (part->role == NULL || strcmp(part->role, "elts") != 0 ||
                    part->symbol == NULL) continue;
                if (fprintf(file, "if(item_%zu.tuple.n<=%zuu)return nv_fail(\"not enough values to unpack\");v_%s=item_%zu.tuple.v[%zuu];",
                            id, target_number, part->symbol, id,
                            target_number) < 0) return -1;
                target_number++;
            }
        } else if (fputs("return nv_fail(\"unsupported native loop target\");", file) < 0) return -1;
        for (i = 0u; i < statement->operand_count; i++) {
            const WrtcLoweringOp *nested = &function->operations[statement->operands[i]];
            if (nested->role != NULL && strcmp(nested->role, "body") == 0 &&
                emit_statement(file, program, function, nested) < 0) return -1;
        }
        return fputs("}}\n", file) < 0 ? -1 : 0;
    }
    if (statement->kind == WRTC_LOWER_OP_WHILE) {
        const WrtcLoweringOp *test = child(function, statement, "test", 0u);
        if (test == NULL || fputs("while(nv_truth(", file) < 0 ||
            emit_expression(file, program, function, test) < 0 ||
            fputs(")){\n", file) < 0) return -1;
        for (i = 0u; i < statement->operand_count; i++) {
            const WrtcLoweringOp *nested = &function->operations[statement->operands[i]];
            if (nested->role != NULL && strcmp(nested->role, "body") == 0 &&
                emit_statement(file, program, function, nested) < 0) return -1;
        }
        return fputs("}\n", file) < 0 ? -1 : 0;
    }
    if (statement->kind == WRTC_LOWER_OP_RAISE) {
        value = child(function, statement, "exc", 0u);
        if (value == NULL) return fputs("return nv_fail(\"native re-raise is unsupported\");\n", file) < 0 ? -1 : 0;
        if (fputs("return ", file) < 0 ||
            emit_expression(file, program, function, value) < 0 ||
            fputs(";\n", file) < 0) return -1;
        return 0;
    }
    if (strcmp(statement->syntax_kind, "Break") == 0)
        return fputs("break;\n", file) < 0 ? -1 : 0;
    if (strcmp(statement->syntax_kind, "Continue") == 0)
        return fputs("continue;\n", file) < 0 ? -1 : 0;
    if (strcmp(statement->syntax_kind, "Expr") == 0) {
        value = child(function, statement, "value", 0u);
        if (value != NULL && value->kind == WRTC_LOWER_OP_DIRECT_CALL) {
            const WrtcLoweredFunction *target_function =
                value->target_function < program->function_count ?
                &program->functions[value->target_function] : NULL;
            const WrtcLoweringOp *first_argument = child(function, value, "args", 0u);
            if (target_function != NULL && target_function->parameter_count != 0u &&
                target_function->parameters[0].boxed_type == WRTC_TYPE_BYTE_VECTOR &&
                first_argument != NULL && first_argument->symbol != NULL) {
                if (fprintf(file, "v_%s=", first_argument->symbol) < 0 ||
                    emit_expression(file, program, function, value) < 0 ||
                    fprintf(file, ";if(v_%s.kind==NV_ERROR)return v_%s;\n",
                            first_argument->symbol, first_argument->symbol) < 0)
                    return -1;
            } else if (fputs("{Nv ignored=", file) < 0 ||
                       emit_expression(file, program, function, value) < 0 ||
                       fputs(";if(ignored.kind==NV_ERROR)return ignored;}\n", file) < 0)
                return -1;
        } else if (value != NULL &&
                   (value->kind == WRTC_LOWER_OP_COLLECTION_APPEND ||
                    value->kind == WRTC_LOWER_OP_COLLECTION_EXTEND)) {
            const WrtcLoweringOp *callable = child(function, value, "func", 0u);
            const WrtcLoweringOp *receiver = callable == NULL ? NULL :
                                              child(function, callable, "value", 0u);
            const WrtcLoweringOp *item = child(function, value, "args", 0u);
            if (receiver == NULL || receiver->symbol == NULL || item == NULL ||
                fprintf(file, value->kind == WRTC_LOWER_OP_COLLECTION_APPEND ?
                        "if(nv_append(&v_%s," : "if(nv_extend(&v_%s,",
                        receiver == NULL || receiver->symbol == NULL ? "invalid" : receiver->symbol) < 0 ||
                emit_expression(file, program, function, item) < 0 ||
                fputs(")<0)return nv_error();\n", file) < 0) return -1;
        }
        return 0;
    }
    if (strcmp(statement->syntax_kind, "Pass") == 0) return 0;
    (void)op_index(function, statement);
    return -1;
}

static int emit_helper(FILE *file, const WrtcLoweringProgram *program,
                       const WrtcLoweredFunction *function, size_t index) {
    size_t i;
    if (fprintf(file, "static Nv nh_%zu(const Nv*a){(void)a;\n", index) < 0) return -1;
    for (i = 0u; i < function->parameter_count; i++)
        if (fprintf(file, "Nv v_%s=a[%zu];(void)v_%s;\n", function->parameters[i].name, i,
                    function->parameters[i].name) < 0)
            return -1;
    for (i = 0u; i < function->local_count; i++) {
        size_t p;
        for (p = 0u; p < function->parameter_count; p++)
            if (strcmp(function->locals[i].name,
                       function->parameters[p].name) == 0) break;
        if (p != function->parameter_count) continue;
        if (fprintf(file, "Nv v_%s=nv_none();(void)v_%s;\n",
                    function->locals[i].name,
                    function->locals[i].name) < 0) return -1;
    }
    for (i = 0u; i < function->operation_count; i++) {
        const WrtcLoweringOp *statement = &function->operations[i];
        if (statement->parent != 0u || statement->role == NULL ||
            strcmp(statement->role, "body") != 0) continue;
        if (emit_statement(file, program, function, statement) < 0) return -1;
    }
    if (function->parameter_count != 0u &&
        function->parameters[0].boxed_type == WRTC_TYPE_BYTE_VECTOR)
        return fprintf(file, "return v_%s;}\n",
                       function->parameters[0].name) < 0 ? -1 : 0;
    return fputs("return nv_none();}\n", file) < 0 ? -1 : 0;
}

static int emit_meta_string(FILE *file, const char *name, const char *value) {
    if (fputs("if(add_string(module,", file) < 0 || quoted(file, name) < 0 ||
        fputc(',', file) == EOF || quoted(file, value) < 0 ||
        fputs(")<0)goto error;\n", file) < 0) return -1;
    return 0;
}

int wrtc_emit_extension(FILE *file, const char *module,
                        const WrtcLoweringProgram *program,
                        const char *source_hash, const char *semantic_hash,
                        const char *revision, const char *target,
                        const char *architecture, const char *extension_suffix,
                        PyObject *artifact_metadata) {
    size_t i, j, public_count = 0u;
    static const char runtime[] =
        "#define PY_SSIZE_T_CLEAN\n#include <Python.h>\n#include <structmember.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "typedef enum{NV_ERROR,NV_NONE,NV_INT,NV_BYTES,NV_TUPLE,NV_TYPE,NV_STR}NvKind;typedef enum{NV_OP_ADD,NV_OP_SUB,NV_OP_MULT,NV_OP_FLOOR_DIV,NV_OP_MOD,NV_OP_LSHIFT,NV_OP_RSHIFT,NV_OP_BIT_AND,NV_OP_BIT_OR,NV_OP_AND,NV_OP_OR,NV_OP_NOT,NV_OP_INVERT,NV_OP_USUB,NV_OP_IN,NV_OP_NOT_IN,NV_OP_IS,NV_OP_IS_NOT,NV_OP_EQ,NV_OP_NOT_EQ,NV_OP_LT,NV_OP_LTE,NV_OP_GT,NV_OP_GTE}NvOp;typedef struct Nv Nv;typedef struct{Nv*v;size_t n;}NvTuple;struct Nv{NvKind kind;uint64_t i;const uint8_t*p;size_t n;void*owner;NvTuple tuple;};typedef struct{void**v;size_t n,cap;}NvArena;static _Thread_local NvArena*nv_active;static int nv_track(void*p){NvArena*a=nv_active;void**grown;size_t cap;if(!a||!p)return 0;if(a->n==a->cap){cap=a->cap?a->cap*2u:32u;if(cap<a->cap||cap>SIZE_MAX/sizeof(*grown)){PyErr_NoMemory();return -1;}grown=PyMem_Realloc(a->v,cap*sizeof(*grown));if(!grown){PyErr_NoMemory();return -1;}a->v=grown;a->cap=cap;}a->v[a->n++]=p;return 0;}static void*nv_alloc(size_t n,int zero){void*p=zero?PyMem_Calloc(n?n:1u,1u):PyMem_Malloc(n?n:1u);if(!p){PyErr_NoMemory();return NULL;}if(nv_track(p)<0){PyMem_Free(p);return NULL;}return p;}static void*nv_realloc(void*p,size_t n){NvArena*a=nv_active;void*q;size_t i;if(!a)return PyMem_Realloc(p,n?n:1u);if(!p){q=PyMem_Malloc(n?n:1u);if(!q){PyErr_NoMemory();return NULL;}if(nv_track(q)<0){PyMem_Free(q);return NULL;}return q;}for(i=a->n;i>0u;i--)if(a->v[i-1u]==p){q=PyMem_Realloc(p,n?n:1u);if(!q){PyErr_NoMemory();return NULL;}a->v[i-1u]=q;return q;}PyErr_SetString(PyExc_RuntimeError,\"native allocation owner is not tracked\");return NULL;}static void nv_arena_clear(NvArena*a){size_t i;for(i=0;i<a->n;i++)PyMem_Free(a->v[i]);PyMem_Free(a->v);a->v=NULL;a->n=a->cap=0u;nv_active=NULL;}static int nv_truth(Nv);static Nv nv_raise(PyObject*,Nv);static Nv nv_error(void);"
        "static Nv nv_none(void){Nv v={NV_NONE,0,NULL,0,NULL,{NULL,0}};return v;}static Nv nv_int(uint64_t x){Nv v=nv_none();v.kind=NV_INT;v.i=x;return v;}"
        "static Nv nv_fail(const char*s){Nv v=nv_none();v.kind=NV_ERROR;PyErr_SetString(PyExc_NotImplementedError,s);return v;}"
        "static Nv nv_borrow(const uint8_t*p,size_t n){Nv v=nv_none();v.kind=NV_BYTES;v.p=p;v.n=n;return v;}static Nv nv_literal(const char*p,size_t n){return nv_borrow((const uint8_t*)p,n);}static Nv nv_byte(Nv x){uint8_t*p;if(x.kind!=NV_INT)return nv_fail(\"byte item is not native int\");p=nv_alloc(1u,0);if(!p)return nv_error();*p=(uint8_t)x.i;{Nv v=nv_borrow(p,1);v.owner=p;v.i=1u;return v;}}"
        "static Nv nv_bytearray(Nv x){size_t n=x.kind==NV_NONE?0u:x.kind==NV_INT?(size_t)x.i:x.kind==NV_BYTES?x.n:0u;uint8_t*p=n?(uint8_t*)nv_alloc(n,1):NULL;Nv v;if(n&&!p)return nv_error();if(x.kind==NV_BYTES&&n)memcpy(p,x.p,n);v=nv_borrow(p,n);v.owner=p;v.i=n;return v;}"
        "static Nv nv_bytes(Nv x){if(x.kind!=NV_BYTES)return nv_fail(\"bytes conversion requires native bytes\");return x;}"
        "static Nv nv_binary(Nv x,Nv y,NvOp op){if(op==NV_OP_AND)return nv_truth(x)?y:x;if(op==NV_OP_OR)return nv_truth(x)?x:y;if(x.kind==NV_INT&&y.kind==NV_INT){switch(op){case NV_OP_ADD:return nv_int(x.i+y.i);case NV_OP_SUB:return nv_int(x.i-y.i);case NV_OP_MULT:return nv_int(x.i*y.i);case NV_OP_BIT_AND:return nv_int(x.i&y.i);case NV_OP_BIT_OR:return nv_int(x.i|y.i);case NV_OP_LSHIFT:return nv_int(y.i<64u?x.i<<y.i:0u);case NV_OP_RSHIFT:return nv_int(y.i<64u?x.i>>y.i:0u);case NV_OP_FLOOR_DIV:return y.i?nv_int(x.i/y.i):nv_fail(\"integer division by zero\");case NV_OP_MOD:return y.i?nv_int(x.i%y.i):nv_fail(\"integer modulo by zero\");default:break;}}if(op==NV_OP_ADD&&x.kind==NV_BYTES&&y.kind==NV_BYTES){size_t n=x.n+y.n;uint8_t*p;if(n<x.n){PyErr_NoMemory();return nv_error();}p=nv_alloc(n?n:1u,0);if(!p)return nv_error();memcpy(p,x.p,x.n);memcpy(p+x.n,y.p,y.n);x.p=p;x.n=n;x.owner=p;x.i=n;return x;}PyErr_Format(PyExc_NotImplementedError,\"unsupported typed native binary (%d,%d,%d)\",(int)x.kind,(int)y.kind,(int)op);return nv_error();}"
        "static Nv nv_binary_checked(Nv x,Nv y,NvOp op){if(x.kind==NV_ERROR)return x;if(y.kind==NV_ERROR)return y;return nv_binary(x,y,op);}"
        "static Nv nv_tuple(const Nv*x,size_t n){Nv*v=n?(Nv*)nv_alloc(n*sizeof(*v),0):NULL;Nv r=nv_none();if(n&&!v)return nv_error();if(n&&x)memcpy(v,x,n*sizeof(*v));r.kind=NV_TUPLE;r.tuple.v=v;r.tuple.n=n;r.owner=v;r.i=n;return r;}"
        "static int nv_reserve(Nv*v,size_t need,size_t item){size_t cap=(size_t)v->i;void*p;if(need<=cap)return 0;cap=cap?cap:4u;while(cap<need){size_t next=cap+cap/2u+1u;if(next<=cap){PyErr_NoMemory();return -1;}cap=next;}if(cap>SIZE_MAX/item){PyErr_NoMemory();return -1;}p=nv_realloc(v->owner,cap*item);if(!p)return -1;v->owner=p;v->i=cap;if(v->kind==NV_BYTES)v->p=(const uint8_t*)p;else v->tuple.v=(Nv*)p;return 0;}static Nv nv_error(void){Nv v=nv_none();v.kind=NV_ERROR;return v;}static int nv_append(Nv*v,Nv x){if(v->kind==NV_BYTES&&x.kind==NV_INT){if(v->owner==NULL&&v->n!=0u)return nv_fail(\"cannot append to borrowed bytes\").kind==NV_ERROR?-1:-1;if(nv_reserve(v,v->n+1u,sizeof(uint8_t))<0)return -1;((uint8_t*)v->p)[v->n++]=(uint8_t)x.i;return 0;}if(v->kind==NV_TUPLE){if(nv_reserve(v,v->tuple.n+1u,sizeof(Nv))<0)return -1;v->tuple.v[v->tuple.n++]=x;return 0;}nv_fail(\"append requires native collection\");return -1;}static int nv_extend(Nv*v,Nv x){size_t need;if(v->kind!=NV_BYTES||x.kind!=NV_BYTES){nv_fail(\"extend requires native bytes\");return -1;}if(x.n>SIZE_MAX-v->n){PyErr_NoMemory();return -1;}need=v->n+x.n;if(nv_reserve(v,need,sizeof(uint8_t))<0)return -1;memcpy((uint8_t*)v->p+v->n,x.p,x.n);v->n=need;return 0;}"
        "static int nv_set(Nv*v,size_t i,Nv x){if(v->kind!=NV_TUPLE||i>=v->tuple.n){nv_fail(\"native record field out of range\");return -1;}v->tuple.v[i]=x;return 0;}"
        "static Nv nv_any_field_eq(Nv v,size_t field,Nv expected){size_t i;if(v.kind!=NV_TUPLE)return nv_fail(\"any requires native container\");for(i=0;i<v.tuple.n;i++){Nv item=v.tuple.v[i];if(item.kind==NV_TUPLE&&field<item.tuple.n&&item.tuple.v[field].kind==expected.kind&&item.tuple.v[field].i==expected.i)return nv_int(1u);}return nv_int(0u);}"
        "static int nv_store(Nv*v,Nv i,Nv x){uint8_t*p=(uint8_t*)v->p;if(v->kind!=NV_BYTES||i.kind!=NV_INT||x.kind!=NV_INT||i.i>=v->n){nv_fail(\"invalid native byte store\");return -1;}p[i.i]=(uint8_t)x.i;return 0;}static int nv_store_slice(Nv*v,Nv lower,Nv upper,Nv x){size_t a=lower.kind==NV_NONE?0u:(size_t)lower.i,b=upper.kind==NV_NONE?v->n:(size_t)upper.i;uint8_t*p=(uint8_t*)v->p;if(v->kind!=NV_BYTES||x.kind!=NV_BYTES||b<a||b>v->n||x.n!=b-a){nv_fail(\"invalid native byte slice store\");return -1;}memcpy(p+a,x.p,x.n);return 0;}static Nv nv_to_bytes(Nv x,Nv length){size_t n,i;Nv v;if(x.kind!=NV_INT||length.kind!=NV_INT||length.i>8u)return nv_fail(\"invalid native endian write\");n=(size_t)length.i;v=nv_bytearray(nv_int(n));if(v.kind==NV_ERROR)return v;for(i=0;i<n;i++)((uint8_t*)v.p)[n-i-1u]=(uint8_t)(x.i>>(8u*i));return v;}"
        "static Nv nv_pop(Nv*v){if(v->kind!=NV_TUPLE||v->tuple.n==0u)return nv_fail(\"pop from empty list\");return v->tuple.v[--v->tuple.n];}"
        "static Nv nv_min(Nv a,Nv b){if(a.kind!=NV_INT||b.kind!=NV_INT)return nv_fail(\"min requires native ints\");return (int64_t)a.i<=(int64_t)b.i?a:b;}static Nv nv_max(Nv a,Nv b){if(a.kind!=NV_INT||b.kind!=NV_INT)return nv_fail(\"max requires native ints\");return (int64_t)a.i>=(int64_t)b.i?a:b;}"
        "static Nv nv_ints(const char*s){Nv a[32],r;size_t n=0;char*e;while(*s&&n<32){while(*s&&(*s<'0'||*s>'9'))s++;if(!*s)break;a[n++]=nv_int(strtoull(s,&e,10));s=e;}r=nv_tuple(a,n);return r;}"
        "static Nv nv_str(const char*s){Nv v=nv_none();v.kind=NV_STR;v.p=(const uint8_t*)s;v.n=strlen(s);return v;}static Nv nv_type(NvKind k){Nv v=nv_none();v.kind=NV_TYPE;v.i=(uint64_t)k;return v;}static Nv nv_typeof(Nv v){return nv_type(v.kind);}static int nv_truth(Nv v){return v.kind==NV_INT?v.i!=0u:(v.kind==NV_BYTES||v.kind==NV_STR)?v.n!=0u:v.kind==NV_TUPLE?v.tuple.n!=0u:v.kind!=NV_NONE&&v.kind!=NV_ERROR;}static Nv nv_bool(Nv v){return nv_int((uint64_t)nv_truth(v));}static Nv nv_len(Nv v){if(v.kind==NV_BYTES||v.kind==NV_STR)return nv_int(v.n);if(v.kind==NV_TUPLE)return nv_int(v.tuple.n);return nv_fail(\"len requires native container\");}static Nv nv_unary(Nv v,NvOp op){if(op==NV_OP_NOT)return nv_int((uint64_t)!nv_truth(v));if(v.kind!=NV_INT)return nv_fail(\"unary requires native int\");if(op==NV_OP_INVERT)return nv_int(~v.i);if(op==NV_OP_USUB)return nv_int(0u-v.i);return v;}static Nv nv_compare(Nv x,Nv y,NvOp op){int r=0;size_t i;if(op==NV_OP_IN||op==NV_OP_NOT_IN){if(y.kind==NV_TUPLE)for(i=0;i<y.tuple.n;i++)if(y.tuple.v[i].kind==x.kind&&y.tuple.v[i].i==x.i){r=1;break;}if(op==NV_OP_NOT_IN)r=!r;return nv_int((uint64_t)r);}if(op==NV_OP_IS||op==NV_OP_EQ)r=x.kind==y.kind&&x.i==y.i&&x.p==y.p;if(op==NV_OP_IS_NOT||op==NV_OP_NOT_EQ)r=!(x.kind==y.kind&&x.i==y.i&&x.p==y.p);if(x.kind==NV_INT&&y.kind==NV_INT){if(op==NV_OP_LT)r=x.i<y.i;else if(op==NV_OP_LTE)r=x.i<=y.i;else if(op==NV_OP_GT)r=x.i>y.i;else if(op==NV_OP_GTE)r=x.i>=y.i;}return nv_int((uint64_t)r);}"
        "static Nv nv_get(Nv v,Nv index){if(index.kind!=NV_INT)return nv_fail(\"native index is not int\");if(v.kind==NV_BYTES){if(index.i>=v.n)return nv_raise(PyExc_IndexError,nv_str(\"index out of range\"));return nv_int(v.p[index.i]);}if(v.kind==NV_TUPLE){if(index.i>=v.tuple.n)return nv_raise(PyExc_IndexError,nv_str(\"tuple index out of range\"));return v.tuple.v[index.i];}return nv_fail(\"native value is not subscriptable\");}static Nv nv_slice(Nv v,Nv lower,Nv upper){size_t a=lower.kind==NV_NONE?0u:(size_t)lower.i,b=upper.kind==NV_NONE?(v.kind==NV_BYTES?v.n:v.tuple.n):(size_t)upper.i;if(b<a)b=a;if(v.kind==NV_BYTES){if(b>v.n)b=v.n;return nv_borrow(v.p+a,b-a);}if(v.kind==NV_TUPLE){if(b>v.tuple.n)b=v.tuple.n;return nv_tuple(v.tuple.v+a,b-a);}return nv_fail(\"native value is not sliceable\");}"
        "static Nv nv_format(const Nv*x,size_t n){size_t i,total=0,pos=0;uint8_t*p;char number[32];for(i=0;i<n;i++){if(x[i].kind==NV_STR)total+=x[i].n;else if(x[i].kind==NV_INT)total+=(size_t)snprintf(number,sizeof(number),\"%llu\",(unsigned long long)x[i].i);else return nv_fail(\"unsupported formatted native value\");}p=nv_alloc(total+1u,0);if(!p)return nv_error();for(i=0;i<n;i++){size_t m;if(x[i].kind==NV_STR){memcpy(p+pos,x[i].p,x[i].n);pos+=x[i].n;}else{m=(size_t)snprintf(number,sizeof(number),\"%llu\",(unsigned long long)x[i].i);memcpy(p+pos,number,m);pos+=m;}}p[pos]=0;{Nv v=nv_str((const char*)p);v.owner=p;return v;}}static Nv nv_raise(PyObject*t,Nv message){Nv v=nv_none();v.kind=NV_ERROR;if(message.kind!=NV_STR)PyErr_SetString(PyExc_RuntimeError,\"native exception message is not a string\");else PyErr_SetString(t,(const char*)message.p);if(message.owner&&!nv_active)PyMem_Free(message.owner);return v;}"
        "static void nv_clear(Nv*v){size_t i;if(nv_active){*v=nv_none();return;}if(v->kind==NV_TUPLE)for(i=0;i<v->tuple.n;i++)nv_clear(&v->tuple.v[i]);if(v->owner)PyMem_Free(v->owner);*v=nv_none();}"
        "static PyObject*nv_box(Nv*v){PyObject*o=NULL;if(v->kind==NV_NONE)o=Py_NewRef(Py_None);else if(v->kind==NV_INT)o=PyLong_FromUnsignedLongLong(v->i);else if(v->kind==NV_BYTES)o=PyBytes_FromStringAndSize((const char*)v->p,(Py_ssize_t)v->n);else if(v->kind==NV_TUPLE){size_t i;o=PyTuple_New((Py_ssize_t)v->tuple.n);if(o)for(i=0;i<v->tuple.n;i++){PyObject*x=nv_box(&v->tuple.v[i]);if(!x){Py_DECREF(o);o=NULL;break;}PyTuple_SET_ITEM(o,(Py_ssize_t)i,x);}}else if(!PyErr_Occurred())PyErr_SetString(PyExc_RuntimeError,\"native helper failed\");return o;}"
        "typedef struct{const char*name,*doc,*ret;const char*const*params,*const*annotations;size_t nparams;}Fn;typedef struct{PyObject_HEAD vectorcallfunc vectorcall;size_t index;PyObject*name,*qualname,*doc,*annotations,*signature;}Callable;static PyTypeObject*callable_type;"
        "static int add_string(PyObject*m,const char*n,const char*v){PyObject*o=PyUnicode_FromString(v);if(!o)return -1;return PyModule_AddObject(m,n,o);}"
        "static void ann_spaces(const char**p){while(**p==' ')++*p;}static PyObject*ann_parse(const char**p){const char*b;size_t n;PyObject*base,*items=NULL,*item,*args,*result;ann_spaces(p);if(strncmp(*p,\"...\",3)==0){*p+=3;return Py_NewRef(Py_Ellipsis);}b=*p;while((**p>='a'&&**p<='z')||(**p>='A'&&**p<='Z')||(**p>='0'&&**p<='9')||**p=='_'||**p=='.')++*p;n=(size_t)(*p-b);if(!n){PyErr_SetString(PyExc_ValueError,\"invalid native annotation descriptor\");return NULL;}if(n==3&&strncmp(b,\"int\",3)==0)base=(PyObject*)&PyLong_Type;else if(n==5&&strncmp(b,\"bytes\",5)==0)base=(PyObject*)&PyBytes_Type;else if(n==4&&strncmp(b,\"bool\",4)==0)base=(PyObject*)&PyBool_Type;else if(n==3&&strncmp(b,\"str\",3)==0)base=(PyObject*)&PyUnicode_Type;else if(n==5&&strncmp(b,\"tuple\",5)==0)base=(PyObject*)&PyTuple_Type;else if(n==4&&strncmp(b,\"list\",4)==0)base=(PyObject*)&PyList_Type;else if(n==6&&strncmp(b,\"object\",6)==0)base=(PyObject*)&PyBaseObject_Type;else if(n==4&&strncmp(b,\"None\",4)==0)return Py_NewRef(Py_None);else{PyErr_Format(PyExc_ValueError,\"unsupported native annotation %.*s\",(int)n,b);return NULL;}ann_spaces(p);if(**p!='[')return Py_NewRef(base);++*p;items=PyList_New(0);if(!items)return NULL;for(;;){item=ann_parse(p);if(!item||PyList_Append(items,item)<0){Py_XDECREF(item);Py_DECREF(items);return NULL;}Py_DECREF(item);ann_spaces(p);if(**p==']'){++*p;break;}if(**p!=','){Py_DECREF(items);PyErr_SetString(PyExc_ValueError,\"invalid native annotation arguments\");return NULL;}++*p;}args=PyList_AsTuple(items);Py_DECREF(items);if(!args)return NULL;result=Py_GenericAlias(base,args);Py_DECREF(args);return result;}static PyObject*ann(const char*s){const char*p=s;PyObject*o=ann_parse(&p);ann_spaces(&p);if(o&&*p){Py_DECREF(o);PyErr_SetString(PyExc_ValueError,\"trailing native annotation text\");return NULL;}return o;}"
        "static PyObject*make_signature(const Fn*f,PyObject*a){PyObject*i=PyImport_ImportModule(\"inspect\"),*p=NULL,*sig=NULL,*kind=NULL,*items=NULL,*x=NULL,*args=NULL,*kw=NULL,*an=NULL,*r=NULL;size_t n;if(!i)goto done;p=PyObject_GetAttrString(i,\"Parameter\");sig=PyObject_GetAttrString(i,\"Signature\");kind=p?PyObject_GetAttrString(p,\"POSITIONAL_OR_KEYWORD\"):NULL;items=PyList_New(0);if(!p||!sig||!kind||!items)goto done;for(n=0;n<f->nparams;n++){PyObject*name=PyUnicode_FromString(f->params[n]);args=name?PyTuple_Pack(2,name,kind):NULL;Py_XDECREF(name);kw=PyDict_New();an=ann(f->annotations[n]);if(!args||!kw||!an||PyDict_SetItemString(kw,\"annotation\",an)<0)goto done;x=PyObject_Call(p,args,kw);Py_CLEAR(args);Py_CLEAR(kw);if(!x||PyList_Append(items,x)<0)goto done;Py_CLEAR(x);if(PyDict_SetItemString(a,f->params[n],an)<0)goto done;Py_CLEAR(an);}an=ann(f->ret);if(!an||PyDict_SetItemString(a,\"return\",an)<0)goto done;args=PyTuple_Pack(1,items);kw=PyDict_New();if(!args||!kw||PyDict_SetItemString(kw,\"return_annotation\",an)<0)goto done;r=PyObject_Call(sig,args,kw);done:Py_XDECREF(i);Py_XDECREF(p);Py_XDECREF(sig);Py_XDECREF(kind);Py_XDECREF(items);Py_XDECREF(x);Py_XDECREF(args);Py_XDECREF(kw);Py_XDECREF(an);return r;}\n";
    if (fputs(runtime, file) < 0) return -1;
    for (i = 0u; i < program->function_count; i++)
        if (fprintf(file, "static Nv nh_%zu(const Nv*);\n", i) < 0) return -1;
    for (i = 0u; i < program->record_count; i++)
        for (j = 0u; j < program->records[i].property_count; j++)
            if (fprintf(file, "static Nv np_%zu_%zu(const Nv*);\n", i, j) < 0)
                return -1;
    for (i = 0u; i < program->function_count; i++)
        if (emit_helper(file, program, &program->functions[i], i) < 0) return -1;
    for (i = 0u; i < program->record_count; i++)
        for (j = 0u; j < program->records[i].property_count; j++) {
            /* Property helper bodies share the same direct typed emitter. */
            if (fprintf(file, "#define nh_%zu np_%zu_%zu\n", program->function_count,
                        i, j) < 0 ||
                emit_helper(file, program, &program->records[i].properties[j],
                            program->function_count) < 0 ||
                fprintf(file, "#undef nh_%zu\n", program->function_count) < 0)
                return -1;
        }
    for (i = 0u; i < program->function_count; i++) {
        const WrtcLoweredFunction *f = &program->functions[i];
        if (fprintf(file, "static const char*params_%zu[]={", i) < 0) return -1;
        for (j = 0u; j < f->parameter_count; j++)
            if (quoted(file, f->parameters[j].name) < 0 || fputc(',', file) == EOF) return -1;
        if (fputs("NULL};\n", file) < 0 || fprintf(file, "static const char*annotations_%zu[]={", i) < 0) return -1;
        for (j = 0u; j < f->parameter_count; j++)
            if (string_or_null(file, f->parameters[j].annotation) < 0 || fputc(',', file) == EOF) return -1;
        if (fputs("NULL};\n", file) < 0) return -1;
        if (f->is_public) public_count++;
    }
    if (fputs("static const Fn functions[]={\n", file) < 0) return -1;
    for (i = 0u; i < program->function_count; i++) {
        const WrtcLoweredFunction *f = &program->functions[i];
        if (fputc('{', file) == EOF || quoted(file, f->name) < 0 || fputc(',', file) == EOF ||
            quoted(file, f->docstring) < 0 || fputc(',', file) == EOF ||
            quoted(file, f->return_annotation) < 0 ||
            fprintf(file, ",params_%zu,annotations_%zu,%zu},\n", i, i, f->parameter_count) < 0) return -1;
    }
    if (fputs("};\n", file) < 0) return -1;
    /* Boundary refinement is generated in source parameter order. */
    for (i = 0u; i < program->function_count; i++) {
        const WrtcLoweredFunction *f = &program->functions[i];
        if (!f->is_public) continue;
        if (fprintf(file, "static PyObject*dispatch_%zu(PyObject*const*a,size_t n){Nv v[%zu],r;NvArena arena={NULL,0u,0u};PyObject*o;", i, f->parameter_count ? f->parameter_count : 1u) < 0) return -1;
        if (fprintf(file, "if(n!=%zu){PyErr_Format(PyExc_TypeError,\"%s() takes %zu arguments (%%zu given)\",n);return NULL;}", f->parameter_count, f->name, f->parameter_count) < 0) return -1;
        for (j = 0u; j < f->parameter_count; j++) {
            const WrtcLoweredParameter *p = &f->parameters[j];
            if (p->boxed_type == WRTC_TYPE_INT) {
                if (fprintf(file, "if(!PyLong_CheckExact(a[%zu])){PyErr_SetString(PyExc_TypeError,\"%s must be int\");return NULL;}v[%zu]=nv_int(PyLong_AsUnsignedLongLong(a[%zu]));if(PyErr_Occurred())return NULL;", j, p->name, j, j) < 0) return -1;
                if (p->has_range && fprintf(file, "if(v[%zu].i<%lluu||v[%zu].i>%lluu){PyErr_Format(PyExc_ValueError,\"%s must be in range %llu..%llu\");return NULL;}", j, p->low, j, p->high, p->name, p->low, p->high) < 0) return -1;
            } else if (p->boxed_type == WRTC_TYPE_BYTES || p->boxed_type == WRTC_TYPE_BUFFER) {
                if (fprintf(file, "if(!PyBytes_CheckExact(a[%zu])){PyErr_SetString(PyExc_TypeError,\"%s must be bytes\");return NULL;}v[%zu]=nv_borrow((const uint8_t*)PyBytes_AS_STRING(a[%zu]),(size_t)PyBytes_GET_SIZE(a[%zu]));", j, p->name, j, j, j) < 0) return -1;
            } else if (fprintf(file, "return(PyErr_SetString(PyExc_TypeError,\"unsupported public native parameter type\"),NULL);") < 0) return -1;
        }
        if (fprintf(file, "nv_active=&arena;r=nh_%zu(v);if(r.kind==NV_ERROR){nv_arena_clear(&arena);return NULL;}o=nv_box(&r);nv_clear(&r);nv_arena_clear(&arena);return o;}\n", i) < 0) return -1;
    }
    if (fputs("static PyObject*invoke(PyObject*self,PyObject*const*a,size_t n,PyObject*k){Callable*c=(Callable*)self;if(k){PyErr_SetString(PyExc_TypeError,\"keyword arguments are not supported\");return NULL;}switch(c->index){", file) < 0) return -1;
    for (i = 0u; i < program->function_count; i++)
        if (program->functions[i].is_public && fprintf(file, "case %zu:return dispatch_%zu(a,(size_t)PyVectorcall_NARGS(n));", i, i) < 0) return -1;
    if (fputs("default:PyErr_SetString(PyExc_RuntimeError,\"invalid native callable\");return NULL;}}", file) < 0) return -1;
    if (fputs("static void destroy(PyObject*self){Callable*c=(Callable*)self;Py_XDECREF(c->name);Py_XDECREF(c->qualname);Py_XDECREF(c->doc);Py_XDECREF(c->annotations);Py_XDECREF(c->signature);Py_TYPE(self)->tp_free(self);}static PyMemberDef members[]={{\"__name__\",Py_T_OBJECT_EX,offsetof(Callable,name),READONLY,NULL},{\"__qualname__\",Py_T_OBJECT_EX,offsetof(Callable,qualname),READONLY,NULL},{\"__doc__\",Py_T_OBJECT_EX,offsetof(Callable,doc),READONLY,NULL},{\"__annotations__\",Py_T_OBJECT_EX,offsetof(Callable,annotations),READONLY,NULL},{\"__signature__\",Py_T_OBJECT_EX,offsetof(Callable,signature),READONLY,NULL},{NULL,0,0,0,NULL}};static PyType_Slot slots[]={{Py_tp_dealloc,destroy},{Py_tp_members,members},{Py_tp_call,PyVectorcall_Call},{0,NULL}};static PyType_Spec spec={\"pymeta.NativeCallable\",sizeof(Callable),0,Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_VECTORCALL|Py_TPFLAGS_IMMUTABLETYPE,slots};static PyObject*make_callable(size_t i){Callable*c=(Callable*)callable_type->tp_alloc(callable_type,0);if(!c)return NULL;c->vectorcall=invoke;c->index=i;c->name=PyUnicode_FromString(functions[i].name);c->qualname=Py_XNewRef(c->name);c->doc=PyUnicode_FromString(functions[i].doc);c->annotations=PyDict_New();c->signature=c->annotations?make_signature(&functions[i],c->annotations):NULL;if(!c->name||!c->qualname||!c->doc||!c->annotations||!c->signature)return Py_DECREF(c),NULL;return(PyObject*)c;}\n", file) < 0) return -1;
    if (fputs("static struct PyModuleDef module_def={PyModuleDef_HEAD_INIT,", file) < 0 || quoted(file, module) < 0 || fputs(",NULL,-1,NULL,NULL,NULL,NULL,NULL};\n#if defined(_WIN32)\n__declspec(dllexport)\n#else\n__attribute__((visibility(\"default\")))\n#endif\nPyMODINIT_FUNC PyInit_", file) < 0 || fputs(module, file) < 0 || fprintf(file, "(void){PyObject*module=NULL,*all=NULL,*registry=NULL,*types=NULL,*factory=NULL,*proxy=NULL,*callable=NULL,*constant=NULL;Nv constant_native=nv_none();size_t pos=0;module=PyModule_Create(&module_def);if(!module)goto error;callable_type=(PyTypeObject*)PyType_FromSpec(&spec);if(!callable_type)goto error;callable_type->tp_vectorcall_offset=offsetof(Callable,vectorcall);all=PyTuple_New(%zu);registry=PyDict_New();if(!all||!registry)goto error;\n", public_count) < 0) return -1;
    if (fputs("(void)&nv_none;(void)&nv_int;(void)&nv_fail;(void)&nv_borrow;(void)&nv_literal;(void)&nv_byte;(void)&nv_bytearray;(void)&nv_bytes;(void)&nv_binary;(void)&nv_binary_checked;(void)&nv_tuple;(void)&nv_error;(void)&nv_append;(void)&nv_extend;(void)&nv_set;(void)&nv_any_field_eq;(void)&nv_store;(void)&nv_store_slice;(void)&nv_to_bytes;(void)&nv_pop;(void)&nv_ints;(void)&nv_min;(void)&nv_max;(void)&nv_str;(void)&nv_type;(void)&nv_typeof;(void)&nv_truth;(void)&nv_bool;(void)&nv_len;(void)&nv_unary;(void)&nv_compare;(void)&nv_get;(void)&nv_slice;(void)&nv_format;(void)&nv_raise;(void)&nv_clear;(void)&nv_box;", file) < 0) return -1;
    for (i = 0u; i < program->function_count; i++)
        if (fprintf(file, "(void)&nh_%zu;", i) < 0) return -1;
    for (i = 0u; i < program->record_count; i++)
        for (j = 0u; j < program->records[i].property_count; j++)
            if (fprintf(file, "(void)&np_%zu_%zu;", i, j) < 0) return -1;
    if (fputc('\n', file) == EOF) return -1;
    for (i = 0u; i < program->constant_count; i++) {
        const WrtcLoweredConstant *constant_value = &program->constants[i];
        if (constant_value->type == WRTC_TYPE_INT) {
            if (fputs("constant=PyLong_FromString(", file) < 0 ||
                quoted(file, constant_value->literal) < 0 ||
                fputs(",NULL,0);", file) < 0) return -1;
        } else if (constant_value->type == WRTC_TYPE_BOOL) {
            if (fprintf(file, "constant=PyBool_FromLong(%s);",
                        strcmp(constant_value->literal, "True") == 0 ? "1" : "0") < 0)
                return -1;
        } else if (constant_value->type == WRTC_TYPE_TUPLE) {
            if (fputs("constant_native=nv_ints(", file) < 0 ||
                quoted(file, constant_value->literal) < 0 ||
                fputs(");constant=nv_box(&constant_native);nv_clear(&constant_native);", file) < 0)
                return -1;
        } else {
            PyErr_Format(PyExc_ValueError,
                         "unsupported published native constant %s",
                         constant_value->name);
            return -1;
        }
        if (fputs("if(!constant||PyModule_AddObjectRef(module,", file) < 0 ||
            quoted(file, constant_value->name) < 0 ||
            fputs(",constant)<0)goto error;Py_CLEAR(constant);\n", file) < 0)
            return -1;
    }
    for (i = 0u; i < program->function_count; i++) if (program->functions[i].is_public) {
        if (fprintf(file, "callable=make_callable(%zu);if(!callable)goto error;if(PyModule_AddObjectRef(module,", i) < 0 || quoted(file, program->functions[i].name) < 0 || fputs(",callable)<0||PyDict_SetItemString(registry,", file) < 0 || quoted(file, program->functions[i].name) < 0 || fputs(",callable)<0)goto error;PyTuple_SET_ITEM(all,(Py_ssize_t)pos++,PyUnicode_FromString(", file) < 0 || quoted(file, program->functions[i].name) < 0 || fputs("));Py_CLEAR(callable);\n", file) < 0) return -1;
    }
    if (fputs("if(PyModule_AddObjectRef(module,\"__all__\",all)<0)goto error;types=PyImport_ImportModule(\"types\");factory=types?PyObject_GetAttrString(types,\"MappingProxyType\"):NULL;proxy=factory?PyObject_CallOneArg(factory,registry):NULL;if(!proxy||PyModule_AddObjectRef(module,\"__pymeta_functions__\",proxy)<0)goto error;", file) < 0) return -1;
    if (emit_meta_string(file,"__pymeta_source_sha256__",source_hash)<0 || emit_meta_string(file,"__pymeta_semantic_sha256__",semantic_hash)<0 || emit_meta_string(file,"__pymeta_compiler_version__","wrtc-pymeta-compiler/0.3")<0 || emit_meta_string(file,"__pymeta_cpython_revision__",revision)<0 || emit_meta_string(file,"__pymeta_cpython_source_revision__","070700ed4d95c16855603cecab3f41f3b587f973")<0 || emit_meta_string(file,"__pymeta_target__",target)<0 || emit_meta_string(file,"__pymeta_architecture__",architecture)<0) return -1;
    if (fputs("constant=PySys_GetObject(\"implementation\");constant=constant?PyObject_GetAttrString(constant,\"cache_tag\"):NULL;if(constant==Py_None){Py_DECREF(constant);constant=PyUnicode_FromString(\"\");}if(!constant||PyModule_AddObject(module,\"__pymeta_cache_tag__\",constant)<0)goto error;constant=NULL;",file)<0) return -1;
    if (fputs("constant=PySys_GetObject(\"abiflags\");constant=constant?Py_NewRef(constant):PyUnicode_FromString(\"\");if(!constant||PyModule_AddObject(module,\"__pymeta_abi_flags__\",constant)<0)goto error;constant=NULL;",file)<0) return -1;
    if (emit_meta_string(file,"__pymeta_extension_suffix__",extension_suffix)<0) return -1;
    if (emit_meta_string(file,"__pymeta_optimization__","release")<0) return -1;
    if (artifact_metadata != NULL) {
        PyObject *key, *value;
        Py_ssize_t position = 0;
        while (PyDict_Next(artifact_metadata, &position, &key, &value)) {
            const char *key_text = PyUnicode_AsUTF8(key);
            const char *value_text = PyUnicode_AsUTF8(value);
            char *attribute;
            size_t length;
            if (key_text == NULL || value_text == NULL) return -1;
            length = strlen(key_text) + sizeof "__pymeta___";
            attribute = malloc(length);
            if (attribute == NULL) {
                PyErr_NoMemory();
                return -1;
            }
            (void)snprintf(attribute, length, "__pymeta_%s__", key_text);
            if (emit_meta_string(file, attribute, value_text) < 0) {
                free(attribute);
                return -1;
            }
            free(attribute);
        }
    }
    return fputs("Py_DECREF(all);Py_DECREF(registry);Py_DECREF(types);Py_DECREF(factory);Py_DECREF(proxy);return module;error:nv_clear(&constant_native);Py_XDECREF(constant);Py_XDECREF(callable);Py_XDECREF(all);Py_XDECREF(registry);Py_XDECREF(types);Py_XDECREF(factory);Py_XDECREF(proxy);Py_XDECREF(module);return NULL;}\n", file) < 0 ? -1 : 0;
}
