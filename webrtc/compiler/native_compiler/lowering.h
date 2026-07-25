#ifndef WRTC_LOWERING_H
#define WRTC_LOWERING_H

#include "compiler_core.h"

#include <stddef.h>

typedef enum {
    WRTC_OWNERSHIP_BORROWED = 0,
    WRTC_OWNERSHIP_OWNED,
    WRTC_OWNERSHIP_MOVED,
    WRTC_OWNERSHIP_BOUNDARY_OWNED
} WrtcOwnershipState;

typedef enum {
    WRTC_STORAGE_NONE = 0,
    WRTC_STORAGE_SCALAR,
    WRTC_STORAGE_BYTE_SPAN,
    WRTC_STORAGE_BYTE_BUILDER,
    WRTC_STORAGE_RECORD,
    WRTC_STORAGE_FIXED_TUPLE,
    WRTC_STORAGE_TYPED_VECTOR,
    WRTC_STORAGE_PYOBJECT
} WrtcStorageKind;

typedef enum {
    WRTC_LOWER_OP_BRANCH = 0,
    WRTC_LOWER_OP_FOR,
    WRTC_LOWER_OP_WHILE,
    WRTC_LOWER_OP_DIRECT_CALL,
    WRTC_LOWER_OP_RAISE,
    WRTC_LOWER_OP_ANY_GENERATOR,
    WRTC_LOWER_OP_RECORD_CONSTRUCT,
    WRTC_LOWER_OP_PROPERTY,
    WRTC_LOWER_OP_COLLECTION_APPEND,
    WRTC_LOWER_OP_COLLECTION_EXTEND,
    WRTC_LOWER_OP_COLLECTION_POP,
    WRTC_LOWER_OP_SLICE,
    WRTC_LOWER_OP_ENDIAN_WRITE,
    WRTC_LOWER_OP_ALLOCATE,
    WRTC_LOWER_OP_RETURN,
    WRTC_LOWER_OP_SCALAR,
    WRTC_LOWER_OP_ASSIGN,
    WRTC_LOWER_OP_BINARY,
    WRTC_LOWER_OP_UNARY,
    WRTC_LOWER_OP_COMPARE,
    WRTC_LOWER_OP_ATTRIBUTE,
    WRTC_LOWER_OP_SUBSCRIPT,
    WRTC_LOWER_OP_BUILTIN_CALL,
    WRTC_LOWER_OP_FUNCTION
} WrtcLoweringOpKind;

typedef struct {
    WrtcLoweringOpKind kind;
    WrtcSourceSpan span;
    size_t target_function;
    char *syntax_kind;
    char *symbol;
    WrtcTypeKind type;
    size_t parent;
    size_t subtree_end;
    unsigned owns_value : 1;
    char *role;
    size_t role_index;
    size_t *operands;
    size_t operand_count;
    char *literal;
    /* Resolved aggregate information. SIZE_MAX means not applicable. */
    size_t record_index;
    WrtcTypeKind element_type;
    size_t element_record_index;
    unsigned bit_width;
    unsigned is_signed : 1;
    unsigned wraps : 1;
    WrtcOwnershipState ownership;
    WrtcStorageKind storage;
    size_t capacity_hint;
    unsigned direct_loop : 1;
    unsigned scalar_replaced : 1;
    unsigned cleanup_on_error : 1;
} WrtcLoweringOp;

typedef struct WrtcTypeShape {
    WrtcTypeKind kind;
    size_t record_index;
    struct WrtcTypeShape *items;
    size_t item_count;
    unsigned variadic : 1;
} WrtcTypeShape;

typedef struct {
    char *name;
    char *annotation;
    WrtcTypeShape shape;
    WrtcTypeKind boxed_type;
    WrtcTypeKind refined_type;
    unsigned bit_width;
    unsigned wraps : 1;
    unsigned has_range : 1;
    unsigned long long low;
    unsigned long long high;
    size_t maximum_length;
    size_t record_index;
    WrtcTypeKind element_type;
    size_t element_record_index;
    unsigned is_signed : 1;
    WrtcOwnershipState ownership;
    WrtcStorageKind storage;
    WrtcSourceSpan span;
} WrtcLoweredParameter;

typedef struct {
    char *name;
    WrtcTypeKind type;
    size_t record_index;
    WrtcTypeKind element_type;
    size_t element_record_index;
    unsigned bit_width;
    unsigned is_signed : 1;
    unsigned wraps : 1;
    unsigned owns_value : 1;
    WrtcOwnershipState ownership;
    WrtcStorageKind storage;
    size_t capacity_hint;
    unsigned scalar_replaced : 1;
    WrtcSourceSpan span;
} WrtcLoweredLocal;

typedef struct {
    char *name;
    char *docstring;
    char *return_annotation;
    WrtcTypeShape return_shape;
    WrtcLoweredParameter *parameters;
    size_t parameter_count;
    WrtcLoweringOp *operations;
    size_t operation_count;
    WrtcTypeKind return_type;
    size_t return_record_index;
    WrtcLoweredLocal *locals;
    size_t local_count;
    size_t cleanup_slot_count;
    unsigned is_public : 1;
} WrtcLoweredFunction;

typedef struct {
    char *name;
    WrtcTypeKind type;
    unsigned has_default : 1;
    char *default_literal;
} WrtcLoweredRecordField;

typedef struct {
    char *name;
    WrtcLoweredRecordField *fields;
    size_t field_count;
    size_t property_count;
    WrtcLoweredFunction *properties;
} WrtcLoweredRecord;

typedef struct {
    char *name;
    WrtcTypeKind type;
    char *literal;
} WrtcLoweredConstant;

typedef struct {
    WrtcLoweredFunction *functions;
    size_t function_count;
    WrtcLoweredRecord *records;
    size_t record_count;
    WrtcLoweredConstant *constants;
    size_t constant_count;
} WrtcLoweringProgram;

/* Build a complete lowering plan or reject the first untranslated reachable AST node. */
int wrtc_lowering_build(const WrtcCompilerCore *core, WrtcLoweringProgram **out);
void wrtc_lowering_free(WrtcLoweringProgram *program);
const WrtcLoweredFunction *wrtc_lowering_find_function(
    const WrtcLoweringProgram *program, const char *name);

#endif
