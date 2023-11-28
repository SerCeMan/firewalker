/* eslint @typescript-eslint/no-explicit-any: 0 */

// #ifndef _WIREFILTER_H_
// #define _WIREFILTER_H_
//
// #include <stdlib.h>
// #include <stdint.h>
//
// #ifdef __cplusplus
// extern "C" {
// #endif

import ffi from 'ffi-napi';
import ref from 'ref-napi';
import ref_struct_di from 'ref-struct-di';
import ref_array_di from 'ref-array-di';
import ref_union_di from 'ref-union-di';

const Struct = ref_struct_di(ref);
const Array = ref_array_di(ref as any) as any;
const Union = ref_union_di(ref);

const lib = {} as any;

//
// typedef struct wirefilter_scheme wirefilter_scheme_t;

const wirefilter_scheme_t = Struct({});

// typedef struct wirefilter_execution_context wirefilter_execution_context_t;

const wirefilter_execution_context_t = Struct({});

// typedef struct wirefilter_filter_ast wirefilter_filter_ast_t;

const wirefilter_filter_ast_t = Struct({});

// typedef struct wirefilter_filter wirefilter_filter_t;

const wirefilter_filter_t = Struct({});

// typedef struct wirefilter_map wirefilter_map_t;

const wirefilter_map_t = Struct({});

// typedef struct wirefilter_array wirefilter_array_t;

const wirefilter_array_t = Struct({});

// typedef struct wirefilter_list wirefilter_list_t;

const wirefilter_list_t = Struct({});

//
// typedef struct {
//     const char *data;
//     size_t length;
// } wirefilter_rust_allocated_str_t;

const wirefilter_rust_allocated_str_t = Struct({
    data: ref.types.CString,
    length: ref.types.size_t,
});

//
// typedef struct {
//     const char *data;
//     size_t length;
// } wirefilter_static_rust_allocated_str_t;

const wirefilter_static_rust_allocated_str_t = Struct({
    data: ref.types.CString,
    length: ref.types.size_t,
});

//
// typedef struct {
//     const char *data;
//     size_t length;
// } wirefilter_externally_allocated_str_t;

export const wirefilter_externally_allocated_str_t = Struct({
    data: ref.types.CString,
    length: ref.types.size_t,
});

//
// typedef struct {
//     const unsigned char *data;
//     size_t length;
// } wirefilter_externally_allocated_byte_arr_t;

export const wirefilter_externally_allocated_byte_arr_t = Struct({
    data: ref.refType(ref.types.uchar),
    length: ref.types.size_t,
});

//
// typedef union {
//     uint8_t success;
//     struct {
//         uint8_t _res1;
//         wirefilter_rust_allocated_str_t msg;
//     } err;
//     struct {
//         uint8_t _res2;
//         wirefilter_filter_ast_t *ast;
//     } ok;
// } wirefilter_parsing_result_t;

const wirefilter_parsing_result_t_err = Struct({
    success: ref.types.uint8,
    _res1: ref.types.uint8,
    msg: wirefilter_rust_allocated_str_t,
});

const wirefilter_parsing_result_t_ok = Struct({
    success: ref.types.uint8,
    _res2: ref.types.uint8,
    ast: ref.refType(wirefilter_filter_ast_t),
});

const wirefilter_parsing_result_t = Union({
    err: wirefilter_parsing_result_t_err,
    ok: wirefilter_parsing_result_t_ok,
});

// typedef union {
//     uint8_t success;
//     struct {
//         uint8_t _res1;
//         wirefilter_rust_allocated_str_t msg;
//     } err;
//     struct {
//         uint8_t _res2;
//         bool value;
//     } ok;
// } wirefilter_boolean_result_t;

const wirefilter_boolean_result_t_err = Struct({
    success: ref.types.uint8,
    // _res1: ref.types.uint8,
    msg: wirefilter_rust_allocated_str_t,
});

const wirefilter_boolean_result_t_ok = Struct({
    success: ref.types.uint8,
    // _res2: ref.types.uint8,
    value: ref.types.bool,
});

const wirefilter_boolean_result_t = Union({
    err: wirefilter_boolean_result_t_err,
    ok: wirefilter_boolean_result_t_ok
});

// typedef wirefilter_boolean_result_t wirefilter_matching_result_t;

const wirefilter_using_result_t = wirefilter_boolean_result_t;

//
// typedef union {
//     uint8_t success;
//     struct {
//         uint8_t _res1;
//         wirefilter_rust_allocated_str_t msg;
//     } err;
//     struct {
//         uint8_t _res2;
//         wirefilter_filter_t *filter;
//     } ok;
// } wirefilter_compiling_result_t;

const wirefilter_compiling_result_t_err = Struct({
    success: ref.types.uint8,
    // _res1: ref.types.uint8,
    msg: wirefilter_rust_allocated_str_t,
});

const wirefilter_compiling_result_t_ok = Struct({
    success: ref.types.uint8,
    // _res2: ref.types.uint8,
    filter: ref.refType(wirefilter_filter_t),
});

const wirefilter_compiling_result_t = Union({
    err: wirefilter_compiling_result_t_err,
    ok: wirefilter_compiling_result_t_ok,
});

//
// typedef wirefilter_boolean_result_t wirefilter_matching_result_t;

const wirefilter_matching_result_t = wirefilter_boolean_result_t;

//
// typedef union {
//     uint8_t success;
//     struct {
//         uint8_t _res1;
//         wirefilter_rust_allocated_str_t msg;
//     } err;
//     struct {
//         uint8_t _res2;
//         wirefilter_rust_allocated_str_t json;
//     } ok;
// } wirefilter_serializing_result_t;

const wirefilter_serializing_result_t_err = Struct({
    success: ref.types.uint8,
    // _res1: ref.types.uint8,
    msg: wirefilter_rust_allocated_str_t,
});

const wirefilter_serializing_result_t_ok = Struct({
    success: ref.types.uint8,
    // _res2: ref.types.uint8,
    json: wirefilter_rust_allocated_str_t,
});

const wirefilter_serializing_result_t = Union({
    err: wirefilter_serializing_result_t_err,
    ok: wirefilter_serializing_result_t_ok,
});

//
// typedef union {
//     uint8_t success;
//     struct {
//         uint8_t _res1;
//         wirefilter_rust_allocated_str_t msg;
//     } err;
//     struct {
//         uint8_t _res2;
//         uint64_t hash;
//     } ok;
// } wirefilter_hashing_result_t;

const wirefilter_hashing_result_t_err = Struct({
    success: ref.types.uint8,
    // _res1: ref.types.uint8,
    msg: wirefilter_rust_allocated_str_t,
});

const wirefilter_hashing_result_t_ok = Struct({
    success: ref.types.uint8,
    // _res2: ref.types.uint8,
    hash: ref.types.uint64,
});

const wirefilter_hashing_result_t = Union({
    err: wirefilter_hashing_result_t_err,
    ok: wirefilter_hashing_result_t_ok,
});

//
// typedef enum {
//     WIREFILTER_TYPE_TAG_IP,
//     WIREFILTER_TYPE_TAG_BYTES,
//     WIREFILTER_TYPE_TAG_INT,
//     WIREFILTER_TYPE_TAG_BOOL,
//     WIREFILTER_TYPE_TAG_ARRAY,
//     WIREFILTER_TYPE_TAG_MAP,
// } wirefilter_type_tag_t;

export enum wirefilter_type_tag_t {
    WIREFILTER_TYPE_TAG_IP,
    WIREFILTER_TYPE_TAG_BYTES,
    WIREFILTER_TYPE_TAG_INT,
    WIREFILTER_TYPE_TAG_BOOL,
    WIREFILTER_TYPE_TAG_ARRAY,
    WIREFILTER_TYPE_TAG_MAP,
}

// typedef struct {
//     uint8_t tag;
//     void *data;
// } wirefilter_type_t;

const wirefilter_type_t = Struct({
    tag: ref.types.uint8,
    data: ref.refType(ref.types.void),
});

// static const wirefilter_type_t WIREFILTER_TYPE_IP = {.tag = WIREFILTER_TYPE_TAG_IP, .data = NULL};

export const WIREFILTER_TYPE_IP = new wirefilter_type_t({
    tag: wirefilter_type_tag_t.WIREFILTER_TYPE_TAG_IP,
    data: null
});

// static const wirefilter_type_t WIREFILTER_TYPE_BYTES = {.tag = WIREFILTER_TYPE_TAG_BYTES, .data = NULL};

export const WIREFILTER_TYPE_BYTES = new wirefilter_type_t({
    tag: wirefilter_type_tag_t.WIREFILTER_TYPE_TAG_BYTES,
    data: null
});

// static const wirefilter_type_t WIREFILTER_TYPE_INT = {.tag = WIREFILTER_TYPE_TAG_INT, .data = NULL};

export const WIREFILTER_TYPE_INT = new wirefilter_type_t({
    tag: wirefilter_type_tag_t.WIREFILTER_TYPE_TAG_INT,
    data: null
});

// static const wirefilter_type_t WIREFILTER_TYPE_BOOL = {.tag = WIREFILTER_TYPE_TAG_BOOL, .data = NULL};

export const WIREFILTER_TYPE_BOOL = new wirefilter_type_t({
    tag: wirefilter_type_tag_t.WIREFILTER_TYPE_TAG_BOOL,
    data: null
});

//
// typedef enum {
//     WIREFILTER_PANIC_CATCHER_FALLBACK_MODE_CONTINUE = 0,
//     WIREFILTER_PANIC_CATCHER_FALLBACK_MODE_ABORT = 1,
// } wirefilter_panic_catcher_fallback_mode_t;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
enum wirefilter_panic_catcher_fallback_mode_t {
    WIREFILTER_PANIC_CATCHER_FALLBACK_MODE_CONTINUE = 0,
    WIREFILTER_PANIC_CATCHER_FALLBACK_MODE_ABORT = 1,
}

//
// void wirefilter_set_panic_catcher_hook();

lib.wirefilter_set_panic_catcher_hook = [ref.types.void, []];

// wirefilter_boolean_result_t wirefilter_set_panic_catcher_fallback_mode(uint8_t mode);

lib.wirefilter_set_panic_catcher_fallback_mode = [wirefilter_boolean_result_t, [
    ref.types.uint8
]];

// void wirefilter_enable_panic_catcher();

lib.wirefilter_enable_panic_catcher = [ref.types.void, []];

// void wirefilter_disable_panic_catcher();

lib.wirefilter_disable_panic_catcher = [ref.types.void, []];

//
// wirefilter_scheme_t *wirefilter_create_scheme();

lib.wirefilter_create_scheme = [ref.refType(wirefilter_scheme_t), []];

// void wirefilter_free_scheme(wirefilter_scheme_t *scheme);

lib.wirefilter_free_scheme = [ref.types.void, [
    ref.refType(wirefilter_scheme_t),
]];

// wirefilter_type_t wirefilter_create_map_type(wirefilter_type_t type);

lib.wirefilter_create_map_type = [wirefilter_type_t, [
    wirefilter_type_t
]];

//
// wirefilter_type_t wirefilter_create_array_type(wirefilter_type_t type);

lib.wirefilter_create_array_type = [wirefilter_type_t, [
    wirefilter_type_t
]];

//
// bool wirefilter_add_type_field_to_scheme(
//     wirefilter_scheme_t *scheme,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_type_t type
// );

lib.wirefilter_add_type_field_to_scheme = [ref.types.bool, [
    ref.refType(wirefilter_scheme_t),
    wirefilter_externally_allocated_str_t,
    wirefilter_type_t,
]];

// wirefilter_list_t *wirefilter_create_always_list();

lib.wirefilter_create_always_list = [ref.refType(wirefilter_list_t), []];

// wirefilter_list_t *wirefilter_create_never_list();

lib.wirefilter_create_never_list = [ref.refType(wirefilter_list_t), []];

// bool wirefilter_add_type_list_to_scheme(
//     wirefilter_scheme_t *scheme,
//     wirefilter_type_t type,
//     wirefilter_list_t *list
// );

lib.wirefilter_add_type_list_to_scheme = [ref.types.bool, [
    ref.refType(wirefilter_scheme_t),
    wirefilter_type_t,
    ref.refType(wirefilter_list_t),
]];

//
// wirefilter_parsing_result_t wirefilter_parse_filter(
//     const wirefilter_scheme_t *scheme,
//     wirefilter_externally_allocated_str_t input
// );

lib.wirefilter_parse_filter = [wirefilter_parsing_result_t, [
    ref.refType(wirefilter_scheme_t),
    wirefilter_externally_allocated_str_t,
]];

// void wirefilter_free_filter_ast(wirefilter_filter_ast_t *ast);

lib.wirefilter_free_filter_ast = [ref.types.void, [
    ref.refType(wirefilter_filter_ast_t)
]];

//
// void wirefilter_free_parsing_result(wirefilter_parsing_result_t result);

lib.wirefilter_free_parsing_result = [ref.types.void, [
    wirefilter_parsing_result_t,
]];

// wirefilter_compiling_result_t wirefilter_compile_filter(wirefilter_filter_ast_t *ast);

lib.wirefilter_compile_filter = [wirefilter_compiling_result_t, [
    ref.refType(wirefilter_filter_ast_t)
]];

//
// void wirefilter_free_compiling_result(wirefilter_compiling_result_t result);

lib.wirefilter_compile_filter = [ref.types.void, [
    wirefilter_compiling_result_t
]];

// void wirefilter_free_compiling_result(wirefilter_compiling_result_t result);

lib.wirefilter_free_compiling_result = [ref.types.void, [
    wirefilter_compiling_result_t
]];

//
// wirefilter_compiling_result_t wirefilter_compile_filter(wirefilter_filter_ast_t *ast);

lib.wirefilter_compile_filter = [wirefilter_compiling_result_t, [
    ref.refType(wirefilter_filter_ast_t),
]];

// void wirefilter_free_compiled_filter(wirefilter_filter_t *filter);

lib.wirefilter_free_compiled_filter = [ref.types.void, [
    ref.refType(wirefilter_filter_t),
]];

//
// wirefilter_execution_context_t *wirefilter_create_execution_context(
//     const wirefilter_scheme_t *scheme
// );

lib.wirefilter_create_execution_context = [ref.refType(wirefilter_execution_context_t), [
    ref.refType(wirefilter_scheme_t),
]];

// void wirefilter_free_execution_context(
//     wirefilter_execution_context_t *exec_ctx
// );

lib.wirefilter_free_execution_context = [ref.types.void, [
    ref.refType(wirefilter_execution_context_t),
]];

//
// bool wirefilter_add_int_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     int32_t value
// );

lib.wirefilter_add_int_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    ref.types.int32,
]];

//
// bool wirefilter_add_bytes_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_externally_allocated_byte_arr_t value
// );

lib.wirefilter_add_bytes_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    wirefilter_externally_allocated_byte_arr_t,
]];

//
// bool wirefilter_add_ipv6_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     uint8_t value[16]
// );

lib.wirefilter_add_ipv6_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_ipv4_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     uint8_t value[4]
// );

lib.wirefilter_add_ipv4_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_bool_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     bool value
// );

lib.wirefilter_add_bool_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    ref.types.bool,
]];

// bool wirefilter_add_map_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_map_t *map
// );

lib.wirefilter_add_map_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    ref.refType(wirefilter_map_t),
]];

//
// bool wirefilter_add_array_value_to_execution_context(
//     wirefilter_execution_context_t *exec_ctx,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_array_t *array
// );

lib.wirefilter_add_array_value_to_execution_context = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t),
    wirefilter_externally_allocated_str_t,
    ref.refType(wirefilter_array_t),
]];

//
// wirefilter_map_t *wirefilter_create_map(wirefilter_type_t type);

lib.wirefilter_create_map = [ref.refType(wirefilter_map_t), [
    wirefilter_type_t
]];

//
// bool wirefilter_add_int_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     int32_t value
// );

lib.wirefilter_add_int_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    ref.types.int32,
]];

//
// bool wirefilter_add_bytes_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_externally_allocated_byte_arr_t value
// );

lib.wirefilter_add_bytes_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    wirefilter_externally_allocated_byte_arr_t,
]];

//
// bool wirefilter_add_ipv6_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     uint8_t value[16]
// );

lib.wirefilter_add_ipv6_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_ipv4_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     uint8_t value[4]
// );

lib.wirefilter_add_ipv4_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_bool_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     bool value
// );

lib.wirefilter_add_bool_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    ref.types.bool,
]];

//
// bool wirefilter_add_map_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_map_t *value
// );

lib.wirefilter_add_map_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    ref.refType(wirefilter_map_t),
]];

//
// bool wirefilter_add_array_value_to_map(
//     wirefilter_map_t *map,
//     wirefilter_externally_allocated_str_t name,
//     wirefilter_array_t *value
// );

lib.wirefilter_add_array_value_to_map = [ref.types.bool, [
    ref.refType(wirefilter_map_t),
    wirefilter_externally_allocated_str_t,
    ref.refType(wirefilter_array_t),
]];

//
// void wirefilter_free_map(wirefilter_map_t *map);

lib.wirefilter_free_map = [ref.types.void, [
    ref.refType(wirefilter_map_t)
]];

//
// wirefilter_array_t *wirefilter_create_array(wirefilter_type_t type);

lib.wirefilter_create_array = [ref.refType(wirefilter_array_t), [
    wirefilter_type_t
]];

//
// bool wirefilter_add_int_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     int32_t value
// );

lib.wirefilter_add_int_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    ref.types.int32,
]];

//
// bool wirefilter_add_bytes_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     wirefilter_externally_allocated_byte_arr_t value
// );

lib.wirefilter_add_bytes_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    wirefilter_externally_allocated_byte_arr_t,
]];

//
// bool wirefilter_add_ipv6_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     uint8_t value[16]
// );

lib.wirefilter_add_ipv6_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_ipv4_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     uint8_t value[4]
// );

lib.wirefilter_add_ipv4_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    Array(ref.types.uint8),
]];

//
// bool wirefilter_add_bool_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     bool value
// );

lib.wirefilter_add_ipv4_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    ref.types.bool,
]];

//
// bool wirefilter_add_map_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     wirefilter_map_t *value
// );

lib.wirefilter_add_map_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    ref.refType(wirefilter_map_t),
]];

//
// bool wirefilter_add_array_value_to_array(
//     wirefilter_array_t *array,
//     uint32_t index,
//     wirefilter_array_t *value
// );

lib.wirefilter_add_array_value_to_array = [ref.types.bool, [
    ref.refType(wirefilter_array_t),
    ref.types.uint32,
    ref.refType(wirefilter_array_t),
]];

//
// void wirefilter_free_array(wirefilter_array_t *array);

lib.wirefilter_free_array = [ref.types.void, [ref.refType(wirefilter_array_t)]];

//
// wirefilter_matching_result_t wirefilter_match(
//     const wirefilter_filter_t *filter,
//     const wirefilter_execution_context_t *exec_ctx
// );

lib.wirefilter_match = [wirefilter_matching_result_t, [
    ref.refType(wirefilter_filter_t),
    ref.refType(wirefilter_execution_context_t),
]];

// void wirefilter_free_matching_result(wirefilter_matching_result_t result);

lib.wirefilter_free_matching_result = [ref.types.void, [wirefilter_matching_result_t]];

//
// wirefilter_using_result_t wirefilter_filter_uses(
//     const wirefilter_filter_ast_t *ast,
//     wirefilter_externally_allocated_str_t field_name
// );

lib.wirefilter_filter_uses = [wirefilter_using_result_t, [
    ref.refType(wirefilter_filter_ast_t),
    wirefilter_externally_allocated_str_t,
]];

// wirefilter_using_result_t wirefilter_filter_uses_list(
//     const wirefilter_filter_ast_t *ast,
//     wirefilter_externally_allocated_str_t field_name
// );

lib.wirefilter_filter_uses_list = [wirefilter_using_result_t, [
    ref.refType(wirefilter_filter_ast_t),
    wirefilter_externally_allocated_str_t,
]];

// wirefilter_hashing_result_t wirefilter_get_filter_hash(const wirefilter_filter_ast_t *ast);

lib.wirefilter_get_filter_hash = [wirefilter_hashing_result_t, [
    ref.refType(wirefilter_filter_ast_t),
]];

// void wirefilter_free_hashing_result(wirefilter_hashing_result_t result);

lib.wirefilter_free_hashing_result = [ref.types.void, [
    wirefilter_hashing_result_t
]];

//
// wirefilter_serializing_result_t wirefilter_serialize_filter_to_json(
//     const wirefilter_filter_ast_t *ast
// );

lib.wirefilter_serialize_filter_to_json = [wirefilter_serializing_result_t, [
    ref.refType(wirefilter_filter_ast_t),
]];

// wirefilter_serializing_result_t wirefilter_serialize_scheme_to_json(
//     const wirefilter_scheme_t *scheme
// );

lib.wirefilter_serialize_scheme_to_json = [wirefilter_serializing_result_t, [
    ref.refType(wirefilter_scheme_t)
]];

//
// wirefilter_serializing_result_t wirefilter_serialize_type_to_json(
//     const wirefilter_type_t *type
// );

lib.wirefilter_serialize_type_to_json = [wirefilter_serializing_result_t, [
    ref.refType(wirefilter_type_t)
]];

//
// wirefilter_serializing_result_t wirefilter_serialize_execution_context_to_json(
//     const wirefilter_execution_context_t *exec_ctx
// );

lib.wirefilter_serialize_execution_context_to_json = [wirefilter_serializing_result_t, [
    ref.refType(wirefilter_execution_context_t)
]];

//
// void wirefilter_free_serializing_result(wirefilter_serializing_result_t result);

lib.wirefilter_free_serializing_result = [ref.types.void, [
    wirefilter_serializing_result_t
]];

//
// void wirefilter_free_string(wirefilter_rust_allocated_str_t str);

lib.wirefilter_free_string = [ref.types.void, [
    wirefilter_rust_allocated_str_t,
]];

//
// wirefilter_static_rust_allocated_str_t wirefilter_get_version();

lib.wirefilter_get_version = [wirefilter_static_rust_allocated_str_t, []];

//
// #ifdef __cplusplus
// }
// #endif
//
// #endif // _WIREFILTER_H_

// patch started

lib.add_standard_functions = [ref.types.void, [
    ref.refType(wirefilter_scheme_t)
]];

lib.set_all_lists_to_nevermatch = [ref.types.bool, [
    ref.refType(wirefilter_execution_context_t)
]];

// patch ended

export function initWirefilter(path: string): any {
    return ffi.Library(path, lib);
}
