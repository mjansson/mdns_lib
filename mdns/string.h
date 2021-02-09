/* string.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C based
 * on our foundation and network libraries. The implementation is based on RFC 6762
 * and RFC 6763.
 *
 * The latest source code maintained by Mattias Jansson is always available at
 *
 * https://github.com/mjansson/mdns_lib
 *
 * The foundation and network library source code maintained by Mattias Jansson
 * is always available at
 *
 * https://github.com/mjansson/foundation_lib
 * https://github.com/mjansson/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify
 * it without any restrictions.
 *
 */

#pragma once

#include <foundation/platform.h>

#include <mdns/types.h>

MDNS_API string_const_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset, char* str, size_t capacity);

MDNS_API int
mdns_string_skip(const void* buffer, size_t size, size_t* offset);

MDNS_API int
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs, const void* buffer_rhs, size_t size_rhs,
                  size_t* ofs_rhs);

MDNS_API void*
mdns_string_make(void* data, size_t capacity, const char* name, size_t length);

MDNS_API void*
mdns_string_make_ref(void* data, size_t capacity, size_t ref_offset);

MDNS_API void*
mdns_string_make_with_ref(void* data, size_t capacity, const char* name, size_t length, size_t ref_offset);
