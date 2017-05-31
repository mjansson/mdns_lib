/* string.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C based
 * on our foundation and network libraries. The implementation is based on RFC 6762
 * and RFC 6763.
 *
 * The latest source code maintained by Rampant Pixels is always available at
 *
 * https://github.com/rampantpixels/mdns_lib
 *
 * The foundation and network library source code maintained by Rampant Pixels
 * is always available at
 *
 * https://github.com/rampantpixels/foundation_lib
 *
 * https://github.com/rampantpixels/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#pragma once

#include <foundation/platform.h>

#include <mdns/types.h>

MDNS_API string_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset,
                    char* str, size_t capacity);

MDNS_API bool
mdns_string_skip(const void* buffer, size_t size, size_t* offset);

MDNS_API bool
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs,
                  const void* buffer_rhs, size_t size_rhs, size_t* ofs_rhs);

MDNS_API void*
mdns_string_make(void* data, size_t capacity, const char* name, size_t length);
