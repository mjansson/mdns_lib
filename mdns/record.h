/* record.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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
#include <network/types.h>

#include <mdns/types.h>

MDNS_API size_t
mdns_records_parse(const network_address_t* from, const void* buffer, size_t size, size_t* offset,
                   mdns_entry_type_t type, size_t records, mdns_record_callback_fn callback);

MDNS_API string_t
mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

MDNS_API mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

MDNS_API network_address_ipv4_t
mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length);

MDNS_API network_address_ipv6_t
mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length);

MDNS_API size_t
mdns_record_parse_txt(const void* buffer, size_t size, size_t offset, size_t length,
                      mdns_record_txt_t* records, size_t capacity);
