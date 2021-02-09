/* mdns.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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
#include <mdns/hashstrings.h>

#include <mdns/socket.h>
#include <mdns/query.h>
#include <mdns/record.h>
#include <mdns/service.h>
#include <mdns/string.h>
#include <mdns/discovery.h>

MDNS_API int
mdns_module_initialize(const mdns_config_t config);

MDNS_API void
mdns_module_finalize(void);

MDNS_API bool
mdns_module_is_initialized(void);

MDNS_API version_t
mdns_module_version(void);

MDNS_API int
mdns_unicast_send(socket_t* sock, const network_address_t* to, const void* buffer, size_t size);

MDNS_API int
mdns_multicast_send(socket_t* sock, const void* buffer, size_t size);

MDNS_API uint16_t
mdns_ntohs(const void* data);

MDNS_API uint32_t
mdns_ntohl(const void* data);

MDNS_API void*
mdns_htons(void* data, uint16_t val);

MDNS_API void*
mdns_htonl(void* data, uint32_t val);
