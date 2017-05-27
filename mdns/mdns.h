/* mdns.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
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
#include <mdns/hashstrings.h>

#include <mdns/socket.h>
#include <mdns/query.h>
#include <mdns/record.h>
#include <mdns/response.h>
#include <mdns/service.h>
#include <mdns/string.h>
#include <mdns/discovery.h>

MDNS_API int
mdns_module_initialize(const mdns_config_t config);

MDNS_API void
mdns_module_shutdown(void);

MDNS_API bool
mdns_module_is_initialized(void);

MDNS_API version_t
mdns_module_version(void);
