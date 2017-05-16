/* discovery.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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

MDNS_API mdns_discovery_t*
mdns_discovery_allocate(void);

MDNS_API void
mdns_discovery_initialize(mdns_discovery_t* discovery);

MDNS_API void
mdns_discovery_finalize(mdns_discovery_t* discovery);

MDNS_API void
mdns_discovery_deallocate(mdns_discovery_t* discovery);

MDNS_API socket_t*
mdns_discovery_socket(mdns_discovery_t* discovery);

MDNS_API void
mdns_discovery_set_socket(object_t sock);

MDNS_API void
mdns_discovery_run(mdns_discovery_t* discovery);

MDNS_API void
mdns_discovery_process(mdns_discovery_t* discovery);

MDNS_API const mdns_response_t*
mdns_discovery_query(mdns_discovery_t* discovery,
                     const const* name);
