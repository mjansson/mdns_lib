/* service.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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
 **
 * https://github.com/rampantpixels/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#pragma once

#include <foundation/platform.h>

#include <mdns/types.h>
#include <mdns/hashstrings.h>

MDNS_API mdns_service_t*
mdns_service_allocate(void);

MDNS_API void
mdns_service_initialize(mdns_service_t* service);

MDNS_API void
mdns_service_finalize(mdns_service_t* service);

MDNS_API void
mdns_service_deallocate(mdns_service_t* service);

MDNS_API object_t
mdns_service_socket(mdns_service_t* service);

MDNS_API void
mdns_service_set_socket(object_t sock);

MDNS_API void
mdns_service_run(mdns_service_t* service);

MDNS_API void
mdns_service_process(mdns_service_t* service);

MDNS_API void
mdns_services_add(mdns_service_t* service, const char* name, mdns_record_t* record);

MDNS_API void
mdns_service_remove(mdns_service_t* service, const char* name);

MDNS_API mdns_record_t*
mdns_service_query(mdns_service_t* service, const mdns_query_t* query);
