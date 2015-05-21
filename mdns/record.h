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
 * https://github.com/rampantpixels/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#pragma once

#include <foundation/platform.h>

#include <mdns/types.h>
#include <mdns/hashstrings.h>


MDNS_API mdns_record_t*       mdns_record_allocate( void );
MDNS_API void                 mdns_record_initialize( mdns_record_t* record );
MDNS_API void                 mdns_record_finalize( mdns_record_t* record );
MDNS_API void                 mdns_record_deallocate( mdns_record_t* record );

MDNS_API void                 mdns_record_add_address( mdns_record_t* record, network_address_t* address );
MDNS_API void                 mdns_record_remove_address( mdns_record_t* record, network_address_t* address );
MDNS_API network_address_t**  mdns_record_address( mdns_record_t* record );

MDNS_API void                 mdns_record_add_txt( mdns_record_t* record, const char* variable, const char* value );
MDNS_API void                 mdns_record_remove_txt( mdns_record_t* record, const char* variable );
MDNS_API mdns_txt_t*          mdns_record_txt( mdns_record_t* record );

