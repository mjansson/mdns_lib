/* mdns.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform mDNS and DNS-DS library in C based
 * on our foundation and network libraries.
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


MDNS_API int     mdns_initialize( void );
MDNS_API void    mdns_shutdown( void );
MDNS_API bool    mdns_is_initialized( void );
