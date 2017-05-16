/* build.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
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


#if defined(MDNS_COMPILE) && MDNS_COMPILE
#  ifdef __cplusplus
#  define MDNS_EXTERN extern "C"
#  define MDNS_API extern "C"
#  else
#  define MDNS_EXTERN extern
#  define MDNS_API extern
#  endif
#else
#  ifdef __cplusplus
#  define MDNS_EXTERN extern "C"
#  define MDNS_API extern "C"
#  else
#  define MDNS_EXTERN extern
#  define MDNS_API extern
#  endif
#endif


#define MDNS_QUERY_SIZE_DEFAULT             512
