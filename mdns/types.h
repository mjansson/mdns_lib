/* types.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
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
#include <foundation/types.h>
#include <network/types.h>

#include <mdns/build.h>

typedef struct mdns_config_t         mdns_config_t;
typedef struct mdns_query_t          mdns_query_t;
typedef struct mdns_query_fixed_t    mdns_query_fixed_t;
typedef struct mdns_record_t         mdns_record_t;
typedef struct mdns_response_t       mdns_response_t;
typedef struct mdns_service_t        mdns_service_t;
typedef struct mdns_txt_t            mdns_txt_t;

struct mdns_config_t {
	int       unused;
};

struct mdns_query_t {
	uint16_t  size;
	uint16_t  capacity;
	char      buffer[];
};

struct mdns_query_fixed_t {
	uint16_t  size;
	uint16_t  capacity;
	char      buffer[MDNS_QUERY_SIZE_DEFAULT];
};
