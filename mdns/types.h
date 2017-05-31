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

enum mdns_record_type {
	MDNS_RECORDTYPE_IGNORE = 0,
	//Address
	MDNS_RECORDTYPE_A = 1,
	//Domain Name pointer
	MDNS_RECORDTYPE_PTR = 12,
	//Arbitrary text string
	MDNS_RECORDTYPE_TXT = 16,
	//IP6 Address [Thomson]
	MDNS_RECORDTYPE_AAAA = 28,
	//Server Selection [RFC2782]
	MDNS_RECORDTYPE_SRV = 33
};

enum mdns_entry_type {
	MDNS_ENTRYTYPE_ANSWER = 1,
	MDNS_ENTRYTYPE_AUTHORITY = 2,
	MDNS_ENTRYTYPE_ADDITIONAL = 3
};

enum mdns_class {
	MDNS_CLASS_IN = 1
};

typedef enum mdns_record_type  mdns_record_type_t;
typedef enum mdns_entry_type   mdns_entry_type_t;
typedef enum mdns_class        mdns_class_t;

typedef int (* mdns_record_callback_fn)(const network_address_t* from,
                                        mdns_entry_type_t entry, uint16_t type,
                                        uint16_t rclass, uint32_t ttl,
                                        const void* data, size_t size, size_t offset, size_t length);

typedef struct mdns_config_t       mdns_config_t;
typedef struct mdns_record_srv_t   mdns_record_srv_t;
typedef struct mdns_record_txt_t   mdns_record_txt_t;

struct mdns_config_t {
	int       unused;
};

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	string_t name;
};

struct mdns_record_txt_t {
	string_const_t key;
	string_const_t value;
};
