/* types.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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
#include <foundation/types.h>
#include <foundation/types.h>
#include <network/types.h>

#include <mdns/build.h>

#define MDNS_PORT 5353
#define MDNS_UNICAST_RESPONSE 0x8000U
#define MDNS_CACHE_FLUSH 0x8000U
#define MDNS_MAX_SUBSTRINGS 64

enum mdns_record_type {
	MDNS_RECORDTYPE_IGNORE = 0,
	// Address
	MDNS_RECORDTYPE_A = 1,
	// Domain Name pointer
	MDNS_RECORDTYPE_PTR = 12,
	// Arbitrary text string
	MDNS_RECORDTYPE_TXT = 16,
	// IP6 Address [Thomson]
	MDNS_RECORDTYPE_AAAA = 28,
	// Server Selection [RFC2782]
	MDNS_RECORDTYPE_SRV = 33,
	// Any available records
	MDNS_RECORDTYPE_ANY = 255
};

enum mdns_entry_type {
	MDNS_ENTRYTYPE_QUESTION = 0,
	MDNS_ENTRYTYPE_ANSWER = 1,
	MDNS_ENTRYTYPE_AUTHORITY = 2,
	MDNS_ENTRYTYPE_ADDITIONAL = 3,
	MDNS_ENTRYTYPE_END = 255
};

enum mdns_class { MDNS_CLASS_IN = 1 };

typedef enum mdns_record_type mdns_record_type_t;
typedef enum mdns_entry_type mdns_entry_type_t;
typedef enum mdns_class mdns_class_t;

typedef int (*mdns_record_callback_fn)(socket_t* sock, const network_address_t* from, mdns_entry_type_t entry,
                                       uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
                                       const void* data, size_t size, size_t name_offset, size_t name_length,
                                       size_t record_offset, size_t record_length, void* user_data);

typedef struct mdns_config_t mdns_config_t;
typedef struct mdns_string_pair_t mdns_string_pair_t;
typedef struct mdns_string_table_t mdns_string_table_t;
typedef struct mdns_record_t mdns_record_t;
typedef struct mdns_record_srv_t mdns_record_srv_t;
typedef struct mdns_record_ptr_t mdns_record_ptr_t;
typedef struct mdns_record_a_t mdns_record_a_t;
typedef struct mdns_record_aaaa_t mdns_record_aaaa_t;
typedef struct mdns_record_txt_t mdns_record_txt_t;

#ifdef _WIN32
typedef int mdns_size_t;
typedef int mdns_ssize_t;
#else
typedef size_t mdns_size_t;
typedef ssize_t mdns_ssize_t;
#endif

struct mdns_config_t {
	int unused;
};

struct mdns_string_pair_t {
	size_t offset;
	size_t length;
	int ref;
};

struct mdns_string_table_t {
	size_t offset[16];
	size_t count;
	size_t next;
};

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	string_const_t name;
};

struct mdns_record_ptr_t {
	string_const_t name;
};

struct mdns_record_a_t {
	struct sockaddr_in addr;
};

struct mdns_record_aaaa_t {
	struct sockaddr_in6 addr;
};

struct mdns_record_txt_t {
	string_const_t key;
	string_const_t value;
};

struct mdns_record_t {
	string_const_t name;
	mdns_record_type_t type;
	union mdns_record_data {
		mdns_record_ptr_t ptr;
		mdns_record_srv_t srv;
		mdns_record_a_t a;
		mdns_record_aaaa_t aaaa;
		mdns_record_txt_t txt;
	} data;
};

struct mdns_header_t {
	uint16_t query_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
};
