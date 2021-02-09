/* query.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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
#include <network/types.h>

//! Send a multicast mDNS query on the given socket for the given service name. The supplied buffer
//  will be used to build the query packet and must be 32 bit aligned. The query ID can be set to
//  non-zero to filter responses, however the RFC states that the query ID SHOULD be set to 0 for
//  multicast queries. The query will request a unicast response if the socket is bound to an
//  ephemeral port, or a multicast response if the socket is bound to mDNS port 5353. Returns the
//  used query ID, or <0 if error.
MDNS_API int
mdns_query_send(socket_t* sock, mdns_record_type_t type, const char* name, size_t length, void* buffer, size_t capacity,
                uint16_t query_id);

//! Receive unicast responses to a mDNS query sent with mdns_discovery_recv, optionally filtering
//  out any responses not matching the given query ID. Set the query ID to 0 to parse
//  all responses, even if it is not matching the query ID set in a specific query. Any data will
//  be piped to the given callback for parsing. Buffer must be 32 bit aligned. Returns the number
//  of responses parsed.
MDNS_API size_t
mdns_query_recv(socket_t* sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data,
                int query_id);

//! Send a unicast or multicast mDNS query answer with a single record to the given address. The
//  answer will be sent multicast if address size is 0, otherwise it will be sent unicast to the
//  given address. Use the top bit of the query class field (MDNS_UNICAST_RESPONSE) to determine
//  if the answer should be sent unicast (bit set) or multicast (bit not set). Buffer must be
//  32 bit aligned. Returns 0 if success, or <0 if error.
MDNS_API int
mdns_query_answer(socket_t* sock, const network_address_t* address, void* buffer, size_t capacity, uint16_t query_id,
                  const char* service, size_t service_length, const char* hostname, size_t hostname_length,
                  uint32_t ipv4, const uint8_t* ipv6, uint16_t port, const char* txt, size_t txt_length);
