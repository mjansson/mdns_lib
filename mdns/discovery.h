/* discovery.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

//! Send a multicast DNS-SD reqeuest on the given socket to discover available services. Returns
//  0 on success, or <0 if error.
MDNS_API int
mdns_discovery_send(socket_t* sock);

//! Recieve unicast responses to a DNS-SD sent with mdns_discovery_send. Any data will be piped to
//  the given callback for parsing. Buffer must be 32 bit aligned. Returns the number of
//  responses parsed.
MDNS_API size_t
mdns_discovery_recv(socket_t* sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data);

//! Send a unicast DNS-SD answer with a single record to the given address. Buffer must be 32 bit
//  aligned. Returns 0 if success, or <0 if error.
MDNS_API int
mdns_discovery_answer(socket_t* sock, const network_address_t* address, void* buffer, size_t capacity,
                      const char* record, size_t length);
