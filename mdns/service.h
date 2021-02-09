/* service.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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
#include <network/types.h>

#include <mdns/types.h>

//! Service incoming multicast DNS-SD and mDNS query requests. The socket should have been bound to port MDNS_PORT using
//! mdns_socket_bind. Buffer must be 32 bit aligned. Returns the number of queries parsed.
static size_t
mdns_service_listen(socket_t* socket, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data);
