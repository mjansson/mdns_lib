/* socket.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

//! Bind a socket for mDNS/DNS-SD. To bind the socket to a specific interface, pass in the appropriate socket address,
//! otherwise use IPv4 INADDR_ANY or IPv6 in6addr_any. To send one-shot discovery requests and queries set 0 as port to
//! assign a random user level ephemeral port. To run discovery service listening for incoming discoveries and queries,
//! you must set MDNS_PORT as port.
MDNS_API bool
mdns_socket_bind(socket_t* socket, const network_address_t* address);
