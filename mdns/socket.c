/* socket.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

#include <foundation/foundation.h>
#include <mdns/mdns.h>
#include <network/network.h>

bool
mdns_socket_bind(socket_t* sock, const network_address_t* address) {
	if (socket_type(sock) != NETWORK_SOCKETTYPE_UDP)
		return false;
	if (sock->state != SOCKETSTATE_NOTCONNECTED)
		return false;
	if (!address)
		return false;

	socket_set_reuse_address(sock, true);
	socket_set_reuse_port(sock, true);
	socket_set_blocking(sock, false);

	if (sock->fd < 0)
		sock->family = address->family;

	if (!socket_create(sock))
		return false;

	network_address_t multicast_addr;
	if (sock->family == NETWORK_ADDRESSFAMILY_IPV4) {
		network_address_ipv4_initialize((network_address_ipv4_t*)&multicast_addr);
		network_address_ipv4_set_ip(&multicast_addr, (((uint32_t)224U) << 24U) | (uint32_t)251U);
		if (!socket_set_multicast_group(sock, &multicast_addr, address, true)) {
			//log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to set multicast group on mDNS socket"));
			return false;
		}
		if (!address) {
			network_address_ipv4_set_ip(&multicast_addr, INADDR_ANY);
			address = &multicast_addr;
		}
	} else if (sock->family == NETWORK_ADDRESSFAMILY_IPV6) {
		network_address_ipv6_initialize((network_address_ipv6_t*)&multicast_addr);
		struct in6_addr ip = {0};
		ip.s6_addr[0] = 0xFF;
		ip.s6_addr[1] = 0x02;
		ip.s6_addr[15] = 0xFB;
		network_address_ipv6_set_ip(&multicast_addr, ip);
		if (!socket_set_multicast_group(sock, &multicast_addr, address, true)) {
			//log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to set multicast group on mDNS socket"));
			return false;
		}
		if (!address) {
			network_address_ipv6_set_ip(&multicast_addr, in6addr_any);
			address = &multicast_addr;
		}
	} else {
		return false;
	}

	if (!socket_bind(sock, address)) {
		log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to bind mDNS socket"));
		return false;
	}

	return true;
}
