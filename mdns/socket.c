/* socket.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
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

#include <foundation/foundation.h>
#include <mdns/mdns.h>
#include <network/network.h>

socket_t*
mdns_socket_allocate(void) {
	socket_t* sock = udp_socket_allocate();
	if (!mdns_socket_bind(sock)) {
		socket_deallocate(sock);
		return nullptr;
	}
	return sock;
}

bool
mdns_socket_bind(socket_t* sock) {
	if (socket_type(sock) != NETWORK_SOCKETTYPE_UDP)
		return false;

	network_address_ipv4_t mdns_multicast_addr, mdns_any_addr;

	network_address_t* multicast_addr = network_address_ipv4_initialize(&mdns_multicast_addr);
	network_address_ipv4_set_ip(multicast_addr, network_address_ipv4_make_ip(224U, 0U, 0U, 251U));
	//TODO: IPv6 support, send to [FF02::FB]:5353

	network_address_t* any_addr = network_address_ipv4_initialize(&mdns_any_addr);

	socket_set_reuse_address(sock, true);
	socket_set_reuse_port(sock, true);

	if (!socket_bind(sock, any_addr)) {
		log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to bind mDNS socket"));
		return false;
	}
	if (!socket_set_multicast_group(sock, multicast_addr, true)) {
		log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to set multicast group on mDNS socket"));
		return false;
	}

	return true;
}
