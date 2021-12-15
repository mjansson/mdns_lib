/* mdns.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

#include <mdns/mdns.h>

#include <foundation/foundation.h>
#include <network/network.h>

static bool mdns_initialized = false;

extern const uint8_t mdns_services_query[46];

const uint8_t mdns_services_query[46] = {
    // Query ID
    0x00, 0x00,
    // Flags
    0x00, 0x00,
    // 1 question
    0x00, 0x01,
    // No answer, authority or additional RRs
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // _services._dns-sd._udp.local.
    0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x07, '_', 'd', 'n', 's', '-', 's', 'd', 0x04, '_', 'u', 'd',
    'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    // PTR record
    0x00, MDNS_RECORDTYPE_PTR,
    // QU (unicast response) and class IN
    0x80, MDNS_CLASS_IN};

int
mdns_module_initialize(const mdns_config_t config) {
	FOUNDATION_UNUSED(config);

	if (mdns_initialized)
		return 0;

	mdns_initialized = true;

	return 0;
}

void
mdns_module_finalize(void) {
	if (!mdns_initialized)
		return;

	mdns_initialized = false;
}

bool
mdns_module_is_initialized(void) {
	return mdns_initialized;
}

uint16_t
mdns_ntohs(const void* data) {
	uint16_t aligned;
	memcpy(&aligned, data, sizeof(uint16_t));
	return ntohs(aligned);
}

uint32_t
mdns_ntohl(const void* data) {
	uint32_t aligned;
	memcpy(&aligned, data, sizeof(uint32_t));
	return ntohl(aligned);
}

void*
mdns_htons(void* data, uint16_t val) {
	val = htons(val);
	memcpy(data, &val, sizeof(uint16_t));
	return pointer_offset(data, sizeof(uint16_t));
}

void*
mdns_htonl(void* data, uint32_t val) {
	val = htonl(val);
	memcpy(data, &val, sizeof(uint32_t));
	return pointer_offset(data, sizeof(uint32_t));
}

int
mdns_unicast_send(socket_t* sock, const network_address_t* to, const void* buffer, size_t size) {
	if (udp_socket_sendto(sock, buffer, size, to) != size)
		return -1;
	return 0;
}

int
mdns_multicast_send(socket_t* sock, const void* buffer, size_t size) {
	struct sockaddr_storage addr_storage;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct sockaddr* saddr = (struct sockaddr*)&addr_storage;
	socklen_t saddrlen = sizeof(struct sockaddr_storage);
	if (sock->family == NETWORK_ADDRESSFAMILY_IPV4) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
#ifdef __APPLE__
		addr.sin_len = sizeof(addr);
#endif
		addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
		addr.sin_port = htons((unsigned short)MDNS_PORT);
		saddr = (struct sockaddr*)&addr;
		saddrlen = sizeof(addr);
	} else if (sock->family == NETWORK_ADDRESSFAMILY_IPV6) {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
#ifdef __APPLE__
		addr6.sin6_len = sizeof(addr6);
#endif
		addr6.sin6_addr.s6_addr[0] = 0xFF;
		addr6.sin6_addr.s6_addr[1] = 0x02;
		addr6.sin6_addr.s6_addr[15] = 0xFB;
		addr6.sin6_port = htons((unsigned short)MDNS_PORT);
		saddr = (struct sockaddr*)&addr6;
		saddrlen = sizeof(addr6);
	} else {
		return -1;
	}

	if (sendto(sock->fd, (const char*)buffer, (mdns_size_t)size, 0, saddr, saddrlen) < 0)
		return -1;
	return 0;
}
