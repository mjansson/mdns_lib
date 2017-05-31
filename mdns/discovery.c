/* service.c  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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

#include <mdns/mdns.h>
#include <foundation/foundation.h>
#include <network/network.h>

static const uint8_t services_query[] = {
	// transaction id
	0x00, 0x00,
	// flags
	0x00, 0x00,
	// questions (count)
	0x00, 0x01,
	// answer RRs
	0x00, 0x00,
	// authority RRs
	0x00, 0x00,
	// additional RRs
	0x00, 0x00,
	// _services.
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	// _dns-sd.
	0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	// _udp.
	0x04, '_', 'u', 'd', 'p',
	// local.
	0x05, 'l', 'o', 'c', 'a', 'l',
	// string terminator
	0x00,
	// PTR (domain name pointer)
	0x00, MDNS_RECORDTYPE_PTR,
	// QU (unicast response) and class IN
	0x80, MDNS_CLASS_IN
};

void
mdns_discovery_send(socket_t* sock) {
	network_address_ipv4_t ipv4_multicast;
	network_address_t* mdns_multicast_addr = network_address_ipv4_initialize(&ipv4_multicast);
	network_address_ipv4_set_ip(mdns_multicast_addr, network_address_ipv4_make_ip(224U, 0U, 0U, 251U));
	network_address_ip_set_port(mdns_multicast_addr, 5353);
	udp_socket_sendto(sock, services_query, sizeof(services_query), mdns_multicast_addr);
}

size_t
mdns_discovery_recv(socket_t* sock, void* buffer, size_t capacity,
                    mdns_record_callback_fn callback) {
	const network_address_t* source;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &source);
	if (!data_size)
		return 0;

	uint16_t* data = (uint16_t*)buffer;

	uint16_t transaction_id = byteorder_bigendian16(*data++);
	uint16_t flags          = byteorder_bigendian16(*data++);
	uint16_t questions      = byteorder_bigendian16(*data++);
	uint16_t answer_rrs     = byteorder_bigendian16(*data++);
	uint16_t authority_rrs  = byteorder_bigendian16(*data++);
	uint16_t additional_rrs = byteorder_bigendian16(*data++);

	if (transaction_id || (flags != 0x8400))
		return 0; //Not a reply to our question

	if (questions > 1)
		return 0;

	int i;
	for (i = 0; i < questions; ++i) {
		size_t ofs = (size_t)pointer_diff(data, buffer);
		size_t verify_ofs = 12;
		//Verify it's our question, _services._dns-sd._udp.local.
		if (!mdns_string_equal(buffer, data_size, &ofs, services_query, sizeof(services_query),
		                       &verify_ofs))
			return 0;
		data = pointer_offset(buffer, ofs);

		uint16_t type = byteorder_bigendian16(*data++);
		uint16_t rclass = byteorder_bigendian16(*data++);

		//Make sure we get a reply based on our PTR question for class IN
		if ((type != MDNS_RECORDTYPE_PTR) || ((rclass & 0x7FFF) != MDNS_CLASS_IN))
			return 0;
	}

	bool do_callback = true;
	size_t records = 0;
	for (i = 0; i < answer_rrs; ++i) {
		size_t ofs = (size_t)pointer_diff(data, buffer);
		size_t verify_ofs = 12;
		//Verify it's an answer to our question, _services._dns-sd._udp.local.
		bool is_answer = mdns_string_equal(buffer, data_size, &ofs, services_query, sizeof(services_query),
		                                   &verify_ofs);
		data = pointer_offset(buffer, ofs);

		uint16_t type = byteorder_bigendian16(*data++);
		uint16_t rclass = byteorder_bigendian16(*data++);
		uint32_t ttl = byteorder_bigendian32(*(uint32_t*)(void*)data); data += 2;
		uint16_t length = byteorder_bigendian16(*data++);

		if (is_answer && do_callback) {
			++records;
			if (callback(source, MDNS_ENTRYTYPE_ANSWER, type, rclass, ttl, buffer,
			             data_size, (size_t)pointer_diff(data, buffer), length))
				do_callback = false;
		}
		data = pointer_offset(data, length);
	}

	size_t offset = (size_t)pointer_diff(data, buffer);
	records += mdns_records_parse(source, buffer, data_size, &offset,
	                              MDNS_ENTRYTYPE_AUTHORITY, authority_rrs, callback);
	records += mdns_records_parse(source, buffer, data_size, &offset,
	                              MDNS_ENTRYTYPE_ADDITIONAL, additional_rrs, callback);

	return records;
}
