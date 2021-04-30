/* service.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

#include <network/udp.h>

extern const uint8_t mdns_services_query[46];

size_t
mdns_service_listen(socket_t* sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data) {
	network_address_t* addr;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &addr);
	if (!data_size)
		return 0;

	const uint16_t* data = (const uint16_t*)buffer;

	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	/*
	This data is unused at the moment, skip
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);
	*/
	data += 3;

	size_t parsed = 0;
	for (int iquestion = 0; iquestion < questions; ++iquestion) {
		size_t question_offset = pointer_diff(data, buffer);
		size_t offset = question_offset;
		size_t verify_ofs = 12;
		int dns_sd = 0;
		if (mdns_string_equal(buffer, data_size, &offset, mdns_services_query, sizeof(mdns_services_query),
		                      &verify_ofs)) {
			dns_sd = 1;
		} else {
			offset = question_offset;
			if (!mdns_string_skip(buffer, data_size, &offset))
				break;
		}
		size_t length = offset - question_offset;
		data = pointer_offset_const(buffer, offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);

		// Make sure we get a question of class IN
		if ((rclass & 0x7FFF) != MDNS_CLASS_IN)
			return 0;
		if (dns_sd && flags)
			continue;

		++parsed;
		if (callback && callback(sock, addr, MDNS_ENTRYTYPE_QUESTION, query_id, rtype, rclass, 0, buffer, data_size,
		                         question_offset, length, question_offset, length, user_data))
			break;
	}

	return parsed;
}
