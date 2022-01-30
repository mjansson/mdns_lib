/* discovery.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

extern const uint8_t mdns_services_query[46];

int
mdns_discovery_send(socket_t* sock) {
	return mdns_multicast_send(sock, mdns_services_query, sizeof(mdns_services_query));
}

size_t
mdns_discovery_recv(socket_t* sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data) {
	const network_address_t* address;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &address);
	if (!data_size)
		return 0;

	size_t records = 0;
	const uint16_t* data = (uint16_t*)buffer;

	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);

	// According to RFC 6762 the query ID MUST match the sent query ID (which is 0 in our case)
	if (query_id || (flags != 0x8400))
		return 0;  // Not a reply to our question

	// It seems some implementations do not fill the correct questions field,
	// so ignore this check for now and only validate answer string
	/*
	if (questions != 1)
	    return 0;
	*/

	int i;
	for (i = 0; i < questions; ++i) {
		size_t offset = (size_t)pointer_diff(data, buffer);
		size_t verify_offset = 12;
		// Verify it's our question, _services._dns-sd._udp.local.
		if (!mdns_string_equal(buffer, data_size, &offset, mdns_services_query, sizeof(mdns_services_query), &verify_offset))
			return 0;
		data = pointer_offset_const(buffer, offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);

		// Make sure we get a reply based on our PTR question for class IN
		if ((rtype != MDNS_RECORDTYPE_PTR) || ((rclass & 0x7FFF) != MDNS_CLASS_IN))
			return 0;
	}

	for (i = 0; i < answer_rrs; ++i) {
		size_t offset = (size_t)pointer_diff(data, buffer);
		size_t verify_offset = 12;
		// Verify it's an answer to our question, _services._dns-sd._udp.local.
		size_t name_offset = offset;
		int is_answer =
		    mdns_string_equal(buffer, data_size, &offset, mdns_services_query, sizeof(mdns_services_query), &verify_offset);
		if (!is_answer && !mdns_string_skip(buffer, data_size, &offset))
 			break;		    
		size_t name_length = offset - name_offset;
		if ((offset + 10) > data_size)
			return records;
		data = pointer_offset_const(buffer, offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint32_t ttl = mdns_ntohl(data);
		data += 2;
		uint16_t length = mdns_ntohs(data++);
		if (length > (data_size - offset))
			return 0;

		if (is_answer) {
			++records;
			offset = (size_t)pointer_diff(data, buffer);
			if (callback && callback(sock, address, MDNS_ENTRYTYPE_ANSWER, query_id, rtype, rclass, ttl, buffer,
			                         data_size, name_offset, name_length, offset, length, user_data))
				return records;
		}
		data = pointer_offset_const(data, length);
	}
	size_t total_records = records;

	size_t offset = (size_t)pointer_diff(data, buffer);
	records = mdns_records_parse(sock, address, buffer, data_size, &offset, MDNS_ENTRYTYPE_AUTHORITY, query_id,
	                             authority_rrs, callback, user_data);
	total_records += records;
	if (records != authority_rrs)
		return total_records;

	records = mdns_records_parse(sock, address, buffer, data_size, &offset, MDNS_ENTRYTYPE_ADDITIONAL, query_id,
	                             additional_rrs, callback, user_data);
	total_records += records;
	if (records != additional_rrs)
		return total_records;

	if (callback)
		callback(sock, address, MDNS_ENTRYTYPE_END, query_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	return total_records;
}
