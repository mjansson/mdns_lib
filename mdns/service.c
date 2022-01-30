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
	const network_address_t* addr = 0;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &addr);
	if (!data_size)
		return 0;

	const uint16_t* data = (const uint16_t*)buffer;

	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);

	size_t records;
 	size_t total_records = 0;
 	for (int iquestion = 0; iquestion < questions; ++iquestion) {
		size_t question_offset = (size_t)pointer_diff(data, buffer);
		size_t offset = question_offset;
		size_t verify_offset = 12;
		int dns_sd = 0;
		if (mdns_string_equal(buffer, data_size, &offset, mdns_services_query, sizeof(mdns_services_query),
		                      &verify_offset)) {
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
		uint16_t class_without_flushbit = rclass & ~MDNS_CACHE_FLUSH;

		// Make sure we get a question of class IN
		if (!((class_without_flushbit == MDNS_CLASS_IN) || (class_without_flushbit == MDNS_CLASS_ANY)))
			return 0;
		if (dns_sd && flags)
			continue;

		++total_records;
		if (callback && callback(sock, addr, MDNS_ENTRYTYPE_QUESTION, query_id, rtype, rclass, 0, buffer, data_size,
		                         question_offset, length, question_offset, length, user_data))
			return total_records;
	}

	size_t offset = (size_t)pointer_diff(data, buffer);
	records = mdns_records_parse(sock, addr, buffer, data_size, &offset,
	                             MDNS_ENTRYTYPE_ANSWER, query_id, answer_rrs, callback, user_data);
	total_records += records;
	if (records != answer_rrs)
		return total_records;

	records =
	    mdns_records_parse(sock, addr, buffer, data_size, &offset,
	                       MDNS_ENTRYTYPE_AUTHORITY, query_id, authority_rrs, callback, user_data);
	total_records += records;
	if (records != authority_rrs)
		return total_records;

	records = mdns_records_parse(sock, addr, buffer, data_size, &offset,
	                             MDNS_ENTRYTYPE_ADDITIONAL, query_id, additional_rrs, callback,
	                             user_data);

	return total_records;
}
