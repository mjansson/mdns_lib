/* query.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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

int
mdns_query_send(socket_t* sock, mdns_record_type_t type, const char* name, size_t length, void* buffer, size_t capacity,
                uint16_t query_id) {
	if (capacity < (17 + length))
		return -1;

	uint16_t rclass = MDNS_CLASS_IN | MDNS_UNICAST_RESPONSE;

	struct sockaddr_storage addr_storage;
	struct sockaddr* saddr = (struct sockaddr*)&addr_storage;
	socklen_t saddrlen = sizeof(addr_storage);
	if (getsockname(sock->fd, saddr, &saddrlen) == 0) {
		if ((saddr->sa_family == AF_INET) && (ntohs(((struct sockaddr_in*)saddr)->sin_port) == MDNS_PORT))
			rclass &= ~MDNS_UNICAST_RESPONSE;
		else if ((saddr->sa_family == AF_INET6) && (ntohs(((struct sockaddr_in6*)saddr)->sin6_port) == MDNS_PORT))
			rclass &= ~MDNS_UNICAST_RESPONSE;
	}

	struct mdns_header_t* header = (struct mdns_header_t*)buffer;
	// Query ID
	header->query_id = htons(query_id);
	// Flags
	header->flags = 0;
	// Questions
	header->questions = htons(1);
	// No answer, authority or additional RRs
	header->answer_rrs = 0;
	header->authority_rrs = 0;
	header->additional_rrs = 0;
	// Fill in question
	// Name string
	void* data = pointer_offset(buffer, sizeof(struct mdns_header_t));
	data = mdns_string_make(data, capacity - 17, name, length);
	if (!data)
		return -1;
	// Record type
	data = mdns_htons(data, type);
	//! Optional unicast response based on local port, class IN
	data = mdns_htons(data, rclass);

	size_t tosend = pointer_diff(data, buffer);
	if (mdns_multicast_send(sock, buffer, (size_t)tosend))
		return -1;
	return query_id;
}

size_t
mdns_query_recv(socket_t* sock, void* buffer, size_t capacity, mdns_record_callback_fn callback, void* user_data,
                int only_query_id) {
	network_address_t* address = 0;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &address);
	if (!data_size)
		return 0;

	const uint16_t* data = (const uint16_t*)buffer;

	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);
	(void)sizeof(flags);

	if ((only_query_id > 0) && (query_id != only_query_id))
		return 0;  // Not a reply to the wanted one-shot query

	if (questions > 1)
		return 0;

	// Skip questions part
	int i;
	for (i = 0; i < questions; ++i) {
		size_t ofs = pointer_diff(data, buffer);
		if (!mdns_string_skip(buffer, data_size, &ofs))
			return 0;
		data = pointer_offset_const(buffer, ofs);
		/* Record type and class not used, skip
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);*/
		data += 2;
	}

	size_t total_records = 0;
	size_t records = 0;
	size_t offset = pointer_diff(data, buffer);
	records = mdns_records_parse(sock, address, buffer, data_size, &offset, MDNS_ENTRYTYPE_ANSWER, query_id, answer_rrs,
	                             callback, user_data);
	total_records += records;
	if (records != answer_rrs)
		return total_records;

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
		callback(sock, address, MDNS_ENTRYTYPE_END, query_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, user_data);

	return total_records;
}

int
mdns_query_answer(socket_t* sock, const network_address_t* address, void* buffer, size_t capacity, uint16_t query_id,
                  const char* service, size_t service_length, const char* hostname, size_t hostname_length,
                  const network_address_ipv4_t* ipv4, const network_address_ipv6_t* ipv6, uint16_t port,
                  const char* txt, size_t txt_length) {
	if (capacity < (sizeof(struct mdns_header_t) + 32 + service_length + hostname_length))
		return -1;

	int unicast = (address ? 1 : 0);
	int use_ipv4 = (ipv4 != 0);
	int use_ipv6 = (ipv6 != 0);
	int use_txt = (txt && txt_length && (txt_length <= 255));

	uint16_t question_rclass = (unicast ? MDNS_UNICAST_RESPONSE : 0) | MDNS_CLASS_IN;
	uint16_t rclass = (unicast ? MDNS_CACHE_FLUSH : 0) | MDNS_CLASS_IN;
	uint32_t ttl = (unicast ? 10 : 60);
	uint32_t a_ttl = ttl;

	// Basic answer structure
	struct mdns_header_t* header = (struct mdns_header_t*)buffer;
	header->query_id = (unicast ? htons(query_id) : 0);
	header->flags = htons(0x8400);
	header->questions = htons(unicast ? 1 : 0);
	header->answer_rrs = htons(1);
	header->authority_rrs = 0;
	header->additional_rrs = htons((unsigned short)(1 + use_ipv4 + use_ipv6 + use_txt));

	void* data = pointer_offset(buffer, sizeof(struct mdns_header_t));
	size_t remain, service_offset = 0, local_offset = 0, full_offset, host_offset;

	// Fill in question if unicast
	if (unicast) {
		service_offset = pointer_diff(data, buffer);
		remain = capacity - service_offset;
		data = mdns_string_make(data, remain, service, service_length);
		local_offset = pointer_diff(data, buffer) - 7;
		remain = capacity - pointer_diff(data, buffer);
		if (!data || (remain <= 4))
			return -1;

		data = mdns_htons(data, MDNS_RECORDTYPE_PTR);
		data = mdns_htons(data, question_rclass);
	}
	remain = capacity - pointer_diff(data, buffer);

	// Fill in answers
	// PTR record for service
	if (unicast) {
		data = mdns_string_make_ref(data, remain, service_offset);
	} else {
		service_offset = pointer_diff(data, buffer);
		remain = capacity - service_offset;
		data = mdns_string_make(data, remain, service, service_length);
		local_offset = pointer_diff(data, buffer) - 7;
	}
	remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain <= 10))
		return -1;
	data = mdns_htons(data, MDNS_RECORDTYPE_PTR);
	data = mdns_htons(data, rclass);
	data = mdns_htonl(data, ttl);
	void* record_length = data;  // length
	data = mdns_htons(data, 0);
	// Make a string <hostname>.<service>.local.
	void* record_data = data;
	full_offset = pointer_diff(data, buffer);
	remain = capacity - full_offset;
	data = mdns_string_make_with_ref(data, remain, hostname, hostname_length, service_offset);
	remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain <= 10))
		return -1;
	mdns_htons(record_length, (uint16_t)pointer_diff(data, record_data));

	// Fill in additional records
	// SRV record for <hostname>.<service>.local.
	data = mdns_string_make_ref(data, remain, full_offset);
	remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain <= 10))
		return -1;
	data = mdns_htons(data, MDNS_RECORDTYPE_SRV);
	data = mdns_htons(data, rclass);
	data = mdns_htonl(data, ttl);
	record_length = data;
	data = mdns_htons(data, 0);  // length
	record_data = data;
	data = mdns_htons(data, 0);     // priority
	data = mdns_htons(data, 0);     // weight
	data = mdns_htons(data, port);  // port
	// Make a string <hostname>.local.
	host_offset = pointer_diff(data, buffer);
	remain = capacity - host_offset;
	data = mdns_string_make_with_ref(data, remain, hostname, hostname_length, local_offset);
	remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain <= 10))
		return -1;
	mdns_htons(record_length, (uint16_t)pointer_diff(data, record_data));

	// A record for <hostname>.local.
	if (use_ipv4) {
		data = mdns_string_make_ref(data, remain, host_offset);
		remain = capacity - pointer_diff(data, buffer);
		if (!data || (remain <= 14))
			return -1;
		data = mdns_htons(data, MDNS_RECORDTYPE_A);
		data = mdns_htons(data, rclass);
		data = mdns_htonl(data, a_ttl);
		data = mdns_htons(data, 4);  // length
		uint32_t ip = htonl(network_address_ipv4_ip((const network_address_t*)ipv4));
		memcpy(data, &ip, 4);  // ipv4 address
		data = pointer_offset(data, 4);
		remain = capacity - pointer_diff(data, buffer);
	}

	// AAAA record for <hostname>.local.
	if (use_ipv6) {
		data = mdns_string_make_ref(data, remain, host_offset);
		remain = capacity - pointer_diff(data, buffer);
		if (!data || (remain <= 26))
			return -1;
		data = mdns_htons(data, MDNS_RECORDTYPE_AAAA);
		data = mdns_htons(data, rclass);
		data = mdns_htonl(data, a_ttl);
		data = mdns_htons(data, 16);  // length
		struct in6_addr ip = network_address_ipv6_ip((const network_address_t*)ipv6);
		memcpy(data, &ip, 16);  // ipv6 address
		data = pointer_offset(data, 16);
		remain = capacity - pointer_diff(data, buffer);
	}

	// TXT record for <hostname>.<service>.local.
	if (use_txt) {
		data = mdns_string_make_ref(data, remain, full_offset);
		remain = capacity - pointer_diff(data, buffer);
		if (!data || (remain <= (11 + txt_length)))
			return -1;
		data = mdns_htons(data, MDNS_RECORDTYPE_TXT);
		data = mdns_htons(data, rclass);
		data = mdns_htonl(data, ttl);
		data = mdns_htons(data, (unsigned short)(txt_length + 1));  // length
		char* txt_record = (char*)data;
		*txt_record++ = (char)txt_length;
		memcpy(txt_record, txt, txt_length);  // txt record
		data = pointer_offset(txt_record, txt_length);
		// Unused until multiple txt records are supported
		// remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	}

	size_t tosend = pointer_diff(data, buffer);
	if (unicast)
		return mdns_unicast_send(sock, address, buffer, tosend);
	return mdns_multicast_send(sock, buffer, tosend);
}
