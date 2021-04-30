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
	data = mdns_string_make(buffer, capacity, data, name, length, 0);
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

static void*
mdns_answer_add_question_unicast(void* buffer, size_t capacity, void* data, mdns_record_type_t record_type,
                                 const char* name, size_t name_length, mdns_string_table_t* string_table) {
	data = mdns_string_make(buffer, capacity, data, name, name_length, string_table);
	size_t remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain <= 4))
		return 0;

	data = mdns_htons(data, record_type);
	data = mdns_htons(data, MDNS_UNICAST_RESPONSE | MDNS_CLASS_IN);

	return data;
}

static void*
mdns_answer_add_record_header(void* buffer, size_t capacity, void* data, mdns_record_t record, uint16_t rclass,
                              uint32_t ttl, mdns_string_table_t* string_table) {
	data = mdns_string_make(buffer, capacity, data, record.name.str, record.name.length, string_table);
	size_t remain = capacity - pointer_diff(data, buffer);
	if (!data || (remain < 10))
		return 0;

	data = mdns_htons(data, record.type);
	data = mdns_htons(data, rclass);
	data = mdns_htonl(data, ttl);
	data = mdns_htons(data, 0);  // Length, to be filled later
	return data;
}

static void*
mdns_answer_add_record(void* buffer, size_t capacity, void* data, mdns_record_t record, uint16_t rclass, uint32_t ttl,
                       mdns_string_table_t* string_table) {
	// TXT records will be coalesced into one record later
	if (!data || (record.type == MDNS_RECORDTYPE_TXT))
		return data;

	data = mdns_answer_add_record_header(buffer, capacity, data, record, rclass, ttl, string_table);
	if (!data)
		return 0;

	// Pointer to length of record to be filled at end
	void* record_length = pointer_offset(data, -2);
	void* record_data = data;

	size_t remain = capacity - pointer_diff(data, buffer);
	switch (record.type) {
		case MDNS_RECORDTYPE_PTR:
			data = mdns_string_make(buffer, capacity, data, record.data.ptr.name.str, record.data.ptr.name.length,
			                        string_table);
			break;

		case MDNS_RECORDTYPE_SRV:
			if (remain <= 6)
				return 0;
			data = mdns_htons(data, record.data.srv.priority);
			data = mdns_htons(data, record.data.srv.weight);
			data = mdns_htons(data, record.data.srv.port);
			data = mdns_string_make(buffer, capacity, data, record.data.srv.name.str, record.data.srv.name.length,
			                        string_table);
			break;

		case MDNS_RECORDTYPE_A:
			if (remain < 4)
				return 0;
			memcpy(data, &record.data.a.addr.sin_addr.s_addr, 4);
			data = pointer_offset(data, 4);
			break;

		case MDNS_RECORDTYPE_AAAA:
			if (remain < 16)
				return 0;
			memcpy(data, &record.data.aaaa.addr.sin6_addr, 16);  // ipv6 address
			data = pointer_offset(data, 16);
			break;

		default:
			break;
	}

	if (!data)
		return 0;

	// Fill record length
	mdns_htons(record_length, (uint16_t)pointer_diff(data, record_data));
	return data;
}

static void*
mdns_answer_add_txt_record(void* buffer, size_t capacity, void* data, mdns_record_t* records, size_t record_count,
                           uint16_t rclass, uint32_t ttl, mdns_string_table_t* string_table) {
	// Pointer to length of record to be filled at end
	void* record_length = 0;
	void* record_data = 0;

	size_t remain = 0;
	for (size_t irec = 0; data && (irec < record_count); ++irec) {
		if (records[irec].type != MDNS_RECORDTYPE_TXT)
			continue;

		if (!record_data) {
			data = mdns_answer_add_record_header(buffer, capacity, data, records[irec], rclass, ttl, string_table);
			record_length = pointer_offset(data, -2);
			record_data = data;
		}

		// TXT strings are unlikely to be shared, just make then raw. Also need one byte for
		// termination, thus the <= check
		size_t string_length = records[irec].data.txt.key.length + records[irec].data.txt.value.length + 1;
		remain = capacity - pointer_diff(data, buffer);
		if (!data || (remain <= string_length) || (string_length > 0x3FFF))
			return 0;

		unsigned char* strdata = (unsigned char*)data;
		*strdata++ = (unsigned char)string_length;
		memcpy(strdata, records[irec].data.txt.key.str, records[irec].data.txt.key.length);
		strdata += records[irec].data.txt.key.length;
		*strdata++ = '=';
		memcpy(strdata, records[irec].data.txt.value.str, records[irec].data.txt.value.length);
		strdata += records[irec].data.txt.value.length;

		data = strdata;
	}

	// Fill record length
	if (record_data)
		mdns_htons(record_length, (uint16_t)pointer_diff(data, record_data));

	return data;
}

static uint16_t
mdns_answer_get_record_count(mdns_record_t* records, size_t record_count) {
	// TXT records will be coalesced into one record
	uint16_t total_count = 0;
	uint16_t txt_record = 0;
	for (size_t irec = 0; irec < record_count; ++irec) {
		if (records[irec].type == MDNS_RECORDTYPE_TXT)
			txt_record = 1;
		else
			++total_count;
	}
	return total_count + txt_record;
}

int
mdns_query_answer_unicast(socket_t* sock, const network_address_t* address, void* buffer, size_t capacity,
                          uint16_t query_id, mdns_record_type_t record_type, const char* name, size_t name_length,
                          mdns_record_t answer, mdns_record_t* authority, size_t authority_count,
                          mdns_record_t* additional, size_t additional_count) {
	if (capacity < (sizeof(struct mdns_header_t) + 32 + 4))
		return -1;

	uint16_t rclass = MDNS_CACHE_FLUSH | MDNS_CLASS_IN;
	uint32_t ttl = 10;

	// Basic answer structure
	struct mdns_header_t* header = (struct mdns_header_t*)buffer;
	header->query_id = htons(query_id);
	header->flags = htons(0x8400);
	header->questions = htons(1);
	header->answer_rrs = htons(1);
	header->authority_rrs = htons(mdns_answer_get_record_count(authority, authority_count));
	header->additional_rrs = htons(mdns_answer_get_record_count(additional, additional_count));

	mdns_string_table_t string_table = {0};
	void* data = pointer_offset(buffer, sizeof(struct mdns_header_t));

	// Fill in question
	data = mdns_answer_add_question_unicast(buffer, capacity, data, record_type, name, name_length, &string_table);

	// Fill in answer
	data = mdns_answer_add_record(buffer, capacity, data, answer, rclass, ttl, &string_table);

	// Fill in authority records
	for (size_t irec = 0; data && (irec < authority_count); ++irec)
		data = mdns_answer_add_record(buffer, capacity, data, authority[irec], rclass, ttl, &string_table);
	data = mdns_answer_add_txt_record(buffer, capacity, data, authority, authority_count, rclass, ttl, &string_table);

	// Fill in additional records
	for (size_t irec = 0; data && (irec < additional_count); ++irec)
		data = mdns_answer_add_record(buffer, capacity, data, additional[irec], rclass, ttl, &string_table);
	data = mdns_answer_add_txt_record(buffer, capacity, data, additional, additional_count, rclass, ttl, &string_table);
	if (!data)
		return -1;

	size_t tosend = pointer_diff(data, buffer);
	return mdns_unicast_send(sock, address, buffer, tosend);
}

static int
mdns_answer_multicast_rclass(socket_t* sock, void* buffer, size_t capacity, uint16_t rclass, mdns_record_t answer,
                             mdns_record_t* authority, size_t authority_count, mdns_record_t* additional,
                             size_t additional_count) {
	if (capacity < (sizeof(struct mdns_header_t) + 32 + 4))
		return -1;

	uint32_t ttl = 60;

	// Basic answer structure
	struct mdns_header_t* header = (struct mdns_header_t*)buffer;
	header->query_id = 0;
	header->flags = htons(0x8400);
	header->questions = 0;
	header->answer_rrs = htons(1);
	header->authority_rrs = htons(mdns_answer_get_record_count(authority, authority_count));
	header->additional_rrs = htons(mdns_answer_get_record_count(additional, additional_count));

	mdns_string_table_t string_table = {0};
	void* data = pointer_offset(buffer, sizeof(struct mdns_header_t));

	// Fill in answer
	data = mdns_answer_add_record(buffer, capacity, data, answer, rclass, ttl, &string_table);

	// Fill in authority records
	for (size_t irec = 0; data && (irec < authority_count); ++irec)
		data = mdns_answer_add_record(buffer, capacity, data, authority[irec], rclass, ttl, &string_table);
	data = mdns_answer_add_txt_record(buffer, capacity, data, authority, authority_count, rclass, ttl, &string_table);

	// Fill in additional records
	for (size_t irec = 0; data && (irec < additional_count); ++irec)
		data = mdns_answer_add_record(buffer, capacity, data, additional[irec], rclass, ttl, &string_table);
	data = mdns_answer_add_txt_record(buffer, capacity, data, additional, additional_count, rclass, ttl, &string_table);
	if (!data)
		return -1;

	size_t tosend = pointer_diff(data, buffer);
	return mdns_multicast_send(sock, buffer, tosend);
}

int
mdns_query_answer_multicast(socket_t* sock, void* buffer, size_t capacity, mdns_record_t answer,
                            mdns_record_t* authority, size_t authority_count, mdns_record_t* additional,
                            size_t additional_count) {
	uint16_t rclass = MDNS_CLASS_IN;
	return mdns_answer_multicast_rclass(sock, buffer, capacity, rclass, answer, authority, authority_count, additional,
	                                    additional_count);
}

int
mdns_announce_multicast(socket_t* sock, void* buffer, size_t capacity, mdns_record_t answer, mdns_record_t* authority,
                        size_t authority_count, mdns_record_t* additional, size_t additional_count) {
	uint16_t rclass = MDNS_CLASS_IN | MDNS_CACHE_FLUSH;
	return mdns_answer_multicast_rclass(sock, buffer, capacity, rclass, answer, authority, authority_count, additional,
	                                    additional_count);
}
