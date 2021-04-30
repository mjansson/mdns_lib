/* record.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
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
#include <network/network.h>
#include <mdns/mdns.h>

string_const_t
mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length, char* strbuffer, size_t capacity) {
	// PTR record is just a string
	if ((size >= offset + length) && (length >= 2))
		return mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
	return string_const(0, 0);
}

mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length, char* strbuffer, size_t capacity) {
	mdns_record_srv_t srv;
	memset(&srv, 0, sizeof(mdns_record_srv_t));
	// Read the priority, weight, port number and the discovery name
	// SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
	// 2 bytes network-order unsigned priority
	// 2 bytes network-order unsigned weight
	// 2 bytes network-order unsigned port
	// string: discovery (domain) name, minimum 2 bytes when compressed
	if ((size >= offset + length) && (length >= 8)) {
		const uint16_t* recorddata = pointer_offset_const(buffer, offset);
		srv.priority = mdns_ntohs(recorddata++);
		srv.weight = mdns_ntohs(recorddata++);
		srv.port = mdns_ntohs(recorddata++);
		offset += 6;
		srv.name = mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
	}
	return srv;
}

network_address_ipv4_t*
mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length, network_address_ipv4_t* addr) {
	network_address_ipv4_initialize(addr);
	if ((size >= offset + length) && (length == 4))
		memcpy(&addr->saddr.sin_addr.s_addr, pointer_offset(buffer, offset), 4);
	return addr;
}

network_address_ipv6_t*
mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length, network_address_ipv6_t* addr) {
	network_address_ipv6_initialize(addr);
	if ((size >= offset + length) && (length == 16))
		memcpy(&addr->saddr.sin6_addr, pointer_offset(buffer, offset), 16);
	return addr;
}

size_t
mdns_record_parse_txt(const void* buffer, size_t size, size_t offset, size_t length, mdns_record_txt_t* records,
                      size_t capacity) {
	size_t parsed = 0;
	const char* strdata;
	size_t separator, sublength;
	size_t end = offset + length;

	if (size < end)
		end = size;

	while ((offset < end) && (parsed < capacity)) {
		strdata = pointer_offset(buffer, offset);
		sublength = *(const unsigned char*)strdata;

		++strdata;
		offset += sublength + 1;

		separator = 0;
		for (size_t c = 0; c < sublength; ++c) {
			// DNS-SD TXT record keys MUST be printable US-ASCII, [0x20, 0x7E]
			if ((strdata[c] < 0x20) || (strdata[c] > 0x7E))
				break;
			if (strdata[c] == '=') {
				separator = c;
				break;
			}
		}

		if (!separator)
			continue;

		if (separator < sublength) {
			records[parsed].key.str = strdata;
			records[parsed].key.length = separator;
			records[parsed].value.str = strdata + separator + 1;
			records[parsed].value.length = sublength - (separator + 1);
		} else {
			records[parsed].key.str = strdata;
			records[parsed].key.length = sublength;
		}

		++parsed;
	}

	return parsed;
}

size_t
mdns_records_parse(socket_t* sock, const network_address_t* from, const void* buffer, size_t size, size_t* offset,
                   mdns_entry_type_t type, uint16_t query_id, size_t records, mdns_record_callback_fn callback,
                   void* user_data) {
	size_t parsed = 0;
	for (size_t i = 0; i < records; ++i) {
		size_t name_offset = *offset;
		mdns_string_skip(buffer, size, offset);
		if (((*offset) + 10) > size)
			return parsed;
		size_t name_length = (*offset) - name_offset;
		const uint16_t* data = pointer_offset(buffer, *offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint32_t ttl = mdns_ntohl(data);
		data += 2;
		uint16_t length = mdns_ntohs(data++);

		*offset += 10;

		if (length <= (size - (*offset))) {
			++parsed;
			if (callback && callback(sock, from, type, query_id, rtype, rclass, ttl, buffer, size, name_offset,
			                         name_length, *offset, length, user_data))
				break;
		}

		*offset += length;
	}
	return parsed;
}
