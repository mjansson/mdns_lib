/* record.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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
#include <network/network.h>
#include <mdns/mdns.h>

size_t
mdns_records_parse(const network_address_t* from, const void* buffer, size_t size, size_t* offset,
                   mdns_entry_type_t type, size_t records, mdns_record_callback_fn callback) {
	size_t parsed = 0;
	bool do_callback = true;
	for (size_t i = 0; i < records; ++i) {
		mdns_string_skip(buffer, size, offset);
		const uint16_t* data = pointer_offset_const(buffer, *offset);

		uint16_t rtype = byteorder_bigendian16(*data++);
		uint16_t rclass = byteorder_bigendian16(*data++);
		uint32_t ttl = byteorder_bigendian32(*(const uint32_t*)(const void*)data); data += 2;
		uint16_t length = byteorder_bigendian16(*data++);

		*offset += 10;

		if (do_callback) {
			++parsed;
			if (callback(from, type, rtype, rclass, ttl, buffer, *offset, length))
				do_callback = false;
		}

		*offset += length;
	}
	return parsed;
}

string_t
mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity) {
	//PTR record is just a string
	if ((size >= offset + length) && (length >= 2))
		return mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
	return string(0, 0);
}

mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity) {
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
		srv.priority = byteorder_bigendian16(*recorddata++);
		srv.weight = byteorder_bigendian16(*recorddata++);
		srv.port = byteorder_bigendian16(*recorddata++);
		offset += 6;
		srv.name = mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
	}
	return srv;
}

network_address_ipv4_t
mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length) {
	network_address_ipv4_t addr;
	network_address_ipv4_initialize(&addr);
	if ((size >= offset + length) && (length == 4)) {
		uint32_t ip = *(const uint32_t*)pointer_offset_const(buffer, offset);
		network_address_ipv4_set_ip((network_address_t*)&addr, byteorder_bigendian32(ip));
	}
	return addr;
}

network_address_ipv6_t
mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length) {
	network_address_ipv6_t addr;
	network_address_ipv6_initialize(&addr);
	if ((size >= offset + length) && (length == 16)) {
		struct in6_addr ip = *(const struct in6_addr*)pointer_offset_const(buffer, offset);
		network_address_ipv6_set_ip((network_address_t*)&addr, ip);
	}
	return addr;
}

size_t
mdns_record_parse_txt(const void* buffer, size_t size, size_t offset, size_t length,
                      mdns_record_txt_t* records, size_t capacity) {
	size_t parsed = 0;
	const char* strdata;
	size_t separator, sublength;
	size_t end = offset + length;

	if (size < end)
		end = size;

	while ((offset < end) && (parsed < capacity)) {
		strdata = pointer_offset_const(buffer, offset);
		sublength = *(const unsigned char*)strdata;

		++strdata;
		offset += sublength + 1;

		separator = 0;
		for (size_t c = 0; c < sublength; ++c) {
			//DNS-SD TXT record keys MUST be printable US-ASCII, [0x20, 0x7E]
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
			records[parsed].key = string_const(strdata, separator);
			records[parsed].value = string_const(strdata + separator + 1, sublength - (separator + 1));
		}
		else {
			records[parsed].key = string_const(strdata, sublength);
		}

		++parsed;
	}

	return parsed;
}
