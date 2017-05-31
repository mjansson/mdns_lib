/* query.c  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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

static atomic32_t query_transaction = 0;

void
mdns_query_send(socket_t* sock, mdns_record_type_t type, const char* name, size_t length,
                void* buffer, size_t capacity) {
	if (capacity < (17 + length))
		return;

	uint16_t* data = buffer;
	//Transaction ID
	*data++ = byteorder_bigendian16((uint16_t)atomic_incr32(&query_transaction));
	//Flags
	*data++ = 0;
	//Questions
	*data++ = byteorder_bigendian16(1);
	//Answer RRs
	*data++ = 0;
	//Authority RRs
	*data++ = 0;
	//Additional RRs
	*data++ = 0;
	//Name string
	data = mdns_string_make(data, capacity - 17, name, length);
	if (!data)
		return;
	//Record type
	*data++ = byteorder_bigendian16(type);
	//! Unicast response, class IN
	*data++ = byteorder_bigendian16(0x8000U | MDNS_CLASS_IN);

	network_address_ipv4_t ipv4_multicast;
	network_address_t* mdns_multicast_addr = network_address_ipv4_initialize(&ipv4_multicast);
	network_address_ipv4_set_ip(mdns_multicast_addr, network_address_ipv4_make_ip(224U, 0U, 0U, 251U));
	network_address_ip_set_port(mdns_multicast_addr, 5353);

	udp_socket_sendto(sock, buffer, (size_t)pointer_diff(data, buffer), mdns_multicast_addr);
}

size_t
mdns_query_recv(socket_t* sock, void* buffer, size_t capacity,
                mdns_record_callback_fn callback) {
	const network_address_t* source;
	size_t data_size = udp_socket_recvfrom(sock, buffer, capacity, &source);
	if (!data_size)
		return 0;

	uint16_t* data = (uint16_t*)buffer;

	uint16_t transaction_id = byteorder_bigendian16(*data++);
	++data;// uint16_t flags          = byteorder_bigendian16(*data++);
	uint16_t questions      = byteorder_bigendian16(*data++);
	uint16_t answer_rrs     = byteorder_bigendian16(*data++);
	uint16_t authority_rrs  = byteorder_bigendian16(*data++);
	uint16_t additional_rrs = byteorder_bigendian16(*data++);

	if (((int32_t)transaction_id != atomic_load32(&query_transaction)))// || (flags != 0x8400))
		return 0; //Not a reply to our last question

	if (questions > 1)
		return 0;

	//Skip questions part
	int i;
	for (i = 0; i < questions; ++i) {
		size_t ofs = (size_t)pointer_diff(data, buffer);
		if (!mdns_string_skip(buffer, data_size, &ofs))
			return 0;
		data = pointer_offset(buffer, ofs);
		++data;
		++data;
	}

	size_t records = 0;
	size_t offset = (size_t)pointer_diff(data, buffer);
	records += mdns_records_parse(source, buffer, data_size, &offset,
	                              MDNS_ENTRYTYPE_ANSWER, answer_rrs, callback);
	records += mdns_records_parse(source, buffer, data_size, &offset,
	                              MDNS_ENTRYTYPE_AUTHORITY, authority_rrs, callback);
	records += mdns_records_parse(source, buffer, data_size, &offset,
	                              MDNS_ENTRYTYPE_ADDITIONAL, additional_rrs, callback);
	return records;	
}
