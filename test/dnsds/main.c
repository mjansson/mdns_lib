/* main.c  -  mDNS library  -  Public Domain  -  2013 Mattias Jansson / Rampant Pixels
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
 * https://github.com/rampantpixels/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#include <mdns/mdns.h>

#include <network/network.h>
#include <foundation/foundation.h>
#include <test/test.h>

static bool
parse_string(void* rawdata, size_t size, size_t* buffer_offset, char* name) {
	char* buffer = rawdata;
	size_t offset = *buffer_offset, ending_offset = 0, len = 0, namelen = 0;
	int infinite_loop_prevention = 5;

	while (offset < size && buffer[offset]) {
		len = (size_t)buffer[offset];
		if (0xC0 == (len & 0xC0)) {
			if (size < offset + 2)
				goto FAIL;

			if (!ending_offset)
				ending_offset = offset + 2;

			offset = (size_t)(((0x3f & buffer[offset]) << 8) | buffer[offset + 1]);
			if (offset >= size || --infinite_loop_prevention == 0)
				goto FAIL;
		}
		else {
			if (size < offset + len + 1)
				goto FAIL;

			memcpy(name + namelen, buffer + offset + 1, len);
			namelen += len;
			offset += len + 1;

			name[namelen++] = '.';
			name[namelen] = 0;
		}
	}

	*buffer_offset = ending_offset ? ending_offset : offset + 1;
	return true;

FAIL:
	name[0] = 0;
	return false;
}

static application_t
test_dnsds_application(void) {
	application_t app;
	memset(&app, 0, sizeof(app));
	app.name = string_const(STRING_CONST("DNS-DS tests"));
	app.short_name = string_const(STRING_CONST("test_dnsds"));
	app.company = string_const(STRING_CONST("Rampant Pixels"));
	app.flags = APPLICATION_UTILITY;
	app.exception_handler = test_exception_handler;
	return app;
}

static memory_system_t
test_dnsds_memory_system(void) {
	return memory_system_malloc();
}

static foundation_config_t
test_dnsds_foundation_config(void) {
	foundation_config_t config;
	memset(&config, 0, sizeof(config));
	return config;
}

static int
test_dnsds_initialize(void) {
	network_config_t config;
	memset(&config, 0, sizeof(network_config_t));
	return network_module_initialize(config);
}

static void
test_dnsds_finalize(void) {
	network_module_finalize();
}

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
	0x00, 0x0c,
	// QU and class IN
	0x80, 0x01
};
static const int services_query_len = sizeof(services_query);

enum dns_srv_types {
	MDNS_RECORDTYPE_IGNORE = 0,
	//Address
	MDNS_RECORDTYPE_A = 1,
	//Name Server
	MDNS_RECORDTYPE_NS = 2,
	//Mail Destination
	MDNS_RECORDTYPE_MD = 3,
	//Mail Forwarder
	MDNS_RECORDTYPE_MF = 4,
	//Canonical Name
	MDNS_RECORDTYPE_CNAME = 5,
	//Start of Authority
	MDNS_RECORDTYPE_SOA = 6,
	//Mailbox
	MDNS_RECORDTYPE_MB = 7,
	//Mail Group
	MDNS_RECORDTYPE_MG = 8,
	//Mail Rename
	MDNS_RECORDTYPE_MR = 9,
	//NULL RR
	MDNS_RECORDTYPE_NULL = 10,
	//Well-known-service
	MDNS_RECORDTYPE_WKS = 11,
	//Domain Name pointer
	MDNS_RECORDTYPE_PTR = 12,
	//Host information
	MDNS_RECORDTYPE_HINFO = 13,
	//Mailbox information
	MDNS_RECORDTYPE_MINFO = 14,
	//Mail exchanger
	MDNS_RECORDTYPE_MX = 15,
	//Arbitrary text string
	MDNS_RECORDTYPE_TXT = 16,
	//for Responsible Person [RFC1183]
	MDNS_RECORDTYPE_RP = 17,
	//for AFS Data Base location [RFC1183]
	MDNS_RECORDTYPE_AFSDB = 18,
	//for X.25 PSDN address [RFC1183]
	MDNS_RECORDTYPE_X25 = 19,
	//for ISDN address [RFC1183]
	MDNS_RECORDTYPE_ISDN = 20,
	//for Route Through [RFC1183]
	MDNS_RECORDTYPE_RT = 21,
	//for NSAP address, NSAP style A record [RFC1706]
	MDNS_RECORDTYPE_NSAP = 22,
	//
	MDNS_RECORDTYPE_NSAP_PTR = 23,
	//for security signature [RFC2931]
	MDNS_RECORDTYPE_SIG = 24,
	//for security key [RFC2535]
	MDNS_RECORDTYPE_KEY = 25,
	//X.400 mail mapping information [RFC2163]
	MDNS_RECORDTYPE_PX = 26,
	//Geographical Position [RFC1712]
	MDNS_RECORDTYPE_GPOS = 27,
	//IP6 Address [Thomson]
	MDNS_RECORDTYPE_AAAA = 28,
	//Location Information [Vixie]
	MDNS_RECORDTYPE_LOC = 29,
	//Next Domain - OBSOLETE [RFC2535, RFC3755]
	MDNS_RECORDTYPE_NXT = 30,
	//Endpoint Identifier [Patton]
	MDNS_RECORDTYPE_EID = 31,
	//Nimrod Locator [Patton]
	MDNS_RECORDTYPE_NIMLOC = 32,
	//Server Selection [RFC2782]
	MDNS_RECORDTYPE_SRV = 33,
	//ATM Address [Dobrowski]
	MDNS_RECORDTYPE_ATMA = 34,
	//Naming Authority Pointer [RFC2168, RFC2915]
	MDNS_RECORDTYPE_NAPTR = 35,
	//Key Exchanger [RFC2230]
	MDNS_RECORDTYPE_KX = 36,
	//CERT [RFC2538]
	MDNS_RECORDTYPE_CERT = 37,
	//A6 [RFC2874]
	MDNS_RECORDTYPE_A6 = 38,
	//DNAME [RFC2672]
	MDNS_RECORDTYPE_DNAME = 39,
	//SINK [Eastlake]
	MDNS_RECORDTYPE_SINK = 40,
	//OPT [RFC2671]
	MDNS_RECORDTYPE_OPT = 41,
	//APL [RFC3123]
	MDNS_RECORDTYPE_APL = 42,
	//Delegation Signer [RFC3658]
	MDNS_RECORDTYPE_DS = 43,
	//SSH Key Fingerprint [RFC-ietf-secsh-dns-05.txt]
	MDNS_RECORDTYPE_SSHFP = 44,
	//RRSIG [RFC3755]
	MDNS_RECORDTYPE_RRSIG = 46,
	//NSEC [RFC3755]
	MDNS_RECORDTYPE_NSEC = 47,
	//DNSKEY [RFC3755]
	MDNS_RECORDTYPE_DNSKEY = 48,
	//[IANA-Reserved]
	MDNS_RECORDTYPE_UINFO = 100,
	//[IANA-Reserved]
	MDNS_RECORDTYPE_UID = 101,
	//[IANA-Reserved]
	MDNS_RECORDTYPE_GID = 102,
	//[IANA-Reserved]
	MDNS_RECORDTYPE_UNSPEC = 103,
	//Transaction Key [RFC2930]
	MDNS_RECORDTYPE_TKEY = 249,
	//Transaction Signature [RFC2845]
	MDNS_RECORDTYPE_TSIG = 250,
	//Incremental transfer [RFC1995]
	MDNS_RECORDTYPE_IXFR = 251,
	//Transfer of an entire zone [RFC1035]
	MDNS_RECORDTYPE_AXFR = 252,
	//Mailbox-related records (MB, MG or MR) [RFC1035]
	MDNS_RECORDTYPE_MAILA = 253,
	//Mail agent RRs (Obsolete - see MX) [RFC1035]
	MDNS_RECORDTYPE_MAILB = 254,
	//Request for all records [RFC1035]
	MDNS_RECORDTYPE_ANY = 255
};

DECLARE_TEST(dnsds, discover) {
	network_address_t** mdns_multicast_addrs;
	network_address_t* mdns_multicast_addr;
	network_address_t** localhost_addrs;
	network_address_t* localhost_addr;
	network_address_t* any_addr;
	socket_t* sock_mdns;
	uint32_t databuf[128];
	char addrbuffer[256];

	log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_info(HASH_TEST, STRING_CONST("Setup socket"));

	localhost_addr = nullptr;
	localhost_addrs = network_address_local();
	for (size_t iaddr = 0; iaddr < array_size(localhost_addrs); ++iaddr) {
		if (localhost_addrs[iaddr]->family == NETWORK_ADDRESSFAMILY_IPV4)
			localhost_addr = localhost_addrs[iaddr];
	}

	EXPECT_NE(localhost_addr, nullptr);
	{
		string_t addrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), localhost_addr, true);
		log_infof(HASH_TEST, STRING_CONST("Listening to %.*s"), STRING_FORMAT(addrstr));
	}

	mdns_multicast_addrs = network_address_resolve(STRING_CONST("224.0.0.251"));
	mdns_multicast_addr = mdns_multicast_addrs[0];

	any_addr = network_address_ipv4_any();
	network_address_ip_set_port(any_addr, 53530);

	sock_mdns = udp_socket_allocate();
	EXPECT_NE(sock_mdns, 0);

	socket_set_reuse_address(sock_mdns, true);
	socket_set_reuse_port(sock_mdns, true);
	EXPECT_TRUE(socket_bind(sock_mdns, any_addr));
	EXPECT_TRUE(socket_set_multicast_group(sock_mdns, mdns_multicast_addr, true));

	network_address_ip_set_port(mdns_multicast_addr, 5353);

	{
		string_t addrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), mdns_multicast_addr, true);
		log_infof(HASH_TEST, STRING_CONST("Sending query to %.*s"), STRING_FORMAT(addrstr));
	}

	udp_socket_sendto(sock_mdns, services_query, services_query_len, mdns_multicast_addr);

	size_t iloop = 0;
	while (iloop++ < 30) {
		const network_address_t* source;

		size_t data_size = udp_socket_recvfrom(sock_mdns, databuf, sizeof(databuf), &source);
		log_infof(HASH_TEST, STRING_CONST("Read bytes: %" PRIsize), data_size);

		if (data_size > 0) {
			char name[256];
			uint16_t* data = (uint16_t*)databuf;
			unsigned char* rawdata = (unsigned char*)databuf;

			uint16_t transaction_id = byteorder_bigendian16(*data++);
			uint16_t flags          = byteorder_bigendian16(*data++);
			uint16_t questions      = byteorder_bigendian16(*data++);
			uint16_t answer_rrs     = byteorder_bigendian16(*data++);
			uint16_t authority_rrs  = byteorder_bigendian16(*data++);
			uint16_t additional_rrs = byteorder_bigendian16(*data++);

			log_infof(HASH_TEST,
			          STRING_CONST("mDNS header parsed: transaction_id %d : flags 0x%04x : questions %d : answer_rrs %d : authority_rrs %d : additional_rrs %d"),
			          (int)transaction_id,
			          (int)flags,
			          (int)questions,
			          (int)answer_rrs,
			          (int)authority_rrs,
			          (int)additional_rrs
			         );

			for (int i = 0; i < questions; ++i) {
				size_t ofs = (size_t)pointer_diff(data, rawdata);
				if (!parse_string(rawdata, data_size, &ofs, name))
					log_info(HASH_TEST, STRING_CONST("Failed to parse string"));
				data = pointer_offset(rawdata, ofs);

				uint16_t type = byteorder_bigendian16(*data++);
				uint16_t rclass = byteorder_bigendian16(*data++);

				log_infof(HASH_TEST, STRING_CONST("  question: %s type %d rclass 0x%x"), name, (int)type, (int)rclass);
			}

			for (int i = 0; i < answer_rrs; ++i) {
				size_t ofs = (size_t)pointer_diff(data, rawdata);
				if (!parse_string(rawdata, data_size, &ofs, name))
					log_info(HASH_TEST, STRING_CONST("Failed to parse string"));
				data = pointer_offset(rawdata, ofs);

				uint16_t type = byteorder_bigendian16(*data++);
				uint16_t rclass = byteorder_bigendian16(*data++);
				uint32_t ttl = byteorder_bigendian32(*(uint32_t*)(void*)data); data += 2;
				uint16_t length = byteorder_bigendian16(*data++);

				log_infof(HASH_TEST, STRING_CONST("  answer: %s type %d rclass 0x%x ttl %d length %d"), name, (int)type,
				          (int)rclass, (int)ttl, (int)length);

				if (type == MDNS_RECORDTYPE_PTR) {
					ofs = (size_t)pointer_diff(data, rawdata);
					if (!parse_string(rawdata, data_size, &ofs, name))
						log_info(HASH_TEST, STRING_CONST("     Failed to parse PTR record string"));
					else
						log_infof(HASH_TEST, STRING_CONST("    PTR %s"), name);
				}

				data = pointer_offset(data, length);
			}

			for (int i = 0; i < authority_rrs; ++i) {
				size_t ofs = (size_t)pointer_diff(data, rawdata);
				if (!parse_string(rawdata, data_size, &ofs, name))
					log_info(HASH_TEST, STRING_CONST("Failed to parse string"));
				data = pointer_offset(rawdata, ofs);

				uint16_t type = byteorder_bigendian16(*data++);
				uint16_t rclass = byteorder_bigendian16(*data++);
				uint32_t ttl = byteorder_bigendian32(*(uint32_t*)(void*)data); data += 2;
				uint16_t length = byteorder_bigendian16(*data++);

				log_infof(HASH_TEST, STRING_CONST("  authority: %s type %d rclass 0x%x ttl %d length %d"), name, (int)type,
				          (int)rclass, (int)ttl, (int)length);

				data = pointer_offset(data, length);
			}

			for (int i = 0; i < additional_rrs; ++i) {
				size_t ofs = (size_t)pointer_diff(data, rawdata);
				if (!parse_string(rawdata, data_size, &ofs, name))
					log_info(HASH_TEST, STRING_CONST("Failed to parse string"));
				data = pointer_offset(rawdata, ofs);

				uint16_t type = byteorder_bigendian16(*data++);
				uint16_t rclass = byteorder_bigendian16(*data++);
				uint32_t ttl = byteorder_bigendian32(*(uint32_t*)(void*)data); data += 2;
				uint16_t length = byteorder_bigendian16(*data++);

				log_infof(HASH_TEST, STRING_CONST("  additional: %s type %d rclass 0x%x ttl %d length %d"), name, (int)type,
				          (int)rclass, (int)ttl, (int)length);

				if (type == MDNS_RECORDTYPE_SRV) {
					uint16_t* recorddata = data;

					// Read the port number and the discovery name
					// SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
					// 2 bytes network-order unsigned priority
					// 2 bytes network-order unsigned weight
					// 2 bytes network-order unsigned port
					// string: discovery (domain) name, minimum 2 bytes when compressed

					uint16_t priority = byteorder_bigendian16(*recorddata++);
					uint16_t weight = byteorder_bigendian16(*recorddata++);
					uint16_t port = byteorder_bigendian16(*recorddata++);
					name[0] = 0;

					if (length >= 8) {
						ofs = (size_t)pointer_diff(recorddata, rawdata);
						parse_string(rawdata, data_size, &ofs, name);
					}

					log_infof(HASH_TEST, STRING_CONST("    SRV %s priority %d weight %d port %d"), name, priority, weight, port);
				}
				else if (type == MDNS_RECORDTYPE_TXT) {
					size_t separator, len;
					int subofs = 0;
					int remain = (int)length;
					while (remain > 0) {
						len = *(data + subofs);
						memcpy(name, data + subofs + 1, len);
						name[len] = 0;

						separator = string_find(name, len, '=', 0);
						if (separator != STRING_NPOS) {
							name[separator] = 0;
							log_infof(HASH_TEST, STRING_CONST("    TXT %s = %s"), name, name + separator + 1);
						}

						subofs += len + 1;
						remain -= len + 1;
					}
				}
				else if (type == MDNS_RECORDTYPE_A) {
					if (length == 4) {
						network_address_t* addr = network_address_ipv4_from_ip(*(uint32_t*)(void*)data);
						string_t addrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), addr, true);

						log_infof(HASH_TEST, STRING_CONST("    A %.*s"), STRING_FORMAT(addrstr));

						memory_deallocate(addr);
					}
				}

				data = pointer_offset(data, length);
			}
		}
		else {
			thread_sleep(1000);
		}
	}

	network_address_array_deallocate(mdns_multicast_addrs);
	network_address_array_deallocate(localhost_addrs);

	socket_deallocate(sock_mdns);

	return 0;
}

static void
test_dnsds_declare(void) {
	ADD_TEST(dnsds, discover);
}

static test_suite_t test_dnsds_suite = {
	test_dnsds_application,
	test_dnsds_memory_system,
	test_dnsds_foundation_config,
	test_dnsds_declare,
	test_dnsds_initialize,
	test_dnsds_finalize,
	0
};

#if BUILD_MONOLITHIC

int
test_dnsds_run(void);

int
test_dnsds_run(void) {
	test_suite = test_dnsds_suite;
	return test_run_all();
}

#else

test_suite_t
test_suite_define(void);

test_suite_t
test_suite_define(void) {
	return test_dnsds_suite;
}

#endif
