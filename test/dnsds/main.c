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

static int
dnsds_callback(const network_address_t* from, uint16_t type,
               uint16_t rclass, uint32_t ttl,
               const void* data, size_t offset, size_t length) {
	char addrbuffer[NETWORK_ADDRESS_NUMERIC_MAX_LENGTH];
	char namebuffer[256];

	string_t fromaddrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), from, true);
	string_t namestr = mdns_string_extract(data, offset + length, &offset, namebuffer, sizeof(namebuffer));
	log_infof(HASH_TEST, STRING_CONST("%.*s : PTR %.*s type %u rclass 0x%x ttl %u length %" PRIsize),
	          STRING_FORMAT(fromaddrstr), STRING_FORMAT(namestr), type, rclass, ttl, length);
	return 0;
}


DECLARE_TEST(dnsds, discover) {
	socket_t* sock_mdns;
	uint32_t databuf[128];

	log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_set_suppress(HASH_MDNS, ERRORLEVEL_NONE);

	sock_mdns = mdns_socket_allocate();
	EXPECT_NE(sock_mdns, nullptr);

	mdns_discovery_send(sock_mdns);

	size_t iloop = 0;
	while (iloop++ < 30) {
		size_t records = mdns_discovery_recv(sock_mdns, databuf, sizeof(databuf), dnsds_callback);
		log_infof(HASH_TEST, STRING_CONST("Records read: %" PRIsize), records);
		thread_sleep(1000);

		/*
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

			string_t sourceaddrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), source, true);
			log_infof(HASH_TEST, STRING_CONST("sent from: %.*s"), STRING_FORMAT(sourceaddrstr));

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
						network_address_ipv4_t a_addr;
						network_address_t* addr = network_address_ipv4_initialize(&a_addr);
						network_address_ipv4_set_ip(addr, byteorder_bigendian32(*(uint32_t*)(void*)data));
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
		*/
	}

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
