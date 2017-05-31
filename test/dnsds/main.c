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
query_callback(const network_address_t* from,
               mdns_entry_type_t entry, uint16_t type,
               uint16_t rclass, uint32_t ttl,
               const void* data, size_t offset, size_t length) {
	char addrbuffer[NETWORK_ADDRESS_NUMERIC_MAX_LENGTH];
	char namebuffer[256] FOUNDATION_ALIGN(8);
	size_t size = offset + length;
	FOUNDATION_UNUSED(entry);
	string_t fromaddrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), from, true);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
	                        ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	if (type == MDNS_RECORDTYPE_PTR) {
		string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
		                                         namebuffer, sizeof(namebuffer));
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %" PRIsize),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(namestr), type, rclass, ttl, length);
	}
	else if (type == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s SRV %.*s priority %d weight %d port %d"),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	}
	else if (type == MDNS_RECORDTYPE_A) {
		network_address_ipv4_t addr = mdns_record_parse_a(data, size, offset, length);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer),
		                                             (network_address_t*)&addr, true);
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s A %.*s"),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(addrstr));
	}
	else if (type == MDNS_RECORDTYPE_AAAA) {
		network_address_ipv6_t addr = mdns_record_parse_aaaa(data, size, offset, length);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer),
		                                             (network_address_t*)&addr, true);
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s AAAA %.*s"),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(addrstr));
	}
	else if (type == MDNS_RECORDTYPE_TXT) {
		mdns_record_txt_t* txtrecord = (void*)namebuffer;
		size_t parsed = mdns_record_parse_txt(data, size, offset, length,
		                                      txtrecord, sizeof(namebuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtrecord[itxt].value.length) {
				log_infof(HASH_TEST, STRING_CONST("%.*s : %s TXT %.*s = %.*s"),
				          STRING_FORMAT(fromaddrstr), entrytype,
				          STRING_FORMAT(txtrecord[itxt].key), STRING_FORMAT(txtrecord[itxt].value));
			}
			else {
				log_infof(HASH_TEST, STRING_CONST("%.*s : %s TXT %.*s"),
				          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(txtrecord[itxt].key));
			}
		}
	}
	else {
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s type %u rclass 0x%x ttl %u length %" PRIsize),
		          STRING_FORMAT(fromaddrstr), entrytype, type, rclass, ttl, length);
	}
	return 0;
}

DECLARE_TEST(dnsds, discover) {
	socket_t* sock_mdns;
	uint32_t databuf[128];

	//log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_set_suppress(HASH_MDNS, ERRORLEVEL_DEBUG);

	sock_mdns = mdns_socket_allocate();
	EXPECT_NE(sock_mdns, nullptr);

	mdns_discovery_send(sock_mdns);

	size_t iloop = 0;
	while (iloop++ < 30) {
		mdns_discovery_recv(sock_mdns, databuf, sizeof(databuf), query_callback);
		thread_sleep(100);
	}

	socket_deallocate(sock_mdns);

	return 0;
}

DECLARE_TEST(dnsds, query) {
	socket_t* sock_mdns;
	uint32_t databuf[128];

	//log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_set_suppress(HASH_MDNS, ERRORLEVEL_DEBUG);

	sock_mdns = mdns_socket_allocate();
	EXPECT_NE(sock_mdns, nullptr);

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_PTR, STRING_CONST("_ssh._tcp.local."), databuf,
	                sizeof(databuf));

	size_t iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_SRV, STRING_CONST("Tinybook._ssh._tcp.local."), databuf,
	                sizeof(databuf));

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_A, STRING_CONST("Tinybook.local."), databuf,
	                sizeof(databuf));

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_AAAA, STRING_CONST("Tinybook.local."), databuf,
	                sizeof(databuf));

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback);
		thread_sleep(100);
	}

	socket_deallocate(sock_mdns);

	return 0;
}

static void
test_dnsds_declare(void) {
	ADD_TEST(dnsds, discover);
	ADD_TEST(dnsds, query);
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
