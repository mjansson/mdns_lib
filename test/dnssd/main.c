/* main.c  -  mDNS library  -  Public Domain  -  2013 Mattias Jansson
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C based
 * on our foundation and network libraries. The implementation is based on RFC 6762
 * and RFC 6763.
 *
 * The latest source code maintained by Mattias Jansson is always available at
 *
 * https://github.com/rampantpixels/mdns_lib
 *
 * The foundation and network library source code maintained by Mattias Jansson
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
test_dnssd_application(void) {
	application_t app;
	memset(&app, 0, sizeof(app));
	app.name = string_const(STRING_CONST("DNS-SD tests"));
	app.short_name = string_const(STRING_CONST("test_dnssd"));
	app.company = string_const(STRING_CONST(""));
	app.flags = APPLICATION_UTILITY;
	app.exception_handler = test_exception_handler;
	return app;
}

static memory_system_t
test_dnssd_memory_system(void) {
	return memory_system_malloc();
}

static foundation_config_t
test_dnssd_foundation_config(void) {
	foundation_config_t config;
	memset(&config, 0, sizeof(config));
	return config;
}

static int
test_dnssd_initialize(void) {
	network_config_t network_config = {0};
	if (network_module_initialize(network_config) < 0)
		return -1;

	mdns_config_t mdns_config = {0};
	if (mdns_module_initialize(mdns_config) < 0)
		return -1;

	return 0;
}

static void
test_dnssd_finalize(void) {
	mdns_module_finalize();
	network_module_finalize();
}

static int
query_callback(socket_t* sock, const network_address_t* from, mdns_entry_type_t entry, uint16_t query_id,
               uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data, size_t size, size_t name_offset,
               size_t name_length, size_t record_offset, size_t record_length, void* user_data) {
	char addrbuffer[NETWORK_ADDRESS_NUMERIC_MAX_LENGTH];
	char FOUNDATION_ALIGN(8) namebuffer[256];
	FOUNDATION_UNUSED(sock);
	FOUNDATION_UNUSED(entry);
	FOUNDATION_UNUSED(user_data);
	FOUNDATION_UNUSED(name_length);
	FOUNDATION_UNUSED(name_offset);
	FOUNDATION_UNUSED(query_id);
	string_t fromaddrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), from, true);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
	                            "answer" :
	                            ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	if (rtype == MDNS_RECORDTYPE_PTR) {
		string_const_t namestr =
		    mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %" PRIsize),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(namestr), rtype, rclass, ttl, record_length);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv =
		    mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s SRV %.*s priority %d weight %d port %d"),
		          STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		network_address_ipv4_t addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer), (network_address_t*)&addr, true);
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s A %.*s"), STRING_FORMAT(fromaddrstr), entrytype,
		          STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		network_address_ipv6_t addr;
		mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer), (network_address_t*)&addr, true);
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s AAAA %.*s"), STRING_FORMAT(fromaddrstr), entrytype,
		          STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		mdns_record_txt_t* txtrecord = (void*)namebuffer;
		size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtrecord,
		                                      sizeof(namebuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtrecord[itxt].value.length) {
				log_infof(HASH_TEST, STRING_CONST("%.*s : %s TXT %.*s = %.*s"), STRING_FORMAT(fromaddrstr), entrytype,
				          STRING_FORMAT(txtrecord[itxt].key), STRING_FORMAT(txtrecord[itxt].value));
			} else {
				log_infof(HASH_TEST, STRING_CONST("%.*s : %s TXT %.*s"), STRING_FORMAT(fromaddrstr), entrytype,
				          STRING_FORMAT(txtrecord[itxt].key));
			}
		}
	} else {
		log_infof(HASH_TEST, STRING_CONST("%.*s : %s type %u rclass 0x%x ttl %u length %" PRIsize),
		          STRING_FORMAT(fromaddrstr), entrytype, rtype, rclass, ttl, record_length);
	}
	return 0;
}

DECLARE_TEST(dnssd, discover) {
	socket_t* sock_mdns[16];
	uint32_t databuf[128];

	// log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_set_suppress(HASH_MDNS, ERRORLEVEL_DEBUG);

	network_address_t** local_address = network_address_local();
	EXPECT_NE(local_address, 0);

	size_t sock_count = array_size(local_address);
	size_t sock_capacity = sizeof(sock_mdns) / sizeof(sock_mdns[0]);
	if (sock_count > sock_capacity)
		sock_count = sock_capacity;

	for (size_t isock = 0; isock < sock_count; ++isock) {
		sock_mdns[isock] = udp_socket_allocate();
		EXPECT_NE(sock_mdns, nullptr);

		EXPECT_TRUE(mdns_socket_bind(sock_mdns[isock], local_address[isock]));
	}

	for (size_t isock = 0; isock < sock_count; ++isock)
		mdns_discovery_send(sock_mdns[isock]);

	size_t iloop = 0;
	while (iloop++ < 50) {
		for (size_t isock = 0; isock < sock_count; ++isock)
			mdns_discovery_recv(sock_mdns[isock], databuf, sizeof(databuf), query_callback, nullptr);
		thread_sleep(100);
	}

	for (size_t isock = 0; isock < sock_count; ++isock)
		socket_deallocate(sock_mdns[isock]);
	for (size_t iaddr = 0, acount = array_size(local_address); iaddr < acount; ++iaddr)
		network_address_deallocate(local_address[iaddr]);
	array_deallocate(local_address);

	return 0;
}

DECLARE_TEST(dnssd, query) {
	socket_t* sock_mdns;
	uint32_t databuf[128];

	log_set_suppress(HASH_NETWORK, ERRORLEVEL_NONE);
	log_set_suppress(HASH_TEST, ERRORLEVEL_NONE);
	log_set_suppress(HASH_MDNS, ERRORLEVEL_NONE);

	sock_mdns = udp_socket_allocate();
	EXPECT_NE(sock_mdns, nullptr);

	EXPECT_TRUE(mdns_socket_bind(sock_mdns, nullptr));

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_PTR, STRING_CONST("_ssh._tcp.local."), databuf, sizeof(databuf), 0);

	size_t iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_PTR, STRING_CONST("_spotify-connect._tcp.local."), databuf,
	                sizeof(databuf), 0);

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_PTR, STRING_CONST("_googlecast._tcp.local."), databuf, sizeof(databuf),
	                0);

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_SRV, STRING_CONST("Tinybook._ssh._tcp.local."), databuf, sizeof(databuf),
	                0);

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_A, STRING_CONST("Tinybook.local."), databuf, sizeof(databuf), 0);

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	mdns_query_send(sock_mdns, MDNS_RECORDTYPE_AAAA, STRING_CONST("Tinybook.local."), databuf, sizeof(databuf), 0);

	iloop = 0;
	while (iloop++ < 30) {
		mdns_query_recv(sock_mdns, databuf, sizeof(databuf), query_callback, nullptr, 0);
		thread_sleep(100);
	}

	socket_deallocate(sock_mdns);

	return 0;
}

static void
test_dnssd_declare(void) {
	ADD_TEST(dnssd, discover);
	ADD_TEST(dnssd, query);
}

static test_suite_t test_dnssd_suite = {test_dnssd_application,
                                        test_dnssd_memory_system,
                                        test_dnssd_foundation_config,
                                        test_dnssd_declare,
                                        test_dnssd_initialize,
                                        test_dnssd_finalize,
                                        0};

#if BUILD_MONOLITHIC

int
test_dnssd_run(void);

int
test_dnssd_run(void) {
	test_suite = test_dnssd_suite;
	return test_run_all();
}

#else

test_suite_t
test_suite_define(void);

test_suite_t
test_suite_define(void) {
	return test_dnssd_suite;
}

#endif
