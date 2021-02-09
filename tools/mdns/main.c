
#include <foundation/foundation.h>
#include <network/network.h>
#include <mdns/mdns.h>

static char recvbuffer[1024];
static char addrbuffer[256];
static char entrybuffer[256];
static char namebuffer[256];

static int
query_callback(socket_t* sock, const network_address_t* from, mdns_entry_type_t entry, uint16_t query_id,
               uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data, size_t size, size_t name_offset,
               size_t name_length, size_t record_offset, size_t record_length, void* user_data) {
	(void)sizeof(sock);
	(void)sizeof(query_id);
	(void)sizeof(name_length);
	(void)sizeof(user_data);
	string_t fromaddrstr = network_address_to_string(addrbuffer, sizeof(addrbuffer), from, false);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
	                            "answer" :
	                            ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	string_const_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
	if (rtype == MDNS_RECORDTYPE_PTR) {
		string_const_t namestr =
		    mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
		log_infof(HASH_MDNS, "%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n", STRING_FORMAT(fromaddrstr),
		          entrytype, STRING_FORMAT(entrystr), STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv =
		    mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
		log_infof(HASH_MDNS, "%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n", STRING_FORMAT(fromaddrstr),
		          entrytype, STRING_FORMAT(entrystr), STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		network_address_ipv4_t addr;
		mdns_record_parse_a(data, size, record_offset, record_length, &addr);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer), (network_address_t*)&addr, false);
		log_infof(HASH_MDNS, "%.*s : %s %.*s A %.*s\n", STRING_FORMAT(fromaddrstr), entrytype, STRING_FORMAT(entrystr),
		          STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		network_address_ipv6_t addr;
		mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
		string_t addrstr = network_address_to_string(namebuffer, sizeof(namebuffer), (network_address_t*)&addr, false);
		log_infof(HASH_MDNS, "%.*s : %s %.*s AAAA %.*s\n", STRING_FORMAT(fromaddrstr), entrytype,
		          STRING_FORMAT(entrystr), STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		mdns_record_txt_t records[16];
		size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, records,
		                                      sizeof(records) / sizeof(records[0]));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (records[itxt].value.length) {
				log_infof(HASH_MDNS, "%.*s : %s %.*s TXT %.*s = %.*s\n", STRING_FORMAT(fromaddrstr), entrytype,
				          STRING_FORMAT(entrystr), STRING_FORMAT(records[itxt].key),
				          STRING_FORMAT(records[itxt].value));
			} else {
				log_infof(HASH_MDNS, "%.*s : %s %.*s TXT %.*s\n", STRING_FORMAT(fromaddrstr), entrytype,
				          STRING_FORMAT(entrystr), STRING_FORMAT(records[itxt].key));
			}
		}
	} else {
		log_infof(HASH_MDNS, "%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", STRING_FORMAT(fromaddrstr),
		          entrytype, STRING_FORMAT(entrystr), rtype, rclass, ttl, (int)record_length);
	}
	return 0;
}

int
main_initialize(void) {
	int ret = 0;
	application_t application = {0};
	foundation_config_t config = {0};

	application.name = string_const(STRING_CONST("mdns"));
	application.short_name = string_const(STRING_CONST("mdns"));
	application.flags = APPLICATION_UTILITY;

	log_enable_prefix(false);
	log_set_suppress(0, ERRORLEVEL_WARNING);

	if ((ret = foundation_initialize(memory_system_malloc(), application, config)) < 0)
		return ret;

	network_config_t network_config = {0};
	if ((ret = network_module_initialize(network_config)) < 0)
		return ret;

	mdns_config_t mdns_config = {0};
	if ((ret = mdns_module_initialize(mdns_config)) < 0)
		return ret;

	return 0;
}

int
main_run(void* main_arg) {
	int result = 0;

	FOUNDATION_UNUSED(main_arg);

	socket_t* sock = udp_socket_allocate();
	if (!sock)
		return -1;

	if (!mdns_socket_bind(sock, 0)) {
		log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to bind mDNS socket"));
		result = -1;
		goto finalize;
	}

	if (mdns_discovery_send(sock) < 0) {
		log_error(HASH_MDNS, ERROR_SYSTEM_CALL_FAIL, STRING_CONST("Failed to send DNS-SD packet"));
		result = -1;
		goto finalize;
	}

	log_infof(HASH_MDNS, STRING_CONST("Reading DNS-SD responses\n"));
	for (int iloop = 0; iloop < 10; ++iloop) {
		mdns_discovery_recv(sock, recvbuffer, sizeof(recvbuffer), query_callback, 0);
		thread_sleep(1000);
	}

finalize:
	if (sock)
		socket_deallocate(sock);

	return result;
}

void
main_finalize(void) {
	mdns_module_finalize();
	network_module_finalize();
	foundation_finalize();
}
