/* types.h  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
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

#pragma once

#include <foundation/platform.h>
#include <foundation/types.h>
#include <network/types.h>

#include <mdns/build.h>

enum mdns_record_type {
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

enum mdns_class {
	MDNS_CLASS_IN = 1
};

typedef enum mdns_record_type  mdns_record_type_t;
typedef enum mdns_class        mdns_class_t;

typedef int (* mdns_record_callback_t)(const network_address_t* from, uint16_t type,
                                       uint16_t rclass, uint32_t ttl,
                                       const void* data, size_t offset, size_t length);

typedef struct mdns_config_t   mdns_config_t;

struct mdns_config_t {
	int       unused;
};
