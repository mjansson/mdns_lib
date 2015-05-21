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
 * https://github.com/rampantpixels/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#include "query.h"


mdsn_query_t* mdns_query_allocate( uint16_t capacity, const char* name )
{
	mdns_query_t* query;

	if( !capacity )
	{
		if( !name )
			capacity = MDNS_QUERY_SIZE_DEFAULT;
	}

	query = memory_allocate( HASH_MDNS, capacity + sizeof( mdns_query_t ), 0, MEMORY_PERSISTENT );
	mdns_query_initialize( query, capacity, name );

	return query;
}


void mdns_query_initialize( mdsn_query_t* query, uint16_t capacity, const char* name )
{
	query->size = 0;
	query->capacity = capacity;

	if( name )
		mdsn_query_append( query, name )
}


void mdns_query_deallocate( mdns_query_t* query )
{
	memory_deallocate( query );
}


void mdns_query_append( mdns_query_t* query, const char* name )
{

}

