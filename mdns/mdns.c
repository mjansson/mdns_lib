/* mdns.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform mDNS and DNS-DS library in C based
 * on our foundation and network libraries.
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

#include <foundation/foundation.h>


static bool _mdns_initialized = false;


int mdns_initialize( void )
{
	if( _mdns_initialized )
		return 0;

	_mdns_initialized = true;

	return 0;
}


void mdns_shutdown( void )
{
	if( !_mdns_initialized )
		return;

	_mdns_initialized = false;
}


bool mdns_is_initialized( void )
{
	return _mdns_initialized;
}

