/* string.h  -  mDNS library  -  Public Domain  -  2015 Mattias Jansson / Rampant Pixels
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

#include <mdns/mdns.h>

#define MDNS_INVALID_POS ((size_t)-1)

typedef struct mdns_string_pair {
	size_t  offset;
	size_t  length;
	bool    ref;
} mdns_string_pair_t;

static bool
is_string_ref(uint8_t val) {
	return (0xC0 == (val & 0xC0));
}

static mdns_string_pair_t
get_next_substring(const void* rawdata, size_t size, size_t offset) {
	const uint8_t* buffer = rawdata;
	mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, false};
	if (!buffer[offset]) {
		pair.offset = offset;
		return pair;
	}
	if (is_string_ref(buffer[offset])) {
		if (size < offset + 2)
			return pair;

		offset = (((size_t)(0x3f & buffer[offset]) << 8) | (size_t)buffer[offset + 1]);
		if (offset >= size)
			return pair;

		pair.ref = true;
	}

	size_t length = (size_t)buffer[offset++];
	if (size < offset + length)
		return pair;

	pair.offset = offset;
	pair.length = length;

	return pair;
}

string_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset,
                    char* str, size_t capacity) {
	size_t cur = *offset;
	size_t end = MDNS_INVALID_POS;
	mdns_string_pair_t substr;
	string_t result = {str, 0};
	char* dst = str;
	size_t remain = capacity;
	do {
		substr = get_next_substring(buffer, size, cur);
		if (substr.offset == MDNS_INVALID_POS)
			return result;
		if (substr.ref && (end == MDNS_INVALID_POS))
			end = cur + 2;
		if (substr.length) {
			size_t to_copy = (substr.length < remain) ? substr.length : remain;
			memcpy(dst, pointer_offset_const(buffer, substr.offset), to_copy);
			dst += to_copy;
			remain -= to_copy;
			if (remain) {
				*dst++ = '.';
				--remain;
			}
		}
		cur = substr.offset + substr.length;
	} while (substr.length);

	if (end == MDNS_INVALID_POS)
		end = cur + 1;
	*offset = end;

	result.length = capacity - remain;
	return result;
}

bool
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs,
                  const void* buffer_rhs, size_t size_rhs, size_t* ofs_rhs) {
	size_t lhs_cur = *ofs_lhs;
	size_t rhs_cur = *ofs_rhs;
	size_t lhs_end = MDNS_INVALID_POS;
	size_t rhs_end = MDNS_INVALID_POS;
	mdns_string_pair_t lhs_substr;
	mdns_string_pair_t rhs_substr;
	do {
		lhs_substr = get_next_substring(buffer_lhs, size_lhs, lhs_cur);
		rhs_substr = get_next_substring(buffer_rhs, size_rhs, rhs_cur);
		if ((lhs_substr.offset == MDNS_INVALID_POS) || (rhs_substr.offset == MDNS_INVALID_POS) ||
		        (lhs_substr.length != rhs_substr.length))
			return false;
		if (memcmp(pointer_offset_const(buffer_lhs, lhs_substr.offset), pointer_offset_const(buffer_rhs,
		           rhs_substr.offset), lhs_substr.length))
			return false;
		if (lhs_substr.ref && (lhs_end == MDNS_INVALID_POS))
			lhs_end = lhs_cur + 2;
		if (rhs_substr.ref && (rhs_end == MDNS_INVALID_POS))
			rhs_end = rhs_cur + 2;
		lhs_cur = lhs_substr.offset + lhs_substr.length;
		rhs_cur = rhs_substr.offset + rhs_substr.length;
	}
	while (lhs_substr.length);

	if (lhs_end == MDNS_INVALID_POS)
		lhs_end = lhs_cur + 1;
	*ofs_lhs = lhs_end;

	if (rhs_end == MDNS_INVALID_POS)
		rhs_end = rhs_cur + 1;
	*ofs_rhs = rhs_end;

	return true;
}
