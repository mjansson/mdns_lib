/* string.c  -  mDNS library  -  Public Domain  -  2014 Mattias Jansson
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C based
 * on our foundation and network libraries. The implementation is based on RFC 6762
 * and RFC 6763.
 *
 * The latest source code maintained by Mattias Jansson is always available at
 *
 * https://github.com/mjansson/mdns_lib
 *
 * The foundation and network library source code maintained by Mattias Jansson
 * is always available at
 *
 * https://github.com/mjansson/foundation_lib
 * https://github.com/mjansson/network_lib
 *
 * This library is put in the public domain; you can redistribute it and/or modify
 * it without any restrictions.
 *
 */

#include <foundation/foundation.h>

#include <mdns/mdns.h>

int
mdns_is_string_ref(uint8_t val) {
	return (0xC0 == (val & 0xC0));
}

mdns_string_pair_t
mdns_get_next_substring(const void* rawdata, size_t size, size_t offset) {
	const uint8_t* buffer = (const uint8_t*)rawdata;
	mdns_string_pair_t pair = {STRING_NPOS, 0, 0};
	if (offset >= size)
		return pair;
	if (!buffer[offset]) {
		pair.offset = offset;
		return pair;
	}
	if (mdns_is_string_ref(buffer[offset])) {
		if (size < offset + 2)
			return pair;

		offset = mdns_ntohs(pointer_offset(buffer, offset)) & 0x3fff;
		if (offset >= size)
			return pair;

		pair.ref = 1;
	}

	size_t length = (size_t)buffer[offset++];
	if (size < offset + length)
		return pair;

	pair.offset = offset;
	pair.length = length;

	return pair;
}

int
mdns_string_skip(const void* buffer, size_t size, size_t* offset) {
	size_t cur = *offset;
	mdns_string_pair_t substr;
	unsigned int counter = 0;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == STRING_NPOS) || (counter++ > MDNS_MAX_SUBSTRINGS))
			return 0;
		if (substr.ref) {
			*offset = cur + 2;
			return 1;
		}
		cur = substr.offset + substr.length;
	} while (substr.length);

	*offset = cur + 1;
	return 1;
}

int
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs, const void* buffer_rhs, size_t size_rhs,
                  size_t* ofs_rhs) {
	size_t lhs_cur = *ofs_lhs;
	size_t rhs_cur = *ofs_rhs;
	size_t lhs_end = STRING_NPOS;
	size_t rhs_end = STRING_NPOS;
	mdns_string_pair_t lhs_substr;
	mdns_string_pair_t rhs_substr;
	unsigned int counter = 0;
	do {
		lhs_substr = mdns_get_next_substring(buffer_lhs, size_lhs, lhs_cur);
		rhs_substr = mdns_get_next_substring(buffer_rhs, size_rhs, rhs_cur);
		if ((lhs_substr.offset == STRING_NPOS) || (rhs_substr.offset == STRING_NPOS) ||
		    (counter++ > MDNS_MAX_SUBSTRINGS))
			return 0;
		if (!string_equal_nocase(pointer_offset_const(buffer_lhs, lhs_substr.offset), lhs_substr.length,
		                         pointer_offset_const(buffer_rhs, rhs_substr.offset), rhs_substr.length))
			return 0;
		if (lhs_substr.ref && (lhs_end == STRING_NPOS))
			lhs_end = lhs_cur + 2;
		if (rhs_substr.ref && (rhs_end == STRING_NPOS))
			rhs_end = rhs_cur + 2;
		lhs_cur = lhs_substr.offset + lhs_substr.length;
		rhs_cur = rhs_substr.offset + rhs_substr.length;
	} while (lhs_substr.length);

	if (lhs_end == STRING_NPOS)
		lhs_end = lhs_cur + 1;
	*ofs_lhs = lhs_end;

	if (rhs_end == STRING_NPOS)
		rhs_end = rhs_cur + 1;
	*ofs_rhs = rhs_end;

	return 1;
}

string_const_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset, char* str, size_t capacity) {
	size_t cur = *offset;
	size_t end = STRING_NPOS;
	mdns_string_pair_t substr;
	string_const_t result;
	result.str = str;
	result.length = 0;
	char* dst = str;
	unsigned int counter = 0;
	size_t remain = capacity;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == STRING_NPOS) || (counter++ > MDNS_MAX_SUBSTRINGS))
			return result;
		if (substr.ref && (end == STRING_NPOS))
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

	if (end == STRING_NPOS)
		end = cur + 1;
	*offset = end;

	result.length = capacity - remain;
	return result;
}

size_t
mdns_string_find(const char* str, size_t length, char c, size_t offset) {
	const void* found;
	if (offset >= length)
		return STRING_NPOS;
	found = memchr(str + offset, c, length - offset);
	if (found)
		return (size_t)pointer_diff(found, str);
	return STRING_NPOS;
}

void*
mdns_string_make(void* data, size_t capacity, const char* name, size_t length) {
	size_t pos = 0;
	size_t last_pos = 0;
	size_t remain = capacity;
	unsigned char* dest = (unsigned char*)data;
	while ((last_pos < length) && ((pos = mdns_string_find(name, length, '.', last_pos)) != STRING_NPOS)) {
		size_t sublength = pos - last_pos;
		if (sublength < remain) {
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		} else {
			return 0;
		}
		last_pos = pos + 1;
	}
	if (last_pos < length) {
		size_t sublength = length - last_pos;
		if (sublength < remain) {
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		} else {
			return 0;
		}
	}
	if (!remain)
		return 0;
	*dest++ = 0;
	return dest;
}

void*
mdns_string_make_ref(void* data, size_t capacity, size_t ref_offset) {
	if (capacity < 2)
		return 0;
	return mdns_htons(data, 0xC000 | (uint16_t)ref_offset);
}

void*
mdns_string_make_with_ref(void* data, size_t capacity, const char* name, size_t length, size_t ref_offset) {
	void* remaindata = mdns_string_make(data, capacity, name, length);
	capacity -= pointer_diff(remaindata, data);
	if (!data || !capacity)
		return 0;
	return mdns_string_make_ref(pointer_offset(remaindata, -1), capacity + 1, ref_offset);
}
