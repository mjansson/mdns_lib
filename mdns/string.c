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
mdns_string_make(void* buffer, size_t capacity, void* data, const char* name, size_t length,
                 mdns_string_table_t* string_table) {
	size_t pos = 0;
	size_t last_pos = 0;
	size_t remain = capacity - pointer_diff(data, buffer);
	if (name[length - 1] == '.')
		--length;
	while (last_pos < length) {
		pos = mdns_string_find(name, length, '.', last_pos);
		size_t sub_length = ((pos != STRING_NPOS) ? pos : length) - last_pos;
		size_t total_length = length - last_pos;

		size_t ref_offset = mdns_string_table_find(string_table, buffer, capacity, pointer_offset(name, last_pos),
		                                           sub_length, total_length);
		if (ref_offset != STRING_NPOS)
			return mdns_string_make_ref(data, remain, ref_offset);

		if (remain <= (sub_length + 1))
			return 0;

		*(unsigned char*)data = (unsigned char)sub_length;
		memcpy(pointer_offset(data, 1), name + last_pos, sub_length);
		mdns_string_table_add(string_table, pointer_diff(data, buffer));

		data = pointer_offset(data, sub_length + 1);
		last_pos = ((pos != STRING_NPOS) ? pos + 1 : length);
		remain = capacity - pointer_diff(data, buffer);
	}

	if (!remain)
		return 0;

	*(unsigned char*)data = 0;
	return pointer_offset(data, 1);
}

void*
mdns_string_make_ref(void* data, size_t capacity, size_t ref_offset) {
	if (capacity < 2)
		return 0;
	return mdns_htons(data, 0xC000 | (uint16_t)ref_offset);
}

size_t
mdns_string_table_find(mdns_string_table_t* string_table, const void* buffer, size_t capacity, const char* str,
                       size_t first_length, size_t total_length) {
	if (!string_table)
		return STRING_NPOS;

	for (size_t istr = 0; istr < string_table->count; ++istr) {
		if (string_table->offset[istr] >= capacity)
			continue;
		size_t offset = 0;
		mdns_string_pair_t sub_string = mdns_get_next_substring(buffer, capacity, string_table->offset[istr]);
		if (!sub_string.length || (sub_string.length != first_length))
			continue;
		if (memcmp(str, pointer_offset(buffer, sub_string.offset), sub_string.length))
			continue;

		// Initial substring matches, now match all remaining substrings
		offset += first_length + 1;
		while (offset < total_length) {
			size_t dot_pos = string_find(str, total_length, '.', offset);
			if (dot_pos == STRING_NPOS)
				dot_pos = total_length;
			size_t current_length = dot_pos - offset;

			sub_string = mdns_get_next_substring(buffer, capacity, sub_string.offset + sub_string.length);
			if (!sub_string.length || (sub_string.length != current_length))
				break;
			if (memcmp(str + offset, pointer_offset(buffer, sub_string.offset), sub_string.length))
				break;

			offset = dot_pos + 1;
		}

		// Return reference offset if entire string matches
		if (offset >= total_length)
			return string_table->offset[istr];
	}

	return STRING_NPOS;
}

void
mdns_string_table_add(mdns_string_table_t* string_table, size_t offset) {
	if (!string_table)
		return;

	string_table->offset[string_table->next] = offset;

	size_t table_capacity = sizeof(string_table->offset) / sizeof(string_table->offset[0]);
	if (++string_table->count > table_capacity)
		string_table->count = table_capacity;
	if (++string_table->next >= table_capacity)
		string_table->next = 0;
}
