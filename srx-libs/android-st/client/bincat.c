#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "bincat.h"

/**
** Reads a 4-byte value from the given position.
**/
static uint32_t read_uint32(const uint8_t *ptr)
{
	uint32_t n = *((uint32_t *) ptr);

	return n;
}

/**
** Writes a 4-byte value to the given position.
**/
static void write_uint32(uint8_t *ptr, uint32_t n)
{
	*((uint32_t *) ptr) = (uint32_t) n;
}

// useful for 1-byte version or unit size of each element
static uint8_t read_uint8(const uint8_t *ptr)
{
	return *ptr;
}

// useful for 1-byte version or unit size of each element
static void write_uint8(uint8_t *ptr, uint8_t n)
{
	*ptr = n;
}

/**
** Advances the pointer to position `pos`.
**
** Returns a pointer to `pos`, or null if `pos` is out of bounds.
**/
static uint8_t *forward(const uint8_t *ptr, uint32_t pos)
{
	uint32_t count = 0; // current element count
	const uint32_t total_size = read_uint32(ptr + 1);
	uint32_t next_pos = 1 + 4; // account for 5 bytes of version and FULLSIZE

	while (next_pos < total_size && count < pos) {
		count++;
		if (count == pos) {
			uint8_t *found = (uint8_t *) (ptr + next_pos); // RM warning: const
			return found;
		}
		// advance to next element
		uint8_t unitsize = read_uint8(ptr + next_pos);
		uint32_t count = read_uint32(ptr + next_pos + 1);
		next_pos += 1 + 4 + (unitsize * count);
	}

	return NULL;
}

uint8_t *bc_init()
{
	const uint8_t version = 1;
	const uint32_t initial_size = 1 + 4; // version || FULLSIZE

	uint8_t *p = calloc(initial_size, sizeof(uint8_t));
	if (!p)
		return NULL;
	write_uint8(p, version);           // version 1
	write_uint32(p + 1, initial_size); // FULLSIZE is 5 (after initialization)

	return p;
}

void bc_free(uint8_t *ptr)
{
	free(ptr);
}

// enlarges `dest` by unitsize*count and appends `src` to `dest`
// supports appending zero-size elements (e.g. array w/ no elements, count=0)
uint8_t bc_cat(uint8_t **dest,
		const void *src, uint8_t unitsize, uint32_t count)
{
	assert(dest);
	assert(*dest);
	assert(unitsize * count > 0 || src);

	uint32_t old_full_size = bc_fullsize(*dest);
	uint32_t new_full_size = old_full_size + 1 + 4 + unitsize * count;
	uint8_t *newptr = realloc(*dest, new_full_size);
	if (!newptr) {
		return BC_FAILURE;
	}

	uint8_t *next_pos = newptr + old_full_size;
	write_uint8(next_pos, unitsize);
	write_uint32(next_pos + 1, count);
	memcpy(next_pos + 1 + 4, src, unitsize * count);

	*((uint32_t *) (newptr + 1)) = new_full_size;

	*dest = newptr;

	return 0;
}

uint8_t bc_get(void *dest, const uint8_t *ptr, uint32_t pos)
{
	assert(dest);
	assert(ptr);

	uint8_t *p = forward(ptr, pos);
	if (!p) {
		return BC_ENOPOS;
	}
	uint32_t element_size = read_uint8(p);
	uint32_t element_count = read_uint32(p + 1);

	// ignoring endianness (would need to process elements of el_size > 1)
	memcpy(dest, p + 1 + 4, element_size * element_count);

	return 0;
}

uint8_t bc_unitsize(const uint8_t *ptr, uint32_t pos)
{
	assert(ptr);

	uint8_t *p = forward(ptr, pos);
	if (!p)
		abort(); // should never reach this, ensure pos is valid

	return read_uint8(p);
}

uint32_t bc_size(const uint8_t *ptr, uint32_t pos)
{
	assert(ptr);

	uint8_t *p = forward(ptr, pos);
	if (!p)
		abort(); // ensure `pos` is valid using `bc_fullcount(-)`

	return read_uint8(p) * read_uint32(p + 1);
}

uint32_t bc_count(const uint8_t *ptr, uint32_t pos)
{
	assert(ptr);

	uint8_t *p = forward(ptr, pos);
	if (!p) {
		// can ensure `pos` is valid using `bc_fullcount(-)`
		abort(); // should never reach this
	}

	return read_uint32(p + 1);
}

/*
* The return value is always, at least, the storage size
* of version (1) and FULLSIZE (4).
*/
uint32_t bc_fullsize(const uint8_t *ptr)
{
	assert(ptr);

	return read_uint32(ptr + 1); // skip version
}

uint32_t bc_fullcount(const uint8_t *ptr)
{
	assert(ptr);

	const uint32_t full_size = read_uint32(ptr + 1);

	uint32_t full_count = 0;
	uint32_t next_pos = 1 + 4; // account for version and FULLSIZE

	while (next_pos < full_size) {
		full_count++;
		uint32_t element_count = read_uint8(ptr + next_pos);
		uint32_t element_size = read_uint32(ptr + next_pos + 1);
		next_pos += 1 + 4 + (element_count * element_size);
	}

	return full_count;
}
