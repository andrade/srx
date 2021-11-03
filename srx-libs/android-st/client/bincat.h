/**
** The *bincat* library.
**
** The format of the underlying buffer is:
** `version|FULLSIZE | (unitsize|count|data)*`.
**
** Just after the initialization, only `version|FULLSIZE` is present.
** `FULLSIZE` includes the entire size of the buffer
** (including `version|FULLSIZE`). We use one byte as an octet.
**
** The library assumes the first position is `1`, not `0`,
** therefore there is no position zero.
**
** The library does not handle endianness.
**
** The buffer can be written to disk or to the stream as is.
** When reading we first receive the `version|FULLSIZE` and thus know the
** remaining size is the value of `FULLSIZE` minus 5 bytes.
**
** No other state is maintained other than what is on the buffer.
** This means the buffer could be manipulated directly. As long as
** all the sizes match, the functions would still work on the buffer.
**/

#pragma once

#include <stdint.h>

// only add relevant errors and keep it to a minimum; success always zero
#define BC_SUCCESS  0
#define BC_FAILURE  1   /* Operation failed: this is a generic error */
#define BC_ENOPOS   2   /* No such position */
//#define BC_ENFOUND  3   /* Object not found: pos maybe valid, but no obj */

/**
** Initializes the memory buffer.
**
** Returns a pointer to the allocated memory, and NULL on error.
**/
uint8_t *bc_init();

/**
** Frees the memory space pointed to by `ptr`.
** If `ptr` is NULL, no operation is performed.
**/
void bc_free(uint8_t *ptr);

/**
** Concatenates a new element to the buffer.
**
** The behavior is undefined when `dest` is invalid.
** The behavior is undefined when `src` is invalid,
** unless `unitsize * count = 0`.
**
** @return      Returns zero on success, or non-zero otherwise.
**/
uint8_t bc_cat(uint8_t **dest,
		const void *src, uint8_t unitsize, uint32_t count);

/**
** Retrieves data from the buffer.
**
** The caller allocates `dest`. The full size of `dest` can be
** found with `unitsize(-) * count(-)` or `size(-)`.
** The number of elements is found with `count(-)`.
**
** The first position is `1`.
**
** @param[in]   dest    pointer to destination buffer
** @param[in]   ptr     pointer to source buffer
** @param[in]   pos     the position to read from the buffer
**
** @return      Returns zero on success, or non-zero otherwise.
**              Returns `ENOPOS` when the position does not exist.
**
** @see         `bc_unitsize(-)`
** @see         `bc_count(-)`
** @see         `bc_size(-)`
**/
uint8_t bc_get(void *dest, const uint8_t *ptr, uint32_t pos);

/**
** Returns the unit size of an element.
**
** This is the storage size of the type stored with `bc_cat`.
** For example, the unit size of a `uint16_t` is `2`, and
** the unit size of a `uint64_t` is `8`.
**
** The behavior is undefined if `ptr` or `pos` are invalid.
**/
uint8_t bc_unitsize(const uint8_t *ptr, uint32_t pos);

/**
** Returns the size of an element.
**
** The header of the element is not included in the size, only data.
**
** The behavior is undefined when either `ptr` or `pos` are invalid.
** The bounds of `pos` are `[1, bc_fullcount(-)]`.
**
** @param[in]   ptr     pointer to buffer
** @param[in]   pos     the position
**
** @return      The size of the element at position `pos`.
**/
uint32_t bc_size(const uint8_t *ptr, uint32_t pos);

/**
** Returns the element count.
**
** Does not fail as long as `ptr` is valid and initialized, and
** `pos` is within bounds.
**
** @return      The number of elements at position `pos`.
**/
uint32_t bc_count(const uint8_t *ptr, uint32_t pos);

/**
** Returns the size of the entire buffer.
** The behavior is undefined when `ptr` is invalid.
**/
uint32_t bc_fullsize(const uint8_t *ptr);

/**
** Returns the number of elements in the buffer.
** The behavior is undefined when `ptr` is invalid.
**/
uint32_t bc_fullcount(const uint8_t *ptr);



// size matters, use size/count correctly.
// This will be used in the future to handle endianness.
//
// Rule #1: caller should allocate everything
// Rule #2: size matters, use size and count variables correctly
// Rule #3: check your return values, zero means success (or use BC_SUCCESS)
//
// Note #1: one byte is 8 bits unless it is not
// Note #2: all is written in big endian (NBO)
// Note #3: library abuses uint32_t, this obviously results in size limitations

// Keep the interface as simple as possible, it's not meant to be a smart one.
