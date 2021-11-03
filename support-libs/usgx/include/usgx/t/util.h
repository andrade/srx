#pragma once

#include <stdarg.h>
#include <stdint.h>

#define fprintf(stream, format, ...) do { printf(format, ##__VA_ARGS__); } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/*********************** Known Functions ***********************/

int printf(const char *format, ...);

/*********************** Other Functions ***********************/

/**
** Converts a uint8_t hex array to string.
**
** a      [in] the uint8_t hex array
** len    [in] the length of `a`
** sep    [in] the separator character, for example, "" or ":" or "::"
** str   [out] the resulting string, only set on success
**
** Returns zero on success, or non-zero on error.
**/
uint8_t usgx_hex_uint8_to_str(const uint8_t *a, uint32_t len,
		const char *sep, char **str);

#ifdef __cplusplus
}
#endif
