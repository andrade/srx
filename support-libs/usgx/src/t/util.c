#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

#include "usgx/t/util.h"
#include "util_t.h"

int printf(const char *format, ...)
{
	int size = 0;
	char *p = NULL;
	va_list ap;

	/* find string size */
	va_start(ap, format);
	size = vsnprintf(p, size, format, ap);
	va_end(ap);

	if (size < 0)
		return size;

	size++; /* for null byte */

	/*char buf[size] = {'\0'};*/
	p = malloc(size);
	if (!p)
		return -1;
	va_start(ap, format);
	size = vsnprintf(p, size, format, ap);
	if (size < 0) {
		free(p);
		return size;
	}
	va_end(ap);

	/* send to untrusted side, 1 for stdout */
	usgx_ocall_print(1, p);
	free(p);

	return size;
}

uint8_t usgx_hex_uint8_to_str(const uint8_t *a, uint32_t len,
		const char *sep, char **str)
{
	// output string has double size of `a` plus space for separators and `\0`
	size_t size = len * 2 + (len - 1) * strlen(sep) + 1;

	char *s = malloc(size);
	if (!s)
		return 1;

	// return empty string when input array is empty
	if (0 == len) {
		*str = s;
		return 0;
	}

	size_t step_len = 2 + strlen(sep); // how much to advance each iteration
	char *next_pos;
	size_t available_size;
	for (uint32_t i = 0; i < len - 1; i++) {
		next_pos = s + i * step_len;
		available_size = size - i * step_len;
		snprintf(next_pos, available_size, "%02"PRIx8"%s", a[i], sep);
	}
	next_pos = s + (len - 1) * step_len;
	available_size = size - (len - 1) * step_len;
	snprintf(next_pos, available_size, "%02"PRIx8, a[len - 1]);

	*str = s;

	return 0;
}

void usgx_ecall_dummy() { /* do nothing */ }
