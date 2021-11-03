// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <sgx_trts.h>

#include "enclave_t.h"

#include "linux.h"

// int printf(const char *format, ...)
// {
// 	int size = 0;
// 	char *str = NULL;
// 	va_list ap;
//
// 	/* find resulting string size */
// 	va_start(ap, format);
// 	size = vsnprintf(str, size, format, ap);
// 	va_end(ap);
//
// 	if (size < 0)
// 		return size;
//
// 	size++; /* for null character */
//
// 	/*char buffer[size] = {'\0'};*/
// 	str = malloc(size);
// 	if (!str)
// 		return -1;
// 	va_start(ap, format);
// 	size = vsnprintf(str, size, format, ap);
// 	if (size < 0) {
// 		free(str);
// 		return size;
// 	}
// 	va_end(ap);
//
// 	/* send to untrusted side, 1 for stdout */
// 	usgx_ocall_print(1, str);
// 	free(str);
//
// 	return size;
// }

char *sgx_strdup(const char *s)
{
	if (!s)
		return NULL; // UB in libc

	size_t size = strlen(s) + 1;

	char *dup = malloc(size);
	if (!dup) {
		abort();
	}
	memcpy(dup, s, size);

	return dup;
}

// not thread safe, returns pointer to static data (as original)
struct tm *localtime(__attribute__((unused)) const time_t *timep)
{
	printf("sgxvfs called (%s)\n", __func__);
	// return NULL;
	static struct tm sp;
	int retval = 1;

	if (sqlite3_ocall_localtime(&retval, timep, &sp) || retval) {
		fprintf(stderr, "ocall failure: localtime\n");
		return NULL;
	}

	return &sp;
}
