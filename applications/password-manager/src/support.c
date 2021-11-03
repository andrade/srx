// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
#include <stdio.h>

#include "enclave_u.h"

/* stream: 1 for stdout, 2 for stderr */
void usgx_ocall_print(int stream, const char *str)
{
	switch (stream) {
	case 1:
		fprintf(stdout, "%s", str);
		break;
	case 2:
		fprintf(stderr, "%s", str);
		break;
	default:
		fprintf(stderr, "unknown stream (%d): %s", stream, str);
		break;
	}
}

#include <string.h>     // memcpy()
#include <time.h>       // localtime()
#include <sys/time.h>   // gettimeofday()

int sqlite3_ocall_time64(long long *time)
{
	static const long long unixEpoch = 24405875*(long long)8640000;
	struct timeval sNow;
	(void)gettimeofday(&sNow, 0);  /* Cannot fail given valid arguments */
	*time = unixEpoch + 1000*(long long)sNow.tv_sec + sNow.tv_usec/1000;
	return 0;
}

int sqlite3_ocall_localtime(const time_t *input, struct tm *output)
{
	struct tm *sp = localtime(input);
	if (!sp) {
		return 1;
	}

	memcpy(output, sp, sizeof(*sp));

	return 0;
}
