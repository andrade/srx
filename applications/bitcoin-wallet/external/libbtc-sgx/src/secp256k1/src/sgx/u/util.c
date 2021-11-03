#include <stdio.h>

#include "sgx_urts.h"
/*#include "bench_verify_u.h"*/

/* stream: 1 for stdout, 2 for stderr */
void ocall_print(int stream, const char *str)
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
