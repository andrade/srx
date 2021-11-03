#include <stdlib.h>
#include <inttypes.h>

#include <usgx/t/util.h>

#include "util.h"

void print_uint8a(const uint8_t *src, size_t n, char mod)
{
	if (0 == n) {
		printf("\n");
	} else if ('x' == mod) {
		for (size_t i = 0; i < n - 1; i++)
			printf("%02"PRIx8":", src[i]);
		printf("%02"PRIx8"\n", src[n - 1]);
	} else if ('d' == mod){
		for (size_t i = 0; i < n - 1; i++)
			printf("%03"PRIu8":", src[i]);
		printf("%03"PRIu8"\n", src[n - 1]);
	} else {
		printf("Unknown mod (`%c`) in `print_uint8a`\n", mod);
	}
}
