#include <stdlib.h>

#include "sgx_void.h"

void __assert_fail(const char *__assertion,
		const char *__file,
		unsigned int __line,
		__const char *__function)
{
	(void) __assertion;
	(void) __file;
	(void) __line;
	(void) __function;
	abort();
}
