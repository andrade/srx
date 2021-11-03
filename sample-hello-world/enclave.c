#include <stdlib.h>
#include <limits.h>

#include <sgx_trts.h>

#include "enclave_t.h"

int soma(int a, int b)
{
	if ((a > 0 && b > INT_MAX - a) || (a < 0 && b < INT_MIN - a)) {
		//TODO: handle overflow error
		abort();
	}

	// invoke authentication via dummy implementation of SRX.
	// normally would use the previously initialized data buffer as argument,
	// but dummy implementation always returns success.
	if (ecall_srx_auth(NULL, 0)) {
		// not zero, authentication failed
		//TODO: handle authentication error
		abort();
	}

	return a + b;
}
