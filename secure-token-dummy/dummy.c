#include <sgx_trts.h>
#include "srx_t.h"

uint8_t ecall_srx_init_tp(void *p __attribute__((unused)),
		size_t n __attribute__((unused)))
{
	return 0x00;
}

uint8_t ecall_srx_auth(const void *p __attribute__((unused)),
		size_t n __attribute__((unused)))
{
	return 0x00;
}
