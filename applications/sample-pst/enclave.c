#include <string.h>

#include <sgx_trts.h>

#include "usgx/t/util.h"

#include "enclave_t.h"

srx_status trigger_auth(const char *path)
{
	const char s[] = "This is an example string to display on the ST";

	return ecall_srx_auth(path, s, strlen(s));
}

srx_status trigger_get_sk(const char *path,
		const uint8_t *salt, size_t n,
		uint8_t *sk, size_t len, int policy)
{
	return ecall_srx_get_sk(path, salt, n, sk, len, policy);
}

srx_status trigger_add_rp(const char *path, const void *p, size_t n)
{
	return ecall_srx_add_rp(path, p, n);
}

srx_status trigger_remove_rp(const char *path, uint64_t rpid)
{
	return ecall_srx_remove_rp(path, rpid);
}

srx_status trigger_list(uint64_t *pids, size_t capacity, size_t *count,
		const char *path) {
	return ecall_srx_list(pids, capacity, count, path);
}
