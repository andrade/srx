#include <stdio.h>
#include <inttypes.h>

#include <sgx_urts.h>

#include "enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

int main(void)
{
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	uint8_t ecall_return = 0;
	int sum_ret = 0;
	int a = 2, b = 3;

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
			&token, &updated, &eid, NULL);
	if (SGX_SUCCESS != ret) {
		printf("app error %#x, failed to create enclave\n", ret);
		return -1;
	}

	// initialize (HST) authentication mechanism
	ret = ecall_srx_init_tp(eid, &ecall_return, NULL, 0);
	if (SGX_SUCCESS != ret) {
		printf("ecall_hst_init: failure\n");
		sgx_destroy_enclave(eid);
		return -1;
	}
	printf("ecall_hst_init: success (retval=0x%02"PRIx8")\n", ecall_return);

	// perform an ECALL that contains an (HST) authentication attempt
	ret = soma(eid, &sum_ret, a, b);
	if (SGX_SUCCESS != ret) {
		printf("soma + ecall_hst_auth: failure\n");
	}
	printf("soma(%d,%d)=%d + ecall_hst_auth: success\n", a, b, sum_ret);

	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		printf("enclave destruction boom");
		printf("sgx_destroy_enclave: failure\n");
		return -1;
	}
	printf("sgx_destroy_enclave: success\n");

	return 0;
}
