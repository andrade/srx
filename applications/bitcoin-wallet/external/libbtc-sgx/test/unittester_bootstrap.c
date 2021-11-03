#include <stdio.h>

#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_urts.h>

#include "unittester_u.h"

#define ENCLAVE_FILE "test/unittester.enclave.signed.so"

int main(void) {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	int value = 0;

	printf("start\n");

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to create enclave (%#x)\n", ret);
		return -1;
	}
	printf("enclave created\n");

	ret = unittester_main(eid, &value);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to make trusted call (%#x)\n", ret);
		return -1;
	}
	printf("unittester_main( ... ) = %d\n", value);

	ret = sgx_destroy_enclave(eid);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to destroy enclave (%#x)\n", ret);
		return -1;
	}
	printf("enclave destroyed\n");

	return 0;
}
