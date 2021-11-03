#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdlib.h>

#if !ENABLE_SGX

int main(int argc, char **argv) {
	return bench_internal_main(argc, argv);
}

#else /* ENABLE_SGX */

#include <stdio.h>

#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_urts.h>
#include "bench_internal_u.h"

#define ENCLAVE_FILE "src/bench_internal.enclave.signed.so"

int main(int argc, char **argv) {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;
	int value = 0;

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to create enclave (%#x)\n", ret);
		return -1;
	}
	printf("enclave created\n");

	/*int my_argc = 8;
	char *my_argv[] = {"hello", "scalar", "add", "field", "group", "hash", "context", "num"};*/
	ret = bench_internal_main(eid, &value, argc, argv);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to make trusted call (%#x)\n", ret);
		return -1;
	}
	printf("bench_internal_main( ... ) = %d\n", value);

	ret = sgx_destroy_enclave(eid);
	if (SGX_SUCCESS != ret) {
		fprintf(stderr, "unable to destroy enclave (%#x)\n", ret);
		return -1;
	}
	printf("enclave destroyed\n");

	return 0;
}

#endif /* ENABLE_SGX */
