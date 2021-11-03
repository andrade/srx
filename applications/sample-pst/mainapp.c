#include <errno.h>
#include <stdio.h>
#include <stdlib.h>                     // abort(), strtoull()
#include <stdbool.h>
#include <string.h>                     // strcasecmp()
#include <inttypes.h>
#include <unistd.h>                     // getopt()

#include <sgx_urts.h>

#include <u/util.h>

#include "enclave_u.h"
#include "disk.h"
#include "network.h"

#define ENCLAVE_FILE "enclave.signed.so"

static const char SRX_STATE_PATH[] = "data.srx";
static const char INIT_RP_PATH[] = "rpinit.srx";

static uint64_t str2u64(const char *s)
{
	errno = 0;
	char *endptr = NULL;

	unsigned long long int ull = strtoull(s, &endptr, 0);

	if (errno || ull > UINT64_MAX) {
		abort();
	}
	if (s == endptr) {
		fprintf(stderr, "`%s` is not a number\n", s);
		abort();
	}

	return (uint64_t) ull;
}

static void print_ret(const char *func, sgx_status_t ss, srx_status xs)
{
	const char s[] = "%s:\n«SGX = OK»\n«SRX = %s»\n";
	fprintf(stdout, s, func, srxerror(xs));
}

static void print_uint8a(const uint8_t *src, size_t n, char mod)
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

static int create_enclave(sgx_enclave_id_t *eid)
{
	sgx_launch_token_t token = {0};
	int updated = 0;
	sgx_status_t ss = SGX_SUCCESS;

	ss = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
			&token, &updated, eid, NULL);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "app error %#x, failed to create enclave\n", ss);
		return 1;
	}
	fprintf(stdout, "sgx_create_enclave(): success\n");

	return 0;
}

static int destroy_enclave(sgx_enclave_id_t *eid)
{
	if (SGX_SUCCESS != sgx_destroy_enclave(*eid)) {
		fprintf(stderr, "sgx_destroy_enclave(): failure\n");
		return 1;
	}
	fprintf(stdout, "sgx_destroy_enclave(): success\n");

	return 0;
}

static int handle_init(bool overwrite)
{
	if (server_connect()) {
		fprintf(stderr, "could not connect to the remote server\n");
		return EXIT_FAILURE;
	}

	sgx_enclave_id_t eid;
	sgx_status_t ss = SGX_SUCCESS;
	srx_status xs = 0;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = ecall_srx_init(eid, &xs, SRX_STATE_PATH);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_init(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_init()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	server_disconnect();

	return EXIT_SUCCESS;
}

static int handle_auth()
{
	sgx_enclave_id_t eid;
	sgx_status_t ss;
	srx_status xs;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = trigger_auth(eid, &xs, SRX_STATE_PATH);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_auth(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_auth()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

// `str` is salt, `length` is length of secret key, `policy` is auth requirement
static int handle_get_sk(const char *str, int length, int policy)
{
	uint8_t salt[strlen(str)];
	memcpy(salt, str, strlen(str));

	uint8_t sk[length];

	sgx_enclave_id_t eid;
	sgx_status_t ss;
	srx_status xs;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = trigger_get_sk(eid, &xs,
			SRX_STATE_PATH, salt, sizeof salt, sk, length, policy);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_get_sk(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_get_sk()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	print_uint8a(sk, length, 'x');

	return EXIT_SUCCESS;
}

static int handle_init_rp()
{
	if (server_connect()) {
		fprintf(stderr, "could not connect to the remote server\n");
		return EXIT_FAILURE;
	}

	sgx_enclave_id_t eid;
	sgx_status_t ss = SGX_SUCCESS;
	srx_status xs = 0;
	uint8_t buf[1024] = {0};
	size_t size = 0;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = ecall_srx_init_rp(eid, &xs, buf, sizeof buf, &size);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_init_rp(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_init_rp()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	server_disconnect();

	if (save_data(buf, size, INIT_RP_PATH))
		return EXIT_FAILURE;
	fprintf(stdout, "handle_init_rp: wrote %zu bytes to disk (%s)\n",
			size, INIT_RP_PATH);

	return EXIT_SUCCESS;
}

static int handle_add_rp()
{
	uint8_t buf[1024] = {0};
	size_t size = 0;
	if (load_data(buf, sizeof buf, &size, INIT_RP_PATH))
		return EXIT_FAILURE;
	fprintf(stdout, "handle_add_rp: read %zu bytes from disk (%s)\n",
			size, INIT_RP_PATH);

	sgx_enclave_id_t eid;
	sgx_status_t ss;
	srx_status xs;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = trigger_add_rp(eid, &xs, SRX_STATE_PATH, buf, size);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_add_rp(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_add_rp()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int handle_remove_rp(uint64_t rpid)
{
	sgx_enclave_id_t eid;
	sgx_status_t ss;
	srx_status xs;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = trigger_remove_rp(eid, &xs, SRX_STATE_PATH, rpid);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_remove_rp(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_remove_rp()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int handle_list()
{
	size_t cap = 32;
	uint64_t pids[cap];
	size_t count;

	sgx_enclave_id_t eid;
	sgx_status_t ss;
	srx_status xs;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = trigger_list(eid, &xs, pids, cap, &count, SRX_STATE_PATH);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_list(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	print_ret("ecall_srx_list()", 0, xs);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	if (!xs) {
		for (size_t i = 0; i < count; i++) {
			fprintf(stdout, "%3zu: 0x%016"PRIx64"\n", i, pids[i]);
		}
	}

	return EXIT_SUCCESS;
}

static int handle_dump()
{
	char buf[4096] = {0};

	sgx_enclave_id_t eid;
	sgx_status_t ss;
	int ecall_return;

	if (create_enclave(&eid))
		return EXIT_FAILURE;

	ss = ecall_srx_dump(eid, &ecall_return, buf, sizeof buf, SRX_STATE_PATH);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_srx_dump(): failure\n");
		destroy_enclave(&eid);
		return EXIT_FAILURE;
	}
	fprintf(stdout, "ecall_srx_dump(): SGX=OK, retval=%d\n", ecall_return);

	if (destroy_enclave(&eid))
		return EXIT_FAILURE;

	if (!ecall_return) {
		fprintf(stdout, "%s", buf);
	}

	return EXIT_SUCCESS;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <init[-f] "
			"| auth "
			"| sk -s <salt> -L <length> -P <policy> " // ex: `-s 123 -L 16 -P 0`
			"| init-rp "
			"| add-rp "
			"| remove -p <rpid> "
			"| list "
			"| dump>\n", prog);
}

int main(int argc, char *argv[])
{
	bool overwrite = false;             // overwrite existing keystore
	bool has_pid = false;
	uint64_t pid = 0;

	char str[128] = {0};
	bool has_str = false;
	int length = 0;
	bool has_len = false;
	int policy = 0;
	bool has_policy = false;

	int opt;
	while ((opt = getopt(argc, argv, "fp:s:L:P:")) != -1) {
		switch (opt) {
		case 'f':
			overwrite = true;
			break;
		case 'p':
			pid = str2u64(optarg);
			has_pid = true;
			break;
		case 's':
			snprintf(str, sizeof str, "%s", optarg);
			has_str = true;
			break;
		case 'L':
			length = atoi(optarg);
			has_len = true;
			break;
		case 'P':
			policy = atoi(optarg);
			has_policy = true;
			break;
		default:
			/* do nothing */
			break;
		}
	}

	// we want exactly one mandatory keyword (other than options)
	if (!argv[optind] || argv[optind + 1]) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	// getopt(3): "By default, getopt() permutes the contents of argv as it scans, so that eventually all the nonoptions  are at the end."

	const char *op_str = argv[optind];
	if (!strcasecmp(op_str, "auth")) {
		return handle_auth();
	} else if (!strcasecmp(op_str, "sk") && has_str && has_len && has_policy) {
		return handle_get_sk(str, length, policy);
	} else if (!strcasecmp(op_str, "init")) {
		return handle_init(overwrite);
	} else if (!strcasecmp(op_str, "init-rp")) {
		return handle_init_rp();
	} else if (!strcasecmp(op_str, "add-rp")) {
		return handle_add_rp();
	} else if (!strcasecmp(op_str, "remove") && has_pid) {
		return handle_remove_rp(pid);
	} else if (!strcasecmp(op_str, "list")) {
		return handle_list();
	} else if (!strcasecmp(op_str, "dump")) {
		return handle_dump();
	} else {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
}

/*
* NOTE: The handle functions return SUCCESS when all goes well,
*       even if the SRX function did not succeed. The handle functions
*       do fail when, for example, SGX returns an error.
*/
