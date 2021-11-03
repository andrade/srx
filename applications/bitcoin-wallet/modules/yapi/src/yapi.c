#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_urts.h>
#include "sgx/u/keystore_u.h"

#include <btc/chainparams.h>
#include <btc/cstr.h>
// #include <btc/ecc.h>
// #include <btc/ecc_key.h>
#include <btc/script.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include "yapi.h"

#define ENCLAVE_FILE "enclave.signed.so"

// path to the sealed data of the SRX (wallet has its own sealed data bundle)
static char srx_path[512];

/**
 * Starts the TEE.
 * Some calls depend on the TEE, if it is not enabled those calls fail.
 * Returns zero on success.
 */
static int yapi_tee_on(yapi *p);

/**
 * Terminates the TEE.
 * Returns zero on success.
 */
static int yapi_tee_off(yapi *p);

static void print_hex(uint8_t *a, uint32_t len)
{
	printf("uint8_t/hex (len=%"PRIu32"):\n", len);
	for (uint32_t i = 0; i < len - 1; i++)
		printf("%02"PRIx8":", a[i]);
	printf("%02"PRIx8"\n", a[len - 1]);
}

static void print_tx(const btc_tx *tx)
{
	cstring *tx_ser = cstr_new_sz(1024);
	btc_tx_serialize(tx_ser, tx, true);

	char tx_hex[tx_ser->len * 2 + 1];
	utils_bin_to_hex((unsigned char *) tx_ser->str, tx_ser->len, tx_hex);

	printf("tx/hex:\n%s\n", tx_hex);
}

static void print_uint256(const uint256 n)
{
	printf("uint256/hex:\n");
	for (int i = 0; i < 32; i++) {
		if (i > 0)
			printf(":");
		printf("%02X", n[i]);
	}
	printf("\n");
}

int yapi_init(const char *srx_path_in, yapi **p)
{
	strncpy(srx_path, srx_path_in, sizeof srx_path);
	srx_path[(sizeof srx_path) - 1] = '\0';
	printf("srx_path (in untrusted) is: %s\n", srx_path);

	// create wallet
	yapi *y = malloc(sizeof(yapi));
	if (!y)
		return 1;

	// enable TEE
	if (yapi_tee_on(y)) {
		free(y);
		return 2;
	}

	// create TEE state
	sgx_status_t ss = SGX_SUCCESS;
	int ret = 0;
	ss = ecall_yapi_wallet_load(y->eid, &ret, srx_path, NULL, 0);
	if (SGX_SUCCESS != ss) {
		yapi_tee_off(y);
		free(y);
		return 3;
	}

	*p = y;

	return 0;
}

int yapi_free(yapi **p)
{
	if (*p) {
		yapi_tee_off(*p);
		free(*p);
		*p = NULL;
	}
	return 0;
}

static int yapi_tee_on(yapi *p)
{
	sgx_status_t ss = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int updated = 0;

	ss = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &(p->eid), NULL);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "unable to create enclave (%#x)\n", ss);
		return 1;
	}
	fprintf(stdout, "enclave created\n");

	// printf("make call test: begin\n");
	// load_wallet_to_enclave(p);
	// printf("make call test: end\n");
	//
	// printf("make call test get key: begin\n");
	// get_key(p);
	// printf("make call test get key: end\n");

	return 0;
}

static int yapi_tee_off(yapi *p)
{
	sgx_status_t ss = sgx_destroy_enclave(p->eid);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "unable to destroy enclave (%#x)\n", ss);
		return 1;
	}
	fprintf(stdout, "enclave destroyed\n");
	return 0;
}

int yapi_keys_derive_to_p2pkh(const yapi *p, const char *dp, char **p2pkh)
{
	int size = 112; // same as in libbtc
	char *out = malloc(size);
	if (!out)
		return 1;
	memset(out, 0, size);

	int ret = 0;
	sgx_status_t ss = ecall_yapi_derive_key_to_p2pkh(p->eid, &ret, dp, out);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "unable to make trusted call (%#x)\n", ss);
		free(out);
		return 2;
	}
	if (ret) {
		free(out);
		return 3;
	}
	printf("ecall_yapi_derive_key_to_p2pkh( ... ) = %d\n", ret);

	*p2pkh = out;
	// *len = 112;

	return 0;
}

/**
 * Converts TX to uint8_t.
 *
 * Returns the uint8_t version of the given TX on success, NULL on error.
 * The result is stored in a static buffer within libbtc.
 * If `with_malloc` is set, then memory is allocated for the return value
 * and libbtc are left cleared.
 */
static uint8_t *tx_to_uint8(const btc_tx *tx, bool with_malloc)
{
	cstring *tx_ser = cstr_new_sz(1024);
	btc_tx_serialize(tx_ser, tx, true);
	char tx_hex[tx_ser->len * 2 + 1];
	utils_bin_to_hex((unsigned char *) tx_ser->str, tx_ser->len, tx_hex);
	cstr_free(tx_ser, true);

	uint8_t *tx_uint8 = utils_hex_to_uint8(tx_hex);

	if (!with_malloc) {
		return tx_uint8;
	} else {
		size_t tx_uint8_size = sizeof(tx_ser->len * 2 + 1);
		uint8_t *p = malloc(tx_uint8_size);
		if (!p) {
			utils_clear_buffers();
			return NULL;
		}
		memcpy(p, tx_uint8, tx_uint8_size);
		utils_clear_buffers();
		return p;
	}
}

// deserialize incoming transaction
// returns TX on success, NULL on error
static btc_tx *uint8_to_tx(const uint8_t *tx_uint8, size_t tx_uint8_size)
{
	char *tx_hex = utils_uint8_to_hex(tx_uint8, tx_uint8_size);
	if (!tx_hex)
		return NULL;

	// printf("tx/hex6/tmp: %s\n", tx_hex);

	size_t tx_bin_size = strlen(tx_hex) / 2 + 1;
	unsigned char tx_bin[tx_bin_size];
	memset(tx_bin, 0, tx_bin_size);
	int tx_bin_len = 0;
	utils_hex_to_bin(tx_hex, tx_bin, strlen(tx_hex), &tx_bin_len);

	// printf("enclave sign result (%d):\n", tx_bin_len);

	btc_tx *tx = btc_tx_new();
	if (!btc_tx_deserialize(tx_bin, tx_bin_len, tx, NULL, true)) {
		btc_tx_free(tx);
		return NULL;
	}
	// printf("·················\n");
	// print_tx(tx);
	// printf("·················\n");
	return tx;
}

int yapi_tx_simple_p2pkh(const yapi *p,
		char **tx_hex,
		const char *prev_tx_hex,
		const char *input_addr_dp, uint32_t ia_index, uint64_t ia_amount,
		const char *output_addr_p2pkh, uint32_t oa_len,
		const uint64_t amount,
		const char *change_addr_dp, uint64_t change_amount)
{
	btc_tx *tx = btc_tx_new();

	//# add transaction output (recipient)
	//FIXME actually address here is in this case P2SH because given by faucet
	if (!btc_tx_add_address_out(tx,
			&btc_chainparams_test,
			amount, output_addr_p2pkh)) {
		btc_tx_free(tx);
		return 1;
	}
	// btc_tx_add_p2pkh_out(tx, amount, --output_addr_p2pkh--);

	//# add change address
	if (change_addr_dp && change_amount > 0) {
		char *change_addr_p2pkh = NULL;

		if (yapi_keys_derive_to_p2pkh(p, change_addr_dp, &change_addr_p2pkh)) {
			btc_tx_free(tx);
			return 2;
		}
		if (!btc_tx_add_address_out(tx,
				&btc_chainparams_test,
				change_amount, change_addr_p2pkh)) {
			free(change_addr_p2pkh);
			btc_tx_free(tx);
			return 3;
		}
		free(change_addr_p2pkh);
	}

	//# add transaction input (sender)
	uint256 txid_hex;
	utils_uint256_sethex((char *) prev_tx_hex, txid_hex); // reverses internally

	btc_tx_in *tx_in = btc_tx_in_new();

	// input_pos should be zero since vector is (me thinks) previously empty
	int input_pos = tx->vin->len;
	memcpy(tx_in->prevout.hash, txid_hex, sizeof(uint256)); // reversed
	tx_in->prevout.n = ia_index;
	tx_in->script_sig = cstr_new_sz(1024);
	// shouldn't script_sig, above, be initialized automatically?
	vector_add(tx->vin, tx_in); // add input to tx
	// Note the input_pos sent to the sign function means input position in
	// the input vector (here) and not the input in the previous TX on the BC.

	//# serialize, send to enclave for signing, deserialize result
	uint8_t *tx_ptr_enclave_in = tx_to_uint8(tx, false);
	if (!tx_ptr_enclave_in) {
		btc_tx_free(tx);
		return 4;
	}
	btc_tx_free(tx);

	uint8_t tx_signed[1024];
	uint32_t tx_signed_len = -1;
	int ret = 0;
	sgx_status_t ss = ecall_yapi_sign_tx(p->eid, &ret,
			tx_ptr_enclave_in, 512,
			input_addr_dp, input_pos, ia_amount,
			tx_signed, &tx_signed_len);
	//utils_clear_buffers(); // clear libbtc buffers (done internally)
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "ecall_yapi_sign_tx(...) FAIL (ss = %#x)\n", ss);
		return 5;
	}
	if (ret) {
		fprintf(stderr, "ecall_yapi_sign_tx(...) FAIL (ret = %d)\n", ret);
		// falha se size de TX for 1024 porque existe verificação >1023 no libbtc quando faço uint8 para hex
		return 6;
	}

	char *tx_hex_libbtc_buf = utils_uint8_to_hex(tx_signed, tx_signed_len);
	if (!tx_hex_libbtc_buf) {
		return 7;
	}

	//# set result/output variables
	size_t tx_hex_len = strlen(tx_hex_libbtc_buf);
	char *tx_hex_tmp_heap = malloc(tx_hex_len + 1);
	if (!tx_hex_tmp_heap) {
		return 8;
	}
	strncpy(tx_hex_tmp_heap, tx_hex_libbtc_buf, tx_hex_len + 1);
	*tx_hex = tx_hex_tmp_heap;

	return 0;
}

int yapi_tx_to_hex(const yapi_tx *tx, uint8_t **hex)
{
	return -1;
}

int yapi_hex_to_tx(const uint8_t *hex, yapi_tx **tx)
{
	return -1;
}

int yapi_to_bytes(const yapi *p, uint8_t **data, size_t *size)
{
	cstring *s = cstr_new_sz(1024);

	//TODO call compute_size and ecall_yapi_fetch_data, Then serialize yapi wallet (untrusted side) state, concatenate both (maybe calculate some checksum), and save to disk. Perhaps skip the checksum on a first phase.
	// Trusted side has seed, and maybe some other stuff.
	// Untrusted side currently has nothing, but could have cached keys and their values, previous TXs we made, and other data.
	// I don't save to disk here, but simply serialize all state in a way it can be recovered with `bytes_to_yapi` and store in buffer!

	// store yapi (untrusted-side) data
	//TODO store data, then store size at beginning
	uint32_t size_u = 0;
	ser_u32(s, size_u);

	// retrieve serialized and encrypted enclave state
	sgx_status_t ss = SGX_SUCCESS;

	uint32_t ct_len = 0;
	ss = ecall_yapi_wallet_compute_size(p->eid, &ct_len);
	if (SGX_SUCCESS != ss) {
		return 1;
	}
	if (0xFFFFFFFF == ct_len) {
		return 2;
	}
	printf("ecall_yapi_wallet_compute_size() = %" PRIu32 "\n", ct_len);

	int ret = 0;
	uint8_t *ciphertext = malloc(ct_len);
	ss = ecall_yapi_wallet_fetch_state(p->eid, &ret, ciphertext, ct_len);
	if (SGX_SUCCESS != ss) {
		free(ciphertext);
		return 3;
	}
	if (ret) {
		free(ciphertext);
		return 4;
	}

	// store keystore (trusted-side) data
	ser_u32(s, ct_len);
	ser_bytes(s, ciphertext, ct_len);

	*data = (uint8_t *) s->str;
	*size = s->len;

	return 0;
}

int bytes_to_yapi(const char *srx_path_in,
		const uint8_t *data, size_t size, yapi **p)
{
	strncpy(srx_path, srx_path_in, sizeof srx_path);
	srx_path[(sizeof srx_path) - 1] = '\0';
	printf("srx_path (in untrusted) is: %s\n", srx_path);

	struct const_buffer buffer = { .p = data, .len = size};

	uint32_t size_untrusted;
	deser_u32(&size_untrusted, &buffer);
	// then retrieve rest of untrusted side stuff

	uint32_t size_trusted;
	deser_u32(&size_trusted, &buffer);
	uint8_t *data_trusted = malloc(size_trusted);
	if (!data_trusted) {
		return 1;
	}
	if (!deser_bytes(data_trusted, &buffer, size_trusted)) {
		free(data_trusted);
		return 2;
	}

	//TODO populate new yapi com data, then start enclave, then populate enclave
	// create wallet
	yapi *y = malloc(sizeof(yapi));
	if (!y) {
		free(data_trusted);
		return 3;
	}

	// now actually populate the yapi struct

	// enable TEE and populate secure data structures
	if (yapi_tee_on(y)) {
		free(data_trusted);
		free(y);
		return 4;
	}
	sgx_status_t ss = SGX_SUCCESS;
	int ret = 0;
	ss = ecall_yapi_wallet_load(y->eid, &ret,
			srx_path, data_trusted, size_trusted);
	if (SGX_SUCCESS != ss) {
		yapi_tee_off(y);
		free(data_trusted);
		free(y);
		return 5;
	}

	*p = y;

	return 0;
}

void srx_platform_init(const char *save_path)
{
	yapi *y = malloc(sizeof(yapi));
	if (!y)
		return 1;

	if (yapi_tee_on(y)) {
		free(y);
		return 1;
	}

	sgx_status_t ss;
	srx_status xs;
	uint8_t buf[1024] = {0};
	size_t size = 0;

	ss = ecall_srx_init_rp(y->eid, &xs, buf, sizeof buf, &size);
	if (ss) {
		fprintf(stderr, "ecall failure: init platform (%#x)\n", ss);
		goto cleanup;
	}
	fprintf(stdout, "ecall success: init platform\n");
	if (xs) {
		fprintf(stderr, "Failed to init platform (%s).\n", srxerror(xs));
		goto cleanup;
	}

	if (save_data(buf, size, save_path))
		goto cleanup;
	printf("init platform: wrote %zu bytes to disk (%s)\n", size, save_path);

cleanup:
	yapi_tee_off(y);
	free(y);
}

void srx_platform_add(const yapi *y, const char *load_path)
{
	uint8_t buf[1024] = {0};
	size_t size = 0;
	if (load_data(buf, sizeof buf, &size, load_path))
	return;
	printf("add platform: read %zu bytes from disk (%s)\n", size, load_path);

	sgx_status_t ss;
	srx_status xs;

	ss = ecall_srx_add_rp(y->eid, &xs, srx_path, buf, size);
	if (ss) {
		fprintf(stderr, "ecall failure: add platform (%#x)\n", ss);
		return;
	}
	fprintf(stdout, "ecall success: add platform\n");
	if (xs) {
		fprintf(stderr, "Failed to add platform (%s).\n", srxerror(xs));
		return;
	}
}

void srx_platform_remove(const yapi *y, uint64_t pid)
{
	sgx_status_t ss;
	srx_status xs;

	ss = ecall_srx_remove_rp(y->eid, &xs, srx_path, pid);
	if (ss) {
		fprintf(stderr, "ecall failure: remove platform (%#x)\n", ss);
		return;
	}
	fprintf(stdout, "ecall success: remove platform\n");
	if (xs) {
		fprintf(stderr, "Failed to remove platform (%s).\n", srxerror(xs));
		return;
	}
}

void srx_platform_list(const yapi *y)
{
	sgx_status_t ss;
	srx_status xs;
	uint64_t pids[32] = {0};
	size_t count = 0;

	ss = ecall_srx_list(y->eid, &xs, pids, 32, &count, srx_path);
	if (ss) {
		fprintf(stderr, "ecall failure: list platforms (%#x)\n", ss);
		return;
	}
	fprintf(stdout, "ecall success: list platforms (count = %zu)\n", count);
	if (xs) {
		fprintf(stderr, "Failed to list platforms (%s).\n", srxerror(xs));
		return;
	}

	for (size_t i = 0; i < sizeof(pids)/sizeof(pids[0]) && pids[i] != 0; i++) {
		printf("pid[%zu] = %#018"PRIx64"\n", i, pids[i]);
	}
}
