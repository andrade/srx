#include "csysperf.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <yapi.h>

#include "cmd_ui.h"
#include "disk.h"

static int str2u8(uint8_t *dest, size_t cap, size_t *size, const char *src)
{
	*size = 0;

	if (strlen(src) > cap * 2) {
		return 1;
	}

	size_t pos = 0;

	// handle odd input
	if (strlen(src) % 2 != 0) {
		uint8_t right;

		if (src[0] >= '0' && src[0] <= '9') {
			right = src[0] - '0';
		} else if (src[0] >= 'a' && src[0] <= 'f') {
			right = src[0] - 'a' + 10;
		} else if (src[0] >= 'A' && src[0] <= 'F') {
			right = src[0] - 'A' + 10;
		} else {
			return 1;
		}

		dest[pos++] = 0x0f & right;
	}

	// pos here is either zero for even or one for odd
	for (size_t i = pos; i < strlen(src); i += 2) {
		uint8_t left, right;

		if (src[i] >= '0' && src[i] <= '9') {
			left = src[i] - '0';
		} else if (src[i] >= 'a' && src[i] <= 'f') {
			left = src[i] - 'a' + 10;
		} else if (src[i] >= 'A' && src[i] <= 'F') {
			left = src[i] - 'A' + 10;
		} else {
			return 1;
		}

		if (src[i+1] >= '0' && src[i+1] <= '9') {
			right = src[i+1] - '0';
		} else if (src[i+1] >= 'a' && src[i+1] <= 'f') {
			right = src[i+1] - 'a' + 10;
		} else if (src[i+1] >= 'A' && src[i+1] <= 'F') {
			right = src[i+1] - 'A' + 10;
		} else {
			return 1;
		}

		dest[pos++] = (0xf0 & left << 4) | (0x0f & right << 0);
	}

	*size = pos;

	return 0;
}

static void compute_srx_path(const char *db_path, char *srx_path, size_t cap)
{
	size_t required_len = strlen(db_path) + 1 + 4;
	if (required_len > cap) {
		fprintf(stderr, "required len is %zu, got %zu\n", required_len, cap);
		abort();
	}
	snprintf(srx_path, cap, "%s.srx", db_path);
}

void yt_init_wallet(const char *path)
{
	char srx_path[260] = {0};
	compute_srx_path(path, srx_path, sizeof srx_path);

	uint8_t *data = NULL;
	size_t size = 0;
	yapi *y = NULL;

	if (yapi_init(srx_path, &y)) {
		fprintf(stderr, "wallet init failure\n");
		return;
	}

	if (yapi_to_bytes(y, &data, &size)) {
		fprintf(stderr, "error serializing wallet\n");
		yapi_free(&y);
		return;
	}

	int result = save_data(data, size, path);
	free(data);
	yapi_free(&y);
	if (result) {
		fprintf(stderr, "error saving wallet to disk\n");
		return;
	}
	fprintf(stdout, "wallet saved to disk: %s\n", path);
}

void yt_derive_address(const char *path, const char *dp)
{
	if (!path || !dp) {
		abort();
	}

	char srx_path[260] = {0};
	compute_srx_path(path, srx_path, sizeof srx_path);

	uint8_t data[1024] = {0};
	size_t size = 0;
	if (load_data(data, sizeof data, &size, path)) {
		fprintf(stderr, "error loading data\n");
		return;
	}

	yapi *y = NULL;
	if (bytes_to_yapi(srx_path, data, size, &y)) {
		fprintf(stderr, "error deserializing wallet\n");
		return;
	}

	char *address = NULL;
	// // bench, warm up
	// for (size_t i = 0; i < 100; i++) {
	// 	yapi_keys_derive_to_p2pkh(y, dp, &address);
	// }
	// CSP_POKE(MICRO, 0);
	// for (size_t i = 0; i < 500; i++) {
	// 	yapi_keys_derive_to_p2pkh(y, dp, &address);
	// }
	// CSP_POKE(MICRO, 1);
	// // bench, result x500: 1.044448989 [microbench]
	if (yapi_keys_derive_to_p2pkh(y, dp, &address)) {
		fprintf(stderr, "error deriving receiving address from dp: %s\n", dp);
		yapi_free(&y);
		return;
	}
	printf("%s  %s  %s\n", dp, "⇝", address);

	// sava data at end, TODO if needed (right now wallet data not changed)

	free(address);
	yapi_free(&y);
}

void tx_t1(const char *path,
		const char *input_prev, int input_index,
		const char *input_dp, long input_amount,
		const char *output_addr, long output_amount,
		const char *change_dp, long change_amount)
{
	if (input_index < 0 || input_amount < 0 || output_amount < 0) {
		abort();
	}

	char srx_path[260] = {0};
	compute_srx_path(path, srx_path, sizeof srx_path);

	uint8_t data[1024] = {0};
	size_t size = 0;
	if (load_data(data, sizeof data, &size, path)) {
		fprintf(stderr, "error loading data\n");
		return;
	}

	yapi *y = NULL;
	if (bytes_to_yapi(srx_path, data, size, &y)) {
		fprintf(stderr, "error deserializing wallet\n");
		return;
	}

	// uint8_t oa_buf[128];
	// size_t oa_len;
	// if (str2u8(oa_buf, sizeof oa_buf, &oa_len, output_addr)) {
	// 	yapi_free(&y);
	// 	fprintf(stderr, "str2u8\n");
	// 	abort();
	// }

	char *tx_hex = NULL;
	// // bench, warm up
	// for (size_t i = 0; i < 100; i++) {
	// 	yapi_tx_simple_p2pkh(y, &tx_hex, input_prev, input_dp,
	// 			(const uint32_t) input_index, (const uint64_t) input_amount,
	// 			output_addr, strlen(output_addr), (const uint64_t) output_amount,
	// 			change_dp, (const uint64_t) change_amount);
	// }
	// CSP_POKE(MICRO, 0);
	// for (size_t i = 0; i < 500; i++) {
	// 	yapi_tx_simple_p2pkh(y, &tx_hex, input_prev, input_dp,
	// 			(const uint32_t) input_index, (const uint64_t) input_amount,
	// 			output_addr, strlen(output_addr), (const uint64_t) output_amount,
	// 			change_dp, (const uint64_t) change_amount);
	// }
	// CSP_POKE(MICRO, 1);
	// // bench, result x500: 2.303022081 [microbench]
	if (yapi_tx_simple_p2pkh(y, &tx_hex, input_prev, input_dp,
			(const uint32_t) input_index, (const uint64_t) input_amount,
			output_addr, strlen(output_addr), (const uint64_t) output_amount,
			// oa_buf, oa_len, (const uint64_t) output_amount,
			change_dp, (const uint64_t) change_amount)) {
		yapi_free(&y);
		fprintf(stderr, "constructing and signing tx\n");
		abort();
	}

	printf("tx/hex/out: %s\n", tx_hex);
	free(tx_hex);

	// sava data at end, TODO if needed (right now wallet data not changed)

	yapi_free(&y);
}

void yt_platform_init(const char *dest_path)
{
	if (!dest_path) {
		abort();
	}

	srx_platform_init(dest_path);
	// if () {
	// 	fprintf(stderr, "error initializing platform to: %s\n", dest_path);
	// 	return;
	// }
	// printf("initialized new platform to: %s\n", dest_path);
}

void yt_platform_add(const char *wallet_path, const char *src_path)
{
	if (!wallet_path || !src_path) {
		abort();
	}

	char srx_path[260] = {0};
	compute_srx_path(wallet_path, srx_path, sizeof srx_path);

	uint8_t data[1024] = {0};
	size_t size = 0;
	if (load_data(data, sizeof data, &size, wallet_path)) {
		fprintf(stderr, "error loading data\n");
		return;
	}

	yapi *y = NULL;
	if (bytes_to_yapi(srx_path, data, size, &y)) {
		fprintf(stderr, "error deserializing wallet\n");
		return;
	}

	srx_platform_add(y, src_path);
	// if (srx_platform_add(y, src_path)) {
	// 	fprintf(stderr, "error adding new platform from: %s\n", src_path);
	// 	yapi_free(&y);
	// 	return;
	// }
	// printf("added new platform to the group\n");

	// sava data at end, if needed (right now wallet data not changed)

	yapi_free(&y);
}

void yt_platform_remove(const char *wallet_path, uint64_t pid)
{
	if (!wallet_path) {
		abort();
	}

	char srx_path[260] = {0};
	compute_srx_path(wallet_path, srx_path, sizeof srx_path);

	uint8_t data[1024] = {0};
	size_t size = 0;
	if (load_data(data, sizeof data, &size, wallet_path)) {
		fprintf(stderr, "error loading data\n");
		return;
	}

	yapi *y = NULL;
	if (bytes_to_yapi(srx_path, data, size, &y)) {
		fprintf(stderr, "error deserializing wallet\n");
		return;
	}

	srx_platform_remove(y, pid);
	// if (srx_platform_remove(y, pid)) {
	// 	fprintf(stderr, "error removing platform with pid: %"PRIu64"\n", pid);
	// 	yapi_free(&y);
	// 	return;
	// }
	// printf("removed platform with pid: %"PRIu64"\n", pid);

	// sava data at end, if needed (right now wallet data not changed)

	yapi_free(&y);
}

void yt_platform_list(const char *wallet_path)
{
	if (!wallet_path) {
		abort();
	}

	char srx_path[260] = {0};
	compute_srx_path(wallet_path, srx_path, sizeof srx_path);

	uint8_t data[1024] = {0};
	size_t size = 0;
	if (load_data(data, sizeof data, &size, wallet_path)) {
		fprintf(stderr, "error loading data\n");
		return;
	}

	yapi *y = NULL;
	if (bytes_to_yapi(srx_path, data, size, &y)) {
		fprintf(stderr, "error deserializing wallet\n");
		return;
	}

	srx_platform_list(y);
	// if (srx_platform_list(y)) {
	// 	fprintf(stderr, "error listing platform\n");
	// 	yapi_free(&y);
	// 	return;
	// }

	// sava data at end, if needed (right now wallet data not changed)

	yapi_free(&y);
}
