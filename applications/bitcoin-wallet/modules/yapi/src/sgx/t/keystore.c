#include <string.h>
#include <inttypes.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>

#include "btc/btc.h"
#include "btc/bip32.h"
#include "btc/chainparams.h"
#include "btc/cstr.h"
#include "btc/ecc.h"
#include "btc/tx.h"
#include "btc/utils.h"

#include "keystore_t.h"

#define SER_KEY_LENGTH 128

// HD master key
static btc_hdnode root;

// check to make sure wallet is loaded, or new seed has been generated.
// is context init'd and ready to serve operations?
static int ready = 0;

// path to the SRX file; wallet itself uses buffers, but
// SRX reads and writes directly to files (ideally, it'd use buffers as well;
// and possibly the same file as the wallet)
static char srx_path[512];

// for sealing
const uint8_t salt[32] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04
};

static const btc_chainparams *chainparams = &btc_chainparams_test;

// send with NULL `dest` to compute size
// `ad` can be NULL
// returns zeron on success
static int aead_enc(uint8_t *dest, size_t cap, size_t *size,
		const uint8_t *key128, const uint8_t *iv96,
		const uint8_t *pt, uint32_t pt_len,
		const uint8_t *ad, uint32_t ad_len)
{
	if (!ad) {
		ad_len = 0;
	}

	// CT size u32 | tag size u32 | AD size u32 | CT | tag | AD
	size_t total = 4 + 4 + 4 + pt_len + 16 + ad_len;
	// printf("total is %zu\n", total);

	*size = total;
	if (!dest) {
		return 0;
	}
	if (cap < total) {
		return 1;
	}

	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	memcpy(&key, key128, 16);
	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes
	uint8_t ciphertext[pt_len];

	sgx_status_t ss = sgx_rijndael128GCM_encrypt(&key, pt, pt_len,
			ciphertext, iv96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		return 1;
	}

	*(uint32_t *) (dest + 0) = pt_len;
	*(uint32_t *) (dest + 4) = 16;
	*(uint32_t *) (dest + 8) = ad_len;

	memcpy(dest + 12, ciphertext, pt_len);
	memcpy(dest + 12 + pt_len, &mac, 16);
	memcpy(dest + 12 + pt_len + 16, ad, ad_len);

	return 0;
}

// send with NULL `pt` to compute size (for PT and for AD)
static int aead_dec(uint8_t *pt, size_t pt_cap, size_t *pt_size,
		uint8_t *ad, size_t ad_cap, size_t *ad_size,
		const uint8_t *key128, const uint8_t *iv96,
		const uint8_t *src, size_t n)
{
	uint32_t ct_len = *(uint32_t *) (src + 0);
	uint32_t ad_len = *(uint32_t *) (src + 8);
	// printf("ct_len is %zu\n", (size_t) ct_len);
	// printf("ad_len is %zu\n", (size_t) ad_len);

	*pt_size = ct_len;
	*ad_size = ad_len;
	if (!pt) {
		return 0;
	}
	if (pt_cap < ct_len) {
		return 1;
	}
	if (ad_cap < ad_len) {
		return 1;
	}

	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	memcpy(&key, key128, 16);

	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes
	memcpy(&mac, src + 12 + ct_len, 16);

	memcpy(ad, src + 12 + ct_len + 16, ad_len);

	sgx_status_t ss = sgx_rijndael128GCM_decrypt(&key, src + 12, ct_len,
			pt, iv96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		if (SGX_ERROR_MAC_MISMATCH == ss) {
			printf("mismatch\n");
			return 2;
		}
		return 1;
	}

	return 0;
}

static int load_wallet_from_buffer(const uint8_t *sealed_data, uint32_t sd_size)
{
	// uint32_t cleartext_len = 0;
	// uint8_t *cleartext = NULL;
	//
	// uint32_t plaintext_len;
	// plaintext_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *) sealed_data);
	// if (0xFFFFFFFF == plaintext_len) {
	// 	return 1;
	// }
	// uint8_t plaintext[plaintext_len];
	// memset(plaintext, 0, plaintext_len);
	//
	// sgx_status_t ss = sgx_unseal_data((sgx_sealed_data_t *) sealed_data,
	// 		cleartext, &cleartext_len, plaintext, &plaintext_len);
	// if (SGX_SUCCESS != ss) {
	// 	return 2;
	// }

	// const uint8_t key128[16] = {0};
	// const uint8_t iv96[12] = {0};

	size_t pt_size = 0;
	size_t ad_size = 0;
	if (aead_dec(0, 0, &pt_size, 0, 0, &ad_size, 0, 0, sealed_data, sd_size)) {
		return 1;
	}

	uint8_t secret_key[16] = {0};
	srx_status xs = ecall_srx_get_sk(srx_path,
			// key128, iv96,
			salt, sizeof salt,
			secret_key, sizeof secret_key, 0);
	if (xs) {
		// fprintf(stderr, "Could not retrieve secret key (SRX)\n");
		return 1;
	}

	uint8_t plaintext[pt_size];
	uint8_t ad[ad_size];
	if (aead_dec(plaintext, pt_size, &pt_size, ad, ad_size, &ad_size,
			secret_key, salt,
			sealed_data, sd_size)) {
		return 1;
	}

	// retrieve HD master key
	char key[SER_KEY_LENGTH];
	memcpy(key, plaintext, SER_KEY_LENGTH);
	if (!btc_hdnode_deserialize(key, chainparams, &root)) {
		return 3;
	}
	btc_hdnode_fill_public_key(&root);

	return 0;
}

static int new_wallet()
{
	//uint8_t seed[32] = {0}; // fixed seed at all zeros
	uint8_t seed[32];
	sgx_status_t ss = sgx_read_rand((unsigned char *) seed, 32);
	if (SGX_SUCCESS != ss)
		return 1;
	// //XXX Testar com fixed seed para comparar resultados com ext tools.
	// for (int i = 0; i < 32; i++) {
	// 	seed[i] = i;
	// }

	if (!btc_hdnode_from_seed(seed, 32, &root)) {
		return 2;
	}

	srx_status xs = ecall_srx_init(srx_path);
	if (xs) {
		return 3;
	}

	return 0;
}

int ecall_yapi_wallet_load(const char *srx_path_in,
		const uint8_t *sealed_data, uint32_t sd_size)
{
	btc_ecc_start(); // initialize static ECC context (libbtc)

	strncpy(srx_path, srx_path_in, sizeof srx_path);
	srx_path[(sizeof srx_path) - 1] = '\0';
	printf("srx_path (in trusted) is: %s\n", srx_path);

	if (sealed_data) {
		if (load_wallet_from_buffer(sealed_data, sd_size))
			return 1;
	} else {
		if (new_wallet())
			return 2;
	}
	ready = 1;

	//TODO Where to call `btc_ecc_stop();`?

	return 0;
}

uint32_t ecall_yapi_wallet_compute_size()
{
	//uint32_t min_bytes = 0xFFFFFFFF;
	uint32_t cleartext_len = 0;
	uint32_t plaintext_len = 0;

	// int str_len = 128; // libbtc code uses 128 internally
	// char str[str_len] = {0};
	// btc_hdnode_serialize_private(&root, root.chain_code, str, str_len);
	plaintext_len += 128;

	size_t size = 0;
	if (aead_enc(NULL, 0, &size, 0, 0, 0, plaintext_len, 0, cleartext_len)) {
		abort();
	}

	return (uint32_t) size;

	// return sgx_calc_sealed_data_size(cleartext_len, plaintext_len);
}

// we assume: cleartext_len + plaintext_len < ciphertext_len <= size
// The lengths must respect what is used in ecall_yapi_wallet_compute_size().
int ecall_yapi_wallet_fetch_state(uint8_t *sealed_data, uint32_t sd_size)
{
	uint32_t cleartext_len = 0;
	uint8_t *cleartext = NULL;

	const uint32_t plaintext_len = 128;
	uint8_t plaintext[plaintext_len];
	memset(plaintext, 0, plaintext_len);

	// store HD master key
	char key[128] = {0}; // libbtc code uses 128 internally
	btc_hdnode_serialize_private(&root, chainparams, key, 128);
	memcpy(plaintext, key, 128);

	// sgx_status_t ss = sgx_seal_data(cleartext_len, cleartext,
	// 		plaintext_len, plaintext,
	// 		sd_size, (sgx_sealed_data_t *) sealed_data);
	// if (SGX_SUCCESS != ss) {
	// 	return 1;
	// }

	// const uint8_t key128[16] = {0};
	// const uint8_t iv96[12] = {0};

	uint8_t secret_key[16] = {0};
	srx_status xs = ecall_srx_get_sk(srx_path,
		salt, sizeof salt,
		secret_key, sizeof secret_key, 0);
	if (xs) {
		// fprintf(stderr, "Could not retrieve secret key (SRX)\n");
		return 1;
	}

	size_t size = 0;
	if (aead_enc(sealed_data, sd_size, &size,
			// key128, iv96,
			secret_key, salt,
			plaintext, plaintext_len,
			cleartext, cleartext_len)) {
		return 1;
	}

	return 0;
}

int ecall_yapi_derive_key_to_p2pkh(const char *dp, char *p2pkh)
{
	if (!ready)
		return 1;

	char s[100] = {0};
	snprintf(s, sizeof s, "Derive key w/ DP = %s ?\n", dp);
	ocall_yapi_print(s);
	srx_status xs = ecall_srx_auth(srx_path, s, strlen(s));
	if (xs) {
		return 1;
	}

	btc_hdnode child;
	if (!btc_hd_generate_key(&child, dp,
			root.private_key, root.chain_code, false)) {
		return 2;
	}

	btc_hdnode_get_p2pkh_address(&child, chainparams, p2pkh, 112);

	return 0;
}

int ecall_yapi_sign_tx(const uint8_t *tx_tosign, uint32_t tx_tosign_len,
		const char *ia_dp, int input_pos, uint64_t ia_amount,
		uint8_t *tx_signed, uint32_t *tx_signed_len)
{
	if (!ready)
		return 1;

	char msg[100] = {0};
	snprintf(msg, sizeof msg,
			"Sign transaction to transfer %"PRIu64"? (dp = %s)\n",
			ia_amount, ia_dp);
	ocall_yapi_print(msg);
	srx_status xs = ecall_srx_auth(srx_path, msg, strlen(msg));
	if (xs) {
		return 1;
	}

	// deserialize incoming transaction
	char *tx_hex_in = utils_uint8_to_hex(tx_tosign, tx_tosign_len);
	if (!tx_hex_in) {
		return 2;
	}
	unsigned char tx_bin_in[strlen(tx_hex_in) / 2 + 1];
	memset(tx_bin_in, 0, strlen(tx_hex_in) / 2 + 1);
	int tx_bin_in_len = 0;
	utils_hex_to_bin(tx_hex_in, tx_bin_in, strlen(tx_hex_in), &tx_bin_in_len);
	btc_tx *tx = btc_tx_new();
	if (!btc_tx_deserialize(tx_bin_in, tx_bin_in_len, tx, NULL, true)) {
		btc_tx_free(tx);
		return 3;
	}

	// derive keys
	btc_hdnode child;
	if (!btc_hd_generate_key(&child, ia_dp,
			root.private_key, root.chain_code, false)) {
		btc_tx_free(tx);
		return 4;
	}
	// change from `btc_hdnode` to `btc_key`
	btc_key key;
	btc_privkey_init(&key);
	for (int i = 0; i < BTC_ECKEY_PKEY_LENGTH; i++)
		key.privkey[i] = child.private_key[i];
	//XXX tmp:
	char s[512] = {0};
	char *ptr = s;
	for (int i = 0; i < BTC_ECKEY_PKEY_LENGTH; i++) {
		snprintf(ptr+i, 512-i, "%02X", child.private_key[i]);
	}
	ocall_yapi_print("priv key:");
	ocall_yapi_print(s);
	//tmp-end
	btc_pubkey pubkey;
	btc_pubkey_init(&pubkey);
	btc_pubkey_from_key(&key, &pubkey);

	// prepare script
	cstring *script = cstr_new_sz(1024);
	uint160 hash160;
	btc_pubkey_get_hash160(&pubkey, hash160);
	btc_script_build_p2pkh(script, hash160);

	// sign input with private key
	uint8_t sigcompact_out[64] = {0};
	uint8_t sigder_out[76] = {0};
	int sigder_len = 0;
	enum btc_tx_sign_result res = btc_tx_sign_input(tx,
		script, ia_amount, &key, input_pos, SIGHASH_ALL,
		sigcompact_out, sigder_out, &sigder_len);

	cstr_free(script, true);

	if (BTC_SIGN_OK != res) {
		char buf55[1024] = {0};
		snprintf(buf55, 1024, "btc sign faail with error code str = %s\n", btc_tx_sign_result_to_str(res));
		ocall_yapi_print(buf55);
		btc_tx_free(tx);
		return 7;
	}

	// serialize outgoing transaction
	cstring *signed_tx = cstr_new_sz(1024);
	btc_tx_serialize(signed_tx, tx, true);
	char *tx_hex_out = malloc(signed_tx->len * 2 + 1);
	if (!tx_hex_out) {
		cstr_free(signed_tx, true);
		btc_tx_free(tx);
		return 8;
	}
	utils_bin_to_hex((unsigned char *) signed_tx->str,
			signed_tx->len, tx_hex_out);
	uint8_t *tx5 = utils_hex_to_uint8(tx_hex_out);
	if (!tx5) {
		cstr_free(signed_tx, true);
		btc_tx_free(tx);
		return 9;
	}
	//*tx_signed_len = signed_tx->len * 2 + 1;
	*tx_signed_len = strlen(tx_hex_out) / 2; // two chars per hex value
	// memcpy_s(tx_signed, 900, tx5, tx_signed_len);
	// memcpy_s(tx_signed, 900, tx5, tx_signed_len);
	for (int i = 0; i < *tx_signed_len; i++)
		*(tx_signed + i) = *(tx5 + i);

	cstr_free(signed_tx, true);
	free(tx_hex_out);

	return 0;
}
