#include <stddef.h>

#include <sgx_trts.h>                   // external support libraries
#include <sgx_tcrypto.h>

#include <DeviceL6.h>                   // internal support libraries
#include <usgx/t/util.h>

#include "rlog.h"                       // uses

#include "device.h"                     // implements

/** Number of bytes of response to compare with locally-computed HMAC. */
static const size_t COMP_N_BYTES = 4;

/**
** Computes possible responses and finds match.
**
** The possible responses are in `[0, max_resp]`.
**
** @param[in]   max_resp   the highest response possible, in [0,255]
** @param[in]   buf        contains the response
** @param[in]   len        length of the response from the ST
** @param[in]   sk_mac     the 32-byte secret key for the HMAC (shared with ST)
** @param[in]   nonce      the 32-byte nonce to prefix the data to MAC
** @param[in]   ncomp      the amount of bytes to compare (from position zero)
**
** @return      Returns the response on success (`>=0`), or
**              negative on error or if a match is not found.
**/
static int find_match(uint8_t max_resp, const char *buf, size_t len,
		const uint8_t *sk_mac, const uint8_t *nonce, size_t ncomp)
{
	if (ncomp > len) {
		R(RLOG_ERROR, "Response too short (got = %zu, want = %zu)", len, ncomp);
		return -2;
	}
	//TODO  Ideal é transformar o buf em byte array porque assim feito uma vez

	unsigned char in[32 + 1];
	memcpy(in, nonce, 32);

	for (uint8_t i = 0; i <= max_resp; i++) {
		in[32] = i;
		unsigned char mac[32] = {0};
		sgx_status_t ss;
		ss = sgx_hmac_sha256_msg(in, sizeof in, sk_mac, 32, mac, sizeof mac);
		if (SGX_SUCCESS != ss) {
			R(RLOG_ERROR, "SGX error computing HMAC");
			return -3;
		}

		R(RLOG_TRACE, "Got mac:");//TORM
		print_uint8a(mac, sizeof mac, 'x');//TORM

		char *str_from_mac = NULL;
		if (usgx_hex_uint8_to_str(mac, ncomp, "", &str_from_mac)) {
			return -4;
		}

		if (!memcmp(buf, str_from_mac, ncomp)) {
			R(RLOG_TRACE, "Match found, i = %d", i);
			free(str_from_mac);
			return i;
		}
		free(str_from_mac);
	}

	return -1;
}

/**
** DER-encodes the structure.
** The caller allocates the destination buffer, `dest`.
** Returns zero on success, or non-zero otherwise.
**/
static int encode_message(uint8_t *dest, size_t dest_len,
		size_t *bytes_encoded, DeviceL6_t *msg)
{
	asn_enc_rval_t rval;

	rval = der_encode(&asn_DEF_DeviceL6, msg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded DeviceL6_t");
		return 1;
	}
	if (!dest) {
		// leave early, purpose was finding required buffer size
		*bytes_encoded = rval.encoded;
		return 0;
	}
	if ((size_t) rval.encoded > dest_len) {
		R(RLOG_VERBOSE, "Buffer not long enough (got = %zu, need = %zu)",
				dest_len, rval.encoded);
		return 2;
	}
	rval = der_encode_to_buffer(&asn_DEF_DeviceL6, msg, dest, dest_len);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding DeviceL6_t");
		return 3;
	}
	*bytes_encoded = rval.encoded;

	R(RLOG_VERBOSE, "Encoded DeviceL6_t (size = %zu)", rval.encoded);

	return 0;
}

/**
** Validates the structure.
** Returns zero on success, or non-zero otherwise.
**/
static int validate_message(const DeviceL6_t *msg)
{
	char errbuf[256];
	size_t errlen = 256;

	if (asn_check_constraints(&asn_DEF_DeviceL6, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating DeviceL6_t: %s", errbuf);
		return 1;
	}

	return 0;
}

static int populate_encryption_message(DeviceEncryptedL6_t *msg,
		const void *data, size_t size, const uint8_t *sk_enc)
{
	uint8_t iv[12];
	if (gen_nonce(iv, sizeof iv)) {
		R(RLOG_ERROR, "Error generating nonce for encryption");
		return 1;
	}
	R(RLOG_TRACE, "Print IV:");//TORM
	print_uint8a(iv, sizeof iv, 'x');//TORM
	uint8_t *ct = NULL;
	uint32_t ct_len = 0;
	uint8_t *tag = NULL;
	uint8_t ad[1] = {0x00};  // using one zero byte as AD
	// § 6.7.6.2: "If the expression is a constant expression, it shall have a value greater than zero."

	if (aead_enc(sk_enc, iv, data, size, ad, sizeof ad, &ct, &ct_len, &tag)) {
		R(RLOG_WARNING, "Error encrypting with AEAD");
		return 3;
	}
	R(RLOG_TRACE, "ct_len = %"PRIu32, ct_len); //TORM

	R(RLOG_TRACE, "Print CT:");//TORM
	print_uint8a(ct, ct_len, 'x');//TORM
	R(RLOG_TRACE, "Print TAG:");//TORM
	print_uint8a(tag, 16, 'x');//TORM

	if (OCTET_STRING_fromBuf(&msg->nonce, (const char *) iv, 12)) {
		R(RLOG_ERROR, "Error adding nonce to DeviceEncryptedL6_t");
		free(ct);
		free(tag);
		return 3;
	}
	if (OCTET_STRING_fromBuf(&msg->ciphertext, (const char *) ct, ct_len)) {
		R(RLOG_ERROR, "Error adding ciphertext to DeviceEncryptedL6_t");
		free(ct);
		free(tag);
		return 4;
	}
	if (OCTET_STRING_fromBuf(&msg->tag, (const char *) tag, 16)) {
		R(RLOG_ERROR, "Error adding tag to DeviceEncryptedL6_t");
		free(ct);
		free(tag);
		return 5;
	}
	if (OCTET_STRING_fromBuf(&msg->ad, (const char *) ad, sizeof ad)) {
		R(RLOG_ERROR, "Error adding associated data to DeviceEncryptedL6_t");
		free(ct);
		free(tag);
		return 6;
	}

	free(ct);
	free(tag);

	return 0;
}

static int populate_cleartext_message(DeviceCleartextL6_t *msg,
		const void *data, size_t size)
{
	if (OCTET_STRING_fromBuf(&msg->cleartext, data, size)) {
		R(RLOG_ERROR, "Error adding data to DeviceCleartextL6_t");
		return 1;
	}
	return 0;
}

/**
** Computes the expected response MAC (hex).
** This is meant for development only.
**
** resp_mac  [out]  destination buffer, caller allocates with 32 bytes
** rn         [in]  expected response nonce, 32 bytes
** sk_mac     [in]  the secret key for computing the MAC, 32 bytes
**/
static void debug_only_compute_resp_mac_hex(unsigned char *resp_mac,
		const uint8_t *rn, const uint8_t *sk_mac)
{
	// input: <mac is 32 bytes> || <response code is 1 byte w/ 0x00 for success>
	unsigned char temp_input[33] = {0};
	memcpy(temp_input, rn, 32);
	if (sgx_hmac_sha256_msg(temp_input, sizeof temp_input,
			sk_mac, 32,
			resp_mac, 32)) {
		abort();
	}
	// This is the MAC the Security Token returns for a successful operation.
	// Avoids having to scan for the QRC during development.
	// Note if this is used, nothing is saved to the ST since nothing is read.
	//R(RLOG_DEBUG | RLOG_LOW, "MAC of successful response (not for production)");
}

/**
** Computes the expected response MAC (string).
** This is meant for development only.
**
** resp_str  [out]  destination buffer, caller allocates with 65 bytes
** rn         [in]  expected response nonce, 32 bytes
** sk_mac     [in]  the secret key for computing the MAC, 32 bytes
**/
static void debug_only_compute_resp_mac_str(char *resp_str,
		const uint8_t *rn, const uint8_t *sk_mac)
{
	unsigned char temp_mac[32] = {0};
	debug_only_compute_resp_mac_hex(temp_mac, rn, sk_mac);

	char *temp_str = NULL;
	if (usgx_hex_uint8_to_str(temp_mac, sizeof(temp_mac), "", &temp_str)) {
		abort();
	}
	strncpy(resp_str, temp_str, strlen(temp_str));
	free(temp_str);
}

int token_exchange_data(int *rc, int expected_max_resp,
		const void *data, size_t size,
		const uint8_t *sk_enc, const uint8_t *sk_mac,
		const uint8_t *rn, size_t rn_size)
{
	DeviceL6_t *device_msg = calloc(1, sizeof *device_msg);
	if (!device_msg) {
		R(RLOG_ERROR, "calloc for DeviceL6_t");
		return 1;
	}

	if (sk_enc) {
		device_msg->present = DeviceL6_PR_encrypted;
		DeviceEncryptedL6_t *msg = &device_msg->choice.encrypted;

		if (populate_encryption_message(msg, data, size, sk_enc)) {
			R(RLOG_ERROR, "Error populating DeviceEncryptedL6_t");
			asn_DEF_DeviceL6.free_struct(&asn_DEF_DeviceL6, device_msg, 0);
			return 2;
		}
	} else {
		device_msg->present = DeviceL6_PR_cleartext;
		DeviceCleartextL6_t *msg = &device_msg->choice.cleartext;

		if (populate_cleartext_message(msg, data, size)) {
			R(RLOG_ERROR, "Error populating DeviceCleartextL6_t");
			asn_DEF_DeviceL6.free_struct(&asn_DEF_DeviceL6, device_msg, 0);
			return 3;
		}
	}

	if (validate_message(device_msg)) {
		asn_DEF_DeviceL6.free_struct(&asn_DEF_DeviceL6, device_msg, 0);
		return 4;
	}

	uint8_t sbuf[4096] = {0};
	size_t bytes_encoded = 0;
	if (encode_message(sbuf, sizeof sbuf, &bytes_encoded, device_msg)) {
		asn_DEF_DeviceL6.free_struct(&asn_DEF_DeviceL6, device_msg, 0);
		return 5;
	}

	asn_DEF_DeviceL6.free_struct(&asn_DEF_DeviceL6, device_msg, 0);

	R(RLOG_DEBUG, "Encoded DeviceL6_t has size = %zu", bytes_encoded);
	print_uint8a(sbuf, bytes_encoded, 'x');

	//TORM  print string para copiar diretamente para Android project:
	for (size_t i = 0; i < bytes_encoded; i++) {
		fprintf(stdout, "%02"PRIx8, sbuf[i]);
	}
	fprintf(stdout, "\nEND\n");

	// Print successful response code (for debugging): -----------------

#ifdef SRX_DEBUG_PRINT_VERIFICATION_CODE
	unsigned char temp_mac_1[32] = {0};
	debug_only_compute_resp_mac_hex(temp_mac_1, rn, sk_mac);
	printf("MAC of successful response (not for production)\n");
	print_uint8a(temp_mac_1, sizeof temp_mac_1, 'x');
#endif

	// Exchange data with the Security Token: --------------------------

	sgx_status_t ss;
	int retval;
	char rbuf[1024] = {0};
	size_t bytes_read = 0;

#ifdef SRX_DEBUG_AUTOFILL
	ss = 0;
	retval = 0;
	debug_only_compute_resp_mac_str(rbuf, rn, sk_mac);
	bytes_read = 65; // 2 per hex plus NUL = 32*2+1
	printf("Autofill is on: %s\n", rbuf);
#else
	printf("Autofill is off\n");
	ss = token_io(&retval, sbuf, bytes_encoded, rbuf, sizeof rbuf, &bytes_read);
#endif
	if (SGX_SUCCESS != ss) {
		R(RLOG_ERROR, "SGX error exchanging data with the ST");
		return 6;
	}
	if (retval) {
		R(RLOG_WARNING, "Error exchanging data with the ST");
		return 7;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST");

	// char *str_ppp = rbuf;//TORM
	R(RLOG_TRACE, "data received is''': %s", rbuf);//TORM

	// Compute set of expected responses; compare with value from ST: --

	if (bytes_read < COMP_N_BYTES) {
		R(RLOG_ERROR, "Response not long enough (got = %zu, need = %zu)",
				bytes_read, COMP_N_BYTES);
		return 8;
	}

	if (rn_size < 32) {
		R(RLOG_ERROR, "Nonce too short (got = %zu, want = %d)", rn_size, 32);
		return 8;
	}

	// uint8_t temp_nonce[32] = {0};
	int temp_rc = find_match(expected_max_resp, rbuf, bytes_read,
			sk_mac, rn, COMP_N_BYTES);
	R(RLOG_TRACE, "temp_resp is: %d", temp_rc);//TORM
	if (temp_rc < 0 || temp_rc > expected_max_resp) {
		R(RLOG_ERROR, "Match out of bounds");
		return 9;
	}
	*rc = temp_rc;

	return 0;

	//TODO
	// prepare outer message, and decide cleartext or encrypted
	// Prepare cleartext or encrypted messafge
	// Validate & Encode outer message
	//TODO PExchange data with device
	//TODO Parse response and find match
	//TODO return result to caller
	//(This function should not leak underlying ASn.1 stuff to caller.)
}
