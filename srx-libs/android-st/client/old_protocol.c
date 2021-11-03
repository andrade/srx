#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include <sgx_trts.h>                   // external support libraries
#include <sgx_tcrypto.h>

#include <TokenChannelMessageEnc.h>     // internal support libraries

#include "rlog.h"                       // uses

#include "protocol.h"                   // implements

/** Number of bytes of response to compare with locally-computed HMAC. */
static const int COMP_N_BYTES = 4;

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
**              negative on error or if a match if not found.
**/
static int find_match(uint8_t max_resp, const char *buf, size_t len,
		const uint8_t *sk_mac, const uint8_t *nonce, int ncomp)
{
	//TODO  Ideal é transformar o buf em byte array porque assim feito uma vez

	unsigned char in[32 + 1];
	memcpy(in, nonce, 32);

	for (uint8_t i = 0; i < max_resp; i++) {
		in[32] = i;
		unsigned char mac[32] = {0};
		sgx_status_t ss;
		ss = sgx_hmac_sha256_msg(in, sizeof in, sk_mac, 32, mac, sizeof mac);
		if (SGX_SUCCESS != ss) {
			R(RLOG_ERROR, "SGX error computing HMAC");
			return -2;
		}

		R(RLOG_TRACE, "Got mac:");//TORM
		print_uint8a(mac, sizeof mac, 'x');//TORM

		char *str_from_mac = NULL;
		if (usgx_hex_uint8_to_str(mac, ncomp, "", &str_from_mac)) {
			return -3;
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

// support function for releasing resources from `token_exchange_data()`
static void ted_free(uint8_t *ct, uint8_t *tag, TokenChannelMessageEnc_t *msg)
{
	free(ct);
	free(tag);
	asn_DEF_TokenChannelMessageEnc
			.free_struct(&asn_DEF_TokenChannelMessageEnc, msg, 0);
}

int token_exchange_data(int *rc, int max_resp,
		const void *data, size_t size,
		const uint8_t *sk_enc, const uint8_t *sk_mac)
{
	int result = 0;

	// Encrypt the data: -----------------------------------------------

	// plaintext = <input-data> || <16-byte-nonce-for-HMAC-response>
	size_t pt_len = size + 16;
	uint8_t pt[pt_len];
	memcpy(pt, data, size);
	if (gen_nonce(pt + size, 16)) {
		R(RLOG_ERROR, "Error generating nonce for MAC response");
		return 1;
	}

	uint8_t iv[12];
	if (gen_nonce(iv, sizeof iv)) {
		R(RLOG_ERROR, "Error generating nonce for encryption");
		return 2;
	}
	R(RLOG_TRACE, "Print IV:");//TORM
	print_uint8a(iv, sizeof iv, 'x');//TORM
	uint8_t *ct = NULL;
	uint32_t ct_len = 0;
	uint8_t *tag = NULL;
	uint8_t ad[1] = {0x00};  // using one zero byte as AD
	// § 6.7.6.2: "If the expression is a constant expression, it shall have a value greater than zero."

	if (aead_enc(sk_enc, iv, pt, pt_len, ad, sizeof ad, &ct, &ct_len, &tag)) {
		R(RLOG_WARNING, "Error encrypting with AEAD");
		return 3;
	}
	R(RLOG_TRACE, "ct_len = %"PRIu32, ct_len); //TORM

	R(RLOG_TRACE, "Print CT:");//TORM
	print_uint8a(ct, ct_len, 'x');//TORM
	R(RLOG_TRACE, "Print TAG:");//TORM
	print_uint8a(tag, 16, 'x');//TORM

	// Encode the request in ASN.1: ------------------------------------

	TokenChannelMessageEnc_t *msg = calloc(1, sizeof *msg);
	if (!msg) {
		R(RLOG_ERROR, "calloc for TokenChannelMessageEnc_t");
		ted_free(ct, tag, NULL);
		return 21;
	}

	if (OCTET_STRING_fromBuf(&msg->nonce, (const char *) iv, 12)) {
		R(RLOG_ERROR, "Error encoding encryption nonce");
		ted_free(ct, tag, msg);
		return 22;
	}
	if (OCTET_STRING_fromBuf(&msg->ciphertext, (const char *) ct, ct_len)) {
		R(RLOG_ERROR, "Error encoding ciphertext");
		ted_free(ct, tag, msg);
		return 23;
	}
	if (OCTET_STRING_fromBuf(&msg->tag, (const char *) tag, 16)) {
		R(RLOG_ERROR, "Error encoding tag");
		ted_free(ct, tag, msg);
		return 24;
	}
	if (OCTET_STRING_fromBuf(&msg->ad, (const char *) ad, sizeof ad)) {
		R(RLOG_ERROR, "Error encoding associated data");
		ted_free(ct, tag, msg);
		return 25;
	}

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_TokenChannelMessageEnc, msg,
			errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenChannelMessageEnc_t: %s", errbuf);
		ted_free(ct, tag, msg);
		return 26;
	}

	asn_enc_rval_t rval;
	rval = der_encode(&asn_DEF_TokenChannelMessageEnc, msg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded TokenChannelMessageEnc_t");
		ted_free(ct, tag, msg);
		return 27;
	}
	uint8_t sbuf[rval.encoded];
	rval = der_encode_to_buffer(&asn_DEF_TokenChannelMessageEnc,
			msg, sbuf, sizeof sbuf);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding TokenChannelMessageEnc_t");
		ted_free(ct, tag, msg);
		return 28;
	}
	R(RLOG_DEBUG, "Encoded TokenChannelMessageEnc_t has size = %zu",
			rval.encoded);

	// Exchange data with the Security Token: --------------------------

	sgx_status_t ss;
	int retval;
	char rbuf[1024] = {0};
	size_t bytes_read = 0;

	ss = token_io(&retval, sbuf, sizeof sbuf, rbuf, sizeof rbuf, &bytes_read);
	if (SGX_SUCCESS != ss) {
		R(RLOG_ERROR, "SGX error exchanging data with the ST");
		ted_free(ct, tag, msg);
		return 31;
	}
	if (retval) {
		R(RLOG_WARNING, "Error exchanging data with the ST");
		ted_free(ct, tag, msg);
		return 32;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST");//TORM

	// char *str_ppp = rbuf;//TORM
	R(RLOG_TRACE, "data received is''': %s", rbuf);//TORM

	// Compute set of expected responses; compare with value from ST: --

	if (bytes_read < COMP_N_BYTES) {
		R(RLOG_ERROR, "Response not long enough (got = %zu, need = %d)",
				bytes_read, COMP_N_BYTES);
		ted_free(ct, tag, msg);
		return 41;
	}

	uint8_t temp_nonce[32] = {0};
	int temp_rc = find_match(max_resp, rbuf, bytes_read, sk_mac, temp_nonce, COMP_N_BYTES);
	R(RLOG_TRACE, "temp_resp is: %d", temp_rc);//TORM
	if (temp_rc < 0 || temp_rc > max_resp) {
		R(RLOG_ERROR, "Match out of bounds");
		ted_free(ct, tag, msg);
		return 42;
	}
	*rc = temp_rc;

	ted_free(ct, tag, msg);
	return 0;
}

uint8_t i2n_m1(
		const uint8_t *comm_nonce, size_t comm_nonce_len,
		const uint8_t *comm_pub, size_t comm_pub_len,
		const uint8_t *seal_nonce, size_t seal_nonce_len,
		const uint8_t *seal_pub, size_t seal_pub_len,
		uint8_t *buffer, size_t *buffer_len)
{
	if (comm_nonce_len > UINT16_MAX || comm_pub_len > UINT16_MAX
			|| seal_nonce_len > UINT16_MAX || seal_pub_len > UINT16_MAX) {
		//TODO log error, too large
		return 1;
	}
	size_t size = comm_nonce_len + comm_pub_len + seal_nonce_len + seal_pub_len;
	if (size > UINT32_MAX) {
		//TODO log error
		return 2;
	}
	if (!buffer) {
		*buffer_len = size;
		return 0;
	}

	printf("foo 1\n");
	void *p = buffer;
	memcpy(p, &size, 4);
	p += 4;

	printf("foo 2\n");
	memcpy(p, &comm_nonce_len, 2);
	p += 2;
	memcpy(p, comm_nonce, comm_nonce_len);
	p += comm_nonce_len;

	memcpy(p, &comm_pub_len, 2);
	p += 2;
	memcpy(p, comm_pub, comm_pub_len);
	p += comm_pub_len;

	memcpy(p, &seal_nonce_len, 2);
	p += 2;
	memcpy(p, seal_nonce, seal_nonce_len);
	p += seal_nonce_len;

	memcpy(p, &seal_pub_len, 2);
	p += 2;
	memcpy(p, seal_pub, seal_pub_len);
	p += seal_pub_len;

	*buffer_len = size;

	return 0;
}
