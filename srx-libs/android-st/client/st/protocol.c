#include <TokenMessage.h>               // internal support libraries

#include "rlog.h"                       // uses

#include "protocol.h"                   // implements

//------------------------------ General Code --------------------------

/**
** Creates and populates the structure.
** Returns the structure on success, or NULL otherwise.
**/
static TokenMessage_t *create_TokenMessage(const enum request_PR type,
		const uint8_t *rn, size_t rn_size)
{
	TokenMessage_t *tmsg = calloc(1, sizeof *tmsg);
	if (!tmsg) {
		R(RLOG_ERROR, "calloc for TokenMessage_t");
		return NULL;
	}

	tmsg->request.present = type;

	if (OCTET_STRING_fromBuf(&tmsg->nonce_mac, (const char *) rn, rn_size)) {
		R(RLOG_ERROR, "Error encoding response nonce");
		asn_DEF_TokenMessage.free_struct(&asn_DEF_TokenMessage, tmsg, 0);
		return NULL;
	}

	return tmsg;
}

/**
** Validates the structure.
** Returns zero on success, or non-zero otherwise.
**/
static int validate_TokenMessage(const TokenMessage_t *tmsg)
{
	char errbuf[256];
	size_t errlen = 256;

	if (asn_check_constraints(&asn_DEF_TokenMessage, tmsg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenMessage_t: %s", errbuf);
		return 1;
	}

	return 0;
}

/**
** DER-encodes the structure.
** The caller allocates the destination buffer, `dest`.
** Returns zero on success, or non-zero otherwise.
**/
static int encode_TokenMessage(uint8_t *dest, size_t dest_len,
		size_t *bytes_encoded, TokenMessage_t *tmsg)
{
	asn_enc_rval_t rval;

	rval = der_encode(&asn_DEF_TokenMessage, tmsg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded TokenMessage_t");
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
	rval = der_encode_to_buffer(&asn_DEF_TokenMessage, tmsg, dest, dest_len);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding TokenMessage_t");
		return 3;
	}
	*bytes_encoded = rval.encoded;

	R(RLOG_VERBOSE, "Encoded TokenMessage_t (size = %zu)", rval.encoded);

	return 0;
}

/**
** Releases the resources associated with the structure.
**/
static void delete_TokenMessage(TokenMessage_t *tmsg)
{
	asn_DEF_TokenMessage.free_struct(&asn_DEF_TokenMessage, tmsg, 0);
}

//------------------------------ Specific Code -------------------------

int encode_TokenAuth(uint8_t *dest, size_t dest_len, size_t *bytes_encoded,
		const char *str, size_t len,
		const uint8_t *rn, size_t rn_size)
{
	TokenMessage_t *tmsg = create_TokenMessage(request_PR_auth, rn, rn_size);
	if (!tmsg) {
		return 1;
	}

	TokenAuth_t *msg = &tmsg->request.choice.auth;
	if (OCTET_STRING_fromBuf(&msg->display_text, str, len)) {
		R(RLOG_ERROR, "Error encoding the text to display");
		delete_TokenMessage(tmsg);
		return 2;
	}
	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_TokenAuth, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenAuth_t: %s", errbuf);
		delete_TokenMessage(tmsg);
		return 3;
	}

	if (validate_TokenMessage(tmsg)) {
		delete_TokenMessage(tmsg);
		return 4;
	}

	if (encode_TokenMessage(dest, dest_len, bytes_encoded, tmsg)) {
		delete_TokenMessage(tmsg);
		return 5;
	}

	delete_TokenMessage(tmsg);

	return 0;
}

static int populate_TokenInitAP(TokenInitAP_t *msg,
		const uint8_t *pid, size_t pid_size,
		const uint8_t *ras_sig, size_t ras_sig_len,
		const uint8_t *sk_enc, size_t sk_enc_len,
		const uint8_t *sk_mac, size_t sk_mac_len)
{
	if (OCTET_STRING_fromBuf(&msg->platform_id, (const char *) pid, pid_size)) {
		R(RLOG_ERROR, "Error encoding platform details of AP");
		return 2;
	}
	if (OCTET_STRING_fromBuf(&msg->ras_sig, (const char *) ras_sig,
			ras_sig_len)) {
		R(RLOG_ERROR, "Error encoding signature from the RAS");
		return 6;
	}
	if (OCTET_STRING_fromBuf(&msg->sk_enc, (const char *) sk_enc,
			sk_enc_len)) {
		R(RLOG_ERROR, "Error encoding the secret key for encryption");
		return 7;
	}
	if (OCTET_STRING_fromBuf(&msg->sk_mac, (const char *) sk_mac,
			sk_mac_len)) {
		R(RLOG_ERROR, "Error encoding the secret key for hashing");
		return 8;
	}

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_TokenInitAP, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenInitAP_t: %s", errbuf);
		return 9;
	}

	return 0;
}

int encode_TokenInitAP(uint8_t *dest, size_t dest_len, size_t *bytes_encoded,
		const uint8_t *pid, size_t pid_size,
		const uint8_t *ras_sig, size_t ras_sig_len,
		const uint8_t *sk_enc, size_t sk_enc_len,
		const uint8_t *sk_mac, size_t sk_mac_len,
		const uint8_t *rn, size_t rn_size)
{
	TokenMessage_t *tmsg = create_TokenMessage(request_PR_init_ap, rn, rn_size);
	if (!tmsg) {
		return 1;
	}

	if (populate_TokenInitAP(&tmsg->request.choice.init_ap,
			pid, pid_size,
			ras_sig, ras_sig_len,
			sk_enc, sk_enc_len, sk_mac, sk_mac_len)) {
		R(RLOG_ERROR, "Error populating TokenInitAP_t");
		delete_TokenMessage(tmsg);
		return 2;
	}

	if (validate_TokenMessage(tmsg)) {
		delete_TokenMessage(tmsg);
		return 3;
	}

	if (encode_TokenMessage(dest, dest_len, bytes_encoded, tmsg)) {
		delete_TokenMessage(tmsg);
		return 4;
	}

	delete_TokenMessage(tmsg);

	return 0;
}

static int populate_TokenInitRP(TokenInitRP_t *msg,
		const void *pid, size_t pid_size,
		const void *sig, size_t sig_size)
{
	asn_TYPE_descriptor_t *td = &asn_DEF_TokenInitRP;

	if (OCTET_STRING_fromBuf(&msg->platform_id, pid, pid_size)) {
		R(RLOG_ERROR, "Error adding encoded platform details to TokenInitRP_t");
		return 2;
	}
	R(RLOG_TRACE | RLOG_LOW, "OCTET_STRING_fromBuf - platform_id= OK");

	if (OCTET_STRING_fromBuf(&msg->ras_sig, sig, sig_size)) {
		R(RLOG_ERROR, "Error adding signature to TokenInitRP_t");
		return 3;
	}
	R(RLOG_TRACE | RLOG_LOW, "OCTET_STRING_fromBuf - ras_sig    = OK");

	char errbuf[256];
	size_t errlen = sizeof(errbuf);
	if (asn_check_constraints(td, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenInitRP_t: %s", errbuf);
		return 4;
	}

	return 0;
}

int encode_TokenInitRP(void *dest, size_t capacity, size_t *bytes_encoded,
		const void *pid, size_t pid_size,
		const void *sig, size_t sig_size,
		const void *rn, size_t rn_size)
{
	TokenMessage_t *tmsg = create_TokenMessage(request_PR_init_rp, rn, rn_size);
	if (!tmsg) {
		return 1;
	}

	if (populate_TokenInitRP(&tmsg->request.choice.init_rp,
			pid, pid_size, sig, sig_size)) {
		R(RLOG_ERROR, "Error populating TokenInitRP_t");
		delete_TokenMessage(tmsg);
		return 2;
	}

	if (validate_TokenMessage(tmsg)) {
		delete_TokenMessage(tmsg);
		return 3;
	}

	if (encode_TokenMessage(dest, capacity, bytes_encoded, tmsg)) {
		delete_TokenMessage(tmsg);
		return 4;
	}

	delete_TokenMessage(tmsg);

	return 0;
}

static int populate_TokenRemoveRP(TokenRemoveRP_t *msg, uint64_t rpid)
{
	asn_TYPE_descriptor_t *td = &asn_DEF_TokenRemoveRP;

	msg->rpid = rpid;

	char errbuf[256];
	size_t errlen = sizeof(errbuf);
	if (asn_check_constraints(td, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenRemoveRP_t: %s", errbuf);
		return 1;
	}

	return 0;
}

int encode_TokenRemoveRP(void *dest, size_t capacity, size_t *bytes_encoded,
		uint64_t rpid,
		const void *rn, size_t rn_size)
{
	TokenMessage_t *tmsg;
	tmsg = create_TokenMessage(request_PR_remove_rp, rn, rn_size);
	if (!tmsg) {
		return 1;
	}

	if (populate_TokenRemoveRP(&tmsg->request.choice.remove_rp, rpid)) {
		R(RLOG_ERROR, "Error populating TokenRemoveRP_t");
		delete_TokenMessage(tmsg);
		return 2;
	}

	if (validate_TokenMessage(tmsg)) {
		delete_TokenMessage(tmsg);
		return 3;
	}

	if (encode_TokenMessage(dest, capacity, bytes_encoded, tmsg)) {
		delete_TokenMessage(tmsg);
		return 4;
	}

	delete_TokenMessage(tmsg);

	return 0;
}

static int populate_TokenReplace(TokenReplace_t *msg, uint64_t rpid)
{
	asn_TYPE_descriptor_t *td = &asn_DEF_TokenReplace;

	msg->rpid = rpid;

	char errbuf[256];
	size_t errlen = sizeof(errbuf);
	if (asn_check_constraints(td, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating TokenReplace_t: %s", errbuf);
		return 1;
	}

	return 0;
}

int encode_TokenReplace(void *dest, size_t capacity, size_t *bytes_encoded,
		uint64_t rpid,
		const void *rn, size_t rn_size)
{
	TokenMessage_t *tmsg;
	tmsg = create_TokenMessage(request_PR_replace, rn, rn_size);
	if (!tmsg) {
		return 1;
	}

	if (populate_TokenReplace(&tmsg->request.choice.replace, rpid)) {
		R(RLOG_ERROR, "Error populating TokenReplace_t");
		delete_TokenMessage(tmsg);
		return 2;
	}

	if (validate_TokenMessage(tmsg)) {
		delete_TokenMessage(tmsg);
		return 3;
	}

	if (encode_TokenMessage(dest, capacity, bytes_encoded, tmsg)) {
		delete_TokenMessage(tmsg);
		return 4;
	}

	delete_TokenMessage(tmsg);

	return 0;
}
