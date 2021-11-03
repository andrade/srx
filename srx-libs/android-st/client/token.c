#include <string.h>
#include <inttypes.h>

#include <sgx_trts.h>

#include <usgx/t/util.h>
#include "srx_t.h"

#include <Message.h>
#include <PlatformID.h>
#include <SignedPlatformID.h>
#include <asn_SEQUENCE_OF.h> // otherwise app can't find define ASN_SEQUENCE_ADD

#include "rlog.h"
#include "bincat.h"
#include "crypto.h"
#include "ds.h"
#include "interr.h"
#include "rp.h"
#include "storage.h"
#include "st/device.h"
#include "st/protocol.h"
#include "tconst.h"

/**
** The keying material of a platform.
** This is different from `struct platform` in `ds.h`, consider merging.
**/
struct platform_keys {
	uint64_t pid;

	uint8_t comm_nonce[32];
	struct srx_kp *ckp;
	uint8_t comm_pub[SRX_MAX_KEYLEN];
	uint32_t comm_pub_len;

	uint8_t seal_nonce[32];
	struct srx_kp *skp;
	uint8_t seal_pub[SRX_MAX_KEYLEN];
	uint32_t seal_pub_len;
};

//------------------------------ Keying Material -----------------------

/**
** Derives the Base Key from the Base Nonce.
**
** The caller allocates the destination buffer.
**
** @param[out]  base_key    The 16-byte Base Key
** @param[in]   base_nonce  The 32-byte Base Nonce (input to derive Base Key)
**
** Returns zero on success, or non-zero otherwise.
**
** @see #generate_base_key_ap()
**/
static int derive_base_key_ap(uint8_t *base_key, const uint8_t *base_nonce)
{
	return get_key_128bit(base_nonce, USGX_KEY_POLICY_SIG, base_key);
}
// for subsequent executions of AP (assuming previously init'd)

/**
** Generates the Base Nonce and the Base Key.
**
** The caller allocates both destination buffers.
**
** @param[out]  base_key    The 16-byte Base Key
** @param[out]  base_nonce  The 32-byte Base Nonce (input to derive Base Key)
**
** @return      Returns zero on success, or non-zero otherwise.
**
** @see #derive_base_key_ap()
*/
//TORM @deprecated
static int generate_base_key_ap(uint8_t *base_key, uint8_t *base_nonce)
{
	if (gen_nonce(base_nonce, 32)) {
		return 1;
	}
	if (get_key_128bit(base_nonce, USGX_KEY_POLICY_SIG, base_key)) {
		return 1;
	}

	return 0;
}
// for first run of AP (system initialization); only called again to change keys

/**
** Derives the sealing keying material.
**
** The Common Sealing Key (CSK) and the Common Initialization Vector (CIV)
** are used to (un)seal the SRX enclave state.
** The CSK and the CIV are derived from
** the Base Key (BK) and the Sealing Nonce (SN).
**
** The caller allocates all output buffers.
**
** @param[out]  csk         The 16-byte CSK
** @param[out]  civ         The 12-byte CIV
** @param[in]   sn          The 32-byte Sealing Nonce
** @param[in]   base_key    The 16-byte Base Key
**
** Returns zero on success, or non-zero otherwise.
**
** @see #generate_sealing_km()
**/
static int derive_sealing_km(uint8_t *csk, uint8_t *civ,
		const uint8_t *sn, const uint8_t *base_key)
{
	if (kbkdf(csk, 16, base_key, 16, sn, 32, CSK_INFO, sizeof CSK_INFO)) {
		return 4;
	}
	if (kbkdf(civ, 12, base_key, 16, sn, 32, CSK_IV_INFO, sizeof CSK_IV_INFO)) {
		return 5;
	}

	return 0;
}
// re-generates CSK/CIV to decrypt the sealed SRX enclave state

/**
** Generates the sealing keying material.
**
** The caller allocates all output buffers.
**
** @param[out]  csk         The 16-byte Common Sealing Key
** @param[out]  civ         The 12-byte Common Initialization Vector
** @param[out]  sn          The 32-byte Sealing Nonce
** @param[in]   base_key    The 16-byte Base Key
**
** Returns zero on success, or non-zero otherwise.
**
** @see  #derive_sealing_km()
**/
static int generate_sealing_km(uint8_t *csk, uint8_t *civ,
		uint8_t *sn, const uint8_t *base_key)
{
	// key wear out
	if (gen_nonce(sn, 32)) {
		return 1;
	}

	if (kbkdf(csk, 16, base_key, 16, sn, 32, CSK_INFO, sizeof CSK_INFO)) {
		return 2;
	}
	if (kbkdf(civ, 12, base_key, 16, sn, 32, CSK_IV_INFO, sizeof CSK_IV_INFO)) {
		return 3;
	}

	return 0;
}
// generates a new CSK/CIV for sealing the SRX enclave state

/**
** Derives the keying material for this platform.
**
** The caller allocates and initializes `pk` to zero.
** The caller is responsible for freeing the key pairs afterwards.
**
** cn:  the 32-byte communication nonce of the platform
** sn:  the 32-byte sealing nonce of the platform
**
** Returns zero on success, or non-zero otherwise.
**/
static int derive_platform_km(struct platform_keys *pk,
		const uint8_t *cn, const uint8_t *sn)
{
	assert(pk);
	assert(!pk->ckp);
	assert(!pk->skp);

	pk->pid = compute_platform_id();
	if (0xFFFFFFFFFFFFFFFF == pk->pid) {
		R(RLOG_DEBUG, "Error computing platform identifier");
		goto error;
	}

	memcpy(pk->comm_nonce, cn, 32);
	memcpy(pk->seal_nonce, sn, 32);

	if (der_kp(&pk->ckp, cn, KP_SALT, KP_COMM_INFO, sizeof(KP_COMM_INFO))) {
		R(RLOG_DEBUG, "Error deriving platform communication key pair");
		goto error;
	}
	if (der_kp(&pk->skp, sn, KP_SALT, KP_SEAL_INFO, sizeof(KP_SEAL_INFO))) {
		R(RLOG_DEBUG, "Error deriving platform sealing key pair");
		goto error;
	}

	uint8_t *comm_pub = NULL;
	uint32_t comm_pub_len = 0;
	if (i2d_pub(pk->ckp, &comm_pub, &comm_pub_len)) {
		goto error;
	}
	memcpy(&pk->comm_pub, comm_pub, comm_pub_len);
	pk->comm_pub_len = comm_pub_len;
	free(comm_pub);

	uint8_t *seal_pub = NULL;
	uint32_t seal_pub_len = 0;
	if (i2d_pub(pk->skp, &seal_pub, &seal_pub_len)) {
		goto error;
	}
	memcpy(&pk->seal_pub, seal_pub, seal_pub_len);
	pk->seal_pub_len = seal_pub_len;
	free(seal_pub);

	//free_kp(pk->ckp);
	//free_kp(pk->skp);
	return 0;

error:
	free_kp(&pk->ckp);
	free_kp(&pk->skp);
	return 1;
}

/**
** Generates the keying material for the platform.
**
** @return      Returns zero on success, or non-zero otherwise.
**/
static int generate_platform_keying_material(struct platform_keys *pk)
{
	assert(pk);

	uint8_t cn[32] = {0};
	uint8_t sn[32] = {0};

	if (gen_nonce(cn, 32) || gen_nonce(sn, 32)) {
		return 1;
	}

	return derive_platform_km(pk, cn, sn);
}

// generates: GSN, GSPK
static int generate_group_km(struct root *root)
{
	struct srx_kp *gskp = NULL; // Group Sealing KP

	if (gen_nonce(root->priv.gsn, sizeof root->priv.gsn)) {
		return 1;
	}

	if (der_kp(&gskp, root->priv.gsn,
			KP_SALT, KP_SEAL_INFO, sizeof(KP_SEAL_INFO))) {
		return 1;
	}

	uint8_t *group_sealing_pub = NULL;
	uint32_t group_sealing_pub_len = 0;
	if (i2d_pub(gskp, &group_sealing_pub, &group_sealing_pub_len)) {
		free_kp(&gskp);
		return 1;
	}
	memcpy(&root->open.gspk, group_sealing_pub, group_sealing_pub_len);
	root->open.gspk_len = group_sealing_pub_len;
	free(group_sealing_pub);

	free_kp(&gskp);

	return 0;
}

/**
** Generates the system keying material.
**
** The KM is stored in `root`, which is initialized by the caller.
**
** @return      Returns zero on success, or non-zero otherwise.
**/
static int populate_system_km(struct root *root)
{
	assert(root);

	if (gen_nonce(root->priv.seed, sizeof root->priv.seed)) {
		return 1;
	}

	// generate Base Key
	if (gen_nonce(root->temp.base_key, sizeof root->temp.base_key)) {
		return 1;
	}

	// generate seal nonce and derive CSK (with base key + seal nonce as input)
	if (gen_nonce(root->open.seal_nonce, 32)) {
		return 3;
	}
	if (kbkdf(root->temp.csk, 16, root->temp.base_key, 16,
			root->open.seal_nonce, 32, CSK_INFO, sizeof(CSK_INFO))) {
		return 4;
	}
	// derive IV for AEAD encryption
	if (kbkdf(root->temp.iv, 12, root->temp.base_key, 16,
			root->open.seal_nonce, 32, CSK_IV_INFO, sizeof(CSK_IV_INFO))) {
		return 5;
	}

	// generate encryption nonce, prepare data (state) for sealing
	if (gen_nonce(root->open.encryption_nonce, 32)) {
		return 6;
	}

	return 0;
}

//------------------------------ DS Manipulation -----------------------

/**
** Finds the index of the RP.
** Returns the index of the RP in the database, or
** negative (`-SRX_E_NOT_FOUND`) if not found.
**/
static int find_rp_pos(struct root *root, uint64_t rpid)
{
	assert(root);

	for (uint32_t i = 0; i < root->open.platforms_count; i++) {
		uint64_t this_pos_pid = root->open.platforms[i].pid;

		if (rpid == this_pos_pid) {
			return i;
		}
	}

	return -SRX_E_NOT_FOUND;
}

/**
** Finds the position for this RP.
**
** The position is either a new one or the old one if the platform is present.
** When the current platform count equals the next position, means new platform.
**
** Returns the position to use, or `SRX_MAX_NODES` if full.
**/
static uint32_t find_next_pos(const struct root *root, const uint64_t pid)
{
	if (root->open.platforms_count == SRX_MAX_NODES) {
		return SRX_MAX_NODES; // full
	}

	for (uint32_t i = 0; i < root->open.platforms_count; i++) {
		uint64_t this_pos_pid = root->open.platforms[i].pid;

		if (pid == this_pos_pid) {
			return i; // found
		}
	}

	return root->open.platforms_count; // new
}

/**
** Adds or updates the details of a platform.
** This includes the platform ID, the nonces and respective public keys, and
** the encrypted Base Key and its tag.
** The platform details are overwritten when the platform already exists.
** Returns zero on success, or non-zero otherwise.
**/
static int update_rp_details(struct root *root, const struct platform_keys *pk)
{
	uint32_t next_pos = find_next_pos(root, pk->pid);
	if (SRX_MAX_NODES == next_pos) {
		R(RLOG_ERROR, "No space for new RP");
		return 1;
	}
	R(RLOG_DEBUG, "Position for this RP at %"PRIu32, next_pos);

	struct platform *p = &root->open.platforms[next_pos];

	p->pid = pk->pid;

	memcpy(p->seal_nonce, pk->seal_nonce, 32);
	memcpy(p->seal_pub, pk->seal_pub, pk->seal_pub_len);
	p->seal_pub_len = pk->seal_pub_len;

	memcpy(root->priv.rp_comm_nonce[next_pos], pk->comm_nonce, 32);
	memcpy(root->temp.comm_pub, pk->comm_pub, pk->comm_pub_len);
	root->temp.comm_pub_len = pk->comm_pub_len;

	struct srx_kp *gskp = NULL;
	if (der_kp(&gskp, root->priv.gsn,
			KP_SALT, KP_SEAL_INFO, sizeof KP_SEAL_INFO)) {
		return 1;
	}

	uint8_t *ebk = p->encrypted_base_key;
	size_t ebk_len;
	uint8_t *ebk_tag = p->ebk_tag;
	if (encrypt_base_key(ebk, SRX_MAX_KEYLEN * 2, &ebk_len, ebk_tag,
			gskp,
			p->seal_pub, p->seal_pub_len,
			root->open.encryption_nonce,
			root->temp.base_key)) {
		free_kp(&gskp);
		return 7;
	}
	p->encrypted_base_key_len = ebk_len;

	free_kp(&gskp);

	if (root->open.platforms_count == next_pos) {
		root->open.platforms_count++;
	}

	return 0;
}

/**
** Removes the details of a RP.
** This includes the platform ID, the nonces and respective public keys, and
** the encrypted Base Key and its tag.
** Returns zero on success, or non-zero otherwise.
** Returns `SRX_E_NOT_FOUND` when the platform does not exist.
**/
static int remove_rp_details(struct root *root, uint64_t rpid)
{
	uint32_t pos = UINT32_MAX;
	for (uint32_t i = 0; i < root->open.platforms_count; i++) {
		uint64_t this_pos_pid = root->open.platforms[i].pid;

		if (rpid == this_pos_pid) {
			pos = i;
			goto found;
		}
	}
	return SRX_E_NOT_FOUND;

found:
	R(RLOG_DEBUG, "Found this RP at position %"PRIu32, pos);

	root->open.platforms_count--;
	for (uint32_t i = pos; i < root->open.platforms_count; i++) {
		root->open.platforms[i] = root->open.platforms[i + 1];
		memcpy(root->priv.rp_comm_nonce[i], root->priv.rp_comm_nonce[i+1], 32);
	}

	return 0;
}

// Replaces the AP. Returns zero on success.
// includes: AP keying material, removing RP, re-gen keys, re-encrypt EBKs
// pk has details of new AP, including sealing key pair
static int replace_ap(struct root *root, const struct platform_keys *pk)
{
	assert(root);
	assert(pk);

	// replace AP's details
	root->open.apid = pk->pid;
	memcpy(root->priv.ap_comm_nonce, pk->comm_nonce, 32);
	memcpy(root->priv.ap_seal_nonce, pk->seal_nonce, 32);
	memcpy(root->open.ap_seal_pub, pk->seal_pub, pk->seal_pub_len);
	root->open.ap_seal_pub_len = pk->seal_pub_len;

	if (generate_base_key_ap(root->temp.base_key, root->open.base_nonce)) {
		return 1;
	}

	if (remove_rp_details(root, pk->pid)) {
		assert(0); // should never get to this point if this platform not a RP
		return 1;
	}

	// re-encrypt «encrypted base keys» of RPs
	if (gen_nonce(root->open.encryption_nonce, 32)) {
		return 1;
	}
	for (uint32_t i = 0; i < root->open.platforms_count; i++) {
		struct platform *p = &root->open.platforms[i];

		uint8_t *ebk = p->encrypted_base_key;
		size_t ebk_len;
		uint8_t *ebk_tag = p->ebk_tag;
		if (encrypt_base_key(ebk, SRX_MAX_KEYLEN * 2, &ebk_len, ebk_tag,
				pk->skp,
				p->seal_pub, p->seal_pub_len,
				root->open.encryption_nonce,
				root->temp.base_key)) {
			return 1;
		}
		p->encrypted_base_key_len = ebk_len;
	}

	return 0;
}

//------------------------------ Other Support Code --------------------

/**
** Creates a `SignedPlatformID` message.
**
** DER-encodes (1) the DER-encoded platform details, and (2) the RAS
** signature over the platform details.
**
** @param[out]  dest           The destination buffer
** @param[in]   capacity       The capacity of the destination buffer
** @param[out]  bytes_encoded  The amount of encoded data in `dest`
** @param[in]   pid            The DER-encoded plataform details
** @param[in]   pid_size       The size of `pid`
** @param[in]   sig            The signature over the encoded plataform details
** @param[in]   sig_size       The size of `sig`
**
** Returns zero on success, or non-zero otherwise.
**/
static int encode_SignedPlatformID(uint8_t *dest,
		size_t capacity, size_t *bytes_encoded,
		const uint8_t *pid, size_t pid_size,
		const uint8_t *sig, size_t sig_size)
{
	assert(dest);
	assert(pid);
	assert(sig);

	SignedPlatformID_t *msg = calloc(1, sizeof *msg);
	if (!msg) {
		R(RLOG_ERROR, "calloc for SignedPlatformID_t");
		return 1;
	}

	if (OCTET_STRING_fromBuf(&msg->pid, (const char *) pid, pid_size)) {
		R(RLOG_ERROR, "Error adding encoded platform details to SignedPlatformID_t");
		asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);
		return 2;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - pid        = OK");

	if (OCTET_STRING_fromBuf(&msg->sig, (const char *) sig, sig_size)) {
		R(RLOG_ERROR, "Error adding signature to SignedPlatformID_t");
		asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);
		return 3;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - sig        = OK");

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_SignedPlatformID,
			msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating SignedPlatformID_t: %s", errbuf);
		asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);
		return 4;
	}

	asn_enc_rval_t rval;
	rval = der_encode(&asn_DEF_SignedPlatformID, msg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded SignedPlatformID_t");
		asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);
		return 5;
	}
	*bytes_encoded = (size_t) rval.encoded;
	if (!dest) {
		return 0; // leave early, purpose was finding required buffer size
	}
	if (*bytes_encoded > capacity) {
		R(RLOG_WARNING, "Buffer not long enough (got = %zu, need = %zu)",
				capacity, *bytes_encoded);
		return 6;
	}
	rval = der_encode_to_buffer(&asn_DEF_SignedPlatformID, msg, dest, capacity);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding SignedPlatformID_t");
		asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);
		return 7;
	}
	R(RLOG_VERBOSE, "Encoded SignedPlatformID_t has size = %zu", rval.encoded);

	asn_DEF_SignedPlatformID.free_struct(&asn_DEF_SignedPlatformID, msg, 0);

	return 0;
}

static int decode_SignedPlatformID(const void *src, size_t n,
		void *pid, size_t pid_cap, size_t *pid_size,
		void *sig, size_t sig_cap, size_t *sig_size)
{
	assert(src);
	assert(pid);
	assert(sig);

	int result = 0;

	SignedPlatformID_t *spid = NULL;
	asn_TYPE_descriptor_t *td = &asn_DEF_SignedPlatformID;
	asn_dec_rval_t dec_retval = ber_decode(NULL, td, (void **) &spid, src, n);
	if (RC_OK != dec_retval.code) {
		R(RLOG_WARNING, "Error decoding SignedPlatformID_t");
		return 1;
	}

	char errbuf[256];
	size_t errlen = sizeof(errbuf);
	if (asn_check_constraints(td, spid, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating SignedPlatformID_t: %s", errbuf);
		result = 2;
		goto finally;
	}

	OCTET_STRING_t *octet_string;

	octet_string = &spid->pid;
	*pid_size = octet_string->size;
	if (*pid_size > pid_cap) {
		result = 3;
		goto finally;
	}
	memcpy(pid, octet_string->buf, octet_string->size);

	octet_string = &spid->sig;
	*sig_size = octet_string->size;
	if (*sig_size > sig_cap) {
		result = 3;
		goto finally;
	}
	memcpy(sig, octet_string->buf, octet_string->size);

finally:
	asn_DEF_SignedPlatformID.free_struct(td, spid, 0);
	return result;
}

/**
** Exchanges data with the Remote Attestation Service.
** Returns zero on success, or non-zero otherwise.
**/
static int ras_exchange(uint8_t *rbuf,
		size_t rbuf_cap, size_t *rbuf_size,
		const uint8_t *sbuf, size_t sbuf_size)
{
	R(RLOG_VERBOSE, "Ready to exchange data with the RAS");

	sgx_status_t ss;
	int retval;

	ss = server_io(&retval, sbuf, sbuf_size, rbuf, rbuf_cap, rbuf_size);
	if (SGX_SUCCESS != ss) {
		R(RLOG_ERROR, "SGX error exchanging data with the RAS");
		return 1;
	}
	if (retval) {
		R(RLOG_WARNING, "Error exchanging data with the RAS");
		return 2;
	}

	R(RLOG_VERBOSE, "Exchanged data with the RAS");

	return 0;
}

/**
** Validates a `Message_t` message.
** Returns zero on success, or non-zero otherwise.
**/
static int validate_message(const Message_t *msg)
{
	char errbuf[256];
	size_t errlen = 256;

	if (asn_check_constraints(&asn_DEF_Message, msg, errbuf, &errlen)) {
		R(RLOG_DEBUG, "Error validating Message_t: %s\n", errbuf);
		return 1;
	}
	if (msg->head.version != version_version_1_0) {
		R(RLOG_DEBUG, "Bad version\n");
		return 2;
	}

	return 0;
}

/**
* Decodes the reply to a signature request.
*
* If the failure reason is an unsufficient buffer size for the signature,
* then the necessary size is placed in `sig_len`.
*
* @param[in]    a             the buffer with the DER-encoded `Message_t`
* @param[in]    n             the length of the buffer `a`
* @param[out]   sig           the pre-allocated buffer for the signature
* @param[in]    sig_cap       the capacity of `sig`
* @param[out]   sig_len       the actual size of `sig` on success
*
* @return       Returns zero on success, or non-zero otherwise.
**/
static int decode_sig_rep(const uint8_t *a, size_t n,
		uint8_t *sig, size_t sig_cap, size_t *sig_len)
{
	Message_t *msg = NULL;
	asn_dec_rval_t dec_retval = ber_decode(NULL, &asn_DEF_Message,
			(void **) &msg, (const void *) a, n);
	if (RC_OK != dec_retval.code) {
		R(RLOG_DEBUG, "Error decoding Message_t\n");
		return 1;
	}
	if (validate_message(msg)) {
		R(RLOG_DEBUG, "Error validating Message_t\n");
		goto failure;
	}
	if (operation_sig_rep != msg->head.operation) {
		// const char err[] = "Unexpected OP code (want = %ld, got = %ld)\n";
		R(RLOG_DEBUG, "Unexpected OP code (want = %ld, got = %ld)\n", operation_sig_rep, msg->head.operation);
		goto failure;
	}

	Body_t *body = msg->body;
	if (!body) {
		R(RLOG_DEBUG, "Missing body\n");
		goto failure;
	}
	if (Body_PR_sig_rep != body->present) {
		R(RLOG_DEBUG, "%s\n", "Incorrect Body_t choice %ld\n", body->present);
		goto failure;
	}

	OCTET_STRING_t *octet_string = &body->choice.sig_rep.ras_sig;
	*sig_len = octet_string->size;
	if (!sig) {
		// null destination buffer, set required buffer size and exit
		goto success;
	}
	if ((size_t) octet_string->size > sig_cap) {
		// const char error[] = "Buffer size not enough (got = %zu, need = %zd)\n";
		R(RLOG_DEBUG, "Buffer size not enough (got = %zu, need = %zd)\n", sig_cap, octet_string->size);
		goto failure;
	}
	memcpy(sig, octet_string->buf, octet_string->size);

success:
	asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
	return 0;
failure:
	asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
	return 1;
}

/**
** Asks the RAS to sign `data`.
** The data is wrapped in DER-encoded messages for transport.
** The signature is placed on `sig` on success.
** Returns zero on success, or non-zero otherwise.
**/
static int ras_sign_data(uint8_t *sig, size_t sig_cap, size_t *sig_len,
		const uint8_t *data, size_t size)
{
	assert(sig);
	assert(data);

	Message_t *msg = calloc(1, sizeof *msg);
	if (!msg) {
		R(RLOG_ERROR, "calloc for Message_t");
		return 1;
	}
	msg->head.version = version_version_1_0;
	msg->head.operation = operation_sig_req;

	Body_t *body = calloc(1, sizeof *body);
	if (!body) {
		R(RLOG_ERROR, "calloc for Body_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 2;
	}
	body->present = Body_PR_sig_req;

	if (OCTET_STRING_fromBuf(&body->choice.sig_req.data,
			(const char *) data, size)) {
		R(RLOG_ERROR, "Error adding data to Body_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 3;
	}

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_Body, body, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating Body_t: %s", errbuf);
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 4;
	}
	msg->body = body;
	if (asn_check_constraints(&asn_DEF_Message, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating Message_t: %s", errbuf);
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 5;
	}

	asn_enc_rval_t rval;
	rval = der_encode(&asn_DEF_Message, msg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded Message_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 11;
	}
	uint8_t sbuf[rval.encoded];
	rval = der_encode_to_buffer(&asn_DEF_Message, msg, sbuf, sizeof sbuf);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding Message_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
		return 12;
	}
	R(RLOG_VERBOSE, "Encoded Message_t has size = %zu", rval.encoded);

	asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
	//asn_DEF_Body.free_struct(&asn_DEF_Body, body, 0); // implicitly done above

	uint8_t rbuf[1024] = {0};
	size_t bytes_read = 0;
	if (ras_exchange(rbuf, sizeof rbuf, &bytes_read, sbuf, sizeof sbuf)) {
		return 21;
	}

	if (decode_sig_rep(rbuf, bytes_read, sig, sig_cap, sig_len)) {
		R(RLOG_DEBUG, "Error decoding reply");
		if (*sig_len > sig_cap) {
			R(RLOG_WARNING, "Destination buffer not large enough "
					"(got = %zu, need = %zu)\n", sig_cap, *sig_len);
		}
		return 31;
	}

	return 0;
}

/**
** Decodes the DER-encoded buffer into the `pk` data structure.
** Returns zero on success, or non-zero otherwise.
**/
static int decode_platform_keying_material(struct platform_keys *pk,
		const void *src, size_t n)
{
	assert(pk);
	assert(src);

	int result = 0;

	PlatformID_t *msg = NULL;
	asn_TYPE_descriptor_t *td = &asn_DEF_PlatformID;
	asn_dec_rval_t dec_retval = ber_decode(NULL, td, (void **) &msg, src, n);
	if (RC_OK != dec_retval.code) {
		R(RLOG_WARNING, "Error decoding PlatformID_t");
		return 1;
	}

	char errbuf[256];
	size_t errlen = sizeof(errbuf);
	if (asn_check_constraints(td, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating PlatformID_t: %s", errbuf);
		result = 2;
		goto finally;
	}

	OCTET_STRING_t *octet_string;

	octet_string = &msg->comm_nonce;
	if ((int) sizeof(pk->comm_nonce) > octet_string->size) {
		R(RLOG_ERROR, "Error extracting communication nonce of RP");
		result = 3;
		goto finally;
	}
	memcpy(pk->comm_nonce, octet_string->buf, octet_string->size);

	octet_string = &msg->comm_pub;
	if (SRX_MAX_KEYLEN < octet_string->size) {
		R(RLOG_ERROR, "Error extracting communication public key of RP");
		result = 4;
		goto finally;
	}
	memcpy(pk->comm_pub, octet_string->buf, octet_string->size);
	pk->comm_pub_len = octet_string->size;

	octet_string = &msg->seal_nonce;
	if ((int) sizeof(pk->seal_nonce) > octet_string->size) {
		R(RLOG_ERROR, "Error extracting sealing nonce of RP");
		result = 5;
		goto finally;
	}
	memcpy(pk->seal_nonce, octet_string->buf, octet_string->size);

	octet_string = &msg->seal_pub;
	if (SRX_MAX_KEYLEN < octet_string->size) {
		R(RLOG_ERROR, "Error extracting sealing public key of RP");
		result = 6;
		goto finally;
	}
	memcpy(pk->seal_pub, octet_string->buf, octet_string->size);
	pk->seal_pub_len = octet_string->size;

	pk->pid = msg->pid;

finally:
	asn_DEF_PlatformID.free_struct(td, msg, 0);
	return result;
}

/**
** DER-encodes the platform details into a `PlatformID_t` message.
** Returns zero on success, or non-zero otherwise.
**/
static int encode_platform_keying_material(uint8_t *dest,
		size_t capacity, size_t *size, const struct platform_keys *pk)
{
	assert(pk);

	PlatformID_t *msg = calloc(1, sizeof *msg);
	if (!msg) {
		R(RLOG_ERROR, "calloc for PlatformID_t");
		return 11;
	}

	if (OCTET_STRING_fromBuf(&msg->comm_nonce,
			(const char *) pk->comm_nonce, sizeof pk->comm_nonce)) {
		R(RLOG_ERROR, "Error adding communication nonce to PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 12;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - comm_nonce = OK");

	if (OCTET_STRING_fromBuf(&msg->comm_pub,
			(const char *) pk->comm_pub, pk->comm_pub_len)) {
		R(RLOG_ERROR, "Error adding communication public key to PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 13;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - comm_pub   = OK");

	if (OCTET_STRING_fromBuf(&msg->seal_nonce,
			(const char *) pk->seal_nonce, sizeof pk->seal_nonce)) {
		R(RLOG_ERROR, "Error adding sealing nonce to PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 14;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - seal_nonce = OK");

	if (OCTET_STRING_fromBuf(&msg->seal_pub,
			(const char *) pk->seal_pub, pk->seal_pub_len)) {
		R(RLOG_ERROR, "Error adding sealing public key to PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 15;
	}
	R(RLOG_DEBUG | RLOG_LOW, "OCTET_STRING_fromBuf - seal_pub   = OK");

	msg->pid = pk->pid;
	R(RLOG_DEBUG | RLOG_LOW, "                     - pid        = OK");

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_PlatformID, msg, errbuf, &errlen)) {
		R(RLOG_ERROR, "Error validating PlatformID_t: %s", errbuf);
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 17;
	}

	asn_enc_rval_t rval;
	rval = der_encode(&asn_DEF_PlatformID, msg, NULL, NULL);
	if (1 > rval.encoded) {
		R(RLOG_ERROR, "Error finding size of encoded PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 21;
	}
	*size = (size_t) rval.encoded;
	if (!dest) {
		return 0; // leave early, purpose was finding required buffer size
	}
	if (*size > capacity) {
		R(RLOG_WARNING, "Buffer not long enough (got = %zu, need = %zu)",
				capacity, *size);
		return 22;
	}
	rval = der_encode_to_buffer(&asn_DEF_PlatformID, msg, dest, capacity);
	if (-1 == rval.encoded) {
		R(RLOG_ERROR, "Error DER-encoding PlatformID_t");
		asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
		return 23;
	}
	R(RLOG_VERBOSE, "Encoded PlatformID_t has size = %zu", rval.encoded);

	asn_DEF_PlatformID.free_struct(&asn_DEF_PlatformID, msg, 0);
	//asn_DEF_Body.free_struct(&asn_DEF_Body, msg, 0); // implicitly done above

	return 0;
}

static int handle_token_init_ap(struct root *root,
		const uint8_t *data, size_t data_len,
		const uint8_t *ras_sig, size_t ras_sig_len)
{
	assert(root);

	//NOTE:  Implementation sends symmetric keys directly to ST, instead of DH
	if (gen_nonce(root->priv.sk_enc, 16)) {
		return -1;
	}
	if (gen_nonce(root->priv.sk_mac, 32)) {
		return -2;
	}

	int rc = -1;
	int max_resp = 3; // use enum shared with token?
	uint8_t resp_nonce[32];
	if (gen_nonce(resp_nonce, 32)) {
		return -3;
	}

	uint8_t dest_buf[2048] = {0};
	size_t bytes_encoded = 0;
	if (encode_TokenInitAP(dest_buf, sizeof dest_buf, &bytes_encoded,
			data, data_len,
			ras_sig, ras_sig_len,
			root->priv.sk_enc, 16,
			root->priv.sk_mac, 32,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_ERROR, "Error encoding message for the ST");
		return -4;
	}

	R(RLOG_VERBOSE, "Ready to exchange data with the ST");

	if (token_exchange_data(&rc, max_resp,
			dest_buf, bytes_encoded,
			NULL, root->priv.sk_mac,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_WARNING, "Error exchanging cleartext with the ST");
		return -5;
	}

	R(RLOG_VERBOSE, "Exchanged data with the ST");

	//TODO  Check response code, RC.
	//      Right now we want it to be zero (OK), which is same OK code as func.
	return rc;
}

// (1) generates this platform KM, (2) encodes, (3) RAS signs
static int handle_server_init_ap(uint8_t *dest, size_t capacity, size_t *size,
		uint8_t *sig, size_t sig_cap, size_t *sig_len,
		const struct root *root)
{
	assert(root);

	struct platform_keys pk = {0};

	if (generate_platform_keying_material(&pk)) {
		return 1;
	}

	if (encode_platform_keying_material(dest, capacity, size, &pk)) {
		return 2;
	}

	if (ras_sign_data(sig, sig_cap, sig_len, dest, *size)) {
		return 3;
	}

	return 0;
}

/**
** Support: Populates the data structure `root`.
**
** Some fields are populated before beginning the initialization.
** Others only when most work is done (diff func), including network
** exchanges with the Remote Attestation Service and the Security Token.
**
** @return      Returns zero on success, or non-zero otherwise.
**
** @see #populate_system_km()
**/
//TORM deprecated
static int populate_root_init_first(struct root *root)
{
	assert(root);

	root->open.apid = compute_platform_id();
	if (0xFFFFFFFFFFFFFFFF == root->open.apid) {
		R(RLOG_WARNING, "Failure computing platform identifier");
		return 1;
	}
	R(RLOG_INFO | RLOG_LOW, "Platform ID = 0x%016"PRIx64, root->open.apid);

	struct srx_kp *ap_comm_kp = NULL;
	struct srx_kp *ap_seal_kp = NULL;

	// generate communication nonce (IKM) and derive communication KP for AP
	if (gen_nonce(root->priv.ap_comm_nonce, 32)) {
		goto finally;
	}
	if (der_kp(&ap_comm_kp, root->priv.ap_comm_nonce,
			KP_SALT, KP_COMM_INFO, sizeof(KP_COMM_INFO))) {
		goto finally;
	}

	// generate sealing nonce (IKM) and derive sealing key pair for AP
	if (gen_nonce(root->priv.ap_seal_nonce, 32)) {
		goto finally;
	}
	if (der_kp(&ap_seal_kp, root->priv.ap_seal_nonce,
			KP_SALT, KP_SEAL_INFO, sizeof(KP_SEAL_INFO))) {
		goto finally;
	}

	// extract communication and sealing public keys of AP
	uint8_t *ap_comm_pub = NULL;
	uint32_t ap_comm_pub_len = 0;
	if (i2d_pub(ap_comm_kp, &ap_comm_pub, &ap_comm_pub_len)) {
		goto finally;
	}
	memcpy(&root->temp.comm_pub, ap_comm_pub, ap_comm_pub_len);
	root->temp.comm_pub_len = ap_comm_pub_len;
	free(ap_comm_pub);
	//TODO add to `struct cleartext`; unnecessary?
	uint8_t *ap_seal_pub = NULL;
	uint32_t ap_seal_pub_len = 0;
	if (i2d_pub(ap_seal_kp, &ap_seal_pub, &ap_seal_pub_len)) {
		goto finally;
	}
	memcpy(&root->open.ap_seal_pub, ap_seal_pub, ap_seal_pub_len);
	root->open.ap_seal_pub_len = ap_seal_pub_len;
	free(ap_seal_pub);

	free_kp(&ap_comm_kp);
	free_kp(&ap_seal_kp);
	return 0;

finally:
	free_kp(&ap_comm_kp);
	free_kp(&ap_seal_kp);
	return 1;
}

//------------------------------ Core (SRX Impl.) Code -----------------

srx_status ecall_srx_init(const char *save_path)
{
	struct root root = {0};
	struct platform_keys pk = {0};

	if (populate_system_km(&root) || generate_group_km(&root)) {
		return SRX_FAILURE;
	}
	if (generate_platform_keying_material(&pk)) {
		return SRX_FAILURE;
	}
	if (update_rp_details(&root, &pk)) {
		free_kp(&pk.ckp);
		free_kp(&pk.skp);
		return SRX_FAILURE;
	}
	free_kp(&pk.ckp);
	free_kp(&pk.skp);

	uint8_t sig[1024];
	size_t sig_len = 0;
	uint8_t dest[1024];
	size_t size = 0;
	if (handle_server_init_ap(dest, sizeof dest, &size,
			sig, sizeof sig, &sig_len, &root)) {
		return SRX_FAILURE;
	}

	if (handle_token_init_ap(&root, dest, size, sig, sig_len)) {
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Ready to serialize, encrypt, and store internal state");
	if (i2eb(save_path, &root)) {
		R(RLOG_ERROR, "Error serializing/encrypting/saving enclave state");
		return SRX_FAILURE;
	}
	R(RLOG_VERBOSE, "Saved enclave state (path: %s)", save_path);

	return SRX_SUCCESS;
}

srx_status ecall_srx_auth(const char *load_path, const char *str, size_t len)
{
	struct root root = {0};

	if (eb2i(load_path, &root)) {
		R(RLOG_ERROR, "Error loading/decrypting/deserializing enclave state");
		return SRX_FAILURE;
	}

	//TODO attestation

	int rc = -1;
	int max_resp = 3; // use enum shared with token?
	uint8_t resp_nonce[32];
	if (gen_nonce(resp_nonce, 32)) {
		return SRX_FAILURE;
	}
	uint8_t dest_buf[2048] = {0};
	size_t bytes_encoded = 0;
	if (encode_TokenAuth(dest_buf, sizeof dest_buf, &bytes_encoded,
			str, len,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_ERROR, "Error encoding message for the ST");
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Ready to exchange data with the ST");
	if (token_exchange_data(&rc, max_resp,
			dest_buf, bytes_encoded,
			root.priv.sk_enc, root.priv.sk_mac,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_WARNING, "Error exchanging cleartext with the ST");
		return SRX_FAILURE;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST");
	if (rc) {
		switch (rc) {
		case 2:
			return SRX_NO_PERM;
		case 3:
			return SRX_NO_AUTH;
		default:
			return SRX_FAILURE;
		}
	}

	return SRX_SUCCESS;
}

srx_status ecall_srx_get_sk(const char *load_path,
		const uint8_t *salt, size_t n,
		uint8_t *sk, size_t len, int policy)
{
	struct root root = {0};

	if (eb2i(load_path, &root)) {
		R(RLOG_ERROR, "Error loading/decrypting/deserializing enclave state");
		return SRX_FAILURE;
	}

	if (!policy) {
		goto success;
	}

	const char str[] = "Return secret key to the caller";
	int rc = -1;
	int max_resp = 3; // use enum shared with token?
	uint8_t resp_nonce[32];
	if (gen_nonce(resp_nonce, 32)) {
		return SRX_FAILURE;
	}
	uint8_t dest_buf[2048] = {0};
	size_t bytes_encoded = 0;
	if (encode_TokenAuth(dest_buf, sizeof dest_buf, &bytes_encoded,
			str, strlen(str),
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_ERROR, "Error encoding message for the ST");
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Ready to exchange data with the ST");
	if (token_exchange_data(&rc, max_resp,
			dest_buf, bytes_encoded,
			root.priv.sk_enc, root.priv.sk_mac,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_WARNING, "Error exchanging cleartext with the ST");
		return SRX_FAILURE;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST");
	if (rc) {
		switch (rc) {
		case 2:
			return SRX_NO_PERM;
		case 3:
			return SRX_NO_AUTH;
		default:
			return SRX_FAILURE;
		}
	}

success:
	if (kbkdf(sk, len, root.priv.seed, sizeof root.priv.seed,
			salt, n, SK_INFO, sizeof SK_INFO)) {
		return SRX_FAILURE;
	}

	return SRX_SUCCESS;
}

// `dest` contains the platform keying material and RAS signature in ASN.1
// The output format is ready to deliver to `ecall_srx_add_rp()`
srx_status ecall_srx_init_rp(void *dest, size_t capacity, size_t *size)
{
	struct platform_keys pk = {0};

	if (generate_platform_keying_material(&pk)) {
		return SRX_FAILURE;
	}

	uint8_t sbuf[1024] = {0};
	size_t sbuf_size = 0;
	if (encode_platform_keying_material(sbuf, sizeof sbuf, &sbuf_size, &pk)) {
		return SRX_FAILURE;
	}

	// ask the RAS to sign the platform keying material
	uint8_t sig[512] = {0};
	size_t sig_len = 0;
	if (ras_sign_data(sig, sizeof sig, &sig_len, sbuf, sbuf_size)) {
		return SRX_FAILURE;
	}

	// encodes the platform keying material with its signature
	if (encode_SignedPlatformID(dest, capacity, size,
			sbuf, sbuf_size, sig, sig_len)) {
		return SRX_FAILURE;
	}

	return SRX_SUCCESS;
}

// OK when platform added in ST and state re-sealed and stored on disk in client
srx_status ecall_srx_add_rp(const char *path, const void *data, size_t size)
{
	struct root root = {0};

	if (eb2i(path, &root)) {
		R(RLOG_ERROR, "Error loading/decrypting/deserializing enclave state");
		return SRX_FAILURE;
	}

	uint8_t pid[512] = {0};
	size_t pid_size = 0;
	uint8_t sig[512] = {0};
	size_t sig_size = 0;

	if (decode_SignedPlatformID(data, size,
			pid, sizeof pid, &pid_size,
			sig, sizeof sig, &sig_size)) {
		R(RLOG_WARNING, "Error decoding the platform details message");
		return SRX_FAILURE;
	}

	//TODO  Validate signature using the public key of the RAS (get from `root`)

	int rc = -1;
	int max_resp = 3; // use enum shared with token?
	uint8_t resp_nonce[32];
	if (gen_nonce(resp_nonce, 32)) {
		return SRX_FAILURE;
	}

	uint8_t dest_buf[2048] = {0};
	size_t bytes_encoded = 0;
	if (encode_TokenInitRP(dest_buf, sizeof dest_buf, &bytes_encoded,
		pid, pid_size, sig, sig_size,
		resp_nonce, sizeof resp_nonce)) {
		R(RLOG_ERROR, "Error encoding message for the ST");
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Ready to exchange data with the ST");
	if (token_exchange_data(&rc, max_resp,
			dest_buf, bytes_encoded,
			root.priv.sk_enc, root.priv.sk_mac,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_WARNING, "Error exchanging ciphertext with the ST");
		return SRX_FAILURE;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST");
	if (rc) {
		switch (rc) {
		case 2:
			return SRX_NO_PERM;
		case 3:
			return SRX_NO_AUTH;
		default:
			return SRX_FAILURE;
		}
	}

	struct platform_keys pk = {0};
	if (decode_platform_keying_material(&pk, pid, pid_size)) {
		return SRX_FAILURE;
	}

	if (update_rp_details(&root, &pk)) {
		return SRX_FAILURE;
	}

	if (i2eb(path, &root)) {
		R(RLOG_ERROR, "Error serializing/encrypting/saving enclave state");
		return SRX_FAILURE;
	}

	return SRX_SUCCESS;
}

srx_status ecall_srx_remove_rp(const char *path, uint64_t rpid)
{
	uint64_t pid = compute_platform_id();
	if (pid == rpid) {
		R(RLOG_ERROR | RLOG_LOW, "Cannot remove itself");
		return SRX_NO_SELF;
	}
	//NOTE: implicitly prevents removing all platforms from the group

	R(RLOG_VERBOSE, "Preparing to remove the RP with ID 0x%016"PRIx64, rpid);

	struct root root = {0};

	if (eb2i(path, &root)) {
		R(RLOG_ERROR, "Error loading/decrypting/deserializing enclave state");
		return SRX_FAILURE;
	}

	int rc = -1;
	int max_resp = 3; // use enum shared with token?
	uint8_t resp_nonce[32];
	if (gen_nonce(resp_nonce, 32)) {
		return SRX_FAILURE;
	}
	uint8_t dest_buf[2048] = {0};
	size_t bytes_encoded = 0;
	if (encode_TokenRemoveRP(dest_buf, sizeof dest_buf, &bytes_encoded,
			rpid, resp_nonce, sizeof resp_nonce)) {
		R(RLOG_ERROR, "Error encoding message for the ST");
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Ready to exchange data with the ST");
	if (token_exchange_data(&rc, max_resp,
			dest_buf, bytes_encoded,
			root.priv.sk_enc, root.priv.sk_mac,
			resp_nonce, sizeof resp_nonce)) {
		R(RLOG_WARNING, "Error exchanging ciphertext with the ST");
		return SRX_FAILURE;
	}
	R(RLOG_VERBOSE, "Exchanged data with the ST (%d)", rc);
	if (rc) {
		switch (rc) {
		case 2:
			return SRX_NO_PERM;
		case 3:
			return SRX_NO_AUTH;
		default:
			return SRX_FAILURE;
		}
	}

	int r1 = remove_rp_details(&root, rpid);
	if (r1) {
		if (r1 == SRX_E_NOT_FOUND) {
			R(RLOG_ERROR, "RP (0x%016"PRIx64") not found", rpid);
			return SRX_NO_ENT;
		}
		return SRX_FAILURE;
	}

	if (i2eb(path, &root)) {
		R(RLOG_ERROR, "Error serializing/encrypting/saving enclave state");
		return SRX_FAILURE;
	}

	R(RLOG_VERBOSE, "Removed the RP with ID 0x%016"PRIx64, rpid);

	return SRX_SUCCESS;
}

srx_status ecall_srx_list(uint64_t *pids, size_t capacity, size_t *count,
		const char *path)
{
	struct root root = {0};

	if (eb2i(path, &root)) {
		R(RLOG_ERROR, "Error loading/decrypting/deserializing enclave state");
		return SRX_FAILURE;
	}

	uint32_t n = root.open.platforms_count; // number of RPs in DB

	if (capacity < (size_t) n) {
		R(RLOG_ERROR, "Too small (got=%zu, want=%zu)", capacity, (size_t) n);
		return SRX_NO_MEM;
	}

	memset(pids, 0, sizeof(uint64_t) * capacity);

	for (uint32_t i = 0; i < n; i++) {
		*(pids + i) = root.open.platforms[i].pid;
	}

	*count = n;

	return SRX_SUCCESS;
}

int ecall_srx_dump(char *s, size_t capacity, const char *path)
{
#ifdef DEBUG
	char *p = s;
	size_t n = capacity;

	struct root root = {0};

	if (eb2i(path, &root)) {
		snprintf(s, capacity, "ERROR\n");
		return 1;
	}

	uint64_t platform_id = compute_platform_id();
	snprintf(p, n,
			"-------------------------------\n"
			"Platform ID: 0x%016"PRIx64"\n"
			"-------------------------------\n", platform_id);
	p += 32 + 13 + 2 + 16 + 1 + 32;
	n -= 32 + 13 + 2 + 16 + 1 + 32;

	dump_ds(p, n, &root);

	return 0;
#else
	snprintf(s, capacity, "ecall_srx_dump() is available only in DEBUG mode\n");
	return 0;
#endif
}
