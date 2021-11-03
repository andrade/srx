#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include <usgx/t/util.h>

#include "bincat.h"
#include "crypto.h"
#include "rlog.h"
#include "tconst.h"

#include "storage.h"

/** Recomputes the CSK for the AP. Returns zero on success. */
//TORM @deprecated
int recompute_csk_ap(struct root *root)
{
	assert(root);

	// derive base key, CSK, and IV
	if (get_key_128bit(root->open.base_nonce,
			USGX_KEY_POLICY_SIG, root->temp.base_key)) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving base key");
		return 1;
	}
	if (kbkdf(root->temp.csk, 16, root->temp.base_key, 16,
			root->open.seal_nonce, 32, CSK_INFO, sizeof(CSK_INFO))) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving CSK");
		return 2;
	}
	if (kbkdf(root->temp.iv, 12, root->temp.base_key, 16,
			root->open.seal_nonce, 32, CSK_IV_INFO, sizeof(CSK_IV_INFO))) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving common sealing IV");
		return 3;
	}

	return 0;
}

/** Recomputes the CSK for the platform at `index`. Returns zero on success. */
static int recompute_csk_rp(struct root *root, size_t index)
{
	assert(root);

	// derive sealing key pair from sealing nonce
	struct srx_kp *pskp = NULL;
	if (der_kp(&pskp, root->open.platforms[index].seal_nonce,
			KP_SALT, KP_SEAL_INFO, sizeof(KP_SEAL_INFO))) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving Platform Sealing KP");
		return 1;
	}

	uint8_t *ebk = root->open.platforms[index].encrypted_base_key;
	size_t ebk_size = root->open.platforms[index].encrypted_base_key_len;
	uint8_t *tag128 = root->open.platforms[index].ebk_tag;
	int r = decrypt_base_key(root->temp.base_key,
			pskp,
			root->open.gspk, root->open.gspk_len,
			root->open.encryption_nonce,
			ebk, ebk_size, tag128);
	free_kp(&pskp);
	if (r) {
		if (r == SRX_E_BAD_MAC) {
			R(RLOG_ERROR, "Error decrypting base key, tag mismatch");
		} else {
			R(RLOG_ERROR, "Error decrypting base key");
		}
		return 1;
	}

	// use base key and common sealing nonce to derive the CSK and the CIV
	if (kbkdf(root->temp.csk, 16,
			root->temp.base_key, 16,
			root->open.seal_nonce, 32,
			CSK_INFO, sizeof(CSK_INFO))) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving CSK");
		return 8;
	}
	if (kbkdf(root->temp.iv, 12,
			root->temp.base_key, 16,
			root->open.seal_nonce, 32,
			CSK_IV_INFO, sizeof(CSK_IV_INFO))) {
		R(RLOG_DEBUG | RLOG_HIGH, "Error deriving CIV");
		return 9;
	}

	return 0;
}

/**
** Recomputes the CSK and the CIV for AEAD.
**
** The Common Sealing Key and Common IV for encryption, and the Base Key,
** are placed in `root`.
**
** @param[io]   root            the main structure to pass data around
**
** @return      Returns zero on success, or non-zero otherwise.
**/
static int recompute_csk(struct root *root)
{
	uint64_t pid = compute_platform_id();
	if (0xFFFFFFFFFFFFFFFF == pid) {
		return 91;
	}
	R(RLOG_INFO | RLOG_LOW, "Platform ID = 0x%016"PRIx64, pid);

	for (size_t i = 0; i < root->open.platforms_count; i++) {
		if (root->open.platforms[i].pid == pid) {
			R(RLOG_DEBUG, "Platform %zu detected, ready to compute CSK", i);
			return recompute_csk_rp(root, i);
		}
	}
	R(RLOG_DEBUG, "Unknown Platform, unable to compute CSK");

	return 92;
}

/**
** Deserializes the data buffer into a `struct plaintext`.
**
** The caller allocates the structure.
**
** @return      Returns zero on success.
**/
static int deserialize_pt(struct plaintext *pt,
		const uint8_t *data, uint32_t size)
{
	const uint8_t *bc = data;
	assert(bc_fullsize(bc) == size);
	//TODO validate format, fail if invalid

	if (bc_get(pt->seed, bc, 1)) {
		return 1;
	}
	if (bc_get(pt->ap_seal_nonce, bc, 2)) {
		return 2;
	}
	if (bc_get(pt->ap_comm_nonce, bc, 3)) {
		return 3;
	}
	if (bc_get(pt->st_comm_pub, bc, 4)) {
		return 4;
	}
	if (bc_get(&pt->st_comm_pub_len, bc, 5)) {
		return 5;
	}
	if (bc_get(pt->rp_comm_nonce, bc, 6)) {
		return 6;
	}
	if (bc_get(pt->sk_enc, bc, 7)) {
		return 7;
	}
	if (bc_get(pt->sk_mac, bc, 8)) {
		return 8;
	}
	if (bc_get(pt->gsn, bc, 9)) {
		return 9;
	}

	return 0;
}

/**
** Deserializes the data buffer into a `struct cleartext`.
**
** The caller allocates the structure.
**
** @return      Returns zero on success.
**/
static int deserialize_ct(struct cleartext *ct,
		const uint8_t *data, uint32_t size)
{
	const uint8_t *bc = data;
	assert(bc_fullsize(bc) == size);
	//TODO validate format, fail if invalid

	//TODO have pos var that increments on fetch but not on return (nor loop is set)
	if (bc_get(ct->base_nonce, bc, 1)) {
		return 1;
	}
	if (bc_get(ct->seal_nonce, bc, 2)) {
		return 2;
	}
	if (bc_get(&ct->apid, bc, 3)) {
		return 3;
	}
	if (bc_get(ct->encryption_nonce, bc, 4)) {
		return 4;
	}
	if (bc_get(ct->gspk, bc, 5)) {
		return 5;
	}
	if (bc_get(&ct->gspk_len, bc, 6)) {
		return 6;
	}
	//NOTE  Could add node count first, then cat only `count` positions in loop
	for (uint32_t index = 0, pos = 7; index < SRX_MAX_NODES; index++) {
		if (bc_get(&ct->platforms[index].pid, bc, pos++)) {
			return pos;
		}
		if (bc_get(ct->platforms[index].seal_nonce, bc, pos++)) {
			return pos;
		}
		if (bc_get(ct->platforms[index].seal_pub, bc, pos++)) {
			return pos;
		}
		if (bc_get(&ct->platforms[index].seal_pub_len, bc, pos++)) {
			return pos;
		}
		if (bc_get(ct->platforms[index].encrypted_base_key, bc, pos++)) {
			return pos;
		}
		if (bc_get(&ct->platforms[index].encrypted_base_key_len, bc, pos++)) {
			return pos;
		}
		if (bc_get(ct->platforms[index].ebk_tag, bc, pos++)) {
			return pos;
		}
		// `pos` increment done in body
	}
	if (bc_get(&ct->platforms_count, bc, 7 + SRX_MAX_NODES * 7)) {
		return 7 + SRX_MAX_NODES * 7;
	}

	return 0;
}

int eb2i(const char *path, struct root *root)
{
	uint8_t status;

	// 1. Read data from path
	uint8_t retval = 0xEE;
	uint8_t data[16 * 1024] = {0}; // just assume won't be larger
	ocall_srx_read(&retval, path, data, sizeof data);
	if (retval) {
		R(RLOG_DEBUG, "Error reading from path (%s)", path);
		return 1;
	}
	R(RLOG_DEBUG, "Read serialized and encrypted internal state from %s", path);

	// 2. Process data after reading
	uint8_t *input = data;
	uint8_t ed[bc_count(input, 1)];
	uint8_t ad[bc_count(input, 2)];
	uint8_t tag[bc_count(input, 3)];
	if (bc_get(ed, input, 1)) {
		return 21;
	}
	if (bc_get(ad, input, 2)) {
		return 22;
	}
	if (bc_get(tag, input, 3)) {
		return 23;
	}
	// no free due to `data` allocation

	// 3. Deserialize cleartext
	if (deserialize_ct(&root->open, ad, sizeof ad)) {
		R(RLOG_DEBUG, "Error deserializing cleartext");
		return 3;
	}

	// 4. Rebuild CSK
	if (recompute_csk(root)) {
		R(RLOG_DEBUG, "Error recomputing CSK and IV");
		return 4;
	}
	R(RLOG_DEBUG, "Reconstructed the Common Sealing Key, CSK");
	//TODO  Reliably detect if debug or production, to print CSK

	// 5. AEAD
	uint8_t *pt = NULL;
	uint32_t pt_len = 0;
	status = aead_dec(root->temp.csk, root->temp.iv,
			ed, sizeof ed, ad, sizeof ad,
			&pt, &pt_len,
			tag);
	if (status) {
		if (SRX_E_BAD_MAC == status) {
			R(RLOG_DEBUG, "Error decrypting internal data, tag mismatch");
			return SRX_E_BAD_MAC;
			// bad CSK and/or IV?
		}
		R(RLOG_DEBUG, "Error decrypting internal data");
		return 5;
	}
	R(RLOG_DEBUG, "Decrypted internal data");

	// 6. Deserialize plaintext
	if (deserialize_pt(&root->priv, pt, pt_len)) {
		free(pt);
		R(RLOG_DEBUG, "Error deserializing plaintext");
		return 6;
	}

	// 7. Release resources
	free(pt);

	return 0;
}

/**
** Serializes a `struct plaintext`.
**
** The memory for the destination buffer is allocated inside.
** The caller releases the buffer with `bc_free`.
**
** @param[out]  data    the destination buffer
** @param[out]  size    the size, in bytes, of the destination buffer
** @param[in]   pt      the data structure to serialize
**
** @return      Returns zero on success, or non-zero otherwise.
**/
static int serialize_pt(uint8_t **data, uint32_t *size,
		const struct plaintext *pt)
{
	uint8_t *bc = bc_init();
	if (!bc) {
		return 1;
	}

	bc_cat(&bc, pt->seed, 1, sizeof pt->seed);
	bc_cat(&bc, pt->ap_seal_nonce, 1, sizeof pt->ap_seal_nonce);
	bc_cat(&bc, pt->ap_comm_nonce, 1, sizeof pt->ap_comm_nonce);
	bc_cat(&bc, pt->st_comm_pub, 1, sizeof pt->st_comm_pub);
	bc_cat(&bc, &pt->st_comm_pub_len, 4, 1);
	bc_cat(&bc, pt->rp_comm_nonce, 1, SRX_MAX_NODES * 32);
	bc_cat(&bc, pt->sk_enc, 1, sizeof pt->sk_enc);
	bc_cat(&bc, pt->sk_mac, 1, sizeof pt->sk_mac);
	bc_cat(&bc, pt->gsn, 1, sizeof pt->gsn);

	*data = bc;
	*size = bc_fullsize(bc);

	return 0;
}

/**
** Serializes a `struct cleartext`.
**
** The memory for the destination buffer is allocated inside.
** The caller releases the buffer with `bc_free`.
**
** @param[out]  data    the destination buffer
** @param[out]  size    the size, in bytes, of the destination buffer
** @param[in]   ct      the data structure to serialize
**
** @return      Returns zero on success, or non-zero otherwise.
**/
static int serialize_ct(uint8_t **data, uint32_t *size,
		const struct cleartext *ct)
{
	uint8_t *bc = bc_init();
	if (!bc) {
		return 1;
	}

	bc_cat(&bc, ct->base_nonce, 1, sizeof ct->base_nonce);
	bc_cat(&bc, ct->seal_nonce, 1, sizeof ct->seal_nonce);
	bc_cat(&bc, &ct->apid, 8, 1);
	bc_cat(&bc, ct->encryption_nonce, 1, sizeof ct->encryption_nonce);
	bc_cat(&bc, ct->gspk, 1, sizeof ct->ap_seal_pub);
	bc_cat(&bc, &ct->gspk_len, 4, 1);
	//NOTE  Could add node count first, then cat only `count` positions in loop
	for (size_t i = 0; i < SRX_MAX_NODES; i++) {
		bc_cat(&bc, &ct->platforms[i].pid, 8, 1);
		bc_cat(&bc, ct->platforms[i].seal_nonce,
				1, sizeof ct->platforms[i].seal_nonce);
		bc_cat(&bc, ct->platforms[i].seal_pub,
				1, sizeof ct->platforms[i].seal_pub);
		bc_cat(&bc, &ct->platforms[i].seal_pub_len, 4, 1);
		bc_cat(&bc, ct->platforms[i].encrypted_base_key,
				1, sizeof ct->platforms[i].encrypted_base_key);
		bc_cat(&bc, &ct->platforms[i].encrypted_base_key_len, 4, 1);
		bc_cat(&bc, ct->platforms[i].ebk_tag,
				1, sizeof ct->platforms[i].ebk_tag);
	}
	bc_cat(&bc, &ct->platforms_count, 4, 1);

	*data = bc;
	*size = bc_fullsize(bc);

	return 0;
}

int i2eb(const char *path, struct root *root)
{
	// 1a. Serialize plaintext
	uint8_t *ptbin = NULL;
	uint32_t ptbin_size = 0;
	if (serialize_pt(&ptbin, &ptbin_size, &root->priv)) {
		R(RLOG_DEBUG, "Error serializing plaintext");
		return 11;
	}

	// 1b. Serialize cleartext
	uint8_t *ctbin = NULL;
	uint32_t ctbin_size = 0;
	if (serialize_ct(&ctbin, &ctbin_size, &root->open)) {
		R(RLOG_DEBUG, "Error serializing cleartext");
		return 12;
	}

	// 2. Derive CSK and CIV
	if (recompute_csk(root)) {
		R(RLOG_DEBUG, "Error recomputing CSK and CIV");
		return 2;
	}

	// 3. AEAD
	uint8_t *ciphertext = NULL;
	uint32_t ciphertext_len = 0;
	uint8_t *tag = NULL;
	if (aead_enc(root->temp.csk, root->temp.iv,
			ptbin, ptbin_size, ctbin, ctbin_size,
			&ciphertext, &ciphertext_len, &tag)) {
		R(RLOG_DEBUG, "Error encrypting internal data");
		return 3;
	}
	R(RLOG_DEBUG, "Encrypted internal data");

	// 4. Prepare data for writing: `ciphertext || ctbin || tag`
	uint8_t *output = bc_init();
	if (!output) {
		return 4;
	}
	bc_cat(&output, ciphertext, 1, ciphertext_len);
	bc_cat(&output, ctbin, 1, ctbin_size);
	bc_cat(&output, tag, 1, 16);

	// 5. Write data to persistent memory
	uint8_t retval = 0xEE;
	ocall_srx_write(&retval, path, output, bc_fullsize(output));
	if (retval) {
		R(RLOG_DEBUG, "Error writing to path (%s)", path);
		return 5;
	}
	R(RLOG_DEBUG, "Wrote serialized and encrypted internal state to %s", path);

	// 6. Release resources
	bc_free(ptbin);
	bc_free(ctbin);
	free(ciphertext);
	free(tag);
	bc_free(output);
	//TODO declare 4 pointers on top, then send here on if failures...

	return 0;
}
