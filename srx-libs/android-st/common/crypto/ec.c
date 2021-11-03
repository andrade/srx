#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "srx/crypto/ec.h"

static const int CURVE = NID_X9_62_prime256v1;

struct srx_kp {
	EVP_PKEY *pkey;
};

/**
** Performs sanity checks on the given key of EC type.
**
** Returns 1, 2, or 3 when valid:
**   - Returns 1 if only public key is present.
**   - Returns 2 if only private key is present.
**   - Returns 3 if both public and private keys are present.
**/
static int validate_pkey_ec(EVP_PKEY *pkey)
{
	int result = 0;

	EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
	if (!ec_key)
		return -1;

	if (1 != EC_KEY_check_key(ec_key)) {
		EC_KEY_free(ec_key);
		return -1;
	}

	if (EC_KEY_get0_private_key(ec_key))
		result = 2;

	if (EC_KEY_get0_public_key(ec_key))
		result++;

	EC_KEY_free(ec_key);

	return result;
}

/**
** Performs sanity checks on the given EVP_PKEY.
**
** Returns 1, 2, or 3 when valid:
**   - Returns 1 if only public key is present.
**   - Returns 2 if only private key is present.
**   - Returns 3 if both public and private keys are present.
**/
static int validate_pkey(EVP_PKEY *pkey)
{
	int key_type = EVP_PKEY_base_id(pkey);

	switch (key_type) {
	case EVP_PKEY_RSA:
	case EVP_PKEY_DSA:
	case EVP_PKEY_DH:
		// not implemented
		return -1;
	case EVP_PKEY_EC:
		return validate_pkey_ec(pkey);
	default:
		// unknown type, NID_undef?
		return -2;
	}
}

int srx_init_kp(struct srx_kp **kp, const uint8_t *priv)
{
	BIGNUM *bignum = NULL;
	EC_KEY *key = NULL;
	EC_POINT *point = NULL;
	EVP_PKEY *pkey = NULL;

	const unsigned char *spriv = priv;
	if (!spriv) {
		unsigned char temp[32] = {0};
		if (1 != RAND_bytes(temp, sizeof temp)) {
			goto fail;
		}
		spriv = temp;
		//TODO guard + SGX rand
	}
	bignum = BN_bin2bn(spriv, 32, NULL);
	if (!bignum) {
		goto fail;
	}

	key = EC_KEY_new_by_curve_name(CURVE);
	if (!key) {
		goto fail;
	}
	if (1 != EC_KEY_set_private_key(key, bignum)) {
		goto fail;
	}

	const EC_GROUP *group = EC_KEY_get0_group(key);
	point = EC_POINT_new(group);
	if (!point) {
		goto fail;
	}
	if (1 != EC_POINT_mul(group, point, bignum, NULL, NULL, NULL)) {
		goto fail;
	}
	if (1 != EC_KEY_set_public_key(key, point)) {
		goto fail;
	}

	pkey = EVP_PKEY_new();
	if (!pkey) {
		goto fail;
	}
	if (1 != EVP_PKEY_set1_EC_KEY(pkey, key)) {
		goto fail;
	}

	struct srx_kp *temp_kp = malloc(sizeof *temp_kp);
	if (!temp_kp) {
		goto fail;
	}
	temp_kp->pkey = pkey;

	*kp = temp_kp;

	BN_free(bignum);
	EC_KEY_free(key);
	EC_POINT_free(point);

	return 0;

fail:
	BN_free(bignum);
	EC_KEY_free(key);
	EC_POINT_free(point);
	EVP_PKEY_free(pkey);
	return 1;
}

void srx_free_kp(struct srx_kp **kp)
{
	if (!kp || !*kp)
		return;
	EVP_PKEY_free((*kp)->pkey);
	*kp = NULL;
}

int srx_load_kp(struct srx_kp **kp, const char *path)
{
	EVP_PKEY *pkey = NULL;
	FILE *fp = fopen(path, "r");

	if (!fp)
		return 1;

	pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);

	fclose(fp);

	if (!pkey)
		return 2;

	// validate and make sure it has both public and private keys
	if (3 != validate_pkey(pkey)) {
		EVP_PKEY_free(pkey);
		return 3;
	}

	struct srx_kp *temp_kp = malloc(sizeof *temp_kp);
	if (!temp_kp) {
		EVP_PKEY_free(pkey);
		return 4;
	}
	temp_kp->pkey = pkey;

	*kp = temp_kp;

	return 0;
}

size_t srx_i2d_priv(uint8_t *dest, size_t len, const struct srx_kp *kp)
{
	EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp->pkey);
	int encoded_bytes;

	encoded_bytes = i2d_ECPrivateKey(key, NULL);
	if (0 >= encoded_bytes) {
		return 0;
	}
	// safe cast, checked for negative above
	if (!dest || (size_t) encoded_bytes > len) {
		return encoded_bytes;
	}

	return i2d_ECPrivateKey(key, (unsigned char **) &dest);
}

int srx_d2i_priv(struct srx_kp **kp, const uint8_t *src, size_t len)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *key = NULL;

	if (!d2i_ECPrivateKey(&key, (const unsigned char **) &src, len)) {
		return 11;
	}

	pkey = EVP_PKEY_new();
	if (!pkey) {
		EC_KEY_free(key);
		return 21;
	}
	if (1 != EVP_PKEY_assign_EC_KEY(pkey, key)) {
		EC_KEY_free(key);
		return 22;
	}

	struct srx_kp *temp_kp = malloc(sizeof *temp_kp);
	if (!temp_kp) {
		EC_KEY_free(key);
		return 31;
	}
	temp_kp->pkey = pkey;
	*kp = temp_kp;

	//EC_KEY_free(key); // no need, not using set1 (will be freed with pkey)

	return 0;
}

size_t srx_i2o_priv(uint8_t *dest, size_t len, const struct srx_kp *kp)
{
	EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp->pkey);
	size_t encoded_bytes;

	encoded_bytes = EC_KEY_priv2oct(key, NULL, 0);
	if (0 >= encoded_bytes) {
		return 0;
	}
	if (!dest || encoded_bytes > len) {
		return encoded_bytes;
	}

	return EC_KEY_priv2oct(key, (unsigned char *) dest, len);
}

size_t srx_i2d_pub(uint8_t *dest, size_t len, const struct srx_kp *kp)
{
	EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp->pkey);
	int encoded_bytes;

	//encoded_bytes = i2d_PUBKEY(kp->pkey, NULL);
	encoded_bytes = i2d_EC_PUBKEY(key, NULL);
	if (0 >= encoded_bytes) {
		return 0;
	}
	// safe cast, checked for negative above
	if (!dest || (size_t) encoded_bytes > len) {
		return encoded_bytes;
	}

	//return i2d_PUBKEY(kp->pkey, (unsigned char **) &dest);
	return i2d_EC_PUBKEY(key, (unsigned char **) &dest);
}

int srx_d2i_pub(struct srx_kp **kp, const uint8_t *src, size_t len)
{
	EVP_PKEY *pkey = NULL;
	EC_KEY *key = NULL;

	if (!d2i_EC_PUBKEY(&key, (const unsigned char **) &src, len)) {
		return 11;
	}

	pkey = EVP_PKEY_new();
	if (!pkey) {
		EC_KEY_free(key);
		return 21;
	}
	if (1 != EVP_PKEY_assign_EC_KEY(pkey, key)) {
		EC_KEY_free(key);
		return 22;
	}

	struct srx_kp *temp_kp = malloc(sizeof *temp_kp);
	if (!temp_kp) {
		EC_KEY_free(key);
		return 31;
	}
	temp_kp->pkey = pkey;
	*kp = temp_kp;

	//EC_KEY_free(key); // no need, not using set1 (will be freed with pkey)

	return 0;
}

size_t srx_i2o_pub(uint8_t *dest, size_t len, const struct srx_kp *kp)
{
	EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp->pkey);
	int encoded_bytes;

	encoded_bytes = i2o_ECPublicKey(key, NULL);
	if (0 >= encoded_bytes) {
		return 0;
	}
	// safe cast, checked for negative above
	if (!dest || (size_t) encoded_bytes > len) {
		return encoded_bytes;
	}

	return i2o_ECPublicKey(key, (unsigned char **) &dest);
}
// return 0 >= encoded_bytes ? 0 : encoded_bytes;

size_t srx_sign(uint8_t *dest, size_t dest_len,
		const void *data, size_t data_len, const struct srx_kp *kp)
{
	assert(data);
	assert(kp);

	EVP_MD_CTX *mdctx = NULL;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		return 1;
	}

	unsigned char *sig = dest;
	size_t sig_len = 0;

	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, kp->pkey)) {
		goto fail;
	}

	if (1 != EVP_DigestSign(mdctx, NULL, &sig_len, data, data_len)) {
		goto fail;
	}
	if (!dest || sig_len > dest_len) {
		return sig_len;
	}
	if (1 != EVP_DigestSign(mdctx, sig, &sig_len, data, data_len)) {
		goto fail;
	}

	EVP_MD_CTX_destroy(mdctx);

	return sig_len;
fail:
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	return 0;
}

srx_status srx_verify(const uint8_t *sig, size_t sig_len,
		const void *data, size_t data_len, const struct srx_kp *kp)
{
	assert(sig);
	assert(data);
	assert(kp);

	srx_status xs;
	EVP_MD_CTX *mdctx = NULL;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		xs = SRX_FAILURE;
		goto finally;
	}

	if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, kp->pkey)) {
		xs = SRX_FAILURE;
		goto finally;
	}

	int ret = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
	if (0 == ret) {
		xs = SRX_BAD_TAG;
		goto finally;
	}
	if (1 != ret) {
		xs = SRX_FAILURE;
		goto finally;
	}
	xs = SRX_SUCCESS;

finally:
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	return xs;
}
