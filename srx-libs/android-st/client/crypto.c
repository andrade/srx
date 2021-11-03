#include <assert.h>
#include <string.h>

#include <sgx_key.h>
#include <sgx_tcrypto.h>
#include <sgx_tprotected_fs.h>
#include <sgx_trts.h>
#include <sgx_utils.h>
#include "tseal_migration_attr.h" // internal to SGX SDK, copied file over here

#include "tSgxSSL_api.h"
#include "tsgxsslio.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/kdf.h"

#include <usgx/t/util.h>

#include "interr.h"
#include "rlog.h"

#include "crypto.h"

/**
** Length of each parameter, such as secret key,
** each X Y of public key, private key, and
** each r s of signature.
**/
#define P256_LENGTH 32

static const int CURVE = NID_X9_62_prime256v1;

struct srx_kp {
	EC_KEY *key;
};
// struct srx_sk {
// };

// print uint8_t buffer to stdout in hex
void print_uint8_buf_hex(uint8_t *buf, size_t size)
{
	for (size_t i = 0; i < size - 1; i++)
		printf("%02"PRIx8":", buf[i]);
	printf("%02"PRIx8"\n", buf[size - 1]);
}

/**
** Wrapper around `sgx_get_key` which is in turn a wrapper around `EGETKEY`.
**
** The nonce is 256 bits and the output key is 128 bits.
** The policy is 0x0001 or 0x0002 for ENCLAVE or SIGNER respectively.
**
** Returns zero on success, or non-zero otherwise.
**/
static uint8_t egetkey_wrapper_2(
	const uint8_t *nonce256,
	const uint16_t policy,
	uint8_t *key128)
{
	// internal length of sgx_key_id_t's key is same as that of nonce256
	assert(SGX_KEYID_SIZE == 32);

	if (policy != 0x0001 && policy != 0x0002) {
		// only these two policies are accepted; replace by enum or def?
		return 1;
	}

	sgx_status_t ss = SGX_ERROR_UNEXPECTED;
	sgx_key_request_t key_request;
	sgx_key_128bit_t secret;

	memset(&key_request, 0, sizeof(sgx_key_request_t));

	// create a report to get ISV security version and CPU security version
	sgx_report_t report;
	ss = sgx_create_report(NULL, NULL, &report);
	if (SGX_SUCCESS != ss) {
		return 2;
	}

	key_request.key_name = SGX_KEYSELECT_SEAL;
	key_request.key_policy = policy;
	memcpy(&key_request.isv_svn, &report.body.isv_svn, sizeof(sgx_isv_svn_t));
	memcpy(&key_request.cpu_svn, &report.body.cpu_svn, sizeof(sgx_cpu_svn_t));
	key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
	key_request.attribute_mask.xfrm = 0x0;
	memcpy(&key_request.key_id.id, nonce256, 32); // key wear out uses nonce
	key_request.misc_mask = TSEAL_DEFAULT_MISCMASK;

	ss = sgx_get_key(&key_request, &secret);
	if (SGX_SUCCESS != ss) {
		return 3;
	}

	// sgx_key_128bit_t is a typedef to uint8_t 16-byte array (see `sgx_key.h`)
	memcpy(key128, &secret, 16);

	return 0;
}

/**
** Serializes an EC key pair to DER.
**
** Returns zero on success in which case `kp_out` is set, or non-zero otherwise.
**/
// OpenSSL 1.1.0+ uses "named form" instead of "explicit form" by default,
// which means we do not have to call EC_GROUP_set_asn1_flag (before call).
static int i2d_kp(const EC_KEY *ec_key, uint8_t **kp_out, uint32_t *kp_len)
{
	assert(ec_key);

	unsigned char *ppout = NULL;
	int byte_count = i2d_ECPrivateKey((EC_KEY *) ec_key, &ppout);
	if (0 > byte_count) {
		return 1;
	}

	*kp_out = (uint8_t *) ppout;
	*kp_len = byte_count;

	return 0;
}

/**
** Deserializes a key pair (DER to internal).
**
** Returns zero on success in which case `ec_key` is set, or non-zero otherwise.
**/
// OpenSSL 1.1.0 or later uses "named form" by default.
static int d2i_kp(const uint8_t *kp_in, uint32_t kp_len, EC_KEY **ec_key)
{
	assert(kp_in);

	const unsigned char *p = kp_in;

	EC_KEY *a = NULL;
	if (!d2i_ECPrivateKey(&a, &p, (long) kp_len)) {
		return 1;
	}

	*ec_key = a;

	return 0;
}

/**
** Transforms an EC_KEY (private) into an hex string suitable for printing.
** (Useful for debugging or providing feedback to caller.)
** Returns zero on success, or non-zero otherwise.
**/
static int i2hs_kp(const EC_KEY *ec_key, char **hex_str)
{
	int required_len = EC_KEY_priv2oct(ec_key, NULL, 0);
	unsigned char buf[required_len];
	size_t buf_len = required_len;
	int actual_len = EC_KEY_priv2oct(ec_key, buf, buf_len);
	if (0 >= actual_len) {
		return 1;
	}

	char *hs = NULL;
	if (usgx_hex_uint8_to_str(buf, buf_len, ":", &hs)) {
		return 2;
	}

	*hex_str = hs;

	return 0;
}

/**
** Serializes an EC key pair to DER (only the public part).
**
** Returns zero on success in which case `pub` is set, or non-zero otherwise.
**/
static int i2d_kp_public(const EC_KEY *ec_key, uint8_t **pub, uint32_t *pub_len)
{
	assert(ec_key);

	unsigned char *ppout = NULL;
	int byte_count = i2d_EC_PUBKEY(ec_key, &ppout);
	if (0 > byte_count) {
		return 1;
	}

	*pub = (uint8_t *) ppout;
	*pub_len = byte_count;

	return 0;
}

/**
** Deserializes a public key (DER to internal).
**
** Returns zero on success in which case `ec_key` is set, or non-zero otherwise.
**/
static int d2i_kp_public(const uint8_t *pub, uint32_t pub_len, EC_KEY **ec_key)
{
	assert(pub);

	// d2i_ECPublicKey
	EC_KEY *a = NULL;
	if (!d2i_EC_PUBKEY(&a, (unsigned char **) &pub, (long) pub_len)) {
		return 1;
	}

	*ec_key = a;

	return 0;
}

/**
** Transforms an EC_KEY (public) into an hex string suitable for printing.
** (Useful for debugging or providing feedback to caller.)
** Returns zero on success, or non-zero otherwise. FIXME docs and body
**/
static int i2hs_public(const EC_KEY *ec_key, char **hex_str)
{
	size_t size = 0;
	unsigned char *buf = NULL;
	BN_CTX *bn_ctx = BN_CTX_new();
	if (!bn_ctx) {
		return 2;
	}
	size = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &buf, bn_ctx);
	if (!size) {
		BN_CTX_free(bn_ctx);
		return 3;
	}
	// printf("size is %zu\n", size);//TORM

	char *hs = NULL;
	if (usgx_hex_uint8_to_str(buf, size, ":", &hs)) {
		BN_CTX_free(bn_ctx);
		OPENSSL_free(buf);
		return 3;
	}
	*hex_str = hs;

	BN_CTX_free(bn_ctx);
	OPENSSL_free(buf);
	return 0;
}

/**
** Computes a unique identifier for the platform.
**
** @param[in]   n256            input for EGETKEY, may be null
** @param[in]   a               input for CMAC, may be null
** @param[in]   alen            length of input for CMAC, may be 0
** @param[in]   policy          policy for EGETKEY, default is MRSIGNER
** @param[out]  output          result of CMAC, used as identifier
**
** @return      Returns zero on success, or non-zero on error.
**/
static uint8_t _compute_platform_id(uint8_t *n256, uint8_t *a, uint32_t alen, const uint16_t policy, uint8_t *output)
{
	// `CMAC(a, EGETKEY(n256 + policy)) : output`

	if (!n256)
		n256 = (uint8_t[32]) {0};

	if (!a)
		a = (uint8_t[0]) {};

	uint8_t ikm[16] = {0};
	if (egetkey_wrapper_2(n256, policy, ikm)) {
		return 1;
	}

	sgx_cmac_128bit_key_t key;
	sgx_cmac_128bit_tag_t mac;

	memcpy(&key, ikm, 16);
	if (SGX_SUCCESS != sgx_rijndael128_cmac_msg(&key, a, alen, &mac)) {
		return 2;
	}
	memcpy(output, &mac, 16);

	return 0;
}

uint64_t compute_platform_id()
{
	uint8_t result[16] = {0};
	if (_compute_platform_id(NULL, NULL, 0, USGX_KEY_POLICY_SIG, result)) {
		return 0xFFFFFFFFFFFFFFFF;
	}

	uint64_t n = 0;
	for (size_t i = 0; i < 8; i++) {
		n |= (uint64_t) result[i] << (i * 8);
	}
	// n &= ~(1ULL << 63); // workaround because of ASN.1 compiler
	n &= 0x7FFFFFFFFFFFFFFF;
	n |= 0x7000000000000000;

#ifdef SRX_PLATFORM_ID
	uint64_t fake_pid = SRX_PLATFORM_ID;
	// fake_pid &= ~(1ULL << 63); // workaround because of ASN.1 compiler
	fake_pid &= 0x7FFFFFFFFFFFFFFF;
	fake_pid |= 0x7000000000000000;
	R(RLOG_VERBOSE | RLOG_LOW, "Platform ID is fake: 0x%016"PRIx64, fake_pid);
	return fake_pid;
#else
	R(RLOG_LOW | RLOG_VERBOSE, "Platform ID is real: 0x%016"PRIx64, n);
#endif

	return n;
}

// ciphertext length same as plaintext length
uint8_t aead_enc(const uint8_t *key128, const uint8_t *nonce96,
		const uint8_t *pt, uint32_t pt_len,
		const uint8_t *ad, uint32_t ad_len,
		uint8_t **ct, uint32_t *ct_len,
		uint8_t **tag128)
{
	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	memcpy(&key, key128, 16);

	uint8_t *ciphertext = malloc(pt_len);
	if (!ciphertext) {
		return 1;
	}

	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes

	sgx_status_t ss = sgx_rijndael128GCM_encrypt(&key, pt, pt_len,
			ciphertext, nonce96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		free(ciphertext);
		return 2;
	}

	uint8_t *tag = malloc(16);
	if (!tag) {
		free(ciphertext);
		return 3;
	}
	memcpy(tag, &mac, 16);
	*tag128 = tag;
	*ct = ciphertext;
	*ct_len = pt_len;

	return 0;
}

// plaintext length same as ciphertext length
uint8_t aead_dec(const uint8_t *key128, const uint8_t *nonce96,
		const uint8_t *ct, uint32_t ct_len,
		const uint8_t *ad, uint32_t ad_len,
		uint8_t **pt, uint32_t *pt_len,
		const uint8_t *tag128)
{
	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	memcpy(&key, key128, 16);

	uint8_t *plaintext = malloc(ct_len);
	if (!plaintext) {
		return 1;
	}

	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes
	memcpy(&mac, tag128, 16);

	sgx_status_t ss = sgx_rijndael128GCM_decrypt(&key, ct, ct_len,
			plaintext, nonce96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		free(plaintext);
		if (SGX_ERROR_MAC_MISMATCH == ss) {
			return SRX_E_BAD_MAC;
		}
		return 2;
	}

	*pt = plaintext;
	*pt_len = ct_len;

	return 0;
}

int aead_enc_noalloc(uint8_t *ct, uint8_t *tag128,
		const uint8_t *pt, uint32_t pt_len,
		const uint8_t *ad, uint32_t ad_len,
		const uint8_t *key128, const uint8_t *nonce96)
{
	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes

	memcpy(&key, key128, 16);

	sgx_status_t ss = sgx_rijndael128GCM_encrypt(&key, pt, pt_len,
			ct, nonce96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		return 1;
	}

	memcpy(tag128, &mac, 16);

	return 0;
}

int aead_dec_noalloc(uint8_t *pt,
		const uint8_t *ct, uint32_t ct_len,
		const uint8_t *ad, uint32_t ad_len,
		const uint8_t *key128, const uint8_t *nonce96, const uint8_t *tag128)
{
	sgx_aes_gcm_128bit_key_t key; // 16 bytes
	sgx_aes_gcm_128bit_tag_t mac; // 16 bytes

	memcpy(&key, key128, 16);
	memcpy(&mac, tag128, 16);

	sgx_status_t ss = sgx_rijndael128GCM_decrypt(&key, ct, ct_len,
			pt, nonce96, 12, ad, ad_len, &mac);
	if (SGX_SUCCESS != ss) {
		if (SGX_ERROR_MAC_MISMATCH == ss) {
			return SRX_E_BAD_MAC;
		}
		return 1;
	}

	return 0;
}

uint8_t gen_nonce(uint8_t *nonce, uint32_t length)
{
	sgx_status_t ss = sgx_read_rand(nonce, length);
	if (SGX_SUCCESS != ss) {
		return 1;
	}
	return 0;
}

uint8_t gen_sk(uint8_t *secret, uint32_t length)
{
	return gen_nonce(secret, length);
}

// RFC 5869
static uint8_t hkdf(uint8_t *okm, uint32_t okm_len,
		const uint8_t *salt, uint32_t salt_len,
		const uint8_t *ikm, uint32_t ikm_len,
		const uint8_t *info, uint32_t info_len)
{
	unsigned char skey[okm_len];
	size_t skeylen = okm_len;


	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!pctx)
		return 1;

	if (1 != EVP_PKEY_derive_init(pctx))
		return 2;
	if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()))
		return 3;
	if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len))
		return 4;
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len))
		return 5;
	if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len))
		return 6;
	if (1 != EVP_PKEY_derive(pctx, skey, &skeylen))
		return 7;

	memcpy(okm, skey, skeylen);

	EVP_PKEY_CTX_free(pctx);

	return 0;
}

uint8_t kbkdf(uint8_t *dest, uint32_t n,
	const uint8_t *ikm, uint32_t ikm_len,
	const uint8_t *salt, uint32_t salt_len,
	const uint8_t *info, uint32_t info_len)
{
	return hkdf(dest, n, salt, salt_len, ikm, ikm_len, info, info_len);
}

uint8_t get_key_128bit(const uint8_t *nonce256,
		const uint16_t policy, uint8_t *key128)
{
	return egetkey_wrapper_2(nonce256, policy, key128);
}

uint8_t ddkp_ec256(const uint8_t *nonce256, const uint8_t *salt256,
		const uint8_t *info, uint32_t info_len,
		uint8_t **kp, uint32_t *kp_len)
{
	// EGETKEY
	uint8_t ikm[16] = {0};
	if (egetkey_wrapper_2(nonce256, USGX_KEY_POLICY_SIG, ikm)) {
		return 1;
	}

	// HKDF
	uint8_t okm[32] = {0};
	if (hkdf(okm, 32, salt256, 32, ikm, 16, info, info_len)) {
		return 2;
	}

	// set EC private and public keys:

	char *str = NULL;
	if (usgx_hex_uint8_to_str(okm, 32, "", &str)) {
		return 3;
	}
	BIGNUM *bignum = NULL;
	if (!BN_hex2bn(&bignum, str)) {
		free(str);
		return 4;
	}
	free(str);

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(CURVE);
	if (!ec_key) {
		BN_free(bignum);
		return 5;
	}
	if (1 != EC_KEY_set_private_key(ec_key, bignum)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		return 6;
	}

	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	EC_POINT *point = EC_POINT_new(group);
	if (!point) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		return 7;
	}
	if (1 != EC_POINT_mul(group, point, bignum, NULL, NULL, NULL)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		EC_POINT_free(point);
		return 8;
	}
	if (1 != EC_KEY_set_public_key(ec_key, point)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		EC_POINT_free(point);
		return 9;
	}
	BN_free(bignum);
	EC_POINT_free(point);

	// serialize
	if (i2d_kp(ec_key, kp, kp_len)) {
		EC_KEY_free(ec_key);
		return 10;
	}



	// test TODO remove this
	char *hex_str = NULL;
	i2hs_kp(ec_key, &hex_str);
	printf("inside ddkp_ec256: hex=%s\n", hex_str);



	EC_KEY_free(ec_key);
	return 0;
}

uint8_t kp_ec256_get_public(const uint8_t *kp, uint32_t kp_len,
		uint8_t **pub, uint32_t *pub_len)
{
	// deserialize key pair
	EC_KEY *ec_key = NULL;
	if (d2i_kp(kp, kp_len, &ec_key)) {
		return 1;
	}

	// serialize only public key
	uint8_t *public_key = NULL;
	uint32_t public_key_len = 0;
	if (i2d_kp_public(ec_key, &public_key, &public_key_len)) {
		EC_KEY_free(ec_key);
		return 10;
	}

	*pub = public_key;
	*pub_len = public_key_len;


	// see code.md at 2 Feb


	// tests
	char *hex_str = NULL;
	if (i2hs_public(ec_key, &hex_str))
		abort();
	printf("kp_ec256_get_public (%"PRIu32"): hex=%s\n", *pub_len, hex_str);
	printf("key rray length of hex: %zu/2\n", strlen(hex_str));
	// length here includes the ":" which makes it longer!
	free(hex_str);




	EC_KEY_free(ec_key);
	return 0;
}

uint8_t der_sk(uint8_t *dest, uint32_t n,
	const uint8_t *nonce256,
	const uint8_t *salt256,
	const uint8_t *info, uint32_t info_len)
{
	// EGETKEY
	uint8_t ikm[16] = {0};
	if (egetkey_wrapper_2(nonce256, USGX_KEY_POLICY_SIG, ikm)) {
		return 1;
	}

	// HKDF
	uint8_t okm[n];
	memset(okm, 0, sizeof(okm));
	if (hkdf(okm, n, salt256, 32, ikm, 16, info, info_len)) {
		return 2;
	}

	memcpy(dest, okm, n);

	return 0;
}


// see code.md at 2 Feb

uint8_t der_kp(struct srx_kp **kp,
		const uint8_t *nonce256,
		const uint8_t *salt256,
		const uint8_t *info, uint32_t info_len)
{
	// EGETKEY
	uint8_t ikm[16] = {0};
	if (egetkey_wrapper_2(nonce256, USGX_KEY_POLICY_SIG, ikm)) {
		return 1;
	}

	// HKDF
	uint8_t okm[32] = {0};
	if (hkdf(okm, 32, salt256, 32, ikm, 16, info, info_len)) {
		return 2;
	}

	// set EC private and public keys:

	char *str = NULL;
	if (usgx_hex_uint8_to_str(okm, 32, "", &str)) {
		return 3;
	}
	BIGNUM *bignum = NULL;
	if (!BN_hex2bn(&bignum, str)) {
		free(str);
		return 4;
	}
	free(str);

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(CURVE);
	if (!ec_key) {
		//err
		BN_free(bignum);
		return 5;
	}
	if (1 != EC_KEY_set_private_key(ec_key, bignum)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		return 6;
	}

	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	EC_POINT *point = EC_POINT_new(group);
	if (!point) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		return 7;
	}
	if (1 != EC_POINT_mul(group, point, bignum, NULL, NULL, NULL)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		EC_POINT_free(point);
		return 8;
	}
	if (1 != EC_KEY_set_public_key(ec_key, point)) {
		BN_free(bignum);
		EC_KEY_free(ec_key);
		EC_POINT_free(point);
		return 9;
	}
	BN_free(bignum);
	EC_POINT_free(point);

	struct srx_kp *p = malloc(sizeof(struct srx_kp *));
	if (!p) {
		EC_KEY_free(ec_key);
		return 10;
	}

	p->key = ec_key;
	*kp = p;

	return 0;
}

uint8_t free_kp(struct srx_kp **kp)
{
	if ((*kp)->key)
		EC_KEY_free((*kp)->key);
	(*kp)->key = NULL;
	free(*kp);
	*kp = NULL;
	return 0x00;
}

uint8_t i2d_pub(const struct srx_kp *kp, uint8_t **pub, uint32_t *pub_len)
{
	if (!(kp->key)) {
		return 1;
	}

	unsigned char *ppout = NULL;
	int byte_count = i2d_EC_PUBKEY(kp->key, &ppout);
	if (0 > byte_count) {
		return 2;
	}

	*pub = (uint8_t *) ppout;
	*pub_len = byte_count;

	return 0;
}

uint8_t d2i_pub(struct srx_kp **kp, const uint8_t *pub, uint32_t pub_len)
{
	if (!pub || pub_len == 0) {
		return 1;
	}

	EC_KEY *ec_key = NULL;
	if (!d2i_EC_PUBKEY(&ec_key, (unsigned char **) &pub, (long) pub_len)) {
		return 2;
	}


	struct srx_kp *p = malloc(sizeof(*p));
	if (!p) {
		EC_KEY_free(ec_key);
		return 3;
	}

	p->key = ec_key;
	*kp = p;

	return 0;
}

uint8_t kp_compute_shared_key_dh(const struct srx_kp *keypair,
		const struct srx_kp *peerkey, uint8_t *shared_secret)
{
	assert(keypair);
	assert(peerkey);
	assert(shared_secret);

	EVP_PKEY *priv = EVP_PKEY_new();
	if (!priv) {
		return 11;
	}
	EVP_PKEY *pub = EVP_PKEY_new();
	if (!pub) {
		EVP_PKEY_free(priv);
		return 12;
	}

	if (1 != EVP_PKEY_set1_EC_KEY(priv, keypair->key)) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		return 13;
	}
	if (1 != EVP_PKEY_set1_EC_KEY(pub, peerkey->key)) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		return 14;
	}

	EVP_PKEY_CTX *ctx = NULL;
	ENGINE *e = NULL;
	unsigned char *skey = NULL;
	size_t key_len = 0;

	ctx = EVP_PKEY_CTX_new(priv, e);
	if (!ctx) {
		return 21;
	}

	if (1 != EVP_PKEY_derive_init(ctx)) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 22;
	}

	if (1 != EVP_PKEY_derive_set_peer(ctx, pub)) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 23;
	}

	if (1 != EVP_PKEY_derive(ctx, NULL, &key_len)) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 24;
	}

	skey = malloc(key_len);
	if (!skey) {
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 25;
	}

	if (P256_LENGTH != key_len) {
		R(RLOG_WARNING, "Unexpected shared secret length "
				"(expected = %d, got = %d)", P256_LENGTH, key_len);
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 26;
	}

	if (1 != EVP_PKEY_derive(ctx, skey, &key_len)) {
		free(skey);
		EVP_PKEY_free(priv);
		EVP_PKEY_free(pub);
		EVP_PKEY_CTX_free(ctx);
		return 27;
	}

	// we use uint8_t buffers for bytes instead of unsigned char like libcrypto
	for (size_t i = 0; i < P256_LENGTH; i++) {
		*(shared_secret + i) = (uint8_t) *(skey + i);
	}

	free(skey);
	EVP_PKEY_free(priv);
	EVP_PKEY_free(pub);
	EVP_PKEY_CTX_free(ctx);

	return 0;
}




// tirei de usgx, RA
static int ecdsa_sign(EVP_PKEY *key_pr,
		const void *data, size_t size,
		unsigned char **signature, size_t *signature_len)
{
	assert(key_pr);
	assert(data && size > 0);
	assert(!*signature);

	EVP_MD_CTX *mdctx = NULL;
	ENGINE *e = NULL;
	//unsigned char sigret[1024] = {0};
	//size_t siglen = sizeof sigret;
	//const unsigned char tbs[] = "hello world";
	//size_t tbslen = sizeof tbs;
	int ret = 0;

	unsigned char *sig = NULL;
	size_t sig_len = 0;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		fprintf(stderr, "EVP_MD_CTX_create: fail (%d)\n", ret);
		return -1;
	}

	ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), e, key_pr);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignInit: fail (%d)\n", ret);
		unsigned long err_long = ERR_get_error();
		fprintf(stderr, "%luL: %s\n", err_long, ERR_error_string(err_long, NULL));
		return -1;
	}

	ret = EVP_DigestSignUpdate(mdctx, data, size);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignUpdate: fail (%d)\n", ret);
		return -1;
	}

	ret = EVP_DigestSignFinal(mdctx, NULL, &sig_len);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignFinal: fail (size) (%d)\n", ret);
		return -1;
	}

	sig = malloc(sig_len);
	if (!sig) {
		fprintf(stderr, "malloc fail\n");
	}

	ret = EVP_DigestSignFinal(mdctx, sig, &sig_len);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignFinal: fail (%d)\n", ret);
		return -1;
	}
	fprintf(stderr, "sig_eln: %zu\n", sig_len);


	for (size_t i = 0; i < sig_len; i++)
		printf("%02X ", sig[i]);
	printf(" /END\n");

	//asn1_ecdsa_sig(sigret, siglen);

	*signature = sig;
	*signature_len = sig_len;

	EVP_MD_CTX_destroy(mdctx);

	return 0;
}

/*// needs to be reviewed
uint8_t sign(uint8_t **dest, uint32_t *dest_len,
		const uint8_t *src, uint32_t src_len,
		const uint8_t *priv, uint32_t priv_len)
{
	EC_KEY *ec_key = NULL;
	if (d2i_kp(priv, priv_len, &ec_key)) {
		return 1;
	}

	// usgx_ec256_signature *tmp_sig = NULL;
	unsigned char *sig = NULL;
	size_t sig_len = 0;

	if (ecdsa_sign(ec_key, src, src_len, &sig, &sig_len)) {
		// fprintf(stderr, "ecdsa_sign: fail\n");
		return 1;
	}

	// uint32_t r[8];
	// uint32_t s[8];
	//
	// if (asn1_to_rs_1(sig, sig_len, r, s)) {
	// 	// fprintf(stderr, "asn1_to_rs_1: fail\n");
	// 	free(sig);
	// 	return 1;
	// }
	//
	// *signature = tmp_sig;

	*dest = sig;
	*dest_len = sig_len;

	free(sig);

	return 0xEE;
}

// this should pull in some library and use its functionality
//TODO release resources
uint8_t verify(const uint8_t *src, uint32_t src_len,
		const uint8_t *pub, uint32_t pub_len,
		const uint8_t *original_sig, uint32_t original_sig_len)
{
	EC_KEY **ec_key = NULL;
	if (d2i_kp_public(pub, pub_len, &ec_key)) {
		return 238;
	}


	ENGINE *e = NULL;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		// fprintf(stderr, "EVP_MD_CTX_create: fail (%d)\n", ret);
		return 238;
	}

	int ret = 0;

	//FIXME  last arg is EVP_PKEY and I'm sending in EC_KEY
	ret = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), e, ec_key);
	if (1 != ret) {
		// fprintf(stderr, "EVP_DigestSignInit: fail (%d)\n", ret);
		// unsigned long err_long = ERR_get_error();
		// fprintf(stderr, "%luL: %s\n", err_long, ERR_error_string(err_long, NULL));
		return 238;
	}

	ret = EVP_DigestVerifyUpdate(mdctx, src, src_len);
	if (1 != ret) {
		// fprintf(stderr, "EVP_DigestSignUpdate: fail (%d)\n", ret);
		return 238;
	}

	unsigned char *sig = NULL;
	size_t sig_len = 0;

	ret = EVP_DigestVerifyFinal(mdctx, NULL, &sig_len);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignFinal: fail (size) (%d)\n", ret);
		return -1;
	}

	sig = malloc(sig_len);
	if (!sig) {
		fprintf(stderr, "malloc fail\n");
	}

	ret = EVP_DigestVerifyFinal(mdctx, sig, &sig_len);
	if (1 != ret) {
		fprintf(stderr, "EVP_DigestSignFinal: fail (%d)\n", ret);
		return -1;
	}
	fprintf(stderr, "sig_eln: %zu\n", sig_len);


	for (size_t i = 0; i < sig_len; i++)
		printf("%02X ", sig[i]);
	printf(" /END\n");

	//asn1_ecdsa_sig(sigret, siglen);

	// *signature = sig;
	// *signature_len = sig_len;

	EVP_MD_CTX_destroy(mdctx);

	//TODO  compare computed and received signatures

	return 0;
}*/

//uint8_t derive_secret(uint8_t *secret, uint32_t secret_len,
//		const uint8_t *nonce, uint32_t nonce_len,
//		const uint8_t *salt, uint32_t salt_len,
//		const char *info)
//{
//	EVP_PKEY_CTX *pctx;
//
//	//TODO: stub, place something here just to test `init_tp`
//
//	BIGNUM *bn = BN_new();
//
//	return 0;
//}

//TODO  specific error for no file is useful since path may be wrong
//@deprecated   No longer using Protected FS Library
uint8_t load_data(const char *path, const uint8_t *key, uint8_t **data, size_t *size)
{
	SGX_FILE *fp = sgx_fopen(path, "rb", (sgx_key_128bit_t *) key);
	if (!fp) {
		printf("errno  (%d)\n", errno);
		return 1;
	}

	// find file size
	if (sgx_fseek(fp, 0L, SEEK_END))
		goto evil_release;
	int64_t sz = sgx_ftell(fp);
	if (sz == -1)
		goto evil_release;
	if (sgx_fseek(fp, 0L, SEEK_SET))
		goto evil_release;
	// restrict max size; sealed file never empty
	if (sz < 1 || sz > 1024 * 1024)
		goto evil_release;
	printf("read size is = %"PRId64"\n", sz);

	uint8_t *p = malloc(sz);
	if (!p)
		goto evil_release;

	// for (size_t br = 0; (br += sgx_fread(p+br, sz-br, 1, fp)) > 0;);
	size_t br = sgx_fread(p, sz, 1, fp); // expect to read exactly 1 nmemb
	if (br != 1) {
		goto evil_release;
	}

	*data = p;
	*size = sz;

	sgx_fclose(fp);
	return 0;

evil_release:
	sgx_fclose(fp);
	return 3;
}

//@deprecated   No longer using Protected FS Library
uint8_t save_data(const char *path, const uint8_t *key, const uint8_t *data, size_t size)
{
	SGX_FILE *fp = sgx_fopen(path, "wb", (sgx_key_128bit_t *) key);
	if (!fp) {
		printf("errno  (%d)\n", errno);
		return 1;
	}

	uint8_t result = 0;
	printf("write size is = %zu\n", size);
	if (sgx_fwrite(data, size, 1, fp) != 1) {
		// write failed
		result = 3;
	}

	if (sgx_fclose(fp)) {
		int errsv = errno;
		printf("sgx_fclose failed (no flush, maybe), errno = %d", errsv);
		result = 4;
	}

	return result;
}
