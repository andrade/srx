#pragma once

#include <stddef.h>
#include <stdint.h>

#include "interr.h"

#define USGX_KEY_POLICY_ENC 0x0001  // derive using enclave measurement register
#define USGX_KEY_POLICY_SIG 0x0002  // derive using signer measurement register

struct srx_kp;
// struct srx_sk;
//functions to: srx_kp to pub or priv or both, and vice_versa. sk to DER and vice-versa for storing in binary.

/**
** Computes a unique platform identifier.
** The identifier is different for every platform+signer combination.
** Returns the identifier on success, or all bits set to 1 on error.
**/
uint64_t compute_platform_id();

/**
** AEAD encryption.
**
** Encrypts plaintext `pt` with secret key `key128` and IV `nonce96`, and
** returns ciphertext `ct` and tag `tag128`.
** Associated data `ad` is optional (can be `NULL`).
**
** Returns zero on success, or non-zero otherwise.
** `ct`, `ct_len`, and `tag128` are set on success.
**/
uint8_t aead_enc(const uint8_t *key128, const uint8_t *nonce96,
		const uint8_t *pt, uint32_t pt_len,
		const uint8_t *ad, uint32_t ad_len,
		uint8_t **ct, uint32_t *ct_len,
		uint8_t **tag128);

/**
** AEAD decryption.
**
** Associated data `ad` is optional (can be `NULL`).
**
** The plaintext, pt, is malloc'd internally. The caller is
** responsible for releasing `pt`, on success.
**
** key128      [in] the 16-byte secret key
** nonce96     [in] the unique 12-byte IV
** ct          [in] the ciphertext
** ct_len      [in] the ciphertext length
** ad          [in] the associated data (it is not encrypted)
** ad_len      [in] the associatd data length
** pt         [out] the plaintext
** pt_len     [out] the plaintext length
** tag128      [in] the 16-byte tag
**
** Returns zero on success, or non-zero otherwise.
** Returns `SRX_E_BAD_MAC` on tag mismatch.
**/
uint8_t aead_dec(const uint8_t *key128, const uint8_t *nonce96,
		const uint8_t *ct, uint32_t ct_len,
		const uint8_t *ad, uint32_t ad_len,
		uint8_t **pt, uint32_t *pt_len,
		const uint8_t *tag128);

/**
** AEAD encryption.
**
** The caller allocates the destination buffers `ct` and `tag128`.
** The length of `ct` is the same as `pt`.
**
** Returns zero on success, or non-zero otherwise.
**
** @see #aead_dec_noalloc()
**/
int aead_enc_noalloc(uint8_t *ct, uint8_t *tag128,
		const uint8_t *pt, uint32_t pt_len,
		const uint8_t *ad, uint32_t ad_len,
		const uint8_t *key128, const uint8_t *nonce96);

/**
** AEAD decryption.
**
** The caller allocates the destination buffer `pt`.
** The length of `pt` is the same as `ct`.
**
** Returns zero on success, or non-zero otherwise.
** Returns `SRX_E_BAD_MAC` on tag mismatch.
**
** @see #aead_enc_noalloc()
**/
int aead_dec_noalloc(uint8_t *pt,
		const uint8_t *ct, uint32_t ct_len,
		const uint8_t *ad, uint32_t ad_len,
		const uint8_t *key128, const uint8_t *nonce96, const uint8_t *tag128);

/**
** Generates a random nonce.
**
** The nonce has length `length` in bytes.
**
** The nonce is placed in `nonce`, which must be of
** length equal to or greater than `length`.
** `nonce` is allocated by caller.
** On failure, the content of `nonce` is unspecified.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t gen_nonce(uint8_t *nonce, uint32_t length);

/**
** Generates a secret key.
**
** The secret key has length `length` and is stored in `secret`.
** The destination pointer is prevously allocated to
** accommodate the secret key.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t gen_sk(uint8_t *secret, uint32_t length);

//uint8_t gen_kp_ec256(uint8_t *pvt_key_r, uint8_t *pub_key_gx, uint8_t *pub_key_gy);

// uint8_t hkdf(uint8_t *okm, uint32_t okm_len,
// 		const uint8_t *salt, uint32_t salt_len,
// 		const uint8_t *ikm, uint32_t ikm_len,
// 		const uint8_t *info, uint32_t info_len);

/**
** Derives additional keys from another key.
**
** dest       [out] the secret key in hex; the caller allocates the array
** n           [in] the length of the secret key
** ikm         [in] input keying material
** ikm_len     [in] length of `ikm`
** salt        [in] a non-secret random value
** salt_len    [in] length of `salt`
** info        [in] the context and application-specific information
** info_len    [in] length of `info`
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t kbkdf(uint8_t *dest, uint32_t n,
		const uint8_t *ikm, uint32_t ikm_len,
		const uint8_t *salt, uint32_t salt_len,
		const uint8_t *info, uint32_t info_len);

/**
** Generates a secret key.
**
** The key is based on the input and on the processor key hierarchy.
** The key is the same when the nonce is repeated.
**
** nonce256  [in] the 256-bit nonce directly affects the key generation
** policy    [in] either `0x0001` or `0x0002` for an enclave- or
**                a signer-specific key respectively
** key128   [out] the generated 128-bit secret key
**/
uint8_t get_key_128bit(const uint8_t *nonce256,
		const uint16_t policy, uint8_t *key128);

/**
** Derives a deterministic key pair from `nonce256`, `salt256`, and `info`.
**
** This function is based on `EGETKEY`.
** Uses `USGX_KEY_POLICY_SIG` by default (SIGNER measurement register).
**
** Returns zero on success in which case `kp` and `kp_len` are set, or
** non-zero otherwise.
**/
uint8_t ddkp_ec256(const uint8_t *nonce256, const uint8_t *salt256,
		const uint8_t *info, uint32_t info_len,
		uint8_t **kp, uint32_t *kp_len);
// Consider accepting policy SIGNER or ENCLAVE (not useful for this case..).

uint8_t kp_ec256_get_public(const uint8_t *kp, uint32_t kp_len, uint8_t **pub, uint32_t *pub_len);



/**
** Derives a deterministic secret key.
**
** The secret key derivation is based on a nonce, a salt, and
** a piece of contextual information.
** The expected length of the secret key (OKM) is `n` and
** the buffer to hold the secret key is allocated by the caller.
**
** dest       [out] the secret key in hex; the caller allocates the array
** n           [in] the length of the secret key
** nonce256    [in] the (secret) IKM for the EGETKEY instruction
** salt256     [in] the (non-secret random) salt for the KBKDF
** info        [in] the context specific information
** info_len    [in] the length of `info`
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t der_sk(uint8_t *dest, uint32_t n,
		const uint8_t *nonce256,
		const uint8_t *salt256,
		const uint8_t *info, uint32_t info_len);

/**
** Derives a deterministic key pair.
**
** The memory for the key pair is allocated inside, and
** must be deallocated by the caller.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t der_kp(struct srx_kp **kp,
		const uint8_t *nonce256,
		const uint8_t *salt256,
		const uint8_t *info, uint32_t info_len);

/**
** Releases the resources allocated by a key pair.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t free_kp(struct srx_kp **kp);

/**
** Converts the public key from internal to DER.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t i2d_pub(const struct srx_kp *kp, uint8_t **pub, uint32_t *pub_len);

/**
** Converts a DER public key to internal.
**
** Returns zero on success, or non-zero otherwise.
**/
uint8_t d2i_pub(struct srx_kp **kp, const uint8_t *pub, uint32_t pub_len);

// [done] d2i_pub // e.g. when receiving KP from Security Token
//i2d_priv  // for serializing and storing if needed? always derived?
//d2i_priv  // for serializing and storing if needed? always derived?

/**
** Computes a shared secret.
**
** Uses the private key of the local platform and the public key of the peer
** to compute a shared secret using ECDH.
**
** The caller allocates `shared_secret`.
**
** @param[in]   keypair         local key pair
** @param[in]   peerkey         public key of peer
** @param[out]  shared_secret   the 32-byte shared secret
**
** @return      Returns zero on success, or non-zero otherwise.
**/
uint8_t kp_compute_shared_key_dh(const struct srx_kp *keypair,
		const struct srx_kp *peerkey, uint8_t *shared_secret);



uint8_t derive_secret(uint8_t *secret, uint32_t secret_len,
		const uint8_t *nonce, uint32_t nonce_len,
		const uint8_t *salt, uint32_t salt_len,
		const char *info);

// load file from disk, places it, unencrypted, in data; rets 0 on success
uint8_t load_data(const char *path, const uint8_t *key,
		uint8_t **data, size_t *size);

// save file to disk; rets 0 on success
uint8_t save_data(const char *path, const uint8_t *key,
		const uint8_t *data, size_t size);
