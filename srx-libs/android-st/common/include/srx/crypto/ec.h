/**
** API for EC crypto based on curve P-256.
**
** - Uses own internal format for keys because
**   the SDK of the Intel SGX may be unavailable.
**/
#pragma once

#include <stdint.h>

#include "srx/status.h"

struct srx_kp;

/**
** Creates a key pair using EC P-256.
**
** The private key is set to `priv` when given, otherwise
** the private key is generated randomly.
**
** @param[out]  kp    the key pair in internal format, allocates mem internally
** @param[in]   priv  the 32-byte private key in OpenSSL's byte order, or NULL
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int srx_init_kp(struct srx_kp **kp, const uint8_t *priv);

/**
** Releases resources of `*kp` and sets it to NULL.
** Does nothing if `*kp` already NULL.
**/
void srx_free_kp(struct srx_kp **kp);

/**
** Loads a key pair from disk.
**
** Allocates memory internally for the key pair.
** The caller releases the resources when the key pair
** is no longer needed with `srx_free_kp`.
**
** @param[out]  kp    the key pair in internal format, allocates mem internally
** @param[in]   path  path to PEM-encoded private key
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int srx_load_kp(struct srx_kp **kp, const char *path);

/**
** Encodes the private key as DER (SEC1).
**
** To find the required size for `dest` can call the function with `dest` NULL.
**
** @param[out]  dest  buffer for private key, allocated by caller; can be NULL
** @param[in]   len   length of `dest`
** @param[in]   kp    a key pair
**
** @return      Returns the number of bytes encoded on success,
**              when `dest` is NULL, or when the buffer is not large enough.
**              Returns zero on error.
**/
size_t srx_i2d_priv(uint8_t *dest, size_t len, const struct srx_kp *kp);

/**
** Decodes a private key from DER (SEC1).
**
** The destination variable, `kp`, is allocated internally on success, and
** the caller releases it with `srx_free_kp()`.
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int srx_d2i_priv(struct srx_kp **kp, const uint8_t *src, size_t len);

/**
** Encodes the private key into octets.
**
** Can set `dest` to NULL to find its required size.
**
** @param[out]  dest  buffer for private key, allocated by caller; can be NULL
** @param[in]   len   length of `dest`
** @param[in]   kp    a key pair
**
** @return      Returns the number of bytes encoded on success,
**              when `dest` is NULL, or when the buffer is not large enough.
**              Returns zero on error.
**/
size_t srx_i2o_priv(uint8_t *dest, size_t len, const struct srx_kp *kp);

/**
** Encodes the public key as DER.
**
** To find the required size for `dest` can call the function with `dest` NULL.
**
** @param[out]  dest  buffer for public key, allocated by caller; can be NULL
** @param[in]   len   length of `dest`
** @param[in]   kp    a key pair
**
** @return      Returns the number of bytes encoded on success,
**              when `dest` is NULL, or when the buffer is not large enough.
**              Returns zero on error.
**/
size_t srx_i2d_pub(uint8_t *dest, size_t len, const struct srx_kp *kp);

/**
** Decodes a public key from DER (SEC1).
**
** The destination variable, `kp`, is allocated internally on success, and
** the caller releases it with `srx_free_kp()`.
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int srx_d2i_pub(struct srx_kp **kp, const uint8_t *src, size_t len);

/**
** Encodes the public key into octets.
**
** Can set `dest` to NULL to find its required size.
**
** @param[out]  dest  buffer for public key, allocated by caller; can be NULL
** @param[in]   len   length of `dest`
** @param[in]   kp    a key pair
**
** @return      Returns the number of bytes encoded on success,
**              when `dest` is NULL, or when the buffer is not large enough.
**              Returns zero on error.
**/
size_t srx_i2o_pub(uint8_t *dest, size_t len, const struct srx_kp *kp);

/**
** Signs `data` using the private key in `kp`.
**
** Can set `dest` to NULL to find its required size.
**
** @param[out]  dest      buffer for signature, allocated by caller; may be NULL
** @param[in]   dest_len  length of `dest`
** @param[in]   data      the data to sign
** @param[in]   data_len  length of `data`
** @param[in]   kp        a key pair containing a private key
**
** @return      Returns the length of the signature on success,
**              when `dest` is NULL, or when the buffer is not large enough.
**              Returns zero on error.
**/
size_t srx_sign(uint8_t *dest, size_t dest_len,
		const void *data, size_t data_len, const struct srx_kp *kp);

/**
** Verifies a signature.
**
** @param[out]  sig       the signature
** @param[in]   sig_len   length of `sig`
** @param[in]   data      the signed data
** @param[in]   data_len  length of `data`
** @param[in]   kp        a key pair containing a public key
**
** @return      Returns SRX_SUCCESS (always zero) on success,
**              returns SRX_FAILURE on error, or
**              returns SRX_BAD_TAG on MAC mismatch.
**/
srx_status srx_verify(const uint8_t *sig, size_t sig_len,
		const void *data, size_t data_len, const struct srx_kp *kp);
