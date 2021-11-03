#pragma once

/**
** DER-encodes the `TokenAuth` message.
**
** The destination buffer, `dest`, can be NULL in which case
** the required buffer size is placed in `bytes_encoded`.
**
** @param[out]  dest           The destination buffer, allocated by the caller
** @param[in]   dest_len       The size of the destination buffer
** @param[out]  bytes_encoded  The number of bytes encoded
** @param[in]   str            The text to display on the token side
** @param[in]   len            The length of the text to display
** @param[in]   rn             The response nonce
** @param[in]   rn_size        The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int encode_TokenAuth(uint8_t *dest, size_t dest_len, size_t *bytes_encoded,
		const char *str, size_t len,
		const uint8_t *rn, size_t rn_size);

/**
** DER-encodes the `TokenInitAP` message.
**
** The destination buffer, `dest`, can be NULL in which case
** the required buffer size is placed in `bytes_encoded`.
**
** @param[out]  dest           The destination buffer, allocated by caller
** @param[in]   dest_len       The size of the destination buffer
** @param[out]  bytes_encoded  The number of bytes encoded
**
** @param[in]   rn             The response nonce
** @param[in]   rn_size        The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int encode_TokenInitAP(uint8_t *dest, size_t dest_len, size_t *bytes_encoded,
		const uint8_t *pid, size_t pid_size,
		const uint8_t *ras_sig, size_t ras_sig_len,
		const uint8_t *sk_enc, size_t sk_enc_len,
		const uint8_t *sk_mac, size_t sk_mac_len,
		const uint8_t *rn, size_t rn_size);

/**
** DER-encodes the `TokenInitRP` message.
**
** The destination buffer, `dest`, can be NULL in which case
** the required buffer size is placed in `bytes_encoded`.
**
** @param[out]  dest           The destination buffer, allocated by caller
** @param[in]   capacity       The capacity of the destination buffer
** @param[out]  bytes_encoded  The amount of bytes encoded
** @param[in]   pid            The DER-encoded platform details
** @param[in]   pid_size       The size of `pid`
** @param[in]   sig            The signature over `pid` by the RAS
** @param[in]   sig_size       The size of `sig`
** @param[in]   rn             The response nonce
** @param[in]   rn_size        The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int encode_TokenInitRP(void *dest, size_t capacity, size_t *bytes_encoded,
		const void *pid, size_t pid_size,
		const void *sig, size_t sig_size,
		const void *rn, size_t rn_size);

/**
** DER-encodes the `TokenRemoveRP` message.
**
** The destination buffer, `dest`, can be NULL in which case
** the required buffer size is placed in `bytes_encoded`.
**
** @param[out]  dest           The destination buffer, allocated by caller
** @param[in]   capacity       The capacity of the destination buffer
** @param[out]  bytes_encoded  The amount of bytes encoded
** @param[in]   pid            The RP ID
** @param[in]   rn             The response nonce
** @param[in]   rn_size        The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int encode_TokenRemoveRP(void *dest, size_t capacity, size_t *bytes_encoded,
		uint64_t rpid,
		const void *rn, size_t rn_size);

/**
** DER-encodes the `TokenReplace` message.
**
** The destination buffer, `dest`, can be NULL in which case
** the required buffer size is placed in `bytes_encoded`.
**
** @param[out]  dest           The destination buffer, allocated by caller
** @param[in]   capacity       The capacity of the destination buffer
** @param[out]  bytes_encoded  The amount of bytes encoded
** @param[in]   pid            The RP ID that replaces the AP
** @param[in]   rn             The response nonce
** @param[in]   rn_size        The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int encode_TokenReplace(void *dest, size_t capacity, size_t *bytes_encoded,
		uint64_t rpid,
		const void *rn, size_t rn_size);
