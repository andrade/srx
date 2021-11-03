#pragma once

/**
** Exchanges data with the security token.
**
** This function sends `data` to the ST, and
** receives as response an integer in [0, max_resp].
**
** NOTE: The amount of possible responses from the ST should be small
** since the client has to compute all possible responses for a match.
** A good rule of thumb is to use a response of zero for success, and
** of values greater than zero for error conditions.
**
** @param[out]  rc         The response from the ST, set on success
** @param[in]   max_resp   The largest possible response from the ST
** @param[in]   data       The data to send to the ST
** @param[in]   size       The size of the buffer to send to the ST
** @param[in]   sk_enc     The shared key for encryption
** @param[in]   sk_mac     The shared key for computing the HMAC over response
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int token_exchange_data(int *rc, int max_resp,
		const void *data, size_t size,
		const uint8_t *sk_enc, const uint8_t *sk_mac);
//int token_exchange_data(const void *data_in, size_t size_in,
//		void *data_out, size_t size_out, size_t *bytes_read);

/**
** Prepare the first network message.
**
** This message is sent from the client to the token.
** The caller allocates the destination buffer, but can call
** with a NULL `buffer` to have the total size set in `buffer_len`.
**
** Format: total-size||comm_nonce_len||comm_nonce||... where
** total-size is a uint32_t with the total length of the buffer and
** each subsequent size is a uint16_t.
**
** comm_nonce      [in] communication nonce
** comm_nonce_len  [in] length of communication nonce
** comm_pub        [in] communication public key
** comm_pub_len    [in] length of communication public key
** seal_nonce      [in] seal nonce
** seal_nonce_len  [in] length of seal nonce
** seal_pub        [in] seal public key
** seal_pub_len    [in] length of seal public key
** buffer         [out] destination buffer, can be NULL
** buffer_len     [out] length of destination buffer
**/
uint8_t i2n_m1(
		const uint8_t *comm_nonce, size_t comm_nonce_len,
		const uint8_t *comm_pub, size_t comm_pub_len,
		const uint8_t *seal_nonce, size_t seal_nonce_len,
		const uint8_t *seal_pub, size_t seal_pub_len,
		uint8_t *buffer, size_t *buffer_len);
