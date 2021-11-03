#pragma once

/**
** Exchanges data with the security token.
**
** This function sends `data` to the ST, and
** receives as response an integer in [0, expected_max_resp].
** The function fails if the response of the Security Token is out of bounds.
**
** NOTE: The amount of possible responses from the ST should be small
** since the client has to compute all possible responses for a match.
** A good rule of thumb is to use a response of zero for success, and
** of values greater than zero for error conditions.
**
** The secret key for encryption, `sk_enc`, may be null in which case
** the data is sent to the Security Token in cleartext.
**
** @param[out]  rc         The response from the ST, set on success
** @param[in]   max_resp   The largest possible response from the ST
** @param[in]   data       The data to send to the ST
** @param[in]   size       The size of the buffer to send to the ST
** @param[in]   sk_enc     The 16-byte shared key for encryption, may be null
** @param[in]   sk_mac     The 32-byte shared key for computing the response
** @param[in]   rn         The 32-byte response nonce
** @param[in]   rn_size    The size of the response nonce
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int token_exchange_data(int *rc, int expected_max_resp,
		const void *data, size_t size,
		const uint8_t *sk_enc, const uint8_t *sk_mac,
		const uint8_t *rn, size_t rn_size);
