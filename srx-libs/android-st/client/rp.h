#pragma once

#include <stddef.h>
#include <stdint.h>

int encrypt_base_key(void *ebk, size_t cap, size_t *size, uint8_t *tag128,
		const struct srx_kp *seal_kp,
		const uint8_t *peer_pub, size_t peer_pub_size,
		const uint8_t *enc_nonce32,
		const uint8_t *base_key16);

int decrypt_base_key(uint8_t *base_key16,
		const struct srx_kp *seal_kp,
		const uint8_t *peer_pub, size_t peer_pub_size,
		const uint8_t *enc_nonce32,
		const void *ebk, size_t size, const uint8_t *tag128);
