#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "tconst.h"

#include "rp.h"

/**
** Derives the 16-byte FSK and the 12-byte IV.
** These encrypt the Base Key.
** The caller allocates the two destination buffers.
** Returns zero on success, or non-zero otherwise.
**/
static int derive_fsk_and_iv(uint8_t *fsk16, uint8_t *iv12,
		const struct srx_kp *seal_kp,
		const uint8_t *peer_pub, size_t peer_pub_size,
		const uint8_t *enc_nonce32)
{
	struct srx_kp *peer_seal_pub = NULL;
	if (d2i_pub(&peer_seal_pub, peer_pub, peer_pub_size)) {
		return 1;
	}

	uint8_t shared_secret[32] = {0};
	if (kp_compute_shared_key_dh(seal_kp, peer_seal_pub, shared_secret)) {
		free_kp(&peer_seal_pub);
		return 2;
	}
	free_kp(&peer_seal_pub);

	if (kbkdf(fsk16, 16,
			shared_secret, 32,
			enc_nonce32, 32,
			FSK_INFO, sizeof FSK_INFO)) {
		return 3;
	}
	if (kbkdf(iv12, 12,
			shared_secret, 32,
			enc_nonce32, 32,
			FSK_IV_INFO, sizeof FSK_IV_INFO)) {
		return 4;
	}

	return 0;
}

/**
** Encrypts the Base Key for one RP.
**
** Requires: AP priv and RP pub (or vice-versa),
**           16-byte Base Key, and 32-byte Encryption Nonce.
** Produces: Encrypted Base Key for a specific RP, and 16-byte tag.
**
** The private key and public key generate a shared key (DH).
** The shared key and the Encryption Nonce derive a Final Shared Key.
** The shared key and the Encryption Nonce derive an IV.
** The Final Shared Key and the IV encrypt the Base Key.
**
** Returns zero on success, or non-zero otherwise.
**
** @see #decrypt_base_key()
**/
int encrypt_base_key(void *ebk, size_t cap, size_t *size, uint8_t *tag128,
		const struct srx_kp *seal_kp,
		const uint8_t *peer_pub, size_t peer_pub_size,
		const uint8_t *enc_nonce32,
		const uint8_t *base_key16)
{
	uint8_t fsk[16];
	uint8_t iv[12];
	if (derive_fsk_and_iv(fsk, iv,
			seal_kp, peer_pub, peer_pub_size, enc_nonce32)) {
		return 1;
	}

	if (16 > cap) {
		return 2; // ciphertext length at least fits Base Key
	}

	if (aead_enc_noalloc(ebk, tag128, base_key16, 16, NULL, 0, fsk, iv)) {
		return 3;
	}
	*size = 16;

	return 0;
}

/**
** Decrypts the Base Key for one RP.
**
** Requires: AP priv and RP pub (or vice-versa),
**           Encrypted Base Key (ciphertext), 32-byte Encryption Nonce, and
**           16-byte tag.
** Produces: 16-byte Base Key for a specific RP.
**
** The private key and public key generate a shared key (DH).
** The shared key and the Encryption Nonce derive a Final Shared Key.
** The shared key and the Encryption Nonce derive an IV.
** The Final Shared Key and the IV decrypt the Base Key.
**
** Returns zero on success, or non-zero otherwise.
**
** @see #encrypt_base_key()
**/
int decrypt_base_key(uint8_t *base_key16,
		const struct srx_kp *seal_kp,
		const uint8_t *peer_pub, size_t peer_pub_size,
		const uint8_t *enc_nonce32,
		const void *ebk, size_t size, const uint8_t *tag128)
{
	uint8_t fsk[16];
	uint8_t iv[12];
	if (derive_fsk_and_iv(fsk, iv,
			seal_kp, peer_pub, peer_pub_size, enc_nonce32)) {
		return 1;
	}

	if (16 != size) {
		return 2; // ciphertext same length as Base Key
	}

	int r = aead_dec_noalloc(base_key16, ebk, 16, NULL, 0, fsk, iv, tag128);
	if (r) {
		if (r == SRX_E_BAD_MAC) {
			// R(RLOG_ERROR, "Error decrypting base key, tag mismatch");
			return SRX_E_BAD_MAC;
		}
		// R(RLOG_ERROR, "Error decrypting base key");
		return 3;
	}

	return 0;
}
