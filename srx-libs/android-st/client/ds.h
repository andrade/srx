/*
* Internal data structures.
*
* `ap` stands for Administrator Platform
* `rp` stands for Regular (or Recovery) Platform
*/

#pragma once

#include <stdint.h>

/** Max number of platforms other than administrator. No limit in design. */
#define SRX_MAX_NODES 16

/** Arbitrary max length for keys for easy stack allocation. */
#define SRX_MAX_KEYLEN 200

struct plaintext {
	uint8_t seed[16];           // derives secret keys for all platforms
	uint8_t ap_seal_nonce[32];  // sealing nonce of administrator
	uint8_t ap_comm_nonce[32];  // communication nonce of administrator
	uint8_t st_comm_pub[SRX_MAX_KEYLEN]; // comm public key of Security Token
	uint32_t st_comm_pub_len;
	uint8_t rp_comm_nonce[SRX_MAX_NODES][32]; // communication nonces for RPs
	uint8_t sk_enc[16];         // secret key for encryption (with ST)
	uint8_t sk_mac[32];         // secret key for hmac'ing (with ST)
	uint8_t gsn[32];            // Group Sealing Nonce, GSN (derives GSKP)
};

struct platform {
	uint64_t pid;
	uint8_t seal_nonce[32];
	uint8_t seal_pub[SRX_MAX_KEYLEN];
	uint32_t seal_pub_len;
	uint8_t encrypted_base_key[SRX_MAX_KEYLEN * 2];
	uint32_t encrypted_base_key_len;
	uint8_t ebk_tag[16];        // tag of the Encrypted Base Key
};

struct cleartext {
	uint8_t base_nonce[32];              // TORM
	uint8_t seal_nonce[32];
	uint64_t apid;                       // TORM
	uint8_t ap_seal_pub[SRX_MAX_KEYLEN]; // TORM
	uint32_t ap_seal_pub_len;            // TORM
	uint8_t encryption_nonce[32];
	uint8_t gspk[SRX_MAX_KEYLEN];        // Group Sealing Public Key, GSPK
	uint32_t gspk_len;
	struct platform platforms[SRX_MAX_NODES];
	uint32_t platforms_count;
};

/**
** Ephemeral data derived or generated during an enclave run.
** This structure is not serialized and stored in persistent memory.
**/
struct ephemeral {
	uint8_t base_key[16];             // derives CSK and IV for AEAD
	uint8_t csk[16];                  // the Common Sealing Key, CSK, for AEAD
	uint8_t iv[16];                   // the IV for AEAD
	uint8_t comm_pub[SRX_MAX_KEYLEN]; // comm public key of *this* platform
	uint32_t comm_pub_len;
};
//REVIEW `comm_pub` necessary if I have a `srx_kp` or similar? (to avoid successive extractions? that's optimization, no good.)

struct root {
	struct plaintext priv; // data to be encrypted
	struct cleartext open; // data stored unencrypted as additional data
	struct ephemeral temp; // for data generated/derived on each enclave run
};
// original had `pt`, `ct`, and `e`, instead of `priv`, `open`, and `temp`
// the new names are more clear on the visibility and lifetime of the data.

/**
** Dumps the root structure into `dest`.
** The caller allocates the buffer, which has size `capacity.`
**/
void dump_ds(char *dest, size_t capacity, const struct root *root);
