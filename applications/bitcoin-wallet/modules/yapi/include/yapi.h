#pragma once

#include <stdint.h>

#include <sgx_eid.h>

/** Represents a Yapi wallet. */
typedef struct yapi_st {
	sgx_enclave_id_t eid;
} yapi;

/** A transaction. */
typedef struct yapi_tx_st {
} yapi_tx;
// unused

/** A public key. Private keys appear only inside the TEE. */
typedef struct yapi_key_st {
} yapi_key;
// unused

/*                wallet / core                */

// int yapi_init(yapi **p, const uint8_t *data, const size_t size);
/**
 * Initialize all necessary structures.
 * Implicitly generates a new HD master key for the wallet.
 * Returns zero on success, non-zero otherwise.
 */
int yapi_init(const char *srx_path, yapi **p);

/**
 * Releases resources.
 *
 * Returns zero on success, in which case *p is set to NULL.
 */
int yapi_free(yapi **p);

/*                keys                */

/**
 * Derives a new key from the secure HD master key.
 *
 * The derivation path of the key follows BIP 32. Example `m/0'/0'/33`.
 * The output format is P2PKH.
 *
 * Returns zero on success, non-zero otherwise.
 */
int yapi_keys_derive_to_p2pkh(const yapi *p, const char *dp, char **p2pkh);

/**
 * Creates a transaction using P2PKH addresses.
 *
 * Whatever amount does not go to recipient or change address is miner fee.
 *
 * tx_hex: the signed transaction, mem allocated internally
 * prev_tx_hex: hash of previous TX (which is used for input)
 * input_addr_dp: derivation path of input address (enclave derives the keys)
 * ia_index: index of the input in the previous hash (usually 0 if only one)
 * output_addr_p2pkh: receiver address
 * oa_len: length of receiver address
 * amount: amount to transfer to receiver
 * change_addr_dp: derivation path for change address, or NULL (no change)
 * change_amount: amount that goes to change address
 */
int yapi_tx_simple_p2pkh(const yapi *p,
		char **tx_hex,
		const char *prev_tx_hex,
		const char *input_addr_dp, uint32_t ia_index, uint64_t ia_amount,
		const char *output_addr_p2pkh, uint32_t oa_len,
		const uint64_t amount,
		const char *change_addr_dp, uint64_t change_amount);

/** Converts a yapi tx to raw format to send to network. */
int yapi_tx_to_hex(const yapi_tx *tx, uint8_t **hex);
// not implemented

/** Converts a raw tx to yapi format. */
int yapi_hex_to_tx(const uint8_t *hex, yapi_tx **tx);
// not implemented

/*                util                */

/**
 * Serializes a Yapi Wallet (bytes, suitable for storage or network transfer).
 *
 * Returns zero on success.
 */
int yapi_to_bytes(const yapi *p, uint8_t **data, size_t *size);

/**
 * Deserializes a byte buffer into a Yapi Wallet.
 *
 * Returns zero on success.
 */
int bytes_to_yapi(const char *srx_path, const uint8_t *data, size_t size, yapi **p);

/*                SRX                */

// path to save initialization data to
void srx_platform_init(const char *save_path);

// path to load initialization data of new platform from (!= from SRX state)
void srx_platform_add(const yapi *p, const char *load_path);

// use list to find the list of platforms IDs in the group
void srx_platform_remove(const yapi *y, uint64_t pid);

// lists the platform IDs of all platforms that have access to the data
void srx_platform_list(const yapi *y);
