#pragma once

// initializes a wallet and saves it to disk at `path`
void yt_init_wallet(const char *path);

// derive an address from a derivation path using the enclave seed
void yt_derive_address(const char *path, const char *dp);

// creates and signs a transaction; prints the transaction to stdout
void tx_t1(const char *path,
		const char *input_prev, int input_index,
		const char *input_dp, long input_amount,
		const char *output_addr, long output_amount,
		const char *change_dp, long change_amount);

void yt_platform_init(const char *dest_path);
void yt_platform_add(const char *wallet_path, const char *src_path);
void yt_platform_remove(const char *wallet_path, uint64_t pid);
void yt_platform_list(const char *wallet_path);
