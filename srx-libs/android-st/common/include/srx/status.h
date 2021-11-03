#pragma once

typedef enum {
	SRX_SUCCESS = 0x00,  // success is always zero

	SRX_BAD_TAG = 0xC0,  // MAC mismatch

	SRX_FAILURE = 0xFF   // generic failure
} srx_status;

// Note #1: Try keeping values grouped by first hex (e.g. `0xC?` for crypto)

// Note #2: Values are in [0,255] in case need compatibility with `uint8_t`

// Note #3: Success is always set to `0` for easy checks

// Note #4: The list should be (very) small and only for the necessary codes
//          The main EDL uses these status codes
//          Internal code may use these but most functions rely on integers
