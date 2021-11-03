#pragma once

#include <stdint.h>

extern const uint8_t KP_SALT[32];

// Context info for deriving the platform communication key pair
extern const uint8_t KP_COMM_INFO[4];
// Context info for deriving the platform sealing key pair
extern const uint8_t KP_SEAL_INFO[4];

// KDF context information for deriving the Common Sealing Key
extern const uint8_t CSK_INFO[3];
// KDF context information for deriving the common encryption IV
extern const uint8_t CSK_IV_INFO[4];

extern const uint8_t FSK_INFO[3];       // Context info for deriving FSK, and
extern const uint8_t FSK_IV_INFO[4];    // derive IV for encryption of Base Key

extern const uint8_t SK_INFO[10];
