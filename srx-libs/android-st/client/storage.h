// Handles data storage from enclave to disk/mem and vice-versa.

#pragma once

// read data
// deserialize AD
// reconstruct secret key x2 (AP and RP)
// decrypt data
// deserialize ED

#include "ds.h"

/**
** Handles entire pipeline from loading encrypted binary to internal structures.
**
** @postcondition       the Base Key is set in `root`     (ephemeral)
** @postcondition       the CSK and CIV are set in `root` (ephemeral)
**
** @param[in]   path    the destination path on the unstrusted side
** @param[in]   root    the destination structure allocated by the caller
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int eb2i(const char *path, struct root *root);

/**
** Handles entire pipeline from internal structures to saving encrypted binary.
**
** @postcondition       the Base Key is set in `root`     (ephemeral)
** @postcondition       the CSK and CIV are set in `root` (ephemeral)
**
** @return      Returns zero on success, or non-zero otherwise.
**/
int i2eb(const char *path, /*const */struct root *root);
