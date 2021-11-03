#pragma once

typedef enum {
	SRX_SUCCESS             = 0,    // success is always zero
	SRX_FAILURE             = 1000, // generic failure

	/** Insufficient memory or target capacity. */
	SRX_NO_MEM              = 1003,

	/** No such entity (e.g. object, path). */
	SRX_NO_ENT              = 1004,

	SRX_BAD_TAG             = 1301, // MAC mismatch

	/** Platform has no access rights for this operation. */
	SRX_NO_PERM             = 1302,

	/** User rejected the operation. */
	SRX_NO_AUTH             = 1303,

	/** Cannot perform it on oneself. */
	SRX_NO_SELF             = 1369,
} srx_status;
