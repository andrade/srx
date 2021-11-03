#pragma once

#include <srx_error.h>

/**
** Returns a string that describes the error code.
** The string must not be modified by the caller.
** The string may be modified by subsequent calls to `srxerror()`.
**/
const char *srxerror(srx_status xs);
