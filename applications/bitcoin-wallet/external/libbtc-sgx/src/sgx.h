/* Copyright 2018 Daniel Andrade, released under the MIT License */

/**
 * This file is included in all other source files.
 *
 * Defines common functions not available inside the enclave.
 */

#ifndef __LIBBTC_SGX_H__
#define __LIBBTC_SGX_H__

#include <limits.h>

/*                endian.h                */

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)

#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)

/*                stdio.h                */

// gobble output, TODO implement with OCALL
#define printf(...) do { 0; } while (0)

static unsigned long next = 1;

static void rand_seed(unsigned int seed)
{
	next = seed;
}

static int rand_next()
{
	next = next * 1103515245 + 12345;
	return ((unsigned)(next / sizeof(UINT_MAX)) % INT_MAX);
}

#define rand() (rand_next())
#define srand(x) do { rand_seed(x); } while (0)

/*                stdlib.h                */

#define exit(x) do { x == 0 ? 0 : 1; } while (0)

#define getenv(x) (NULL)

#endif
