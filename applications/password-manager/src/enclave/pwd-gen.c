// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#include <stdio.h>
#include <stdlib.h>

#include <sgx_trts.h>

#include "utils.h"

/* Simply generate secure password
 * and output it to the stdout
 *
 * Caller must free the return value.
 */
char *generate_password(int length)
{
    char *pass = tmalloc((length + 1) * sizeof(char));

    if (sgx_read_rand((unsigned char *) pass, length)) {
        fprintf(stderr, "SGX random generator failed. Abort.\n");
        abort();
    }

    pass[length] = '\0';

    fprintf(stdout, "%s\n", pass);

    return pass;
}
