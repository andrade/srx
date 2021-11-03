/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_BENCH_H
#define SECP256K1_BENCH_H

#include <stdio.h>
#include <string.h>
#include <math.h>

#if !ENABLE_SGX

#include "sys/time.h"

static double gettimedouble(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
}

#else /* ENABLE_SGX */

#include <stdlib.h>
#include <inttypes.h>

#include "sgx_trts.h"
#include "sgx_tae_service.h"
/*#include "enclave_t.h"*/

#include "sgx/t/util.h"

static double gettimedouble(void) {
    sgx_status_t ss;
    sgx_time_t time;
    sgx_time_source_nonce_t nonce;

    ss = sgx_get_trusted_time(&time, &nonce);
    if (ss != SGX_SUCCESS)
        abort();

    return (double) time;
    /* NOTE uint64_t left capacity greater than double */
    /* NOTE not retrying busy calls */
    /* NOTE not checking nonce */
}

#endif /* ENABLE_SGX */

void print_number(double x) {
    double y = x;
    int c = 0;
    if (y < 0.0) {
        y = -y;
    }
    while (y > 0 && y < 100.0) {
        y *= 10.0;
        c++;
    }
    printf("%.*f", c, x);
}

void run_benchmark(char *name, void (*benchmark)(void*), void (*setup)(void*), void (*teardown)(void*), void* data, int count, int iter) {
    int i;
    double min = HUGE_VAL;
    double sum = 0.0;
    double max = 0.0;
#if ENABLE_SGX
    if (sgx_create_pse_session())
        abort();
#endif
    for (i = 0; i < count; i++) {
        double begin, total;
        if (setup != NULL) {
            setup(data);
        }
        begin = gettimedouble();
        benchmark(data);
        total = gettimedouble() - begin;
        if (teardown != NULL) {
            teardown(data);
        }
        if (total < min) {
            min = total;
        }
        if (total > max) {
            max = total;
        }
        sum += total;
    }
#if ENABLE_SGX
    if (sgx_close_pse_session())
        abort();
#endif
    printf("%s: min ", name);
    print_number(min * 1000000.0 / iter);
    printf("us / avg ");
    print_number((sum / count) * 1000000.0 / iter);
    printf("us / max ");
    print_number(max * 1000000.0 / iter);
    printf("us\n");
}

int have_flag(int argc, char** argv, char *flag) {
    char** argm = argv + argc;
    argv++;
    if (argv == argm) {
        return 1;
    }
    while (argv != NULL && argv != argm) {
        if (strcmp(*argv, flag) == 0) {
            return 1;
        }
        argv++;
    }
    return 0;
}

#endif /* SECP256K1_BENCH_H */
