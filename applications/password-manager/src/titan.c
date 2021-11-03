// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#define _POSIX_C_SOURCE 201112L

#include <stdio.h>
#include <stdlib.h>
#include <time.h> // for measuring execution time with clock_gettime()
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include "cmd_ui.h"
// #include "entry.h"
// #include "db.h"
// #include "utils.h"
// #include "pwd-gen.h"
// #include "crypto.h"
// #include "network.h" // connect/disconnect agora feito diretamente network.c

#define CSP_INIT
#include "csysperf.h"

#include <sgx_urts.h>
#include "enclave_u.h"
#define E_FILE "enclave.signed.so"

static int show_password = 0;
static int force = 0;
static int auto_encrypt = 0;

static double v = 1.3;

sgx_enclave_id_t enclave_id = 0;

#if CSP_ENABLED
// measurements for create and destroy enclave
static void bench_enclave_lc()
{
    #define BENCH_N 600 // warm up plus iterations
    sgx_status_t ss[BENCH_N] = {0};
    sgx_enclave_id_t enclave_id[BENCH_N] = {0};

    // bench, warm up
    for (size_t i = 0; i < 100; i++) {
        ss[i] = sgx_create_enclave(E_FILE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id[i], NULL);
    }
    CSP_POKE(MICRO, 0);
    for (size_t i = 0; i < 500; i++) {
        ss[100+i] = sgx_create_enclave(E_FILE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id[100+i], NULL);
    }
    CSP_POKE(MICRO, 1);
    // bench, result x500: 33.251887141 [microbench]

    for (size_t i = 0; i < 100+500; i++) {
        if (SGX_SUCCESS != ss[i]) {
            fprintf(stderr, "sgx_create_enclave: failure (%#x)\n", ss[i]);
            abort();
        }
    }

    // bench, warm up
    for (size_t i = 0; i < 100; i++) {
        ss[i] = sgx_destroy_enclave(enclave_id[i]);
    }
    CSP_POKE(MICRO, 0);
    for (size_t i = 0; i < 500; i++) {
        ss[100+i] = sgx_destroy_enclave(enclave_id[100+i]);
    }
    CSP_POKE(MICRO, 1);
    // bench, result x500: 0.768155147 [microbench]

    for (size_t i = 0; i < 100+500; i++) {
        if (SGX_SUCCESS != ss[i]) {
            fprintf(stderr, "sgx_destroy_enclave: failure (%#x)\n", ss);
            abort();
        }
    }
}
#endif

static bool create_enclave()
{
    sgx_status_t ss = SGX_SUCCESS;

    ss = sgx_create_enclave(E_FILE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "sgx_create_enclave: failure (%#x)\n", ss);
		return 1;
	}
	fprintf(stdout, "sgx_create_enclave: success\n");

    return 0;
}

static bool destroy_enclave()
{
    sgx_status_t ss = SGX_SUCCESS;

    ss = sgx_destroy_enclave(enclave_id);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "sgx_destroy_enclave: failure (%#x)\n", ss);
		return 1;
	}
	fprintf(stdout, "sgx_destroy_enclave: success\n");

    return 0;
}

static uint64_t str2u64(const char *s)
{
	errno = 0;
	char *endptr = NULL;

	unsigned long long int ull = strtoull(s, &endptr, 0);

	if (errno || ull > UINT64_MAX) {
		abort();
	}
	if (s == endptr) {
		fprintf(stderr, "`%s` is not a number\n", s);
		abort();
	}

	return (uint64_t) ull;
}

static void version()
{
    printf("Titan SGX version %.1f (pre-α)\n", v);
}

static void usage()
{
#define HELP "\
SYNOPSIS\n\
\n\
    titan [flags] [options]\n\
\n\
OPTIONS\n\
\n\
    -i --init                <path>   Initialize new database\n\
    -e --encrypt                      Encrypt the current password database\n\
    -E --encrypt-file        <path>   Encrypt a file using strong encryption  ✗\n\
    -w --encrypt-directory   <path>   Encrypt all files in the directory      ✗\n\
    -d --decrypt             <path>   Decrypt password database\n\
    -D --decrypt-file        <path>   Decrypt a file encrypted with Titan     ✗\n\
    -W --decrypt-directory   <path>   Decrypt all files in the directory      ✗\n\
    -a --add                          Add new entry\n\
    -s --show-db-path                 Show current database path\n\
    -u --use-db              <path>   Switch using another database\n\
    -r --remove              <id>     Remove entry pointed by id\n\
    -f --find                <search> Search entries                          ✗\n\
    -F --regex               <search> Search entries with regular expressions ✗\n\
    -c --edit                <id>     Edit entry pointed by id                ✗\n\
    -l --list-entry          <id>     List entry pointed by id\n\
    -t --show-latest         <count>  Show latest <count> entries             ✗\n\
    -A --list-all                     List all entries\n\
    -h --help                         Show short help and exit. This page\n\
    -g --gen-password        <length> Generate password                       ✗\n\
    -q --quick               <search> This is the same as running             ✗\n\
                                      --show-passwords -f\n\
\n\
    --platform-init                   Initialize a platform             (SRX)\n\
    --platform-add                    Add initialized platform to group (SRX)\n\
    --platform-remove                 Remove a platform from the group  (SRX)\n\
    --platform-list                   List platforms with data access   (SRX)\n\
\n\
    -V --version                      Show version number of program\n\
\n\
FLAGS\n\
\n\
    --auto-encrypt                    Automatically encrypt after exit\n\
    --show-passwords                  Show passwords in listings\n\
    --force                           Ignore everything and force operation   ✗\n\
                                      --force only works with --init option\n\
\n\
For more information and examples see man titan(1).\n\
\n\
AUTHORS\n\
    Copyright (C) 2019 Daniel Andrade\n\
    Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>\n\
\n\
NOTES\n\
    Only a subset of these options have been adapted for Intel SGX.\n\
    The remaining options are still listed but do nothing when used.\n\
"
    printf(HELP);
}

// int main_two(int argc, char **argv);
// int main(int argc, char **argv)
// {
//     printf("string argv[1]: %s\n", argv[1]);
//     // const char *operation = "--add";
//     const char *operation = "-l1";
//     if (argc > 1 && (!strcmp(argv[1], operation))) {
//         for (size_t i = 0; i < 100; i++) {
//             optind = 1;
//             main_two(argc, argv);
//         }
//         CSP_POKE(MICRO, 0);
//         for (size_t i = 0; i < 500; i++) {
//             optind = 1;
//             main_two(argc, argv);
//         }
//         CSP_POKE(MICRO, 1);
//         CSP_REPORT(0);
//     } else {
//         main_two(argc, argv);
//     }
// }
// int main_two(int argc, char **argv)
int main(int argc, char *argv[])
{
    // CSP_POKE(MAIN, 0);

#if !defined (EVAL_EXCLUDE_LIFECYCLE) && defined (EVAL_INCLUDE_LIFECYCLE)
    clockid_t clock_id = CLOCK_PROCESS_CPUTIME_ID;
    struct timespec begin, end;
    int ret_begin, ret_end;

    ret_begin = clock_gettime(clock_id, &begin);
#endif

    // CSP_POKE(SERVER_C, 0);
    // if (server_connect()) {
    //     fprintf(stderr, "could not connect to the remote server\n");
    //     return 1;
    // }
    // CSP_POKE(SERVER_C, 1);

    // CSP_POKE(ENCLAVE_C, 0);
    if (create_enclave()) {
        return 1;
    }
    // CSP_POKE(ENCLAVE_C, 1);

#if defined (EVAL_EXCLUDE_LIFECYCLE) && !defined (EVAL_INCLUDE_LIFECYCLE)
    clockid_t clock_id = CLOCK_PROCESS_CPUTIME_ID;
    struct timespec begin, end;
    int ret_begin, ret_end;

    ret_begin = clock_gettime(clock_id, &begin);
#endif

    int c;

    if(argc == 1)
    {
        usage();
        return 0;
    }

    while(true)
    {
        static struct option long_options[] =
        {
            {"init",                  required_argument, 0, 'i'},
            {"decrypt",               required_argument, 0, 'd'},
            // {"decrypt-file",          required_argument, 0, 'D'},
            // {"decrypt-directory",     required_argument, 0, 'W'},
            {"encrypt",               no_argument,       0, 'e'},
            // {"encrypt-file",          required_argument, 0, 'E'},
            // {"encrypt-directory",     required_argument, 0, 'w'},
            {"add",                   no_argument,       0, 'a'},
            {"remove",                required_argument, 0, 'r'},
            {"find",                  required_argument, 0, 'f'},
            {"regex",                 required_argument, 0, 'F'},
            {"edit",                  required_argument, 0, 'c'},
            {"list-entry",            required_argument, 0, 'l'},
            {"use-db",                required_argument, 0, 'u'},
            {"list-all",              no_argument,       0, 'A'},
            {"help",                  no_argument,       0, 'h'},
            {"version",               no_argument,       0, 'V'},
            {"show-db-path",          no_argument,       0, 's'},
            {"gen-password",          required_argument, 0, 'g'},
            {"quick",                 required_argument, 0, 'q'},
            {"show-latest",           required_argument, 0, 't'},
            {"platform-init",         required_argument, 0, 'I'},
            {"platform-add",          required_argument, 0, 'N'},
            {"platform-remove",       required_argument, 0, 'R'},
            {"platform-list",         no_argument,       0, 'L'},
            {"auto-encrypt",          no_argument,       &auto_encrypt,  1},
            {"show-passwords",        no_argument,       &show_password, 1},
            {"force",                 no_argument,       &force, 1},
            {0, 0, 0, 0}
        };

        int option_index = 0;

        c = getopt_long(argc, argv, "i:d:D:W:eE:w:ar:f:F:c:l:Asu:hVg:q:t:",
                        long_options, &option_index);

        if(c == -1)
            break;

        switch(c)
        {
        case 0:
            /* Handle flags here automatically */
            break;
        case 'i':
            // CSP_POKE(INIT_DB_N_SAVE_FUNC, 0);
            init_database(optarg, force, auto_encrypt);
            // CSP_POKE(INIT_DB_N_SAVE_FUNC, 1);
            break;
        case 'd': //decrypt
            decrypt_database(optarg);
            break;
        // case 'D':
        //     decrypt_any_file(optarg);
        //     break;
        case 'e': //encrypt
            encrypt_database();
            break;
        // case 'E':
        //     encrypt_any_file(optarg);
        //     break;
        // case 'w':
        //     encrypt_directory(optarg);
        //     break;
        // case 'W':
        //     decrypt_directory(optarg);
        //     break;
        case 'a':
            // // bench, warm up
            // for (size_t i = 0; i < 100; i++)
            //     add_new_entry(auto_encrypt);
            // CSP_POKE(MICRO, 0);
            // for (size_t i = 0; i < 500; i++)
            //     add_new_entry(auto_encrypt);
            // CSP_POKE(MICRO, 1);
            // // bench, result x500 (+cache): 0.406428736 [microbench]
            // // bench, result x500 (-cache): 0.911295881 [microbench]
            // CSP_POKE(LOAD_N_ADD_ENTRY_N_SAVE_FUNC, 0);
            add_new_entry(auto_encrypt);
            // CSP_POKE(LOAD_N_ADD_ENTRY_N_SAVE_FUNC, 1);
            break;
        case 's':
            show_current_db_path();
            break;
        case 'h':
            usage();
            break;
        case 'r':
            remove_entry(atoi(optarg), auto_encrypt);
            break;
        case 'u':
            set_use_db(optarg);
            break; //TODO this `break` was missing in raw, was it on purpose?
        // case 'f':
        //     find(optarg, show_password, auto_encrypt);
        //     break;
        // case 'F':
        //     find_regex(optarg, show_password);
        //     break;
        // case 'c':
        //     edit_entry(atoi(optarg), auto_encrypt);
        //     break;
        case 'l':
            // // bench, warm up
            // for (size_t i = 0; i < 100; i++)
            //     list_by_id(atoi(optarg), show_password, auto_encrypt);
            // CSP_POKE(MICRO, 0);
            // for (size_t i = 0; i < 500; i++)
            //     list_by_id(atoi(optarg), show_password, auto_encrypt);
            // CSP_POKE(MICRO, 1);
            // // bench, result x500 (+cache): 0.161206352 [microbench]
            // // bench, result x500 (-cache): 0.457206496 [microbench]
            // CSP_POKE(LOAD_N_LIST_ID_FUNC, 0);
            list_by_id(atoi(optarg), show_password, auto_encrypt);
            // CSP_POKE(LOAD_N_LIST_ID_FUNC, 1);
            break;
        case 'A':
            // CSP_POKE(LOAD_N_LIST_ALL_FUNC, 0);
            list_all(show_password, auto_encrypt, -1);
            // CSP_POKE(LOAD_N_LIST_ALL_FUNC, 1);
            break;
        case 'V':
            version();
            break;
        case 'I':
            srx_platform_init(optarg);
            break;
        case 'N':
            srx_platform_add(optarg);
            break;
        case 'R':
            srx_platform_remove(str2u64(optarg));
            break;
        case 'L':
            srx_platform_list();
            break;
        // case 'g':
        //     generate_password(atoi(optarg));
        //     break;
        // case 'q':
        //     show_password = 1;
        //     find(optarg, show_password, auto_encrypt);
        //     break;
        // case 't':
        //     show_latest_entries(show_password, auto_encrypt, atoi(optarg));
        //     break;
        case '?':
            usage();
            break;
        }
    }

#if defined (EVAL_EXCLUDE_LIFECYCLE) && !defined (EVAL_INCLUDE_LIFECYCLE)
    ret_end = clock_gettime(clock_id, &end);

    if (ret_begin || ret_end) {
        fprintf(stderr, "process execution time in seconds: BAD CLOCK\n");
        return 1;
    }

    double execution_time = (end.tv_nsec - begin.tv_nsec) / 1000000000.0
    + (end.tv_sec - begin.tv_sec);
    long long secs = (end.tv_sec - begin.tv_sec);
    long nsecs = (end.tv_nsec - begin.tv_nsec);
    printf("process execution time in seconds: %lld.%.9ld\n", secs, nsecs);
    // printf("process execution time in seconds: %f\n", execution_time);
    printf("process execution time excludes LC\n");
#endif

    // CSP_POKE(ENCLAVE_D, 0);
    destroy_enclave();
    // CSP_POKE(ENCLAVE_D, 1);
    // CSP_POKE(SERVER_D, 0);
    // server_disconnect();
    // CSP_POKE(SERVER_D, 1);

#if !defined (EVAL_EXCLUDE_LIFECYCLE) && defined (EVAL_INCLUDE_LIFECYCLE)
    ret_end = clock_gettime(clock_id, &end);

    if (ret_begin || ret_end) {
        fprintf(stderr, "process execution time in seconds: BAD CLOCK\n");
        return 1;
    }

    double execution_time = (end.tv_nsec - begin.tv_nsec) / 1000000000.0
    + (end.tv_sec - begin.tv_sec);
    long long secs = (end.tv_sec - begin.tv_sec);
    long nsecs = (end.tv_nsec - begin.tv_nsec);
    printf("process execution time in seconds: %lld.%.9ld\n", secs, nsecs);
    // printf("process execution time in seconds: %f\n", execution_time);
    printf("process execution time includes LC\n");
#endif

    // CSP_POKE(MAIN, 1);
    // bench_enclave_lc();
    // CSP_REPORT(0);

    return 0;
}
