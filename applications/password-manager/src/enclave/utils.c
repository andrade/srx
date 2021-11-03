// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
// #include <string.h>
// #include <sys/stat.h>
#include "entry.h"
#include "utils.h"
// #include "crypto.h"

#include "enclave_t.h"

// #define COLOR_DEFAULT "\x1B[0m"
//
// static char *get_output_color()
// {
//     char *color = getenv("TITAN_COLOR");
//
//     if(color == NULL)
//         return COLOR_DEFAULT;
//
//     if(strcmp(color, "BLUE") == 0)
//         return "\x1B[34m";
//     else if(strcmp(color, "RED") == 0)
//         return "\x1B[31m";
//     else if(strcmp(color, "GREEN") == 0)
//         return "\x1B[32m";
//     else if(strcmp(color, "YELLOW") == 0)
//         return "\x1B[33m";
//     else if(strcmp(color, "MAGENTA") == 0)
//         return "\x1B[35m";
//     else if(strcmp(color, "CYAN") == 0)
//         return "\x1B[36m";
//     else if(strcmp(color, "WHITE") == 0)
//         return "\x1B[37m";
//     else
//         return COLOR_DEFAULT; /* Handle empty variable too */
// }

void print_entry(Entry_t *entry, int show_password)
{
    titan_ocall_print_entry(entry->id,
            entry->title,
            entry->user,
            entry->url,
            show_password ? entry->password : NULL,
            entry->notes,
            entry->stamp,
            show_password);
}

// bool file_exists(const char *path)
// {
//     struct stat buf;
//
//     if(stat(path, &buf) != 0)
//         return false;
//
//     return true;
// }
//
// /* Function checks that we have a valid path
//  * in our lock file and if the database is not
//  * encrypted.
//  */
// bool has_active_database()
// {
//     char *path = NULL;
//
//     path = get_lockfile_path();
//
//     if(!path)
//         return false;
//
//     struct stat buf;
//
//     if(stat(path, &buf) != 0)
//     {
//         free(path);
//         return false;
//     }
//
//     //If the database is encrypted, it's not active so return false
//     if(is_file_encrypted(path))
//     {
//         free(path);
//         return false;
//     }
//
//     free(path);
//
//     return true;
// }
//
// /* Returns the path of ~/.titan.sgx.lock file.
//  * Caller must free the return value */
// char *get_lockfile_path()
// {
//     char *home = NULL;
//     char *path = NULL;
//
//     home = getenv("HOME");
//
//     if(!home)
//         return NULL;
//
//     /* /home/user/.titan.sgx.lock */
//     path = tmalloc(sizeof(char) * (strlen(home) + 13));
//
//     strcpy(path, home);
//     strcat(path, "/.titan.sgx.lock");
//
//     return path;
// }

/* Reads and returns the path of database.
 * Caller must free the return value */
char *read_active_database_path()
{
    size_t size = 512;
    char *db_path = tmalloc(size);

    sgx_status_t ss;
    int rc;

    ss = titan_ocall_read_active_database_path(&rc, db_path, size);
    if (ss) {
        fprintf(stderr, "ocall failure: read active DB path (%#x)\n", ss);
        free(db_path);
        return NULL;
    }
    fprintf(stdout, "ocall success: read active DB path (%#x)\n", ss);
    if (rc) {
        free(db_path);
        return NULL;
    }

    return db_path;
}

// void write_active_database_path(const char *db_path)
// {
//     FILE *fp = NULL;
//     char *path = NULL;
//
//     path = get_lockfile_path();
//
//     if(!path)
//         return;
//
//     fp = fopen(path, "w");
//
//     if(!fp)
//     {
//         fprintf(stderr, "Error creating lock file\n");
//         free(path);
//         return;
//     }
//
//     fprintf(fp, "%s", db_path);
//     fclose(fp);
//
//     free(path);
// }

//Simple malloc wrapper to prevent enormous error
//checking every where in the code
void *tmalloc(size_t size)
{
    void *data = NULL;

    data = malloc(size);

    if(data == NULL)
    {
        fprintf(stderr, "Malloc failed. Abort.\n");
        abort();
    }

    return data;
}

void compute_srx_path(const char *db_path, char *srx_path, size_t cap)
{
    size_t required_len = strlen(db_path) + 1 + 4;
    if (required_len > cap) {
        fprintf(stderr, "required len is %zu, got %zu\n", required_len, cap);
        abort();
    }
    snprintf(srx_path, cap, "%s.srx", db_path);
}
