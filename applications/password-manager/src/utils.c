// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT
/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */

#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include "entry.h"
#include "utils.h"
// #include "crypto.h"   // is_file_encrypted() no longer used in original form

#include <sgx_eid.h>
#include <sgx_error.h>

#include "enclave_u.h"

extern sgx_enclave_id_t enclave_id;

#define COLOR_DEFAULT "\x1B[0m"

static char *get_output_color()
{
    char *color = getenv("TITAN_COLOR");

    if(color == NULL)
        return COLOR_DEFAULT;

    if(strcmp(color, "BLUE") == 0)
        return "\x1B[34m";
    else if(strcmp(color, "RED") == 0)
        return "\x1B[31m";
    else if(strcmp(color, "GREEN") == 0)
        return "\x1B[32m";
    else if(strcmp(color, "YELLOW") == 0)
        return "\x1B[33m";
    else if(strcmp(color, "MAGENTA") == 0)
        return "\x1B[35m";
    else if(strcmp(color, "CYAN") == 0)
        return "\x1B[36m";
    else if(strcmp(color, "WHITE") == 0)
        return "\x1B[37m";
    else
        return COLOR_DEFAULT; /* Handle empty variable too */
}

void titan_ocall_print_entry(int id,
        char *title, char *user, char *url,
        char *password, char *notes, char *stamp,
        int show_password)
{
    Entry_t entry = {
        .id = id,
        .title = title,
        .user = user,
        .url = url,
        .password = password,
        .notes = notes,
        .stamp = stamp,
        .next = NULL
    };
    print_entry(&entry, show_password);
}

bool print_entry(Entry_t *entry, int show_password)
{
    char *color = get_output_color();

    fprintf(stdout, "=====================================================================\n");

    /* Set the color */
    fprintf(stdout, "%s", color);

    fprintf(stdout, "ID: %d\n", entry->id);
    fprintf(stdout, "Title: %s\n", entry->title);
    fprintf(stdout, "User: %s\n", entry->user);
    fprintf(stdout, "Url: %s\n", entry->url);

    if(show_password == 1)
        fprintf(stdout, "Password: %s\n", entry->password);
    else
        fprintf(stdout, "Password: **********\n");

    fprintf(stdout, "Notes: %s\n", entry->notes);
    fprintf(stdout, "Modified: %s\n", entry->stamp);

    /* Reset the color */
    fprintf(stdout, "%s", COLOR_DEFAULT);

    fprintf(stdout, "=====================================================================\n");

    return 0;
}

bool file_exists(const char *path)
{
    struct stat buf;

    if(stat(path, &buf) != 0)
        return false;

    return true;
}

/* Function checks that we have a valid path
 * in our lock file ~~and if the database is not
 * encrypted~~.
 */
bool has_active_database(sgx_enclave_id_t eid)
{
    char *path = NULL;

    path = get_lockfile_path();

    if(!path)
        return false;

    struct stat buf;

    if(stat(path, &buf) != 0)
    {
        free(path);
        return false;
    }

    // //If the database is encrypted, it's not active so return false
    // sgx_status_t ss;
    // bool is_encrypted;
    // ss = titan_ecall_is_file_encrypted(eid, &is_encrypted, path);
    // if (ss) {
    //     fprintf(stderr, "ecall failure: is_file_encrypted (%#x)\n", ss);
    //     abort();
    // }
    // if(is_encrypted)
    // {
    //     free(path);
    //     return false;
    // }

    free(path);

    return true;
}

/* Returns the path of ~/.titan.sgx.lock file.
 * Caller must free the return value */
char *get_lockfile_path()
{
    char *home = NULL;
    char *path = NULL;

    home = getenv("HOME");

    if(!home)
        return NULL;

    /* /home/user/.titan.sgx.lock */
    path = tmalloc(sizeof(char) * (strlen(home) + 13));

    strcpy(path, home);
    strcat(path, "/.titan.sgx.lock");

    return path;
}

int titan_ocall_read_active_database_path(char *path, size_t capacity)
{
    char *db_path = read_active_database_path();
    if (!db_path) {
        return 1;
    }

    strncpy(path, db_path, capacity);
    path[capacity - 1] = '\0';

    free(db_path);

    return 0;
}

/* Reads and returns the path of currently decrypted
 * database. Caller must free the return value */
char *read_active_database_path()
{
    FILE *fp = NULL;
    char *path = NULL;
    char *lockpath = NULL;
    size_t len;

    path = get_lockfile_path();

    if(!path)
        return NULL;

    fp = fopen(path, "r");

    if(!fp)
    {
        free(path);
        return NULL;
    }

    /* We only need the first line from the file */

    if(getline(&lockpath, &len, fp) < 0)
    {
        if(lockpath)
            free(lockpath);

        fclose(fp);
        free(path);

        return NULL;
    }

    fclose(fp);
    free(path);

    return lockpath;
}

void write_active_database_path(const char *db_path)
{
    FILE *fp = NULL;
    char *path = NULL;

    path = get_lockfile_path();

    if(!path)
        return;

    fp = fopen(path, "w");

    if(!fp)
    {
        fprintf(stderr, "Error creating lock file\n");
        free(path);
        return;
    }

    fprintf(fp, "%s", db_path);
    fclose(fp);

    free(path);
}

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
