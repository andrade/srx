/*
 * Copyright (C) 2018 Niko Rosvall <niko@byteptr.com>
 */


#ifndef __UTILS_H
#define __UTILS_H

#include <stddef.h>
// #include <stdbool.h>
#include "entry.h"

void print_entry(Entry_t *entry, int show_password);
// char *get_lockfile_path();
// void write_active_database_path(const char *db_path);
char *read_active_database_path();
// bool has_active_database();      //TORM: used outside enclave in counterpart
void *tmalloc(size_t size);
// bool file_exists(const char *path);

/**
** Computes the path to the SRX sealed data.
**
** The path is based on the database path and placed in `srx_path`.
** The destination buffer is allocated by the caller and has capacity `cap`.
**/
void compute_srx_path(const char *db_path, char *srx_path, size_t cap);

#endif
