// Copyright 2019 Daniel Andrade
// SPDX-License-Identifier:  MIT

#pragma once

#include <tsgxsslio.h>

/* --------[                     Linux                     ]-------- */

int printf(const char *format, ...);

#define fprintf(stream, format, ...) do { printf(format, ##__VA_ARGS__); } while (0)

//#define FILE void

//char *strdup(const char *s);
char *sgx_strdup(const char *s);
#define strdup(s) sgx_strdup(s)
