#ifndef _SGX_UTIL_H
#define _SGX_UTIL_H

#include <stdarg.h>

#define fprintf(stream, format, ...) do { printf(format, ##__VA_ARGS__); } while (0)

/*#define fprintf(stream, format, ...) do { printf(format, ...); } while (0)

#define puts(strptr) do { ocall_print(1, #strptr "\n"); } while (0)*/

/*#define puts(strptr) do { } while (0)*/

/*extern int stdin, stdout, stderr;*/

#ifdef __cplusplus
extern "C" {
#endif

int printf(const char *format, ...);

/*int fprintf(FILE *stream, const char *format, ...);*/

int putchar(int c);

int puts(const char *s);

#ifdef __cplusplus
}
#endif

#endif
