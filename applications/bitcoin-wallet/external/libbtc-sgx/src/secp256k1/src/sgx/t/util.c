#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/*#include "sgx_trts.h"*/
/*#include "tests_exhaustive_t.h"*/
/*#include "bench_verify_t.h"*/
#include "util.h"

/*#include "sgx_util.h"*/

/*int stdin = 0, stdout = 1, stderr = 2;*/



/*#define fprintf(stream, format, ...) do { printf(format, ...); } while (0)*/

/*#define puts(strptr) do { ocall_print(1, #strptr "\n"); } while (0)*/

int printf(const char *format, ...)
{
    int size = 0;
    char *p = NULL;
    va_list ap;
    
    /* find string size */
    va_start(ap, format);
    size = vsnprintf(p, size, format, ap);
    va_end(ap);
    
    if (size < 0)
        return size;

    size++; /* for null byte */
    
    /*char buf[size] = {'\0'};*/
    p = malloc(size);
    if (!p)
        return -1;
    va_start(ap, format);
    size = vsnprintf(p, size, format, ap);
    if (size < 0) {
        free(p);
        return size;
    }
    va_end(ap);
    
    /* send to untrusted side, 1 for stdout */
    ocall_print(1, p);
    free(p);
    
    return size;
}

/*int fprintf(FILE *stream, const char *format, ...)
{
    return 0;
}*/

int putchar(int c)
{
    printf("%c", c);
    return c;
}

int puts(const char *s)
{
    return printf("%s\n", s);
}
