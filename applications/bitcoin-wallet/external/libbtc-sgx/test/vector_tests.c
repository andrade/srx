/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libbtc-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/utils.h>
#include <btc/vector.h>

#if WITH_SGX
#include <mbusafecrt.h>
#endif

struct teststruct {
    void* dummy1;
    void* dummy2;
};

#if WITH_SGX
/**
 * Returns a pointer to a new string, duplicate of `s`.
 * The new string is malloc'd and the caller must free it.
 * Returns null on failure.
 */
static char *duplicate_str(const char *s)
{
    size_t size = strlen(s) + 1;
    char *copy = malloc(size);
    if (!copy)
        return NULL;
    if (strcpy_s(copy, size, s)) {
        free(copy);
        return NULL;
    }
    return copy;
}
#endif

void free_dummy(void* data)
{
    btc_free(((struct teststruct*)data)->dummy1);
    btc_free(((struct teststruct*)data)->dummy2);
    btc_free((struct teststruct*)data);
}

void test_vector()
{
    btc_bool res;
    char str0[] = "string";
    char str1[] = "rumba";

    vector* vec = vector_new(10, NULL);
    assert(vec != NULL);
    assert(vec->len == 0);
    assert(vec->alloc > 0);

    res = vector_add(vec, str0);
    assert(res == true);
    assert(vec->len == 1);

    res = vector_add(vec, str1);
    assert(res == true);
    assert(vec->len == 2);

    assert(vector_find(vec, str0) == 0);
    assert(vector_find(vec, "test") == -1);
    assert(vector_find(vec, str1) == 1);

    assert(strcmp(vector_idx(vec, 0), "string") == 0);
    assert(strcmp(vector_idx(vec, 1), "rumba") == 0);

    vector_remove_idx(vec, 0);
    assert(res == true);
    assert(strcmp(vector_idx(vec, 0), "rumba") == 0);

    vector_free(vec, true);

    vec = vector_new(10, free);
#if !WITH_SGX
    res = vector_add(vec, strdup("TEST0"));
    assert(res == true);
    res = vector_add(vec, strdup("TEST1"));
    assert(res == true);

    char* a_str = strdup("TEST2");
#else
    res = vector_add(vec, duplicate_str("TEST0"));
    assert(res == true);
    res = vector_add(vec, duplicate_str("TEST1"));
    assert(res == true);

    char* a_str = duplicate_str("TEST2");
#endif
    res = vector_add(vec, a_str);
    assert(res == true);
    assert(vec->len == 3);
    res = vector_remove(vec, a_str);
    assert(res == true);
    assert(vec->len == 2);
    vector_free(vec, true);


    /* test resize */
    vec = vector_new(1, free);
    res = vector_resize(vec, 30);
    assert(res == true);
    res = vector_resize(vec, 30);
    assert(res == true);
    char str[80];
    int i;
    for (i = 0; i < 20; i++) {
#if !WITH_SGX
        sprintf(str, "TEST%d", i);
        res = vector_add(vec, strdup(str));
#else
        sprintf_s(str, sizeof(str), "TEST%d", i);
        res = vector_add(vec, duplicate_str(str));
#endif
        assert(res == true);
        assert(vec->len == (size_t)i + 1);
    }

    res = vector_resize(vec, 5);
    assert(res == true);
    assert(strcmp(vector_idx(vec, 0), "TEST0") == 0);
    assert(strcmp(vector_idx(vec, 4), "TEST4") == 0);
    assert(vector_idx(vec, 5) == NULL);

    vector_remove_range(vec, 0, 4);
    assert(strcmp(vector_idx(vec, 0), "TEST4") == 0);
    vector_free(vec, true);


    /* test custom free callback handler */
    struct teststruct* some_data = btc_calloc(1, sizeof(struct teststruct));
    some_data->dummy1 = btc_calloc(1, 10);
    some_data->dummy2 = btc_calloc(1, 10);

    vec = vector_new(1, free_dummy);
    vector_add(vec, some_data);
    vector_free(vec, true);
}
