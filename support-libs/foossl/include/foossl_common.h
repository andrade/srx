#ifndef FOOSSL_COMMON_H
#define FOOSSL_COMMON_H

#include <openssl/ssl.h>

/**
** Reads n bytes from the SSL source and copies them
** into the caller allocated buffer.
**
** The function keeps reading until the required number of bytes
** have been read or the source channel returns an error.
**
** Returns 0 on success.
** On failure, caller should release ssl-related resources.
**/
int foossl_read(SSL *ssl, void *buffer, int n);

/**
** Writes n bytes from the source buffer into the target SSL channel.
**
** The function keeps writing until the required numbers of bytes
** have been written or the target channel returns an error.
**
** Returns 0 on success.
** On failure, caller should release ssl-related resources.
**/
int foossl_write(SSL *ssl, const void *buffer, int n);

#endif
