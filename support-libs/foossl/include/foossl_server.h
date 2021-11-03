#ifndef FOOSSL_SERVER_H
#define FOOSSL_SERVER_H

#include "openssl/ssl.h"

struct foossl_server_st {
	int sfd;
	SSL_CTX *ctx;
};

// functions return zero on success

int foossl_server_connect(struct foossl_server_st *foossl, int port);
int foossl_server_destroy(struct foossl_server_st *foossl);

/**
** Accepts a client connection request and
** connects the given ssl object with the file descriptor.
**
** Returns 0 on success.
**
** @see foossl_server_loop_release()
**/
int foossl_server_loop_acquire(struct foossl_server_st *foossl, SSL **ssl);

//NOTE: Could have `foossl_server_loop_acquire_2` that is like the one above, but has a third and fourth output arguments, one for IP and another for port of client. This can still be achieved by using SSL_get_fd to retrieve the underlying socket FD, and then using getpeername on it to retrieve the addr from which info can be extracted. The only issue is that by having to do that on the fd it is actually more wasted cycles since inside `foossl_server_loop_acquire` the address structure is already available so we could simply extract the info here. OTOH, if we do this and don't need the info, it's resource waste; hence having normal function and the other with the _1 added to its name that also returns IP and port.

/**
** Releases resources acquired in foossl_server_loop_acquire.
**
** Returns 0 on success.
**
** @see foossl_server_loop_acquire
**/
int foossl_server_loop_release(SSL *ssl);

int foossl_destroy();

// connect should receive params for key.pem/cert.pem

#endif
