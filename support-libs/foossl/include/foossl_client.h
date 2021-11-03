#ifndef FOOSSL_CLIENT_H
#define FOOSSL_CLIENT_H

#include "openssl/ssl.h"

struct foossl_client_st {
	int sfd;
	SSL_CTX *ctx;
	SSL *ssl;
};

// functions return zero on success

int foossl_client_connect(struct foossl_client_st *foossl,
		const char *host, int port);
int foossl_client_destroy(struct foossl_client_st *foossl);

// server certificate is not verified (its using a self-signed certificate)

#endif
