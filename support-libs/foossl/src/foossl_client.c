#define _POSIX_C_SOURCE 201112L

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "foossl_client.h"

/**
** Creates a plain socket and attempts to connect.
**
** Returns a file descriptor for the connected socket on success, and
** returns -1 on error.
**/
static int socket_connect(const char *host, int port)
{
	int sfd = -1;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char service[sizeof(port) + 1];
	int ret;

	// convert port (see getaddrinfo(3))
	if (snprintf(service, sizeof(service), "%d", port) < 0) {
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_protocol = 0;
	ret = getaddrinfo(host, service, &hints, &result);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}
	// try each address until successful, close on each failure
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;
		close(sfd);
	}
	freeaddrinfo(result); //FIXME  Before rp==NULL?
	if (rp == NULL) {
		fprintf(stderr, "could not connect\n");
		return -1;
	}

	return sfd;
}

/**
** Creates a TLS endpoint, connects it with a socket, and begins the handshake.
**
** Returns 0 on success, and -1 on error.
**/
static int ssl_connect(struct foossl_client_st *foossl)
{
	// deprecated in OpenSSL 1.1.0 (also don't use specific method version):
	// SSL_load_error_strings();
	// SSL_library_init();
	// const SSL_METHOD *method = TLSv1_2_server_method();
	const SSL_METHOD *method = TLS_client_method();

	foossl->ctx = SSL_CTX_new(method);
	if (!foossl->ctx) {
		perror("ssl_ctx_new");
		return -1;
	}

	foossl->ssl = SSL_new(foossl->ctx);
	if (!foossl->ssl) {
		perror("ssl_new");
		return -1;
	}

	if (SSL_set_fd(foossl->ssl, foossl->sfd) != 1) {
		perror("ssl_set_fd");
		return -1;
	}

	if (SSL_connect(foossl->ssl) != 1) {
		perror("ssl_connect");
		return -1;
	}

	return 0;
}

int foossl_client_connect(struct foossl_client_st *foossl,
		const char *host, int port)
{
	foossl->sfd = -1;
	foossl->ctx = NULL;
	foossl->ssl = NULL;

	foossl->sfd = socket_connect(host, port);
	if (foossl->sfd == -1) {
		fprintf(stderr, "could not connect to %s:%d\n", host, port);
		return -1;
	}
	fprintf(stdout, "connected to %s:%d\n", host, port);

	if (ssl_connect(foossl)) {
		fprintf(stderr, "could not open a secure channel\n");
		return -1;
	}

	return 0;
}

int foossl_client_destroy(struct foossl_client_st *foossl)
{
	if (foossl->sfd)
		close(foossl->sfd);
	if (foossl->ssl)
		SSL_free(foossl->ssl);
	if (foossl->ctx)
		SSL_CTX_free(foossl->ctx);

	return 0;
}
